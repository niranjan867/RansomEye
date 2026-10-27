"""Focused tests for the RansomEye PCAP network analyzer."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from ransomeye import dashboard_server
from ransomeye.pcap_analyzer import (
    ANALYZER_VERSION,
    MAX_PCAP_SIZE,
    PcapAnalyzer,
    PcapAnalysisError,
    STATUS_COMPLETE,
    STATUS_EMPTY,
    STATUS_MALFORMED,
    STATUS_UNSUPPORTED_FORMAT,
    ingest_pcap_finding,
)
from ransomeye.storage import EvidenceStore

# --------------------------------------------------------------------------- #
# Deterministic PCAP builders (classic libpcap, little-endian, Ethernet)
# --------------------------------------------------------------------------- #

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
LINKTYPE_ETHERNET = 1


def _global_header(linktype: int = LINKTYPE_ETHERNET) -> bytes:
    return PCAP_MAGIC_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)


def _ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00" * 6 + b"\x01" * 6 + struct.pack("!H", ethertype) + payload


def _ipv4_header(proto: int, total_len: int, src: str = "10.0.0.1", dst: str = "8.8.8.8") -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )


def _udp_dns_packet(qname: str, qtype: int = 1, src_ip: str = "10.0.0.1",
                    dst_ip: str = "8.8.8.8", src_port: int = 55555,
                    dst_port: int = 53, txid: int = 0x1234) -> bytes:
    labels = b""
    for part in qname.split("."):
        enc = part.encode("ascii")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"
    dns = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(dns), 0) + dns
    ip = _ipv4_header(17, 20 + len(udp), src=src_ip, dst=dst_ip)
    return _ethernet_frame(ip + udp)


def _tcp_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, 0x02, 65535, 0, 0)
    ip = _ipv4_header(6, 20 + len(tcp), src=src_ip, dst=dst_ip)
    return _ethernet_frame(ip + tcp)


def _http_get_packet(host: str, user_agent: str = "", src_ip: str = "10.0.0.1",
                     dst_ip: str = "203.0.113.5", src_port: int = 51234,
                     dst_port: int = 80) -> bytes:
    body_lines = [b"GET / HTTP/1.1", f"Host: {host}".encode("ascii")]
    if user_agent:
        body_lines.append(f"User-Agent: {user_agent}".encode("ascii"))
    body_lines.append(b"")
    body_lines.append(b"")
    http = b"\r\n".join(body_lines)
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, 0x18, 65535, 0, 0) + http
    ip = _ipv4_header(6, 20 + len(tcp), src=src_ip, dst=dst_ip)
    return _ethernet_frame(ip + tcp)


def _pack_record(packet: bytes, ts_sec: int = 1700000000, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)) + packet


def _build_pcap(packets: list[bytes], linktype: int = LINKTYPE_ETHERNET,
                start_ts: int = 1700000000) -> bytes:
    buf = _global_header(linktype)
    for i, pkt in enumerate(packets):
        buf += _pack_record(pkt, ts_sec=start_ts + i, ts_usec=0)
    return buf


# --------------------------------------------------------------------------- #
# Parser-level tests
# --------------------------------------------------------------------------- #

def test_empty_file_returns_structured_result():
    r = PcapAnalyzer().analyze_bytes(b"", file_name="empty.pcap")
    assert r.analysis_status == STATUS_EMPTY
    assert r.warnings


def test_non_pcap_file_is_unsupported():
    r = PcapAnalyzer().analyze_bytes(b"not a pcap at all", file_name="x.bin")
    assert r.analysis_status == STATUS_UNSUPPORTED_FORMAT


def test_pcapng_capture_is_unsupported_but_safe():
    r = PcapAnalyzer().analyze_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, file_name="t.pcapng")
    assert r.analysis_status == STATUS_UNSUPPORTED_FORMAT
    assert any("pcapng" in w.lower() for w in r.warnings)


def test_truncated_global_header_is_malformed():
    r = PcapAnalyzer().analyze_bytes(PCAP_MAGIC_LE + b"\x00", file_name="short.pcap")
    assert r.analysis_status == STATUS_MALFORMED


def test_valid_dns_query_parses():
    pcap = _build_pcap([_udp_dns_packet("example.com")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="dns.pcap")
    assert r.analysis_status == STATUS_COMPLETE
    assert r.total_packets == 1
    assert r.dns_count == 1
    assert r.dns_queries[0].qname == "example.com"
    assert r.dns_queries[0].qtype == "A"


def test_tcp_syn_opens_flow():
    pcap = _build_pcap([_tcp_syn_packet("10.0.0.1", "203.0.113.5", 51234, 443)])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="syn.pcap")
    assert r.analysis_status == STATUS_COMPLETE
    assert len(r.flows) == 1
    assert r.flows[0].dst_port == 443


def test_malformed_packet_is_counted_not_fatal():
    pcap = _global_header() + _pack_record(b"\x00\x02")  # too short for Ethernet
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="bad.pcap")
    assert r.analysis_status == STATUS_COMPLETE
    assert r.total_packets == 1
    assert r.malformed_packets == 1


def test_truncated_per_packet_header_stops_gracefully():
    pcap = _global_header() + b"\x00\x00\x00"  # only partial header
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="truncated.pcap")
    assert r.analysis_status in (STATUS_COMPLETE, STATUS_EMPTY)
    assert any("truncated" in w.lower() for w in r.warnings)


def test_oversized_file_rejected(tmp_path):
    big = tmp_path / "big.pcap"
    big.write_bytes(b"\x00" * (MAX_PCAP_SIZE + 1))
    with pytest.raises(PcapAnalysisError):
        PcapAnalyzer().analyze_file(big)


def test_unc_path_rejected(tmp_path):
    with pytest.raises(PcapAnalysisError):
        PcapAnalyzer().analyze_file(r"\\server\share\x.pcap")


def test_deterministic_results():
    pcap = _build_pcap([_udp_dns_packet("example.com"), _tcp_syn_packet("10.0.0.1", "203.0.113.5", 55555, 443)])
    r1 = PcapAnalyzer().analyze_bytes(pcap, file_name="t.pcap")
    r2 = PcapAnalyzer().analyze_bytes(pcap, file_name="t.pcap")
    assert r1.sha256 == r2.sha256
    assert [q.qname for q in r1.dns_queries] == [q.qname for q in r2.dns_queries]
    assert [i.rule_id for i in r1.indicators] == [i.rule_id for i in r2.indicators]


# --------------------------------------------------------------------------- #
# Rule tests
# --------------------------------------------------------------------------- #

def test_high_abuse_tld_rule():
    pcap = _build_pcap([_udp_dns_packet("malicious.xyz")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="tld.pcap")
    assert any(i.rule_id == "PCAP-DNS-TLD-001" for i in r.indicators)


def test_dga_rule_fires_on_random_label():
    pcap = _build_pcap([_udp_dns_packet("xkqzvbbqrstdfghjklpzmnwrr.com")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="dga.pcap")
    assert any(i.rule_id == "PCAP-DNS-DGA-002" for i in r.indicators)


def test_repeated_dns_rule():
    packets = [_udp_dns_packet("c2.example.com", txid=i) for i in range(25)]
    pcap = _build_pcap(packets)
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="rep.pcap")
    assert any(i.rule_id == "PCAP-DNS-REPEATED-007" for i in r.indicators)


def test_raw_ip_http_host_rule():
    pcap = _build_pcap([_http_get_packet("203.0.113.5")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="http.pcap")
    assert any(i.rule_id == "PCAP-NET-RAW-IP-004" for i in r.indicators)


def test_suspicious_user_agent_rule():
    pcap = _build_pcap([_http_get_packet("example.org", user_agent="python-urllib/3.11")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="ua.pcap")
    assert any(i.rule_id == "PCAP-NET-SUSPICIOUS-UA-005" for i in r.indicators)


def test_high_volume_rule():
    packets = [
        _tcp_syn_packet("10.0.0.1", "203.0.113.5", 50000 + i, 443)
        for i in range(55)
    ]
    pcap = _build_pcap(packets)
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="vol.pcap")
    assert any(i.rule_id == "PCAP-NET-HIGH-VOLUME-006" for i in r.indicators)


def test_rare_port_rule():
    pcap = _build_pcap([_tcp_syn_packet("10.0.0.1", "203.0.113.5", 50000, 31337)])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="rare.pcap")
    assert any(i.rule_id == "PCAP-NET-RARE-PORT-003" for i in r.indicators)


# --------------------------------------------------------------------------- #
# Evidence integration
# --------------------------------------------------------------------------- #

def _make_capture_file(tmp_path: Path, name: str, packets: list[bytes]) -> Path:
    p = tmp_path / name
    p.write_bytes(_build_pcap(packets))
    return p


def test_ingest_persists_provenance_and_findings(tmp_path):
    cap = _make_capture_file(tmp_path, "ingest.pcap", [
        _udp_dns_packet("c2.xyz"),
        _tcp_syn_packet("10.0.0.1", "203.0.113.5", 55555, 443),
    ])
    db = tmp_path / "ingest.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-01", "pcap ingest")

    result = PcapAnalyzer().analyze_file(cap)
    created = ingest_pcap_finding(store, "CASE-PCAP-01", result)
    assert created, "expected at least one finding (xyz TLD)"

    findings = store.get_case_findings("CASE-PCAP-01")
    assert any(f["finding_type"].startswith("pcap_") for f in findings)
    assert all(f.get("event_ids") for f in findings), "finding_evidence must be wired"

    custody = store.get_custody_events("CASE-PCAP-01")
    assert any(c["action"] == "reviewed" and "ransomeye-pcap-analyzer" in c["analyst"] for c in custody)
    store.close()


def test_ingest_is_idempotent(tmp_path):
    cap = _make_capture_file(tmp_path, "idem.pcap", [_udp_dns_packet("c2.xyz")])
    db = tmp_path / "idem.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-02", "idem")

    result = PcapAnalyzer().analyze_file(cap)
    first = ingest_pcap_finding(store, "CASE-PCAP-02", result)
    second = ingest_pcap_finding(store, "CASE-PCAP-02", result)
    assert first and not second, "re-ingest must not create duplicate findings"

    findings = store.get_case_findings("CASE-PCAP-02")
    rule_ids = {_rule_id_of(f) for f in findings}
    assert "PCAP-DNS-TLD-001" in rule_ids
    store.close()


def _rule_id_of(finding: dict) -> str:
    reason = finding.get("reason", "")
    if reason.startswith("["):
        return reason.split("]", 1)[0][1:]
    return ""


def test_ingest_links_evidence_events_to_findings(tmp_path):
    cap = _make_capture_file(tmp_path, "link.pcap", [_udp_dns_packet("foo.xyz")])
    db = tmp_path / "link.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-03", "link")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-03", result)

    findings = store.get_case_findings("CASE-PCAP-03")
    tld_finding = next(f for f in findings if _rule_id_of(f) == "PCAP-DNS-TLD-001")
    assert tld_finding["event_ids"]
    # The linked event must be a dns_query event in the store
    linked_event_id = tld_finding["event_ids"][0]
    ev = store.get_event("CASE-PCAP-03", linked_event_id)
    assert ev is not None
    assert ev["event_type"] in ("dns_query", "file_stream_hash")
    store.close()


def test_timeline_includes_pcap_events(tmp_path):
    cap = _make_capture_file(tmp_path, "tl.pcap", [_udp_dns_packet("example.org")])
    db = tmp_path / "tl.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-04", "tl")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-04", result)
    events = store.get_case_events("CASE-PCAP-04")
    assert any(e["event_type"] == "dns_query" for e in events)
    assert any(e["source"] == "pcap" for e in events)
    store.close()


# --------------------------------------------------------------------------- #
# CLI tests
# --------------------------------------------------------------------------- #

def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd, capture_output=True, text=True,
    )


def test_cli_pcap_analyzes_file(tmp_path):
    cap = _make_capture_file(tmp_path, "cli.pcap", [_udp_dns_packet("example.com")])
    res = _run_cli(["pcap", "--file", str(cap)], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "RANSOMEYE PCAP NETWORK ANALYSIS" in res.stdout


def test_cli_pcap_json_output(tmp_path):
    cap = _make_capture_file(tmp_path, "cli_json.pcap", [_udp_dns_packet("example.com")])
    res = _run_cli(["pcap", "--file", str(cap), "--json"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["analysis_status"] == "complete"
    assert data["dns_count"] == 1


def test_cli_pcap_ingests_into_case(tmp_path):
    cap = _make_capture_file(tmp_path, "cli_ingest.pcap", [_udp_dns_packet("c2.xyz")])
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("CASE-CLI-PCAP-01", "cli")
    store.close()
    res = _run_cli([
        "pcap", "--file", str(cap), "--database", str(db), "--case", "CASE-CLI-PCAP-01",
    ], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "ingested into case" in res.stdout


# --------------------------------------------------------------------------- #
# API tests
# --------------------------------------------------------------------------- #

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_server(tmp_path):
    port = _find_free_port()
    dashboard_server.DB_PATH = tmp_path / "api.db"
    EvidenceStore(dashboard_server.DB_PATH).close()
    httpd = dashboard_server.HTTPServer(("127.0.0.1", port), dashboard_server.DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _post_json(url: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_api_pcap_analyze_without_case(running_server, tmp_path):
    cap = _make_capture_file(tmp_path, "api.pcap", [_udp_dns_packet("example.com")])
    code, res = _post_json(f"{running_server}/api/pcap/analyze", {"file_path": str(cap)})
    assert code == 200
    assert res["analysis"]["analysis_status"] == "complete"
    assert res["finding_ids"] is None


def test_api_pcap_missing_file_path(running_server):
    code, res = _post_json(f"{running_server}/api/pcap/analyze", {})
    assert code == 400


def test_api_pcap_file_not_found(running_server):
    code, res = _post_json(f"{running_server}/api/pcap/analyze", {"file_path": "C:/does/not/exist.pcap"})
    assert code == 404


# --------------------------------------------------------------------------- #
# XSS probes and static security assertions
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
]


def test_malicious_qname_round_trips_as_data(tmp_path):
    """A capture whose DNS QNAME labels include markup round-trips as inert string data."""
    # Build a DNS packet with an attacker-controlled single-label name (bounded ASCII).
    probe = "evil-script"  # DNS labels cannot contain '<' per RFC; we test the string channel instead.
    pcap = _build_pcap([_udp_dns_packet(f"{probe}.xyz")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="probe.pcap")
    blob = json.dumps(r.to_dict())
    assert probe in blob
    # Verify qname is a plain string field, never structural.
    assert all(isinstance(q["qname"], str) for q in r.to_dict()["dns_queries"])


def test_malicious_http_host_round_trips_as_data(tmp_path):
    """HTTP Host and User-Agent headers can carry markup; must be string data in the result."""
    for probe in _XSS_PROBES:
        pcap = _build_pcap([_http_get_packet(host=probe, user_agent=probe)])
        r = PcapAnalyzer().analyze_bytes(pcap, file_name="probe.pcap")
        for h in r.to_dict()["http_records"]:
            assert isinstance(h["host"], str)
            assert isinstance(h["user_agent"], str)


def test_malicious_capture_filename_preserved_as_data(tmp_path):
    for probe in _XSS_PROBES:
        pcap = _build_pcap([_udp_dns_packet("example.com")])
        r = PcapAnalyzer().analyze_bytes(pcap, file_name=f"{probe}.pcap")
        assert r.file_name == f"{probe}.pcap"
        blob = json.dumps(r.to_dict())
        assert probe in blob


def test_pcap_analyzer_source_has_no_dangerous_calls():
    src = (Path(dashboard_server.__file__).parent / "pcap_analyzer.py").read_text(encoding="utf-8")
    for sink in ("subprocess.", "import subprocess", "eval(", "exec(", "os.system(", "spec_from_file_location"):
        assert sink not in src, f"PCAP analyzer must not contain '{sink}'"


def test_pcap_analyzer_has_no_outbound_network():
    src = (Path(dashboard_server.__file__).parent / "pcap_analyzer.py").read_text(encoding="utf-8")
    for sink in ("urllib.request", "http.client", "requests.get", "urlopen", "socket.create_connection"):
        assert sink not in src, f"PCAP analyzer must not import outbound network: '{sink}'"


def test_app_js_still_has_zero_dangerous_sinks():
    """The global dashboard safe-DOM invariant must survive the PCAP view."""
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write(", "eval(", "new Function"):
        assert sink not in app_js, f"PCAP view regressed safe-DOM invariant: '{sink}'"


def test_pcap_view_registered_in_nav_and_router():
    static_dir = Path(dashboard_server.__file__).parent / "static"
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    app_js = (static_dir / "app.js").read_text(encoding="utf-8")
    assert 'data-view="pcap"' in html
    assert 'id="tpl-pcap"' in html
    assert "case 'pcap': initPcap();" in app_js
    assert "'pcap'" in app_js.split("const GLOBAL_VIEWS")[1].split("]")[0]


# --------------------------------------------------------------------------- #
# Safety / correctness regression tests (lock in verified-safe behavior)
# --------------------------------------------------------------------------- #

PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"


def _build_pcap_be(packets: list[bytes]) -> bytes:
    """Big-endian classic libpcap builder for endianness regression."""
    buf = PCAP_MAGIC_BE + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    for i, pkt in enumerate(packets):
        buf += struct.pack(">IIII", 1700000000 + i, 0, len(pkt), len(pkt)) + pkt
    return buf


def test_big_endian_capture_parses():
    """Captures with the big-endian pcap magic must parse packets correctly."""
    pcap = _build_pcap_be([_udp_dns_packet("example.com")])
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="be.pcap")
    assert r.analysis_status == STATUS_COMPLETE
    assert r.total_packets == 1
    assert r.dns_count == 1
    assert r.dns_queries[0].qname == "example.com"


def test_vlan_tagged_ethernet_frame_unwraps():
    """Ethernet frames with a single 802.1Q VLAN tag must still reach IPv4 parsing."""
    # Rebuild a DNS packet but wrap it with a VLAN tag.
    inner = _udp_dns_packet("example.com")
    # strip the outer Ethernet (first 14 bytes) and rewrap with VLAN tag
    ip_and_up = inner[14:]
    vlan_frame = b"\x00" * 6 + b"\x01" * 6 + b"\x81\x00" + b"\x00\x64" + b"\x08\x00" + ip_and_up
    pcap = _global_header() + _pack_record(vlan_frame)
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="vlan.pcap")
    assert r.analysis_status == STATUS_COMPLETE
    assert r.dns_count == 1
    assert r.dns_queries[0].qname == "example.com"


def test_dns_compression_pointer_loop_is_safe():
    """A DNS QNAME that is a self-referential compression pointer must not loop or crash."""
    # QNAME = 0xC00C (compression pointer to offset 12, i.e. itself).
    dns = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
           + b"\xc0\x0c" + struct.pack("!HH", 1, 1))
    udp = struct.pack("!HHHH", 55555, 53, 8 + len(dns), 0) + dns
    ip = _ipv4_header(17, 20 + len(udp))
    frame = _ethernet_frame(ip + udp)
    pcap = _global_header() + _pack_record(frame)

    import time
    t0 = time.time()
    r = PcapAnalyzer().analyze_bytes(pcap, file_name="pointer_loop.pcap")
    elapsed = time.time() - t0

    assert elapsed < 1.0, f"compression-pointer parsing took {elapsed:.3f}s"
    assert r.analysis_status == STATUS_COMPLETE
    # The parser treats a question-section compression pointer as end-of-name;
    # the resulting empty QNAME means no dns_query event is emitted, which is
    # the intended safe behavior.
    assert r.dns_count == 0


def test_pcap_findings_appear_in_report(tmp_path):
    """PCAP findings and their evidence events must be included in the case report."""
    from ransomeye.report import generate_case_report

    cap = _make_capture_file(tmp_path, "report.pcap", [_udp_dns_packet("c2.xyz")])
    db = tmp_path / "report.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-RPT", "report integration")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-RPT", result)
    store.close()

    report_text = generate_case_report(db, "CASE-PCAP-RPT")
    assert "pcap_network_dns" in report_text
    assert "PCAP-DNS-TLD-001" in report_text
    assert "dns_query" in report_text
    assert "EVT-PCAP-" in report_text


def test_pcap_events_participate_in_timeline(tmp_path):
    """PCAP network and DNS events must appear in the case timeline for investigation."""
    from ransomeye.timeline import get_case_timeline

    cap = _make_capture_file(tmp_path, "tl2.pcap", [
        _udp_dns_packet("example.com"),
        _tcp_syn_packet("10.0.0.1", "203.0.113.5", 50000, 443),
    ])
    db = tmp_path / "tl2.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-TL", "timeline")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-TL", result)
    store.close()

    timeline = get_case_timeline(db, "CASE-PCAP-TL")
    event_types = {ev["event_type"] for ev in timeline}
    assert "dns_query" in event_types
    assert "network_connect" in event_types


def test_pcap_events_do_not_fabricate_process_attribution(tmp_path):
    """PCAP events must never carry fabricated process_name / command_line /
    image_path / process_guid, since a PCAP cannot defensibly identify an
    endpoint process."""
    from ransomeye.timeline import get_case_timeline

    cap = _make_capture_file(tmp_path, "no_proc.pcap", [
        _udp_dns_packet("example.com"),
        _tcp_syn_packet("10.0.0.1", "203.0.113.5", 50000, 443),
    ])
    db = tmp_path / "no_proc.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-NOPROC", "no proc")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-NOPROC", result)
    store.close()

    events = get_case_timeline(db, "CASE-PCAP-NOPROC")
    pcap_events = [e for e in events if e.get("source") in ("pcap", "pcap_analyzer")]
    assert pcap_events, "expected PCAP-sourced events"
    for ev in pcap_events:
        # Core forensic correctness guarantee for PCAP evidence.
        assert not ev.get("process_name"), f"process_name must not be fabricated: {ev}"
        assert not ev.get("command_line"), f"command_line must not be fabricated: {ev}"
        assert not ev.get("process_guid"), f"process_guid must not be fabricated: {ev}"
        assert not ev.get("parent_pid"), f"parent_pid must not be fabricated: {ev}"
