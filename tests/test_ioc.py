"""Focused tests for the RansomEye IOC extractor."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from ransomeye import dashboard_server
from ransomeye.ioc_extractor import (
    MAX_IOC_INPUT_SIZE,
    IocAnalysisError,
    IocExtractor,
    STATUS_COMPLETE,
    STATUS_EMPTY,
    ingest_ioc_finding,
)
from ransomeye.storage import EvidenceStore


# --------------------------------------------------------------------------- #
# Positive extraction tests
# --------------------------------------------------------------------------- #

def _types(r) -> set[str]:
    return {o.ioc_type for o in r.observations}


def test_extracts_public_ipv4():
    r = IocExtractor().analyze_text("contact 203.0.113.5 for details.")
    assert "ipv4" in _types(r)
    assert any(o.value_normalized == "203.0.113.5" for o in r.observations)


def test_excludes_reserved_ipv4():
    r = IocExtractor().analyze_text("127.0.0.1 0.0.0.0 169.254.169.254 255.255.255.255")
    assert "ipv4" not in _types(r)


def test_ipv4_followed_by_sentence_period_still_matches():
    r = IocExtractor().analyze_text("Attacker IP: 198.51.100.1.")
    assert any(o.value_normalized == "198.51.100.1" for o in r.observations)


def test_extracts_ipv6_with_compression():
    r = IocExtractor().analyze_text("peer 2001:db8::1 and fe80::1 and ::1")
    v = {o.value_normalized for o in r.observations if o.ioc_type == "ipv6"}
    assert "2001:db8::1" in v
    assert "fe80::1" in v
    # ::1 (loopback) and :: (unspecified) must be excluded.
    assert "::1" not in v


def test_extracts_url_and_normalizes_scheme_and_host():
    r = IocExtractor().analyze_text("Visit HTTPS://Evil.Example.ORG/Payload for drop.")
    urls = [o for o in r.observations if o.ioc_type == "url"]
    assert urls
    assert urls[0].value_normalized.startswith("https://evil.example.org")


def test_defangs_url_hxxp_and_bracket_dot():
    r = IocExtractor().analyze_text("drop at hxxps://evil[.]example[.]top/foo")
    urls = [o for o in r.observations if o.ioc_type == "url"]
    assert any("https://evil.example.top" in o.value_normalized for o in urls)


def test_extracts_domain_and_filters_file_extensions():
    r = IocExtractor().analyze_text("See evil.example.com and powershell.exe and malware.dll and good.io")
    domains = {o.value_normalized for o in r.observations if o.ioc_type == "domain"}
    assert "evil.example.com" in domains
    assert "good.io" in domains
    assert "powershell.exe" not in domains
    assert "malware.dll" not in domains


def test_extracts_email_fixes_12x_bug():
    """12X had a bug ('[A-Z|a-z]' matches literal '|'); verify we reject it."""
    r = IocExtractor().analyze_text("Contact bad@evil.example.com or user@sub.example.co")
    emails = {o.value_normalized for o in r.observations if o.ioc_type == "email"}
    assert "bad@evil.example.com" in emails
    assert "user@sub.example.co" in emails
    # The 12X-bugged form "foo@evil.|xyz" must NOT be an email.
    r2 = IocExtractor().analyze_text("corrupt foo@evil.|xyz string")
    assert "email" not in _types(r2)


def test_extracts_hashes_md5_sha1_sha256():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = IocExtractor().analyze_text(f"md5 {md5}  sha1 {sha1}  sha256 {sha256}")
    types = _types(r)
    assert "md5" in types and "sha1" in types and "sha256" in types


def test_hash_normalized_to_lowercase():
    sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    r = IocExtractor().analyze_text(sha256)
    o = [o for o in r.observations if o.ioc_type == "sha256"][0]
    assert o.value_normalized == sha256.lower()
    assert o.value_original == sha256  # provenance preserved


def test_btc_requires_valid_base58check():
    """Satoshi genesis BTC address is valid; a random Base58-shape string is not."""
    valid = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    invalid = "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r_valid = IocExtractor().analyze_text(valid)
    r_invalid = IocExtractor().analyze_text(invalid)
    assert "btc" in _types(r_valid)
    assert "btc" not in _types(r_invalid)


def test_eth_candidate_is_excluded_when_also_sha1():
    """40-hex strings that also match SHA-1 must not double-report as ETH."""
    # This is a 40-hex blob; it matches both SHA-1 and ETH shapes.
    blob = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    r = IocExtractor().analyze_text(f"{blob} and 0x{blob}")
    types = _types(r)
    assert "sha1" in types
    assert "eth" not in types, "A 40-hex SHA-1 must not be double-reported as ETH"


def test_eth_candidate_fires_for_non_sha1_hex():
    """0x-prefixed hex that doesn't collide with a SHA-1 in the input is kept."""
    r = IocExtractor().analyze_text("tx target 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert "eth" in _types(r)


def test_lolbin_rule_fires():
    r = IocExtractor().analyze_text("script runs vssadmin delete shadows /all /quiet")
    assert "lolbin" in _types(r)


# --------------------------------------------------------------------------- #
# Normalization and provenance
# --------------------------------------------------------------------------- #

def test_dedup_within_type():
    r = IocExtractor().analyze_text("evil.example.com evil.example.com Evil.Example.COM")
    domains = [o for o in r.observations if o.ioc_type == "domain"]
    assert len(domains) == 1


def test_provenance_offset_and_context():
    text = "line1\nURL: https://evil.example.net/x\nline3"
    r = IocExtractor().analyze_text(text)
    url = [o for o in r.observations if o.ioc_type == "url"][0]
    assert url.offset > 0
    assert "https" in url.context_preview


def test_source_tag_is_text_for_text_input():
    r = IocExtractor().analyze_text("https://evil.example.net")
    assert all(o.source == "text" for o in r.observations)


# --------------------------------------------------------------------------- #
# Binary input
# --------------------------------------------------------------------------- #

def test_binary_file_ascii_strings_extracted(tmp_path):
    data = b"\x00\x00" + b"https://evil.example.net/path" + b"\x00" + b"user@evil.example.org" + b"\x00" * 10
    p = tmp_path / "x.bin"
    p.write_bytes(data)
    r = IocExtractor().analyze_file(p)
    assert r.is_binary
    sources = {o.source for o in r.observations}
    assert "binary_ascii" in sources


def test_binary_file_utf16_strings_extracted(tmp_path):
    s = "https://evil.example.net/u"
    data = b"\x00" * 4 + s.encode("utf-16le") + b"\x00" * 10
    p = tmp_path / "u.bin"
    p.write_bytes(data)
    r = IocExtractor().analyze_file(p)
    assert any(o.source == "binary_utf16" for o in r.observations)


# --------------------------------------------------------------------------- #
# Resource limits + malformed input
# --------------------------------------------------------------------------- #

def test_empty_input():
    r = IocExtractor().analyze_text("")
    assert r.analysis_status == STATUS_EMPTY
    assert r.observations == []


def test_oversized_input_rejected(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * (MAX_IOC_INPUT_SIZE + 1))
    with pytest.raises(IocAnalysisError):
        IocExtractor().analyze_file(p)


def test_unc_path_rejected():
    with pytest.raises(IocAnalysisError):
        IocExtractor().analyze_file(r"\\server\share\x.bin")


def test_per_type_cap_enforced():
    text = " ".join(f"host-{i}.example.net" for i in range(400))
    r = IocExtractor().analyze_text(text)
    domain_count = sum(1 for o in r.observations if o.ioc_type == "domain")
    assert domain_count <= 300
    assert any("Per-type cap" in w for w in r.warnings)


def test_deterministic_results():
    text = "a@b.com c@d.org https://evil.example.com 203.0.113.5"
    r1 = IocExtractor().analyze_text(text)
    r2 = IocExtractor().analyze_text(text)
    assert r1.sha256 == r2.sha256
    assert [o.value_normalized for o in r1.observations] == [o.value_normalized for o in r2.observations]


# --------------------------------------------------------------------------- #
# Evidence integration
# --------------------------------------------------------------------------- #

def _ioc_text() -> str:
    return (
        "URL https://evil.example.top/payload "
        "contact bad@evil.example.org "
        "IP 203.0.113.5 "
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "powershell.exe -enc base64=="
    )


def test_ingest_creates_provenance_and_findings(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    db = tmp_path / "ioc.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-01", "ioc")

    r = IocExtractor().analyze_file(p)
    created = ingest_ioc_finding(store, "CASE-IOC-01", r)
    assert created, "expected findings for multiple types"

    findings = store.get_case_findings("CASE-IOC-01")
    types = {f["finding_type"] for f in findings}
    assert any(t.startswith("ioc_observation_") for t in types)
    assert any(t == "ioc_contextual_lolbin" for t in types)
    assert all(f.get("event_ids") for f in findings)
    store.close()


def test_ingest_idempotent(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    db = tmp_path / "ioc2.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-02", "idem")

    r = IocExtractor().analyze_file(p)
    first = ingest_ioc_finding(store, "CASE-IOC-02", r)
    second = ingest_ioc_finding(store, "CASE-IOC-02", r)
    assert first and not second
    store.close()


def test_ingest_records_custody(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("https://evil.example.net", encoding="utf-8")
    db = tmp_path / "cust.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-C", "custody")
    r = IocExtractor().analyze_file(p)
    ingest_ioc_finding(store, "CASE-IOC-C", r)
    custody = store.get_custody_events("CASE-IOC-C")
    assert any(c["action"] == "reviewed" and "ioc-extractor" in c["analyst"] for c in custody)
    store.close()


def test_report_integration(tmp_path):
    from ransomeye.report import generate_case_report
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    db = tmp_path / "rpt.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-RPT", "rpt")
    r = IocExtractor().analyze_file(p)
    ingest_ioc_finding(store, "CASE-IOC-RPT", r)
    store.close()
    text = generate_case_report(db, "CASE-IOC-RPT")
    assert "ioc_observation_" in text
    assert "EVT-IOC-" in text


def test_timeline_includes_ioc_provenance(tmp_path):
    from ransomeye.timeline import get_case_timeline
    p = tmp_path / "a.txt"
    p.write_text("https://evil.example.net", encoding="utf-8")
    db = tmp_path / "tl.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-TL", "tl")
    r = IocExtractor().analyze_file(p)
    ingest_ioc_finding(store, "CASE-IOC-TL", r)
    store.close()
    events = get_case_timeline(db, "CASE-IOC-TL")
    assert any(e["source"] == "ioc_extractor" for e in events)


def test_ioc_events_never_fabricate_process_attribution(tmp_path):
    from ransomeye.timeline import get_case_timeline
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    db = tmp_path / "np.db"
    store = EvidenceStore(db)
    store.create_case("CASE-IOC-NP", "np")
    r = IocExtractor().analyze_file(p)
    ingest_ioc_finding(store, "CASE-IOC-NP", r)
    store.close()
    for ev in get_case_timeline(db, "CASE-IOC-NP"):
        if ev["source"] == "ioc_extractor":
            assert not ev.get("process_name")
            assert not ev.get("command_line")
            assert not ev.get("process_guid")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd, capture_output=True, text=True,
    )


def test_cli_ioc_runs(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    res = _run_cli(["ioc", "--file", str(p)], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "RANSOMEYE IOC EXTRACTION" in res.stdout


def test_cli_ioc_json(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("https://evil.example.net", encoding="utf-8")
    res = _run_cli(["ioc", "--file", str(p), "--json"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["analysis_status"] == "complete"


def test_cli_ioc_ingests_into_case(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text(_ioc_text(), encoding="utf-8")
    db = tmp_path / "cli.db"
    store = EvidenceStore(db); store.create_case("CASE-IOC-CLI", "cli"); store.close()
    res = _run_cli([
        "ioc", "--file", str(p), "--database", str(db), "--case", "CASE-IOC-CLI",
    ], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "ingested into case" in res.stdout


# --------------------------------------------------------------------------- #
# API
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


def test_api_ioc_analyze_without_case(running_server, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("https://evil.example.net", encoding="utf-8")
    code, res = _post_json(f"{running_server}/api/ioc/analyze", {"file_path": str(p)})
    assert code == 200
    assert res["analysis"]["analysis_status"] == "complete"
    assert res["finding_ids"] is None


def test_api_ioc_missing_file_path(running_server):
    code, res = _post_json(f"{running_server}/api/ioc/analyze", {})
    assert code == 400


def test_api_ioc_file_not_found(running_server):
    code, res = _post_json(f"{running_server}/api/ioc/analyze",
                           {"file_path": "C:/does/not/exist.bin"})
    assert code == 404


# --------------------------------------------------------------------------- #
# XSS probes and static source assertions
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]


def test_xss_probes_round_trip_as_data():
    """Attacker markup in IOC input must round-trip as plain string data."""
    for probe in _XSS_PROBES:
        text = (
            f"malicious marker {probe} "
            f"domain evil.example.xyz "
            f"url http://{probe}.example.net/"
        )
        r = IocExtractor().analyze_text(text)
        blob = json.dumps(r.to_dict())
        # The probe must appear in the serialized output as inert string data.
        assert probe in blob or probe.lower() in blob


def test_xss_probes_in_filename_preserved(tmp_path):
    p = tmp_path / "ioc_xss.txt"
    p.write_text("https://evil.example.net", encoding="utf-8")
    r = IocExtractor().analyze_file(p)
    r.file_name = "<img src=x onerror=alert(1)>.txt"
    d = r.to_dict()
    assert d["file_name"] == "<img src=x onerror=alert(1)>.txt"


def test_source_has_no_subprocess_eval_exec():
    src = (Path(dashboard_server.__file__).parent / "ioc_extractor.py").read_text(encoding="utf-8")
    for sink in ("subprocess.", "import subprocess", "eval(", "exec(",
                 "os.system(", "spec_from_file_location"):
        assert sink not in src, f"IOC extractor must not contain '{sink}'"


def test_source_has_no_outbound_network():
    src = (Path(dashboard_server.__file__).parent / "ioc_extractor.py").read_text(encoding="utf-8")
    for sink in ("urllib.request", "http.client", "requests.get", "urlopen",
                 "socket.create_connection", "virustotal", "abuseipdb", "otxapi"):
        assert sink not in src, f"IOC extractor must not reach the network: '{sink}'"


def test_app_js_still_has_zero_dangerous_sinks():
    """Global safe-DOM invariant must survive the IOC view."""
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write(", "eval(", "new Function"):
        assert sink not in app_js, f"IOC view regressed safe-DOM invariant: '{sink}'"


def test_ioc_view_registered_in_nav_and_router():
    static_dir = Path(dashboard_server.__file__).parent / "static"
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    app_js = (static_dir / "app.js").read_text(encoding="utf-8")
    assert 'data-view="ioc"' in html
    assert 'id="tpl-ioc"' in html
    assert "case 'ioc': initIoc();" in app_js
    assert "'ioc'" in app_js.split("const GLOBAL_VIEWS")[1].split("]")[0]
