"""Phase 2C.3 — Investigation-graph compatibility with PCAP network evidence."""

from __future__ import annotations

import socket
import struct
from collections import Counter
from pathlib import Path

import pytest

from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.pcap_analyzer import PcapAnalyzer, ingest_pcap_finding
from ransomeye.storage import EvidenceStore


# --------------------------------------------------------------------------- #
# Deterministic libpcap builders (duplicated locally; keep test independent)
# --------------------------------------------------------------------------- #

_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_LINKTYPE_ETHERNET = 1


def _global_header() -> bytes:
    return _PCAP_MAGIC_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, _LINKTYPE_ETHERNET)


def _tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, 0x02, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return b"\x00" * 6 + b"\x01" * 6 + b"\x08\x00" + ip + tcp


def _udp_dns(qname: str, dst_ip: str = "8.8.8.8", txid: int = 0x1234) -> bytes:
    labels = b""
    for part in qname.split("."):
        enc = part.encode("ascii")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"
    dns = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 55555, 53, 8 + len(dns), 0) + dns
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        socket.inet_aton("10.0.0.1"), socket.inet_aton(dst_ip),
    )
    return b"\x00" * 6 + b"\x01" * 6 + b"\x08\x00" + ip + udp


def _wrap(packet: bytes, ts: int) -> bytes:
    return struct.pack("<IIII", ts, 0, len(packet), len(packet)) + packet


def _write_pcap(tmp_path: Path, name: str, packets: list[bytes]) -> Path:
    buf = _global_header()
    for i, p in enumerate(packets):
        buf += _wrap(p, 1700000000 + i)
    p = tmp_path / name
    p.write_bytes(buf)
    return p


# --------------------------------------------------------------------------- #
# Core compatibility: PCAP network_connect → NETWORK node
# --------------------------------------------------------------------------- #

def test_pcap_network_connect_creates_network_node(tmp_path):
    cap = _write_pcap(tmp_path, "net.pcap", [_tcp_syn("10.0.0.1", "203.0.113.5", 51234, 443)])
    db = tmp_path / "graph.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-NET", "pcap net")
    result = PcapAnalyzer().analyze_file(cap)
    ingest_pcap_finding(store, "CASE-PCAP-NET", result)
    store.close()

    inv = load_investigation(db, "CASE-PCAP-NET")
    graph = build_investigation_graph(inv)

    network_nodes = [n for n in graph.nodes.values() if n.node_type == "NETWORK"]
    assert any(n.node_id == "NETWORK:203.0.113.5:443" for n in network_nodes)


def test_pcap_dst_ip_dst_port_keys_are_honored(tmp_path):
    """Smallest-fix regression: PCAP stores dst_ip/dst_port; the graph used to
    look only at destination_ip/destination_port and therefore produced no
    NETWORK node for PCAP evidence."""
    cap = _write_pcap(tmp_path, "keys.pcap", [_tcp_syn("10.0.0.1", "198.51.100.9", 55555, 8443)])
    db = tmp_path / "keys.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-KEYS", "keys")
    ingest_pcap_finding(store, "CASE-PCAP-KEYS", PcapAnalyzer().analyze_file(cap))
    store.close()

    inv = load_investigation(db, "CASE-PCAP-KEYS")
    graph = build_investigation_graph(inv)
    assert "NETWORK:198.51.100.9:8443" in graph.nodes


def test_sysmon_destination_ip_still_works(tmp_path):
    """Compatibility: Sysmon-style destination_ip/destination_port events must
    continue to anchor NETWORK nodes exactly as before."""
    db = tmp_path / "sysmon.db"
    store = EvidenceStore(db)
    store.create_case("CASE-SYSMON", "sysmon")
    store.save_event("CASE-SYSMON", {
        "event_id": "evt-sysmon-net-1",
        "timestamp": "2026-10-08T00:00:00",
        "source": "sysmon",
        "event_type": "network_connect",
        "process_name": "evil.exe",
        "pid": 1234,
        "process_guid": "{AAAA}",
        "network": {
            "destination_ip": "203.0.113.5",
            "destination_port": 4444,
            "protocol": "tcp",
        },
    })
    store.close()

    inv = load_investigation(db, "CASE-SYSMON")
    graph = build_investigation_graph(inv)
    assert "NETWORK:203.0.113.5:4444" in graph.nodes
    # The Sysmon event has a real process; the CONNECTED_TO edge still fires.
    rels = [e.relationship for e in graph.edges if e.target_id == "NETWORK:203.0.113.5:4444"]
    assert "CONNECTED_TO" in rels


def test_pcap_dns_query_creates_network_dns_node(tmp_path):
    cap = _write_pcap(tmp_path, "dns.pcap", [_udp_dns("c2.evil.example")])
    db = tmp_path / "dns.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-DNS", "dns")
    ingest_pcap_finding(store, "CASE-PCAP-DNS", PcapAnalyzer().analyze_file(cap))
    store.close()

    inv = load_investigation(db, "CASE-PCAP-DNS")
    graph = build_investigation_graph(inv)
    assert "NETWORK:dns:c2.evil.example" in graph.nodes
    net_node = graph.nodes["NETWORK:dns:c2.evil.example"]
    assert net_node.attributes.get("query_name") == "c2.evil.example"


# --------------------------------------------------------------------------- #
# Core forensic invariant: no fabricated PROCESS attribution
# --------------------------------------------------------------------------- #

def test_pcap_does_not_fabricate_process_nodes(tmp_path):
    """Regression: previously an empty-string pid produced a bogus
    PROCESS:PID: node for every PCAP evidence event."""
    cap = _write_pcap(tmp_path, "np.pcap", [
        _tcp_syn("10.0.0.1", "203.0.113.5", 50000, 443),
        _udp_dns("foo.example"),
    ])
    db = tmp_path / "np.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-NP", "np")
    ingest_pcap_finding(store, "CASE-PCAP-NP", PcapAnalyzer().analyze_file(cap))
    store.close()

    inv = load_investigation(db, "CASE-PCAP-NP")
    graph = build_investigation_graph(inv)
    process_nodes = [n for n in graph.nodes.values() if n.node_type == "PROCESS"]
    for n in process_nodes:
        # Any PROCESS node must carry a real identity, never an empty pid.
        assert n.node_id != "PROCESS:PID:"
        assert not n.node_id.endswith(":PID:")
    # In this PCAP-only case we expect zero PROCESS nodes.
    assert process_nodes == []


# --------------------------------------------------------------------------- #
# EVIDENCE → NETWORK anchoring when no process context exists
# --------------------------------------------------------------------------- #

def test_pcap_network_node_is_anchored_to_evidence(tmp_path):
    cap = _write_pcap(tmp_path, "anchor.pcap", [_tcp_syn("10.0.0.1", "203.0.113.9", 50000, 1337)])
    db = tmp_path / "anchor.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-ANCHOR", "anchor")
    ingest_pcap_finding(store, "CASE-PCAP-ANCHOR", PcapAnalyzer().analyze_file(cap))
    store.close()

    inv = load_investigation(db, "CASE-PCAP-ANCHOR")
    graph = build_investigation_graph(inv)
    net_id = "NETWORK:203.0.113.9:1337"
    assert net_id in graph.nodes
    edges_to_net = [e for e in graph.edges if e.target_id == net_id]
    assert edges_to_net, "NETWORK node must be reachable through at least one edge"
    # The anchoring edge is from an EVIDENCE node (not a fabricated PROCESS).
    assert all(e.source_id.startswith("EVIDENCE:") for e in edges_to_net)
    assert all(e.relationship == "OBSERVED" for e in edges_to_net)


def test_pcap_dns_node_is_anchored_to_evidence(tmp_path):
    cap = _write_pcap(tmp_path, "dnsanchor.pcap", [_udp_dns("payload.badhost.example")])
    db = tmp_path / "dnsanchor.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PCAP-DNS-ANCHOR", "dns anchor")
    ingest_pcap_finding(store, "CASE-PCAP-DNS-ANCHOR", PcapAnalyzer().analyze_file(cap))
    store.close()

    inv = load_investigation(db, "CASE-PCAP-DNS-ANCHOR")
    graph = build_investigation_graph(inv)
    net_id = "NETWORK:dns:payload.badhost.example"
    assert net_id in graph.nodes
    edges = [e for e in graph.edges if e.target_id == net_id]
    assert edges
    assert all(e.source_id.startswith("EVIDENCE:") for e in edges)
    assert all(e.relationship == "DNS_QUERIED" for e in edges)


# --------------------------------------------------------------------------- #
# Non-PCAP graph behavior unchanged
# --------------------------------------------------------------------------- #

def test_process_centric_file_graph_still_works(tmp_path):
    """A classic process_create + file_modify event pair must still produce
    the PROCESS/FILE/SPAWNED/MODIFIED relationships."""
    db = tmp_path / "proc.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PROC", "proc")
    store.save_event("CASE-PROC", {
        "event_id": "evt-proc-1",
        "timestamp": "2026-10-08T00:00:00",
        "source": "sysmon",
        "event_type": "process_create",
        "process_name": "powershell.exe",
        "pid": 100,
        "process_guid": "{AA}",
        "parent_pid": 10,
        "parent_process_guid": "{PARENT}",
        "parent_image": "explorer.exe",
    })
    store.save_event("CASE-PROC", {
        "event_id": "evt-proc-2",
        "timestamp": "2026-10-08T00:00:01",
        "source": "sysmon",
        "event_type": "file_modify",
        "process_name": "powershell.exe",
        "pid": 100,
        "process_guid": "{AA}",
        "file_path": r"C:\Users\victim\doc.txt",
    })
    store.close()

    inv = load_investigation(db, "CASE-PROC")
    graph = build_investigation_graph(inv)
    assert "PROCESS:{AA}" in graph.nodes
    assert "PROCESS:{PARENT}" in graph.nodes
    rels = {e.relationship for e in graph.edges}
    assert "SPAWNED" in rels
    assert "MODIFIED" in rels


# --------------------------------------------------------------------------- #
# PCAP evidence identity unchanged (not accidentally rewritten in 2C.3)
# --------------------------------------------------------------------------- #

def test_pcap_event_identity_is_still_deterministic(tmp_path):
    """Phase 2C.3 must NOT alter PCAP evidence identity."""
    cap = _write_pcap(tmp_path, "id.pcap", [_tcp_syn("10.0.0.1", "203.0.113.5", 55555, 443)])
    r1 = PcapAnalyzer().analyze_file(cap)
    r2 = PcapAnalyzer().analyze_file(cap)
    assert r1.sha256 == r2.sha256
    assert len(r1.flows) == len(r2.flows) == 1
