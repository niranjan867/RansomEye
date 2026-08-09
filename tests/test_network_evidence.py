import pytest
from datetime import datetime, timezone
from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.advanced_timeline import build_advanced_timeline

def test_network_connection_normalization():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-NET-001",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_name="powershell.exe",
        process_guid="{ABC-123}",
        pid="2048",
        network={
            "destination_ip": "203.0.113.20",
            "destination_port": "443",
            "protocol": "tcp",
            "source_ip": "192.168.1.50",
            "source_port": "52341",
            "destination_hostname": "example.test"
        }
    )

    assert ev.network["destination_ip"] == "203.0.113.20"
    assert ev.network["protocol"] == "tcp"

def test_dns_normalization():
    ts = datetime(2026, 8, 8, 10, 30, 1, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-DNS-001",
        timestamp=ts,
        source="sysmon",
        event_type="dns_query",
        process_name="powershell.exe",
        process_guid="{ABC-123}",
        network={
            "query_name": "example.test",
            "query_results": "203.0.113.20"
        }
    )

    assert ev.network["query_name"] == "example.test"
    assert ev.network["query_results"] == "203.0.113.20"

def test_ipv6_and_udp_support():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-NET-IPV6",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_guid="{PROC-123}",
        network={
            "destination_ip": "2001:db8::10",
            "destination_port": "53",
            "protocol": "udp"
        }
    )

    inv = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    net_nodes = graph.get_nodes("NETWORK")
    assert len(net_nodes) == 1
    assert net_nodes[0].node_id == "NETWORK:2001:db8::10:53"

def test_process_to_network_edge_creation():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-NET-002",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_name="curl.exe",
        process_guid="{CURL-123}",
        network={
            "destination_ip": "198.51.100.1",
            "destination_port": "80"
        }
    )

    inv = Investigation(
        case={"case_id": "TEST-02"},
        evidence=[ev],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)

    # We should have a PROCESS node and a NETWORK node
    proc_nodes = graph.get_process_nodes()
    net_nodes = graph.get_nodes("NETWORK")

    assert len(proc_nodes) == 1
    assert proc_nodes[0].node_id == "PROCESS:{CURL-123}"
    assert len(net_nodes) == 1
    assert net_nodes[0].node_id == "NETWORK:198.51.100.1:80"

    edges = graph.get_edges()
    conn_edges = [e for e in edges if e.relationship == "CONNECTED_TO"]
    assert len(conn_edges) == 1
    assert conn_edges[0].source_id == "PROCESS:{CURL-123}"
    assert conn_edges[0].target_id == "NETWORK:198.51.100.1:80"
    assert ev.event_id in conn_edges[0].evidence_ids

def test_duplicate_network_edge_merging():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev1 = EvidenceEvent(
        event_id="EVT-NET-01",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_guid="{PROC-1}",
        network={"destination_ip": "1.1.1.1", "destination_port": "443"}
    )
    ev2 = EvidenceEvent(
        event_id="EVT-NET-02",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_guid="{PROC-1}",
        network={"destination_ip": "1.1.1.1", "destination_port": "443"}
    )

    inv = Investigation(
        case={"case_id": "TEST-03"},
        evidence=[ev1, ev2],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    conn_edges = [e for e in graph.get_edges() if e.relationship == "CONNECTED_TO"]

    assert len(conn_edges) == 1
    assert len(conn_edges[0].evidence_ids) == 2
    assert "EVT-NET-01" in conn_edges[0].evidence_ids
    assert "EVT-NET-02" in conn_edges[0].evidence_ids

def test_dns_no_graph_edge():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-DNS-02",
        timestamp=ts,
        source="sysmon",
        event_type="dns_query",
        process_guid="{PROC-2}",
        network={"query_name": "malicious.test"}
    )

    inv = Investigation(
        case={"case_id": "TEST-04"},
        evidence=[ev],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    net_nodes = graph.get_nodes("NETWORK")
    assert len(net_nodes) == 0  # DNS should not create a NETWORK node directly
    conn_edges = [e for e in graph.get_edges() if e.relationship == "CONNECTED_TO"]
    assert len(conn_edges) == 0

def test_network_attack_reconstruction():
    ts1 = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 8, 8, 10, 30, 1, tzinfo=timezone.utc)
    ev_net = EvidenceEvent(
        event_id="EVT-NET",
        timestamp=ts1,
        source="sysmon",
        event_type="network_connect",
        process_name="powershell.exe",
        network={"destination_ip": "10.0.0.1", "destination_port": "80", "protocol": "tcp"}
    )
    ev_dns = EvidenceEvent(
        event_id="EVT-DNS",
        timestamp=ts2,
        source="sysmon",
        event_type="dns_query",
        process_name="cmd.exe",
        network={"query_name": "test.local", "query_results": "10.0.0.2"}
    )

    inv = Investigation(
        case={"case_id": "TEST-05"},
        evidence=[ev_net, ev_dns],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)

    assert len(seq.stages) == 2
    assert seq.stages[0].stage_type == "NETWORK_ACTIVITY"
    assert seq.stages[0].title == "powershell.exe \u2192 10.0.0.1:80"
    assert seq.stages[0].attributes["protocol"] == "tcp"

    assert seq.stages[1].stage_type == "NETWORK_ACTIVITY"
    assert seq.stages[1].title == "DNS Query: test.local"
    assert seq.stages[1].description == "Result: 10.0.0.2"

def test_advanced_timeline_rendering():
    ts = datetime(2026, 8, 8, 10, 30, 15, tzinfo=timezone.utc)
    ev_net = EvidenceEvent(
        event_id="EVT-NET-001",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_name="powershell.exe",
        network={"destination_ip": "203.0.113.20", "destination_port": "443", "protocol": "tcp"}
    )

    inv = Investigation(
        case={"case_id": "TEST-06"},
        evidence=[ev_net],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    tl = build_advanced_timeline(inv, seq, graph)

    rendered = tl.render()
    assert "powershell.exe \u2192 203.0.113.20:443" in rendered
    assert "Protocol: TCP" in rendered
    assert "Evidence: EVT-NET-001" in rendered

def test_network_correlation():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceEvent(
        event_id="EVT-NET-01",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        network={"destination_ip": "1.1.1.1"}
    )

    finding = {
        "finding_id": "F-01",
        "title": "Suspicious Connection",
        "event_ids": ["EVT-NET-01"]
    }

    corr = {
        "incident_id": "INC-01",
        "evidence_event_ids": ["EVT-NET-01"],
        "start_time": "2026-08-08T10:30:00Z",
        "end_time": "2026-08-08T10:30:00Z"
    }

    inv = Investigation(
        case={"case_id": "TEST-07"},
        evidence=[ev],
        findings=[finding],
        correlations=[corr],
        timeline=[],
        processes={"nodes": {}},
        assessment=None
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)

    # We should have a FINDING upgraded network event, AND a CORRELATION stage
    # Wait, the finding will upgrade the event.
    assert len(seq.stages) == 2
    # One of them is CORRELATION
    corr_stage = next(s for s in seq.stages if s.stage_type == "CORRELATION")
    assert corr_stage.title == "Incident: INC-01"
    assert "EVT-NET-01" in corr_stage.evidence_ids
