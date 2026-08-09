"""Tests for the Investigation Evidence Graph."""

from datetime import datetime

from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import build_investigation_graph


def _create_empty_investigation() -> Investigation:
    return Investigation(
        case={"case_id": "TEST-001", "case_name": "Empty"},
        evidence=[],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}, "children": {}, "roots": []},
        assessment=None
    )


def test_empty_investigation():
    inv = _create_empty_investigation()
    graph = build_investigation_graph(inv)

    assert len(graph.get_nodes()) == 1
    assert graph.get_node("CASE:TEST-001") is not None
    assert len(graph.get_edges()) == 0


def test_case_node_creation():
    inv = _create_empty_investigation()
    graph = build_investigation_graph(inv)

    case_node = graph.get_node("CASE:TEST-001")
    assert case_node.node_type == "CASE"
    assert case_node.attributes["case_id"] == "TEST-001"


def test_process_and_evidence_node_creation():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-001",
            timestamp=datetime(2026, 1, 1),
            source="test",
            event_type="process_creation",
            process_name="cmd.exe",
            process_guid="GUID-123",
            pid=100
        )
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("EVIDENCE:EVT-001") is not None
    assert graph.get_node("PROCESS:GUID-123") is not None
    # Verify no parent process was created since there's no parent info
    assert len(graph.get_process_nodes()) == 1


def test_parent_child_process_guid_relationship():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-001",
            timestamp=datetime(2026, 1, 1),
            source="test",
            event_type="process_creation",
            process_name="cmd.exe",
            process_guid="CHILD-GUID",
            parent_process_guid="PARENT-GUID"
        )
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("PROCESS:PARENT-GUID") is not None
    edges = graph.get_edges_for_node("PROCESS:CHILD-GUID")
    assert len(edges) == 1
    edge = edges[0]
    assert edge.relationship == "SPAWNED"
    assert edge.source_id == "PROCESS:PARENT-GUID"
    assert edge.target_id == "PROCESS:CHILD-GUID"
    assert edge.evidence_ids == ("EVT-001",)


def test_parent_child_pid_fallback_relationship():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-001",
            timestamp=datetime(2026, 1, 1),
            source="test",
            event_type="process_creation",
            process_name="cmd.exe",
            pid=100,
            parent_pid=50
        )
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("PROCESS:PID:50") is not None
    assert graph.get_node("PROCESS:PID:100") is not None
    edges = graph.get_edges_for_node("PROCESS:PID:100")
    assert len(edges) == 1
    assert edges[0].relationship == "SPAWNED"


def test_process_file_relationship():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-002",
            timestamp=datetime(2026, 1, 1),
            source="test",
            event_type="file_modify",
            process_guid="GUID-1",
            file_path="C:\\test.txt"
        )
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("FILE:c:\\test.txt") is not None
    edges = graph.get_edges_for_node("FILE:c:\\test.txt")
    assert len(edges) == 1
    assert edges[0].relationship == "MODIFIED"


def test_process_network_relationship():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-003",
            timestamp=datetime(2026, 1, 1),
            source="test",
            event_type="network_connect",
            process_guid="GUID-1",
            network={"destination_ip": "8.8.8.8", "destination_port": 443}
        )
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("NETWORK:8.8.8.8:443") is not None
    edges = graph.get_edges_for_node("NETWORK:8.8.8.8:443")
    assert len(edges) == 1
    assert edges[0].relationship == "CONNECTED_TO"
    assert edges[0].source_id == "PROCESS:GUID-1"


def test_finding_and_evidence_relationship():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(event_id="EVT-1", timestamp=datetime.now(), source="a", event_type="file_create")
    ]
    inv.findings = [
        {"finding_id": 99, "finding_type": "Test", "event_ids": ["EVT-1"]}
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("FINDING:99") is not None
    edges = graph.get_edges_for_node("FINDING:99")
    assert len(edges) == 1
    assert edges[0].relationship == "SUPPORTS"
    assert edges[0].source_id == "EVIDENCE:EVT-1"
    assert edges[0].target_id == "FINDING:99"


def test_correlation_and_finding_association():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(event_id="EVT-1", timestamp=datetime.now(), source="a", event_type="file_create")
    ]
    inv.findings = [
        {"finding_id": 99, "event_ids": ["EVT-1"]}
    ]
    inv.correlations = [
        {"incident_id": "INC-1", "evidence_event_ids": ["EVT-1"]}
    ]
    graph = build_investigation_graph(inv)

    assert graph.get_node("CORRELATION:INC-1") is not None
    edges = [e for e in graph.get_edges_for_node("CORRELATION:INC-1") if e.relationship == "ASSOCIATED_WITH"]
    assert len(edges) == 1
    assert edges[0].source_id == "FINDING:99"
    assert edges[0].target_id == "CORRELATION:INC-1"
    assert edges[0].evidence_ids == ("EVT-1",)


def test_correlation_to_assessment_relationship():
    inv = _create_empty_investigation()
    inv.correlations = [{"incident_id": "INC-1"}]
    inv.assessment = {"score": 100}
    graph = build_investigation_graph(inv)

    assert graph.get_node("ASSESSMENT:TEST-001") is not None
    edges = graph.get_edges_for_node("ASSESSMENT:TEST-001")
    assert len(edges) == 1
    assert edges[0].relationship == "CONTRIBUTES_TO"
    assert edges[0].source_id == "CORRELATION:INC-1"
    assert edges[0].target_id == "ASSESSMENT:TEST-001"


def test_duplicate_node_and_edge_prevention():
    inv = _create_empty_investigation()
    # 2 events from the same process modifying the same file
    inv.evidence = [
        EvidenceEvent(
            event_id="EVT-1", timestamp=datetime.now(), source="test", event_type="file_modify",
            process_guid="PROC-1", file_path="C:\\test.txt"
        ),
        EvidenceEvent(
            event_id="EVT-2", timestamp=datetime.now(), source="test", event_type="file_modify",
            process_guid="PROC-1", file_path="C:\\test.txt"
        )
    ]
    graph = build_investigation_graph(inv)

    assert len(graph.get_process_nodes()) == 1
    assert len(graph.get_file_nodes()) == 1

    # We should only have 1 MODIFIED edge between them, combining evidence IDs
    mod_edges = [e for e in graph.get_edges() if e.relationship == "MODIFIED"]
    assert len(mod_edges) == 1
    assert mod_edges[0].evidence_ids == ("EVT-1", "EVT-2")


def test_deterministic_generation():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(event_id="EVT-1", timestamp=datetime.now(), source="test", event_type="file_modify", process_guid="P-1", file_path="f1"),
        EvidenceEvent(event_id="EVT-2", timestamp=datetime.now(), source="test", event_type="file_modify", process_guid="P-2", file_path="f2")
    ]
    graph1 = build_investigation_graph(inv)
    graph2 = build_investigation_graph(inv)

    assert graph1.summary("TEST") == graph2.summary("TEST")
    assert [e.edge_id for e in graph1.get_edges()] == [e.edge_id for e in graph2.get_edges()]


def test_query_methods():
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(event_id="E-1", timestamp=datetime.now(), source="t", event_type="process_creation", process_guid="P-1", parent_process_guid="P-0")
    ]
    inv.findings = [{"finding_id": 1, "event_ids": ["E-1"]}]
    graph = build_investigation_graph(inv)

    assert len(graph.get_process_children("PROCESS:P-0")) == 1
    assert graph.get_process_children("PROCESS:P-0")[0].node_id == "PROCESS:P-1"

    assert len(graph.get_process_parents("PROCESS:P-1")) == 1
    assert graph.get_process_parents("PROCESS:P-1")[0].node_id == "PROCESS:P-0"

    assert len(graph.get_supporting_evidence("FINDING:1")) == 1
    assert graph.get_supporting_evidence("FINDING:1")[0].node_id == "EVIDENCE:E-1"


def test_missing_optional_fields():
    # e.g., missing process info
    inv = _create_empty_investigation()
    inv.evidence = [
        EvidenceEvent(event_id="EVT-1", timestamp=datetime.now(), source="a", event_type="file_create")
    ]
    graph = build_investigation_graph(inv)
    # Should not crash, just won't create process/file edge
    assert len(graph.get_process_nodes()) == 0


def test_end_to_end_synthetic_investigation():
    inv = _create_empty_investigation()
    inv.case["case_id"] = "RE-M13-001"

    t = datetime.now()
    inv.evidence = [
        EvidenceEvent(event_id="EVT-001", timestamp=t, source="x", event_type="process_creation", process_name="explorer.exe", pid=1000),
        EvidenceEvent(event_id="EVT-002", timestamp=t, source="x", event_type="process_creation", process_name="powershell.exe", pid=2000, parent_pid=1000),
        EvidenceEvent(event_id="EVT-003", timestamp=t, source="x", event_type="process_creation", process_name="suspicious.exe", pid=3000, parent_pid=2000),
        EvidenceEvent(event_id="EVT-004", timestamp=t, source="x", event_type="file_modify", pid=3000, file_path="C:\\file.doc"),
        EvidenceEvent(event_id="EVT-005", timestamp=t, source="x", event_type="file_create", pid=3000, file_path="C:\\ransom.txt"),
    ]
    inv.findings = [{"finding_id": 1, "event_ids": ["EVT-004", "EVT-005"]}]
    inv.correlations = [{"incident_id": "INC-1", "evidence_event_ids": ["EVT-004", "EVT-005"]}]
    inv.assessment = {"score": 99}

    graph = build_investigation_graph(inv)

    summary = graph.summary("RE-M13-001")
    assert "Processes:     3" in summary
    assert "Files:         2" in summary
    assert "Evidence:      5" in summary
    assert "Findings:      1" in summary
    assert "Correlations:  1" in summary
    assert "Assessment:    1" in summary
    assert "SPAWNED        2" in summary
    assert "CREATED        1" in summary
    assert "MODIFIED       1" in summary
    assert "SUPPORTS       2" in summary
    assert "ASSOCIATED_WITH 1" in summary
    assert "CONTRIBUTES_TO 1" in summary
