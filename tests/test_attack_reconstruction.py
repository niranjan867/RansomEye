"""Tests for attack reconstruction and advanced timeline."""

from datetime import datetime, timezone

import pytest

from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack


def test_empty_investigation():
    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    assert len(seq.stages) == 0
    assert "ATTACK RECONSTRUCTION" in seq.summary()


def test_single_process_execution():
    ev = EvidenceEvent(
        event_id="EVT-01",
        timestamp=datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc),
        source="sysmon",
        event_type="process_creation",
        process_name="cmd.exe",
        pid=1000,
        process_guid="guid-1000",
        command_line="cmd.exe /c echo hello",
    )
    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    assert len(seq.stages) == 1
    stage = seq.stages[0]
    assert stage.stage_type == "PROCESS_EXECUTION"
    assert "EVT-01" in stage.evidence_ids
    assert "PROCESS:guid-1000" in stage.process_ids
    assert "cmd.exe [PID 1000]" in stage.title
    assert stage.description == "cmd.exe /c echo hello"


def test_suspicious_powershell_finding():
    ev = EvidenceEvent(
        event_id="EVT-PS",
        timestamp=datetime(2026, 8, 8, 10, 30, 5, tzinfo=timezone.utc),
        source="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        pid=2000,
        command_line="powershell -EncodedCommand SQBFAFgA",
    )
    finding = {
        "finding_id": "F-001",
        "finding_type": "suspicious_powershell",
        "title": "Encoded PowerShell",
        "event_ids": ["EVT-PS"],
    }

    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    assert len(seq.stages) == 1
    stage = seq.stages[0]
    assert stage.stage_type == "SUSPICIOUS_COMMAND"
    assert "F-001" in stage.finding_ids
    assert "EVT-PS" in stage.evidence_ids
    assert stage.title == "Encoded PowerShell"


def test_mass_file_modification():
    ev1 = EvidenceEvent(
        event_id="EVT-F1",
        timestamp=datetime(2026, 8, 8, 10, 30, 10, tzinfo=timezone.utc),
        source="sysmon",
        event_type="file_modify",
        file_path=r"C:\Users\test\doc1.txt",
        process_guid="guid-suspicious"
    )
    ev2 = EvidenceEvent(
        event_id="EVT-F2",
        timestamp=datetime(2026, 8, 8, 10, 30, 15, tzinfo=timezone.utc),
        source="sysmon",
        event_type="file_modify",
        file_path=r"C:\Users\test\doc2.txt",
        process_guid="guid-suspicious"
    )
    finding = {
        "finding_id": "F-MASS",
        "finding_type": "mass_file_modification",
        "title": "150 files modified",
        "event_ids": ["EVT-F1", "EVT-F2"],
    }

    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev1, ev2],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    # Should be grouped into one stage
    assert len(seq.stages) == 1
    stage = seq.stages[0]
    assert stage.stage_type == "MASS_FILE_MODIFICATION"
    assert "EVT-F1" in stage.evidence_ids
    assert "EVT-F2" in stage.evidence_ids
    assert stage.timestamp == ev1.timestamp
    assert stage.end_time == ev2.timestamp
    assert "PROCESS:guid-suspicious" in stage.process_ids


def test_correlation_and_assessment():
    ev = EvidenceEvent(
        event_id="EVT-01",
        timestamp=datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc),
        source="sysmon",
        event_type="process_creation",
    )
    corr = {
        "incident_id": "INC-001",
        "start_time": "2026-08-08T10:30:00+00:00",
        "end_time": "2026-08-08T10:35:00+00:00",
        "evidence_event_ids": ["EVT-01"],
        "processes": [{"process_guid": "p1"}],
    }
    assess = {
        "score": 90,
        "severity": "CRITICAL",
        "confidence": 0.95
    }

    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev],
        findings=[],
        correlations=[corr],
        timeline=[],
        processes={"nodes": {}},
        assessment=assess,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    assert len(seq.stages) == 3
    assert seq.stages[0].stage_type == "PROCESS_EXECUTION"
    assert seq.stages[1].stage_type == "CORRELATION"
    assert seq.stages[1].correlation_ids == ("INC-001",)
    assert seq.stages[2].stage_type == "ASSESSMENT"
    assert seq.stages[2].timestamp is None  # Assessment should not have a timestamp

    summary = seq.summary()
    assert "────────────────────────────" in summary
    assert "ASSESSMENT" in summary
    assert "CRITICAL" in summary


def test_network_and_ransom_note():
    ev_net = EvidenceEvent(
        event_id="EVT-NET",
        timestamp=datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc),
        source="sysmon",
        event_type="network_connect",
        network={"destination_ip": "1.2.3.4", "destination_port": 443}
    )
    ev_note = EvidenceEvent(
        event_id="EVT-NOTE",
        timestamp=datetime(2026, 8, 8, 10, 30, 5, tzinfo=timezone.utc),
        source="sysmon",
        event_type="file_create",
        file_path="C:\\README.txt"
    )
    finding = {
        "finding_id": "F-NOTE",
        "finding_type": "ransom_note",
        "title": "Ransom note created",
        "event_ids": ["EVT-NOTE"]
    }

    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev_net, ev_note],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    assert len(seq.stages) == 2
    assert seq.stages[0].stage_type == "NETWORK_ACTIVITY"
    assert "1.2.3.4" in seq.stages[0].description
    assert seq.stages[1].stage_type == "RANSOM_NOTE"
    assert seq.stages[1].title == "Ransom note created"


def test_deterministic_ordering():
    ts = datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc)
    ev1 = EvidenceEvent(event_id="EVT-01", timestamp=ts, source="sysmon", event_type="process_creation")
    ev2 = EvidenceEvent(event_id="EVT-02", timestamp=ts, source="sysmon", event_type="file_create")

    investigation = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev1, ev2],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(investigation)
    seq = reconstruct_attack(investigation, graph)

    # Process Execution (10) should sort before File Activity (30)
    assert seq.stages[0].stage_type == "PROCESS_EXECUTION"
    assert seq.stages[1].stage_type == "FILE_ACTIVITY"
