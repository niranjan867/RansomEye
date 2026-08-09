"""Tests for Advanced Investigation Timeline."""

from datetime import datetime, timezone

from ransomeye.advanced_timeline import (
    AdvancedTimeline,
    TimelineEntry,
    build_advanced_timeline,
)
from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack


def test_empty_investigation():
    inv = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    assert len(timeline.get_entries()) == 0
    assert "ADVANCED INVESTIGATION TIMELINE" in timeline.summary()


def test_process_and_command():
    ev_proc = EvidenceEvent(
        event_id="EVT-01",
        timestamp=datetime(2026, 8, 8, 10, 30, 0, tzinfo=timezone.utc),
        source="sysmon",
        event_type="process_creation",
        process_name="cmd.exe",
        pid=1000,
        process_guid="guid-1000",
    )
    ev_ps = EvidenceEvent(
        event_id="EVT-02",
        timestamp=datetime(2026, 8, 8, 10, 30, 5, tzinfo=timezone.utc),
        source="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        pid=2000,
        parent_pid=1000,
        parent_process_guid="guid-1000",
        parent_image="cmd.exe",
        process_guid="guid-2000",
        command_line="powershell -EncodedCommand SQBFAFgA",
    )
    finding = {
        "finding_id": "F-001",
        "finding_type": "suspicious_powershell",
        "title": "Encoded PowerShell",
        "event_ids": ["EVT-02"],
    }

    inv = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev_proc, ev_ps],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 2

    assert entries[0].entry_type == "PROCESS"
    assert entries[0].timestamp == ev_proc.timestamp

    assert entries[1].entry_type == "COMMAND"
    assert "EVT-02" in entries[1].evidence_ids
    assert "F-001" in entries[1].finding_ids
    assert entries[1].parent_process_name == "cmd.exe"

    render_out = timeline.render()
    assert "Parent: cmd.exe" in render_out


def test_mass_modification():
    ev1 = EvidenceEvent(
        event_id="EVT-M1",
        timestamp=datetime(2026, 8, 8, 10, 30, 10, tzinfo=timezone.utc),
        source="sysmon",
        event_type="file_modify",
        file_path="C:\\doc1.txt"
    )
    ev2 = EvidenceEvent(
        event_id="EVT-M2",
        timestamp=datetime(2026, 8, 8, 10, 30, 15, tzinfo=timezone.utc),
        source="sysmon",
        event_type="file_modify",
        file_path="C:\\doc2.txt"
    )
    finding = {
        "finding_id": "F-MASS",
        "finding_type": "mass_file_modification",
        "title": "Mass file modification",
        "event_ids": ["EVT-M1", "EVT-M2"],
    }

    inv = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev1, ev2],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 1
    assert entries[0].entry_type == "MASS_FILE_MODIFICATION"
    assert entries[0].timestamp == ev1.timestamp
    assert entries[0].end_time == ev2.timestamp

    render_out = timeline.render()
    assert "10:30:10 — 10:30:15" in render_out or "10:30:10" in render_out
    assert "EVT-M1 ... EVT-M2" not in render_out  # length is 2, so joined
    assert "EVT-M1, EVT-M2" in render_out


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
        "processes": [],
    }
    assess = {
        "score": 90,
        "severity": "CRITICAL",
        "confidence": 0.95
    }

    inv = Investigation(
        case={"case_id": "TEST-01"},
        evidence=[ev],
        findings=[],
        correlations=[corr],
        timeline=[],
        processes={"nodes": {}},
        assessment=assess,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 3
    assert entries[0].entry_type == "PROCESS"
    assert entries[1].entry_type == "CORRELATION"
    assert entries[1].timestamp.isoformat() == "2026-08-08T10:30:00+00:00"
    assert entries[1].end_time.isoformat() == "2026-08-08T10:35:00+00:00"
    assert entries[2].entry_type == "ASSESSMENT"
    assert entries[2].timestamp is None

    # Check query APIs
    assert len(timeline.get_entries_by_type("PROCESS")) == 1
    assert len(timeline.get_entries_for_evidence("EVT-01")) == 2  # PROCESS and CORRELATION
    assert len(timeline.get_entries_for_correlation("INC-001")) == 1

    summary = timeline.metadata_summary()
    assert "CRITICAL" in summary
    assert "90/100" in summary
