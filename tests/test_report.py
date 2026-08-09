from ransomeye.report import generate_case_report, write_case_report
from ransomeye.storage import EvidenceStore


def test_generate_case_report(tmp_path):
    from ransomeye.storage import EvidenceStore

    database_path = tmp_path / "report.db"

    store = EvidenceStore(database_path)
    store.create_case(
        case_id="REPORT-001",
        case_name="Report Test",
        host="TEST-PC",
    )
    store.save_event(
        "REPORT-001",
        {
            "event_id": "event-1",
            "timestamp": "2026-08-08T21:48:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1000",
            "parent_pid": "500",
            "process_guid": "child-guid",
            "parent_process_guid": "parent-guid",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_command_line": "explorer.exe",
            "command_line": "powershell.exe -NoProfile",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
    )
    store.close()

    report = generate_case_report(
        database_path,
        "REPORT-001",
    )

    assert "RANSOMEYE CASE REPORT" in report
    assert "REPORT-001" in report
    assert "Report Test" in report
    assert "ASSESSMENT" in report
    assert "TIMELINE" in report
    assert "PROCESS TREE" in report
    assert "Schema:     5" in report
    assert "Command line:" in report

    assert "Process GUID:" in report
    assert "Parent GUID:" in report
    assert "Parent image:" in report


def test_case_report_includes_lifecycle_history(tmp_path):
    database_path = tmp_path / "case.db"
    output_path = tmp_path / "case-report.txt"

    store = EvidenceStore(database_path)
    store.create_case(case_id="RE-V2-LIVE-001", case_name="Lifecycle Report")
    store.update_case_status(
        case_id="RE-V2-LIVE-001",
        status="TRIAGED",
        note="Reviewed stored process timeline",
    )
    store.close()

    write_case_report(
        database_path=database_path,
        case_id="RE-V2-LIVE-001",
        output_path=output_path,
    )

    report = output_path.read_text(encoding="utf-8")

    assert "Case lifecycle" in report
    assert "Current status: TRIAGED" in report
    assert "OPEN -> TRIAGED" in report
    assert "Reviewed stored process timeline" in report


def test_case_report_includes_current_status_without_history(tmp_path):
    database_path = tmp_path / "case.db"
    output_path = tmp_path / "case-report.txt"

    store = EvidenceStore(database_path)
    store.create_case(case_id="RE-OPEN-001", case_name="Lifecycle Report")
    store.close()

    write_case_report(
        database_path=database_path,
        case_id="RE-OPEN-001",
        output_path=output_path,
    )

    report = output_path.read_text(encoding="utf-8")

    assert "Current status: OPEN" in report
    assert "Case lifecycle" in report
    assert "No status changes recorded." in report


def test_case_report_includes_chain_of_custody(tmp_path):
    database_path = tmp_path / "case.db"
    output_path = tmp_path / "case-report.txt"

    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Report")
    store.record_custody_event(
        case_id="CASE-001",
        artifact_path="reports/case-report.txt",
        sha256="a" * 64,
        action="created",
        analyst="analyst@example.com",
        note="Initial report generated",
        verification_result=None,
    )
    store.close()

    write_case_report(
        database_path=database_path,
        case_id="CASE-001",
        output_path=output_path,
    )

    report = output_path.read_text(encoding="utf-8")

    assert "CHAIN OF CUSTODY" in report
    assert "Artifact: reports/case-report.txt" in report
    assert "Action: created" in report
    assert "Analyst: analyst@example.com" in report
    assert "SHA-256: " + "a" * 64 in report
    assert "Verification: N/A" in report
    assert "Note: Initial report generated" in report


def test_case_report_shows_failed_verification(tmp_path):
    database_path = tmp_path / "case.db"
    output_path = tmp_path / "case-report.txt"

    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-002", case_name="Custody Report")
    store.record_custody_event(
        case_id="CASE-002",
        artifact_path="reports/case-report.txt",
        sha256="b" * 64,
        action="verified",
        analyst="analyst@example.com",
        note="Manifest mismatch",
        verification_result=False,
    )
    store.close()

    write_case_report(
        database_path=database_path,
        case_id="CASE-002",
        output_path=output_path,
    )

    report = output_path.read_text(encoding="utf-8")

    assert "CHAIN OF CUSTODY" in report

    assert "Verification: FAILED" in report
    assert "Note: Manifest mismatch" in report


def test_report_includes_evidence_traceability_for_linked_finding(tmp_path):
    database_path = tmp_path / "trace_report.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-TR-REP", "Traceability Report Test")
    store.save_event(
        "CASE-TR-REP",
        {
            "event_id": "evt-tr-101",
            "timestamp": "2026-08-08T20:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "3333",
        },
    )
    store.save_finding(
        "CASE-TR-REP",
        {"type": "suspicious_cmd", "score": 15, "reason": "Suspicious cmd execution"},
        event_ids=["evt-tr-101"],
    )
    store.close()

    report = generate_case_report(database_path, "CASE-TR-REP")

    assert "EVIDENCE TRACEABILITY" in report
    assert "Finding #1: suspicious_cmd" in report
    assert "Evidence Event ID: evt-tr-101" in report
    assert "Time:              2026-08-08T20:00:00Z" in report
    assert "Process:           cmd.exe" in report
    assert "PID:               3333" in report


def test_finding_linked_to_multiple_events_prints_all_evidence_ids(tmp_path):
    database_path = tmp_path / "multi_ev_report.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-MEV-REP", "Multi Event Report Test")
    store.save_event("CASE-MEV-REP", {"event_id": "evt-m1", "timestamp": "2026-08-08T20:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.save_event("CASE-MEV-REP", {"event_id": "evt-m2", "timestamp": "2026-08-08T20:00:01Z", "source": "sysmon", "event_type": "process_creation"})
    store.save_finding(
        "CASE-MEV-REP",
        {"type": "multi_event_rule", "score": 25, "reason": "Multi event pattern"},
        event_ids=["evt-m1", "evt-m2"],
    )
    store.close()

    report = generate_case_report(database_path, "CASE-MEV-REP")

    assert "EVIDENCE TRACEABILITY" in report
    assert "Evidence Event ID: evt-m1" in report
    assert "Evidence Event ID: evt-m2" in report


def test_finding_without_evidence_remains_reportable(tmp_path):
    database_path = tmp_path / "no_ev_report.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-NOEV-REP", "No Evidence Report Test")
    store.save_finding("CASE-NOEV-REP", {"type": "manual_rule", "score": 5, "reason": "No evidence attached"})
    store.close()

    report = generate_case_report(database_path, "CASE-NOEV-REP")

    assert "EVIDENCE TRACEABILITY" in report
    assert "No evidence links." in report


def test_report_renders_correlations_supplied_by_assessment(tmp_path):
    database_path = tmp_path / "supplied_corr.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-SUPP", "Supplied Correlation Test")
    store.close()

    custom_assessment = {
        "score": 50,
        "severity": "LOW",
        "confidence": 0.8,
        "reasons": ["Test reason"],
        "techniques": ["T1059"],
        "correlation_count": 1,
        "correlations": [
            {
                "incident_id": "INC-SUPP-001",
                "process_key": "guid:{SUPP-GUID}",
                "start_time": "2026-08-08T12:00:00Z",
                "end_time": "2026-08-08T12:00:05Z",
                "duration": 5.0,
                "evidence_event_ids": ["evt-supp-1", "evt-supp-2"],
            }
        ],
    }

    report = generate_case_report(database_path, "CASE-SUPP", assessment=custom_assessment)

    assert "CORRELATIONS" in report
    assert "Incident:    INC-SUPP-001" in report
    assert "Process Key: guid:{SUPP-GUID}" in report
    assert "Events:      evt-supp-1, evt-supp-2" in report


def test_report_module_contains_no_direct_correlate_events_import():
    import ransomeye.report as report_mod

    assert "correlate_events" not in report_mod.__dict__


def test_report_renders_no_correlations_for_empty_list(tmp_path):
    database_path = tmp_path / "empty_corr.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-EMP-CORR", "Empty Correlation Test")
    store.close()

    custom_assessment = {
        "score": 0,
        "severity": "SAFE",
        "confidence": 0.95,
        "reasons": [],
        "techniques": [],
        "correlation_count": 0,
        "correlations": [],
    }

    report = generate_case_report(database_path, "CASE-EMP-CORR", assessment=custom_assessment)

    assert "CORRELATIONS" in report
    assert "No correlations." in report


def test_assessment_path_computes_correlations_once_and_report_consumes_result(monkeypatch, tmp_path):
    from ransomeye import threat_assessment

    correlation_call_count = 0
    original_correlate = threat_assessment.correlate_events

    def spy_correlate(events):
        nonlocal correlation_call_count
        correlation_call_count += 1
        return original_correlate(events)

    monkeypatch.setattr(threat_assessment, "correlate_events", spy_correlate)

    database_path = tmp_path / "single_corr_call.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-SINGLE-CALL", "Single Call Test")
    store.save_event(
        "CASE-SINGLE-CALL",
        {
            "event_id": "evt-sc-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "test.exe",
            "process_guid": "{SC-GUID}",
        },
    )
    store.close()

    # Generate report without passing assessment -> report triggers assess_threat once
    report = generate_case_report(database_path, "CASE-SINGLE-CALL")

    assert correlation_call_count == 1
    assert "CORRELATIONS" in report
    assert "Incident:    INC-0001" in report
