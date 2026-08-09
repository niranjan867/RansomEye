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


def test_report_includes_correlations_section(tmp_path):
    database_path = tmp_path / "corr_report.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-CORR-REP", "Correlation Report Test")
    store.save_event(
        "CASE-CORR-REP",
        {
            "event_id": "evt-c1",
            "timestamp": "2026-08-08T20:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "notepad.exe",
            "process_guid": "{GUID-NOTEPAD}",
        },
    )
    store.close()

    report = generate_case_report(database_path, "CASE-CORR-REP")

    assert "CORRELATIONS" in report
    assert "Incident:    INC-0001" in report
    assert "Process Key: guid:{GUID-NOTEPAD}" in report
    assert "Events:      evt-c1" in report


def test_end_to_end_traceability_report(monkeypatch, tmp_path):
    from ransomeye import pipeline

    events = [
        {
            "event_id": "e2e-ps-999",
            "timestamp": "2026-08-08T18:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "7777",
            "parent_pid": "1000",
            "process_guid": "{E2E-PS-GUID}",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand SGVsbG8=",
            "metadata": {"rule": "Sysmon Event ID 1"},
        }
    ]

    monkeypatch.setattr(pipeline, "read_process_creation_events", lambda limit: events)
    database_path = tmp_path / "e2e_report.db"

    pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-E2E-001",
        case_name="End to End Traceability",
        limit=10,
    )

    report = generate_case_report(database_path, "RE-E2E-001")

    assert "RANSOMEYE CASE REPORT" in report
    assert "FINDINGS" in report
    assert "EVIDENCE TRACEABILITY" in report
    assert "Finding #1: suspicious_powershell" in report
    assert "Evidence Event ID: e2e-ps-999" in report
    assert "Process:           powershell.exe" in report
    assert "PID:               7777" in report
    assert "CORRELATIONS" in report
    assert "Incident:    INC-0001" in report
    assert "Events:      e2e-ps-999" in report
