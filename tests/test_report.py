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
    assert "Schema:     4" in report
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
