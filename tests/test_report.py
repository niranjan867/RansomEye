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
    assert "Schema:     6" in report
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
    original_correlate = threat_assessment.correlate_findings

    def spy_correlate(findings, evidence, processes=None):
        nonlocal correlation_call_count
        correlation_call_count += 1
        return original_correlate(findings, evidence, processes)

    monkeypatch.setattr(threat_assessment, "correlate_findings", spy_correlate)

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
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "1000",
            "process_guid": "{SC-GUID}",
        },
    )
    store.close()

    # Generate report without passing assessment and without stored assessment -> report triggers assess_threat once
    report = generate_case_report(database_path, "CASE-SINGLE-CALL")

    assert correlation_call_count == 1
    assert "CORRELATIONS" in report
    assert "Incident:    INC-" in report


# --- Milestone 21.2 Persisted Assessment Report Integration Tests ---


def test_report_uses_persisted_assessment_from_database(tmp_path):
    database_path = tmp_path / "persisted_report.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-PERSIST", "Persisted Case")
    store.save_event(
        "CASE-PERSIST",
        {
            "event_id": "evt-p-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1000",
        },
    )
    persisted_assessment = {
        "score": 65,
        "severity": "MEDIUM",
        "confidence": 0.85,
        "reasons": ["Persisted reason 1", "Persisted reason 2"],
        "techniques": ["T1059.001"],
        "correlations": [
            {
                "incident_id": "INC-PERSISTED-123",
                "process_key": "guid:{PERSIST-GUID}",
                "start_time": "2026-08-08T15:00:00Z",
                "end_time": "2026-08-08T15:00:10Z",
                "duration": 10.0,
                "evidence_event_ids": ["evt-p-1"],
            }
        ],
    }
    store.save_assessment("CASE-PERSIST", persisted_assessment)
    store.close()

    report = generate_case_report(database_path, "CASE-PERSIST")

    assert "Score:      65" in report
    assert "Severity:   MEDIUM" in report
    assert "Confidence: 0.85" in report
    assert "- Persisted reason 1" in report
    assert "- Persisted reason 2" in report
    assert "- T1059.001" in report
    assert "CORRELATIONS" in report
    assert "Incident:    INC-PERSISTED-123" in report
    assert "Process Key: guid:{PERSIST-GUID}" in report
    assert "Duration:    10.0s" in report
    assert "Events:      evt-p-1" in report


def test_report_does_not_call_assess_threat_when_persisted_assessment_exists(monkeypatch, tmp_path):
    from ransomeye import threat_assessment

    assess_called = False

    def fake_assess(events, processes=None):
        nonlocal assess_called
        assess_called = True
        raise AssertionError("assess_threat should not be called when persisted assessment exists")

    monkeypatch.setattr(threat_assessment, "assess_threat", fake_assess)

    database_path = tmp_path / "no_recompute.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-NO-RECOMP", "No Recompute Case")
    store.save_event(
        "CASE-NO-RECOMP",
        {
            "event_id": "evt-nr-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
        },
    )
    persisted_assessment = {
        "score": 40,
        "severity": "LOW",
        "confidence": 0.70,
        "reasons": ["Already assessed"],
        "techniques": ["T1059"],
        "correlations": [],
    }
    store.save_assessment("CASE-NO-RECOMP", persisted_assessment)
    store.close()

    report = generate_case_report(database_path, "CASE-NO-RECOMP")

    assert not assess_called
    assert "Score:      40" in report
    assert "Severity:   LOW" in report
    assert "- Already assessed" in report


def test_explicit_assessment_takes_precedence_over_persisted_assessment(tmp_path):
    database_path = tmp_path / "explicit_precedence.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-PRECEDENCE", "Precedence Case")
    store.save_assessment(
        "CASE-PRECEDENCE",
        {
            "score": 20,
            "severity": "SAFE",
            "confidence": 0.50,
            "reasons": ["Persisted old reason"],
            "techniques": [],
            "correlations": [],
        },
    )
    store.close()

    override_assessment = {
        "score": 90,
        "severity": "CRITICAL",
        "confidence": 0.99,
        "reasons": ["Overridden critical reason"],
        "techniques": ["T1486"],
        "correlations": [
            {
                "incident_id": "INC-OVERRIDE-999",
                "process_key": "pid:1234",
                "start_time": "2026-08-08T16:00:00Z",
                "end_time": "2026-08-08T16:00:05Z",
                "duration": 5.0,
                "evidence_event_ids": ["evt-ov-1"],
            }
        ],
    }

    report = generate_case_report(database_path, "CASE-PRECEDENCE", assessment=override_assessment)

    assert "Score:      90" in report
    assert "Severity:   CRITICAL" in report
    assert "- Overridden critical reason" in report
    assert "Incident:    INC-OVERRIDE-999" in report
    assert "Persisted old reason" not in report
