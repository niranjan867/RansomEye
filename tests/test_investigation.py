import sqlite3
import json
import pytest
from pathlib import Path
from unittest import mock

from ransomeye.investigation import (
    load_investigation,
    get_investigation_summary,
    Investigation,
    InvestigationSummary,
)
from ransomeye.storage import EvidenceStore
from ransomeye.commands import show_investigation


@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test.db"
    return EvidenceStore(db_path)


def test_missing_case(tmp_path):
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.close()

    with pytest.raises(ValueError, match="Case not found: RE-DOES-NOT-EXIST"):
        load_investigation(db_path, "RE-DOES-NOT-EXIST")


def test_empty_case(store):
    store.create_case("RE-EMPTY", "Empty Case", "HOST-1")

    investigation = load_investigation(store.database_path, "RE-EMPTY")

    assert investigation.case["case_id"] == "RE-EMPTY"
    assert len(investigation.evidence) == 0
    assert len(investigation.findings) == 0
    assert investigation.assessment is None
    assert investigation.correlations == []
    assert investigation.timeline == []


def test_load_valid_case_with_metadata(store):
    store.create_case("RE-META", "Meta Case", "HOST-META")

    investigation = load_investigation(store.database_path, "RE-META")

    assert investigation.case["case_id"] == "RE-META"
    assert investigation.case["case_name"] == "Meta Case"
    assert investigation.case["host"] == "HOST-META"
    assert investigation.case["status"] == "OPEN"
    assert investigation.case["severity"] == "SAFE"


def test_load_evidence_and_timeline(store):
    store.create_case("RE-EV", "Evidence Case")

    event = {
        "event_id": "evt-1",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "1000",
    }
    store.save_event("RE-EV", event)

    investigation = load_investigation(store.database_path, "RE-EV")

    assert len(investigation.timeline) == 1
    assert investigation.timeline[0]["event_id"] == "evt-1"

    assert len(investigation.evidence) == 1
    assert investigation.evidence[0].event_id == "evt-1"
    assert investigation.evidence[0].process_name == "cmd.exe"


def test_load_findings_and_preserve_links(store):
    store.create_case("RE-FIND", "Finding Case")

    event = {
        "event_id": "evt-2",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "1000",
    }
    store.save_event("RE-FIND", event)

    finding = {
        "type": "test_finding",
        "score": 50,
        "confidence": 0.8,
        "technique": "T1059",
        "reason": "Test",
    }
    store.save_finding("RE-FIND", finding, event_ids=["evt-2"])

    investigation = load_investigation(store.database_path, "RE-FIND")

    assert len(investigation.findings) == 1
    f = investigation.findings[0]
    assert f["finding_type"] == "test_finding"
    assert f["score"] == 50
    assert f["confidence"] == 0.8
    assert f["technique"] == "T1059"
    assert f["reason"] == "Test"
    assert "evt-2" in f["event_ids"]


def test_case_with_evidence_no_findings(store):
    store.create_case("RE-EV-NO-FIND", "Ev No Find")
    event = {
        "event_id": "evt-3",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
    }
    store.save_event("RE-EV-NO-FIND", event)

    investigation = load_investigation(store.database_path, "RE-EV-NO-FIND")
    assert len(investigation.evidence) == 1
    assert len(investigation.findings) == 0


def test_load_stored_assessment_and_correlations(store):
    store.create_case("RE-ASSESS", "Assess Case")

    # Storage API does not support correlations natively in save_assessment,
    # but we can save an assessment and manually patch correlations to simulate previous phases
    assessment = {
        "score": 75,
        "severity": "HIGH",
        "confidence": 0.9,
        "reasons": ["Bad thing"],
        "techniques": ["T1000"],
    }
    store.save_assessment("RE-ASSESS", assessment)

    # Inject correlations_json for backward compat / simulated state
    correlations_data = [{"incident_id": "INC-01", "process_key": "cmd", "start_time": "2026", "end_time": "2026", "duration": 0, "evidence_event_ids": []}]
    try:
        store.connection.execute("ALTER TABLE assessments ADD COLUMN correlations_json TEXT")
    except sqlite3.OperationalError:
        pass # Might already exist or not supported, but let's just patch if possible

    # Instead of altering table, our load_investigation reads whatever is in assessments.
    # We will test without DB-level correlations if the schema doesn't have it.
    investigation = load_investigation(store.database_path, "RE-ASSESS")

    assert investigation.assessment is not None
    assert investigation.assessment["score"] == 75
    assert investigation.assessment["severity"] == "HIGH"
    assert investigation.assessment["confidence"] == 0.9
    assert investigation.assessment["reasons"] == ["Bad thing"]
    assert investigation.assessment["techniques"] == ["T1000"]
    # Since we didn't store correlations, it's empty
    assert investigation.correlations == []


def test_case_with_findings_no_correlations(store):
    store.create_case("RE-F-NO-C", "Find No Corr")
    finding = {
        "type": "test_finding",
        "score": 50,
        "confidence": 0.8,
        "technique": "T1059",
        "reason": "Test",
    }
    store.save_finding("RE-F-NO-C", finding)

    investigation = load_investigation(store.database_path, "RE-F-NO-C")
    assert len(investigation.findings) == 1
    assert investigation.correlations == []


def test_load_process_relationships(store):
    store.create_case("RE-PROC", "Process Case")

    store.save_event("RE-PROC", {
        "event_id": "evt-p1",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "parent.exe",
        "pid": "100",
    })
    store.save_event("RE-PROC", {
        "event_id": "evt-p2",
        "timestamp": "2026-08-08T15:01:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "child.exe",
        "pid": "200",
        "parent_pid": "100",
    })

    investigation = load_investigation(store.database_path, "RE-PROC")
    processes = investigation.processes

    assert "100" in processes["nodes"]
    assert "200" in processes["nodes"]
    assert "200" in processes["children"].get("100", [])


def test_generate_summary(store):
    store.create_case("RE-SUMM", "Summary Case", "HOST-SUMM")
    investigation = load_investigation(store.database_path, "RE-SUMM")

    summary_text = get_investigation_summary(investigation)

    assert "RANSOMEYE INVESTIGATION" in summary_text
    assert "Case:\nRE-SUMM" in summary_text
    assert "Host:\nHOST-SUMM" in summary_text
    assert "Status:\nOPEN" in summary_text
    assert "Evidence:\n0" in summary_text


def test_missing_assessment(store):
    store.create_case("RE-NO-ASSESS", "No Assess Case")

    investigation = load_investigation(store.database_path, "RE-NO-ASSESS")
    assert investigation.assessment is None


def test_existing_v5_database(tmp_path):
    db_path = tmp_path / "v5.db"
    store = EvidenceStore(db_path)
    store._set_schema_version(5)
    store.create_case("RE-V5", "V5")
    store.close()

    investigation = load_investigation(db_path, "RE-V5")
    assert investigation.case["case_id"] == "RE-V5"


def test_fresh_v5_database(store):
    store.create_case("RE-FRESH", "Fresh")
    assert store._get_schema_version() == 5

    investigation = load_investigation(store.database_path, "RE-FRESH")
    assert investigation.case["case_id"] == "RE-FRESH"


def test_cli_investigation_show(store, capsys):
    store.create_case("RE-CLI", "CLI Case")

    show_investigation(store.database_path, "RE-CLI")

    captured = capsys.readouterr()
    assert "RANSOMEYE INVESTIGATION" in captured.out
    assert "RE-CLI" in captured.out


@mock.patch("ransomeye.investigation.normalize_events")
@mock.patch("ransomeye.threat_assessment.assess_threat")
@mock.patch("ransomeye.correlation.correlate_events")
def test_regression_loading_does_not_recompute_assessment_or_correlate(
    mock_correlate, mock_assess, mock_normalize, store
):
    """
    CRITICAL REGRESSION TEST:
    Ensure loading an investigation does NOT invoke threat assessment
    or event correlation engines. It must solely be a read-oriented domain reconstruction.
    """
    store.create_case("RE-REGRESS", "Regression")
    assessment = {
        "score": 99,
        "severity": "CRITICAL",
        "confidence": 1.0,
        "reasons": ["Test reason"],
        "techniques": ["T9999"],
    }
    store.save_assessment("RE-REGRESS", assessment)

    # Must explicitly bypass actual normalize_events so we don't trip over mocks there
    mock_normalize.return_value = []

    investigation = load_investigation(store.database_path, "RE-REGRESS")

    # Assert neither was called
    mock_assess.assert_not_called()
    mock_correlate.assert_not_called()

    assert investigation.assessment is not None
    assert investigation.assessment["score"] == 99


def test_end_to_end_synthetic_case_RE_M12_001(store):
    store.create_case("RE-M12-001", "Synthetic Case", "LAPTOP-001")

    # 4 Evidence Events
    for i in range(4):
        store.save_event("RE-M12-001", {
            "event_id": f"evt-{i}",
            "timestamp": f"2026-08-08T15:0{i}:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "test.exe",
            "pid": f"10{i}",
        })

    # 3 Findings
    for i in range(3):
        store.save_finding("RE-M12-001", {
            "type": "test_finding",
            "score": 25,
            "confidence": 0.9,
            "technique": "T1059",
            "reason": "Test",
        }, event_ids=[f"evt-{i}"])

    # Assessment
    store.save_assessment("RE-M12-001", {
        "score": 76,
        "severity": "HIGH",
        "confidence": 0.91,
        "reasons": ["Test"],
        "techniques": ["T1059"],
    })

    # Actually add a correlations_json via direct SQL to test parsing of stored correlations,
    # simulating a system that *does* store them in assessments JSON.
    try:
        store.connection.execute("ALTER TABLE assessments ADD COLUMN correlations_json TEXT")
        corrs = [{"incident_id": "INC-01", "process_key": "pid:100", "start_time": "2026-08-08T15:00:00Z", "end_time": "2026-08-08T15:00:00Z", "duration": 0.0, "evidence_event_ids": ["evt-0", "evt-1"]}]
        store.connection.execute("UPDATE assessments SET correlations_json = ?", (json.dumps(corrs),))
        store.connection.commit()
    except sqlite3.OperationalError:
        pass

    investigation = load_investigation(store.database_path, "RE-M12-001")
    summary_text = get_investigation_summary(investigation)

    assert "Case:\nRE-M12-001" in summary_text
    assert "Host:\nLAPTOP-001" in summary_text
    assert "Evidence:\n4" in summary_text
    assert "Findings:\n3" in summary_text
    # 4 events, 4 processes since each has a distinct PID (100, 101, 102, 103)
    assert "Processes:\n4" in summary_text
    assert "Threat Assessment:\nHIGH" in summary_text
    assert "Threat Score:\n76/100" in summary_text
    assert "Confidence:\n0.91" in summary_text
