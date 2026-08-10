from datetime import datetime, timezone
import json

from ransomeye.storage import EvidenceStore


def test_case_and_event_are_saved(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)

    store.create_case(
        case_id="RE-TEST-001",
        case_name="Storage Test",
        host="TEST-PC",
    )

    event = {
        "event_id": "event-001",
        "timestamp": datetime(
            2026,
            8,
            8,
            15,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        "source": "simulation",
        "event_type": "process_create",
        "process_name": "powershell.exe",
        "pid": "4532",
        "parent_pid": "1200",
        "command_line": "powershell.exe Get-Date",
        "metadata": {"test": True},
    }

    store.save_event("RE-TEST-001", event)

    saved_case = store.get_case("RE-TEST-001")
    saved_events = store.get_case_events("RE-TEST-001")

    assert saved_case["case_name"] == "Storage Test"
    assert saved_case["host"] == "TEST-PC"
    assert len(saved_events) == 1
    assert saved_events[0]["process_name"] == "powershell.exe"

    store.close()


def test_assessment_is_saved_and_updates_case(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)

    store.create_case(
        case_id="RE-TEST-002",
        case_name="Assessment Test",
    )

    assessment = {
        "score": 65,
        "severity": "MEDIUM",
        "confidence": 0.85,
        "reasons": ["Suspicious behavior detected"],
        "techniques": ["T1059.001"],
    }

    store.save_assessment("RE-TEST-002", assessment)

    saved_case = store.get_case("RE-TEST-002")

    assert saved_case["severity"] == "MEDIUM"

    store.close()


def test_finding_is_saved(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)

    store.create_case(
        case_id="RE-TEST-003",
        case_name="Finding Test",
    )

    finding = {
        "type": "suspicious_powershell",
        "score": 10,
        "confidence": 0.8,
        "technique": "T1059.001",
        "reason": "Encoded PowerShell detected",
    }

    store.save_finding("RE-TEST-003", finding)

    row = store.connection.execute(
        """
        SELECT *
        FROM findings
        WHERE case_id = ?
        """,
        ("RE-TEST-003",),
    ).fetchone()

    assert row["finding_type"] == "suspicious_powershell"
    assert row["score"] == 10
    assert row["technique"] == "T1059.001"

    store.close()


def test_assessment_saves_empty_correlations_by_default(tmp_path):
    database_path = tmp_path / "default_corr.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-DEF-CORR", "Default Correlation Test")

    assessment = {
        "score": 50,
        "severity": "MEDIUM",
        "confidence": 0.8,
        "reasons": ["test"],
        "techniques": [],
    }

    store.save_assessment("CASE-DEF-CORR", assessment)
    row = store.connection.execute("SELECT * FROM assessments").fetchone()
    assert row["correlations_json"] == "[]"
    store.close()


def test_assessment_persists_correlation_data_correctly(tmp_path):
    database_path = tmp_path / "persist_corr.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-PERSIST-CORR", "Correlation Persistence Test")

    correlations = [
        {
            "incident_id": "INC-TEST-001",
            "finding_ids": ["F-001", "F-002"],
            "evidence_ids": ["EVT-001", "EVT-002"],
            "process_ids": ["PROCESS:TEST"],
            "start_time": "2026-08-10T10:00:00+00:00",
            "end_time": "2026-08-10T10:00:30+00:00",
        }
    ]

    assessment = {
        "score": 80,
        "severity": "HIGH",
        "confidence": 0.95,
        "reasons": ["PowerShell + file behavior"],
        "techniques": [],
        "correlations": correlations,
    }

    store.save_assessment("CASE-PERSIST-CORR", assessment)

    row = store.connection.execute("SELECT * FROM assessments").fetchone()
    assert row["correlations_json"] is not None
    loaded_correlations = json.loads(row["correlations_json"])
    assert len(loaded_correlations) == 1
    assert loaded_correlations[0]["incident_id"] == "INC-TEST-001"
    assert loaded_correlations[0]["finding_ids"] == ["F-001", "F-002"]
    store.close()
