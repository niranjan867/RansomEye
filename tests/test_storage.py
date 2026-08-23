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


def test_storage_evidence_queries(tmp_path):
    from ransomeye.storage import EvidenceStore
    database_path = tmp_path / "search_test.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-SEARCH", "Search Test")

    event_network = {
        "event_id": "EVT-NET-01",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "network_connect",
        "process_name": "powershell.exe",
        "network": {"DestinationIp": "203.0.113.55"},
        "metadata": {"test": "val"},
    }

    event_file = {
        "event_id": "EVT-FILE-02",
        "timestamp": "2026-08-08T15:01:00Z",
        "source": "sysmon",
        "event_type": "file_create",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c vssadmin delete shadows",
        "file_path": "C:\\\\Windows\\\\System32\\\\vssadmin.exe",
        "network": {},
        "metadata": {"hash": "abc123hash"},
    }

    store.save_event("CASE-SEARCH", event_network)
    store.save_event("CASE-SEARCH", event_file)

    # 1. get_event returns expected event and hydrates JSON
    evt1 = store.get_event("CASE-SEARCH", "EVT-NET-01")
    assert evt1 is not None
    assert evt1["event_id"] == "EVT-NET-01"
    assert evt1["network_json"] == {"DestinationIp": "203.0.113.55"}
    assert evt1["metadata_json"] == {"test": "val"}

    # 2. get_event returns None for unknown event
    assert store.get_event("CASE-SEARCH", "EVT-UNKNOWN") is None

    # 3. get_event scoped to case_id
    assert store.get_event("OTHER-CASE", "EVT-NET-01") is None

    # 4. search_events finds by event ID
    res = store.search_events("CASE-SEARCH", "EVT-FILE-02")
    assert len(res) == 1
    assert res[0]["event_id"] == "EVT-FILE-02"

    # 5. search_events finds by IP in network_json
    res = store.search_events("CASE-SEARCH", "203.0.113.55")
    assert len(res) == 1
    assert res[0]["event_id"] == "EVT-NET-01"

    # 6. search_events finds by command line fragment (case-insensitive)
    res = store.search_events("CASE-SEARCH", "VSSADMIN")
    assert len(res) == 1
    assert res[0]["event_id"] == "EVT-FILE-02"

    # 7. search_events finds by process name
    res = store.search_events("CASE-SEARCH", "powershell")
    assert len(res) == 1
    assert res[0]["event_id"] == "EVT-NET-01"

    # 8. search_events finds by metadata hash
    res = store.search_events("CASE-SEARCH", "abc123hash")
    assert len(res) == 1

    # 9. search_events is scoped to case_id
    assert len(store.search_events("OTHER", "powershell")) == 0

    # 10. search results are ordered by timestamp ascending
    res = store.search_events("CASE-SEARCH", "sysmon")
    assert len(res) == 2
    assert res[0]["event_id"] == "EVT-NET-01"
    assert res[1]["event_id"] == "EVT-FILE-02"

    # 11. empty query returns empty list
    assert len(store.search_events("CASE-SEARCH", "")) == 0

    store.close()
