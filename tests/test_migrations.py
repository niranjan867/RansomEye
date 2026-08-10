import sqlite3

import pytest

from ransomeye.storage import EvidenceStore


def event(event_id, process_name="child.exe"):
    return {
        "event_id": event_id,
        "timestamp": "2026-08-08T21:48:01Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": process_name,
        "pid": "2000",
        "parent_pid": "1000",
        "process_guid": "child-guid",
        "parent_process_guid": "parent-guid",
        "parent_image": r"C:\Windows\System32\powershell.exe",
        "parent_command_line": "powershell.exe -NoProfile",
        "command_line": "child.exe",
        "metadata": {"rule": "Sysmon Event ID 1"},
    }


def table_columns(database_path):
    connection = sqlite3.connect(database_path)
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(events)")
    }
    connection.close()
    return columns


def test_new_database_receives_schema_version_six(tmp_path):
    database_path = tmp_path / "migrations.db"
    store = EvidenceStore(database_path)

    assert store._get_schema_version() == 6

    store.close()


def test_existing_cases_remain_after_reopening_database(tmp_path):
    database_path = tmp_path / "migrations.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="RE-MIG-001", case_name="Migration Test")
    store.close()

    reopened = EvidenceStore(database_path)
    case = reopened.get_case("RE-MIG-001")

    assert case is not None
    assert case["case_name"] == "Migration Test"

    reopened.close()


def test_v1_database_upgrades_to_v2(tmp_path):
    database_path = tmp_path / "v1.db"

    store = EvidenceStore(database_path)
    store.close()

    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA user_version = 1")
    connection.commit()
    connection.close()

    store = EvidenceStore(database_path)
    store.close()

    assert {
        "parent_process_guid",
        "parent_image",
        "parent_command_line",
    }.issubset(table_columns(database_path))


def test_existing_events_survive_v2_migration(tmp_path):
    database_path = tmp_path / "existing.db"

    store = EvidenceStore(database_path)
    store.create_case("CASE-1", "Migration Test", "TEST-PC")
    store.save_event("CASE-1", event("event-before"))
    store.close()

    store = EvidenceStore(database_path)
    store.close()

    connection = sqlite3.connect(database_path)
    row = connection.execute(
        """
        SELECT process_name
        FROM events
        WHERE event_id = ?
        """,
        ("event-before",),
    ).fetchone()
    connection.close()

    assert row == ("child.exe",)


def test_new_events_persist_parent_metadata(tmp_path):
    database_path = tmp_path / "metadata.db"

    store = EvidenceStore(database_path)
    store.create_case("CASE-2", "Metadata Test", "TEST-PC")
    store.save_event("CASE-2", event("event-after"))
    store.close()

    connection = sqlite3.connect(database_path)
    row = connection.execute(
        """
        SELECT
            parent_process_guid,
            parent_image,
            parent_command_line
        FROM events
        WHERE event_id = ?
        """,
        ("event-after",),
    ).fetchone()
    connection.close()

    assert row == (
        "parent-guid",
        r"C:\Windows\System32\powershell.exe",
        "powershell.exe -NoProfile",
    )


def test_reopening_v2_database_upgrades_to_v6_safely(tmp_path):
    database_path = tmp_path / "reopen.db"

    first = EvidenceStore(database_path)
    first.close()

    second = EvidenceStore(database_path)
    second.close()

    connection = sqlite3.connect(database_path)
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    connection.close()

    assert version == 6


def test_unsupported_future_schema_version_fails_clearly(tmp_path):
    database_path = tmp_path / "future.db"
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="Unsupported database schema version: 99"):
        EvidenceStore(database_path)


def test_existing_v4_database_migrates_to_v6(tmp_path):
    database_path = tmp_path / "v4_migrate.db"

    store = EvidenceStore(database_path)
    store.create_case("CASE-V4", "V4 Migration Case")
    store.save_event("CASE-V4", event("evt-v4-1"))
    store.save_finding("CASE-V4", {"type": "v4_finding", "score": 10, "reason": "v4 test"})
    store.close()

    conn = sqlite3.connect(database_path)
    conn.execute("PRAGMA user_version = 4")
    conn.execute("DROP TABLE IF EXISTS finding_evidence")
    conn.commit()
    conn.close()

    reopened = EvidenceStore(database_path)
    assert reopened._get_schema_version() == 6

    case = reopened.get_case("CASE-V4")
    events = reopened.get_case_events("CASE-V4")
    findings = reopened.get_case_findings("CASE-V4")

    assert case is not None
    assert len(events) == 1
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "v4_finding"
    reopened.close()


def test_finding_evidence_table_exists_and_supports_multiple_links(tmp_path):
    database_path = tmp_path / "links.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-LINKS", "Link Test")
    store.save_event("CASE-LINKS", event("evt-1"))
    store.save_event("CASE-LINKS", event("evt-2"))
    store.save_event("CASE-LINKS", event("evt-3"))

    fid1 = store.save_finding(
        "CASE-LINKS",
        {"type": "multi_event", "score": 20, "reason": "multiple events"},
        event_ids=["evt-1", "evt-2"],
    )

    fid2 = store.save_finding(
        "CASE-LINKS",
        {"type": "shared_event", "score": 15, "reason": "shared event"},
        event_ids=["evt-2", "evt-3"],
    )

    assert store.get_finding_event_ids(fid1) == ["evt-1", "evt-2"]
    assert store.get_finding_event_ids(fid2) == ["evt-2", "evt-3"]

    linked_events = store.get_finding_events(fid1)
    assert len(linked_events) == 2
    assert [e["event_id"] for e in linked_events] == ["evt-1", "evt-2"]
    store.close()


def test_duplicate_links_are_safely_ignored(tmp_path):
    database_path = tmp_path / "dup.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-DUP", "Dup Test")
    store.save_event("CASE-DUP", event("evt-1"))

    fid = store.save_finding(
        "CASE-DUP",
        {"type": "test_dup", "score": 5, "reason": "dup test"},
        event_ids=["evt-1", "evt-1"],
    )
    store.link_finding_evidence(fid, "evt-1")

    assert store.get_finding_event_ids(fid) == ["evt-1"]
    store.close()


def test_invalid_parent_references_rejected_when_foreign_keys_enabled(tmp_path):
    database_path = tmp_path / "fk.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-FK", "FK Test")

    with pytest.raises(sqlite3.IntegrityError):
        store.link_finding_evidence(9999, "nonexistent-evt")

    store.close()


def test_pragma_foreign_key_check_returns_no_violations(tmp_path):
    database_path = tmp_path / "fkcheck.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-FKC", "FK Check Test")
    store.save_event("CASE-FKC", event("evt-1"))
    fid = store.save_finding(
        "CASE-FKC",
        {"type": "fkc_finding", "score": 10, "reason": "fk check"},
        event_ids=["evt-1"],
    )

    conn = sqlite3.connect(database_path)
    conn.execute("PRAGMA foreign_keys = ON")
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    conn.close()

    assert len(violations) == 0
    store.close()


def test_existing_v5_database_migrates_to_v6(tmp_path):
    database_path = tmp_path / "v5_migrate.db"

    conn = sqlite3.connect(database_path)
    conn.execute("PRAGMA user_version = 5")
    conn.executescript("""
    CREATE TABLE cases (
        case_id TEXT PRIMARY KEY,
        case_name TEXT NOT NULL,
        host TEXT,
        status TEXT NOT NULL DEFAULT 'OPEN',
        severity TEXT NOT NULL DEFAULT 'SAFE',
        created_at TEXT NOT NULL
    );
    CREATE TABLE assessments (
        assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        score INTEGER NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        reasons_json TEXT NOT NULL,
        techniques_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    INSERT INTO cases (case_id, case_name, host, status, severity, created_at)
    VALUES ('CASE-V5', 'V5 Migration', 'PC-V5', 'OPEN', 'SAFE', '2026-08-10T10:00:00Z');
    INSERT INTO assessments (case_id, score, severity, confidence, reasons_json, techniques_json, created_at)
    VALUES ('CASE-V5', 60, 'MEDIUM', 0.85, '["reasons"]', '["tech"]', '2026-08-10T10:05:00Z');
    """)
    conn.commit()
    conn.close()

    store = EvidenceStore(database_path)
    assert store._get_schema_version() == 6

    case = store.get_case("CASE-V5")
    assert case["case_name"] == "V5 Migration"
    assert case["host"] == "PC-V5"

    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM assessments WHERE case_id = 'CASE-V5'").fetchone()
    conn.close()

    assert row["score"] == 60
    assert row["severity"] == "MEDIUM"
    assert row["confidence"] == 0.85
    assert row["reasons_json"] == '["reasons"]'
    assert row["techniques_json"] == '["tech"]'
    assert row["correlations_json"] == "[]"

    store.close()
