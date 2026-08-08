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


def test_new_database_receives_schema_version_three(tmp_path):
    database_path = tmp_path / "migrations.db"
    store = EvidenceStore(database_path)

    assert store._get_schema_version() == 3

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


def test_reopening_already_current_database_is_safe(tmp_path):
    database_path = tmp_path / "migrations.db"
    store = EvidenceStore(database_path)
    store.close()

    reopened = EvidenceStore(database_path)
    assert reopened._get_schema_version() == 3

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


def test_reopening_v2_database_is_safe(tmp_path):
    database_path = tmp_path / "reopen.db"

    first = EvidenceStore(database_path)
    first.close()

    second = EvidenceStore(database_path)
    second.close()

    connection = sqlite3.connect(database_path)
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    connection.close()

    assert version == 3


def test_unsupported_future_schema_version_fails_clearly(tmp_path):
    database_path = tmp_path / "future.db"
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="Unsupported database schema version: 99"):
        EvidenceStore(database_path)
