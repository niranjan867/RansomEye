import sqlite3

import pytest

from ransomeye.storage import EvidenceStore


def test_new_case_starts_open(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)

    store.create_case(case_id="RE-DETECTION-001", case_name="Detection Case")

    case = store.get_case("RE-DETECTION-001")

    assert case is not None
    assert case["status"] == "OPEN"

    store.close()


def test_case_status_can_be_triaged(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)

    store.create_case(case_id="RE-DETECTION-001", case_name="Detection Case")
    store.update_case_status("RE-DETECTION-001", "TRIAGED")

    case = store.get_case("RE-DETECTION-001")

    assert case is not None
    assert case["status"] == "TRIAGED"

    store.close()


def test_status_change_creates_history_row(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)

    store.create_case(case_id="RE-DETECTION-001", case_name="Detection Case")
    store.update_case_status(
        "RE-DETECTION-001",
        "TRIAGED",
        note="Reviewed encoded PowerShell finding",
    )

    history = store.get_case_history("RE-DETECTION-001")

    assert len(history) == 1
    assert history[0]["old_status"] == "OPEN"
    assert history[0]["new_status"] == "TRIAGED"
    assert history[0]["note"] == "Reviewed encoded PowerShell finding"

    store.close()


def test_invalid_status_is_rejected(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)

    store.create_case(case_id="RE-DETECTION-001", case_name="Detection Case")

    with pytest.raises(ValueError, match="Unsupported case status"):
        store.update_case_status("RE-DETECTION-001", "PENDING")

    store.close()


def test_case_can_be_reopened(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)

    store.create_case(case_id="RE-DETECTION-001", case_name="Detection Case")
    store.update_case_status("RE-DETECTION-001", "TRIAGED")
    store.update_case_status("RE-DETECTION-001", "REOPENED")

    case = store.get_case("RE-DETECTION-001")
    history = store.get_case_history("RE-DETECTION-001")

    assert case is not None
    assert case["status"] == "REOPENED"
    assert [row["new_status"] for row in history] == ["TRIAGED", "REOPENED"]

    store.close()


def test_current_migration_creates_case_history_table(tmp_path):
    database_path = tmp_path / "case_lifecycle.db"
    store = EvidenceStore(database_path)
    store.close()

    connection = sqlite3.connect(database_path)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    connection.close()

    assert "case_history" in tables
    assert version == 6
