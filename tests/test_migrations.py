import sqlite3

import pytest

from ransomeye.storage import EvidenceStore


def test_new_database_receives_schema_version_one(tmp_path):
    database_path = tmp_path / "migrations.db"
    store = EvidenceStore(database_path)

    assert store._get_schema_version() == 1

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
    assert reopened._get_schema_version() == 1

    reopened.close()


def test_unsupported_future_schema_version_fails_clearly(tmp_path):
    database_path = tmp_path / "future.db"
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="Unsupported database schema version: 99"):
        EvidenceStore(database_path)
