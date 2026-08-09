"""Database backup tests for RansomEye."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.storage import EvidenceStore, backup_database, check_database_integrity


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_healthy_database_creates_valid_backup(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Backup Case")
    store.save_event("CASE-001", {"event_id": "evt-1", "timestamp": "2026-08-09T12:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.close()

    result_path = backup_database(source_db, backup_db)
    assert result_path == backup_db
    assert backup_db.is_file()
    assert check_database_integrity(backup_db) is True

    backup_store = EvidenceStore(backup_db)
    case = backup_store.get_case("CASE-001")
    assert case is not None
    assert case["case_name"] == "Backup Case"
    backup_store.close()


def test_backup_passes_integrity_check(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-002", "Integrity Case")
    store.close()

    backup_database(source_db, backup_db)
    assert check_database_integrity(backup_db) is True


def test_existing_destination_is_not_overwritten(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_db.write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Backup destination already exists"):
        backup_database(source_db, backup_db)

    assert backup_db.read_text(encoding="utf-8") == "do not overwrite"


def test_missing_source_returns_clean_error(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.db"
    backup_db = tmp_path / "backup.db"

    with pytest.raises(FileNotFoundError, match="Database not found"):
        backup_database(missing_db, backup_db)

    result = _run_cli(["database", "backup", "--database", str(missing_db), "--output", str(backup_db)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Database backup failed:" in result.stderr


def test_corrupt_source_returns_clean_error(tmp_path: Path) -> None:
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"INVALID SQLITE FILE HEADER")
    backup_db = tmp_path / "backup.db"

    with pytest.raises(sqlite3.Error):
        backup_database(corrupt_db, backup_db)

    assert not backup_db.exists()

    result = _run_cli(["database", "backup", "--database", str(corrupt_db), "--output", str(backup_db)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Database backup failed:" in result.stderr


def test_failed_backup_removes_partial_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    def mock_check_database_integrity(*args, **kwargs):
        return False

    monkeypatch.setattr("ransomeye.storage.check_database_integrity", mock_check_database_integrity)

    with pytest.raises(sqlite3.DatabaseError, match="Backup integrity check failed"):
        backup_database(source_db, backup_db)

    assert not backup_db.exists()


def test_source_bytes_are_unchanged(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    initial_bytes = source_db.read_bytes()
    backup_database(source_db, backup_db)
    assert source_db.read_bytes() == initial_bytes


def test_cli_returns_0_on_success(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-CLI", "CLI Backup Case")
    store.close()

    result = _run_cli(["database", "backup", "--database", str(source_db), "--output", str(backup_db)], cwd=tmp_path)
    assert result.returncode == 0
    assert "Database backup created:" in result.stdout
    assert backup_db.is_file()
    assert check_database_integrity(backup_db) is True


def test_cli_returns_1_on_failure(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_db.write_text("existing", encoding="utf-8")

    result = _run_cli(["database", "backup", "--database", str(source_db), "--output", str(backup_db)], cwd=tmp_path)
    assert result.returncode == 1
    assert "Database backup failed:" in result.stderr
