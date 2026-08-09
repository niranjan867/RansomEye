"""Database restore validation tests for RansomEye."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.storage import EvidenceStore, backup_database, check_database_integrity, restore_database


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_valid_backup_restores_successfully(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-RESTORE", "Restore Test Case")
    store.save_event("CASE-RESTORE", {"event_id": "evt-res-1", "timestamp": "2026-08-09T13:00:00Z", "source": "sysmon", "event_type": "file_access"})
    store.close()

    backup_database(source_db, backup_db)

    res_path = restore_database(backup_db, restored_db)
    assert res_path == restored_db
    assert restored_db.is_file()


def test_restored_database_passes_integrity_check(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-INTEGRITY", "Integrity Check Case")
    store.close()

    backup_database(source_db, backup_db)
    restore_database(backup_db, restored_db)

    assert check_database_integrity(restored_db) is True


def test_restored_database_contains_expected_case_data(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-DATA", "Data Preserved Case", host="HOST-01")
    store.save_finding("CASE-DATA", {"type": "SUSP_PROC", "score": 80, "confidence": 0.9, "technique": "T1059", "reason": "Suspicious execution"})
    store.close()

    backup_database(source_db, backup_db)
    restore_database(backup_db, restored_db)

    restored_store = EvidenceStore(restored_db)
    case = restored_store.get_case("CASE-DATA")
    assert case is not None
    assert case["case_name"] == "Data Preserved Case"
    assert case["host"] == "HOST-01"

    findings = restored_store.get_case_findings("CASE-DATA")
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "SUSP_PROC"
    restored_store.close()


def test_existing_destination_is_not_overwritten(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_database(source_db, backup_db)

    restored_db.write_text("do not overwrite existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Restore destination already exists"):
        restore_database(backup_db, restored_db)

    assert restored_db.read_text(encoding="utf-8") == "do not overwrite existing"


def test_missing_backup_fails_cleanly(tmp_path: Path) -> None:
    missing_backup = tmp_path / "missing_backup.db"
    restored_db = tmp_path / "restored.db"

    with pytest.raises(FileNotFoundError, match="Backup not found"):
        restore_database(missing_backup, restored_db)

    result = _run_cli(["database", "restore", "--backup", str(missing_backup), "--output", str(restored_db)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Database restore failed:" in result.stderr


def test_corrupt_backup_fails_cleanly(tmp_path: Path) -> None:
    corrupt_backup = tmp_path / "corrupt_backup.db"
    corrupt_backup.write_bytes(b"INVALID SQLITE FILE HEADER")
    restored_db = tmp_path / "restored.db"

    with pytest.raises(sqlite3.Error):
        restore_database(corrupt_backup, restored_db)

    assert not restored_db.exists()

    result = _run_cli(["database", "restore", "--backup", str(corrupt_backup), "--output", str(restored_db)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Database restore failed:" in result.stderr


def test_failed_restore_removes_partial_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_database(source_db, backup_db)

    def mock_check_database_integrity(*args, **kwargs):
        return False

    monkeypatch.setattr("ransomeye.storage.check_database_integrity", mock_check_database_integrity)

    with pytest.raises(sqlite3.DatabaseError, match="Restored database integrity check failed"):
        restore_database(backup_db, restored_db)

    assert not restored_db.exists()


def test_backup_source_bytes_remain_unchanged(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_database(source_db, backup_db)
    initial_backup_bytes = backup_db.read_bytes()

    restore_database(backup_db, restored_db)
    assert backup_db.read_bytes() == initial_backup_bytes


def test_cli_success_returns_0(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-CLI", "CLI Restore Case")
    store.close()

    backup_database(source_db, backup_db)

    result = _run_cli(["database", "restore", "--backup", str(backup_db), "--output", str(restored_db)], cwd=tmp_path)
    assert result.returncode == 0
    assert "Database restored:" in result.stdout
    assert restored_db.is_file()
    assert check_database_integrity(restored_db) is True


def test_cli_failure_returns_1(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-001", "Source Case")
    store.close()

    backup_database(source_db, backup_db)
    restored_db.write_text("existing content", encoding="utf-8")

    result = _run_cli(["database", "restore", "--backup", str(backup_db), "--output", str(restored_db)], cwd=tmp_path)
    assert result.returncode == 1
    assert "Database restore failed:" in result.stderr


def test_database_restore_audit_events_are_emitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RANSOMEYE_LOG_PATH", str(audit_log))

    source_db = tmp_path / "source.db"
    backup_db = tmp_path / "backup.db"
    restored_db = tmp_path / "restored.db"

    store = EvidenceStore(source_db)
    store.create_case("CASE-LOG", "Logging Case")
    store.close()

    backup_database(source_db, backup_db)

    # 1. Success restore
    restore_database(backup_db, restored_db)

    # 2. Rejected restore (existing output)
    with pytest.raises(FileExistsError):
        restore_database(backup_db, restored_db)

    # 3. Failure restore (missing backup)
    missing_backup = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        restore_database(missing_backup, tmp_path / "res_missing.db")

    lines = audit_log.read_text(encoding="utf-8").splitlines()
    restore_events = [json.loads(line) for line in lines if json.loads(line)["event"] == "database_restore"]

    outcomes = [evt["outcome"] for evt in restore_events]
    assert "success" in outcomes
    assert "rejected" in outcomes
    assert "failure" in outcomes
