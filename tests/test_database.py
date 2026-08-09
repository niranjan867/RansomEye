"""Database integrity and maintenance tests for RansomEye."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.storage import EvidenceStore, check_database_integrity


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_healthy_database_returns_true(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Integrity Test Case")
    store.close()

    assert check_database_integrity(db_path) is True


def test_missing_database_raises_file_not_found(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError, match="Database not found"):
        check_database_integrity(missing_db)


def test_corrupt_database_raises_database_error(tmp_path: Path) -> None:
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"INVALID SQLITE FILE HEADER")

    with pytest.raises(sqlite3.DatabaseError, match="Database integrity check failed"):
        check_database_integrity(corrupt_db)


def test_cli_returns_0_for_healthy_database(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "CLI Integrity Test")
    store.close()

    result = _run_cli(["database", "check", "--database", str(db_path)], cwd=tmp_path)
    assert result.returncode == 0
    assert "Database integrity: OK" in result.stdout


def test_cli_returns_1_for_missing_database(tmp_path: Path) -> None:
    missing_db = tmp_path / "missing.db"
    result = _run_cli(["database", "check", "--database", str(missing_db)], cwd=tmp_path)
    assert result.returncode == 1
    assert "Database integrity check failed:" in result.stderr


def test_cli_returns_1_for_corrupt_database(tmp_path: Path) -> None:
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"INVALID SQLITE FILE HEADER")

    result = _run_cli(["database", "check", "--database", str(corrupt_db)], cwd=tmp_path)
    assert result.returncode == 1
    assert "Database integrity check failed:" in result.stderr


def test_database_file_unchanged_after_integrity_check(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Immutable Check")
    store.close()

    initial_content = db_path.read_bytes()
    initial_stat = db_path.stat()

    assert check_database_integrity(db_path) is True

    after_content = db_path.read_bytes()
    after_stat = db_path.stat()

    assert initial_content == after_content
    assert initial_stat.st_size == after_stat.st_size
