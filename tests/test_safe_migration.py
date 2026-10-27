"""Focused tests for Safe SQLite Schema Migrations in RansomEye."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from ransomeye.storage import (
    CURRENT_SCHEMA_VERSION,
    EvidenceStore,
    MigrationBackupError,
    MigrationError,
)

BASELINE_PROD_HASH = "9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB"


def _create_v1_database(db_path: Path) -> None:
    """Create a synthetic historical Schema Version 1 SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            host TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            severity TEXT NOT NULL DEFAULT 'SAFE',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            process_name TEXT,
            pid TEXT,
            parent_pid TEXT,
            process_guid TEXT,
            command_line TEXT,
            file_path TEXT,
            file_count INTEGER,
            network_json TEXT,
            confidence REAL,
            metadata_json TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            score INTEGER NOT NULL,
            confidence REAL,
            technique TEXT,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE assessments (
            assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            reasons_json TEXT NOT NULL,
            techniques_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
        """
    )
    conn.execute(
        "INSERT INTO cases VALUES ('CASE-HIST-01', 'Historical Incident', 'HOST-01', 'OPEN', 'HIGH', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO events VALUES ('EVT-01', 'CASE-HIST-01', '2026-01-01T00:01:00Z', 'sysmon', 'process_creation', 'cmd.exe', '100', '50', 'G1', 'cmd.exe /c whoami', NULL, 0, '{}', 0.9, '{}')"
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()


def test_latest_schema_no_unnecessary_backup(tmp_path: Path) -> None:
    """1. Opening a database at the latest schema version does not create an unnecessary backup."""
    db_path = tmp_path / "latest.db"
    store = EvidenceStore(db_path)
    assert store._get_schema_version() == CURRENT_SCHEMA_VERSION
    store.close()

    # Re-open database
    store2 = EvidenceStore(db_path)
    try:
        assert store2._get_schema_version() == CURRENT_SCHEMA_VERSION
        assert store2.last_migration_backup is None
        backups = list(tmp_path.glob("*.bak"))
        assert len(backups) == 0, f"Unexpected backups created: {backups}"
    finally:
        store2.close()


def test_historical_schema_creates_verified_backup(tmp_path: Path) -> None:
    """2. Migrating a supported historical schema creates a valid backup before migration."""
    db_path = tmp_path / "historical_v1.db"
    _create_v1_database(db_path)

    store = EvidenceStore(db_path)
    try:
        assert store._get_schema_version() == CURRENT_SCHEMA_VERSION
        assert store.last_migration_backup is not None
        assert store.last_migration_backup.is_file()
        assert store.last_migration_backup.name == "historical_v1.db.bak"
    finally:
        store.close()


def test_backup_readable_and_retains_original_version(tmp_path: Path) -> None:
    """3. The backup remains readable and retains the original schema version and data."""
    db_path = tmp_path / "historical_v1.db"
    _create_v1_database(db_path)

    store = EvidenceStore(db_path)
    backup_path = store.last_migration_backup
    store.close()

    assert backup_path is not None and backup_path.is_file()

    bconn = sqlite3.connect(backup_path)
    try:
        integrity = bconn.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        ver = bconn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == 1

        case_row = bconn.execute("SELECT case_id, case_name FROM cases").fetchone()
        assert case_row[0] == "CASE-HIST-01"
        assert case_row[1] == "Historical Incident"

        evt_row = bconn.execute("SELECT event_id, process_name FROM events").fetchone()
        assert evt_row[0] == "EVT-01"
        assert evt_row[1] == "cmd.exe"
    finally:
        bconn.close()


def test_existing_backup_never_silently_overwritten(tmp_path: Path) -> None:
    """4. An existing backup is never silently overwritten."""
    db_path = tmp_path / "test_no_overwrite.db"
    _create_v1_database(db_path)

    # Pre-create standard backup with sentinel content
    canary_backup = tmp_path / "test_no_overwrite.db.bak"
    canary_backup.write_bytes(b"CANARY_PREEXISTING_BACKUP_DO_NOT_TOUCH")

    store = EvidenceStore(db_path)
    try:
        assert store.last_migration_backup is not None
        assert store.last_migration_backup != canary_backup
        assert store.last_migration_backup.is_file()

        # Verify canary backup was NOT overwritten
        assert canary_backup.read_bytes() == b"CANARY_PREEXISTING_BACKUP_DO_NOT_TOUCH"

        # Verify new backup has correct SQLite database content
        bconn = sqlite3.connect(store.last_migration_backup)
        try:
            assert bconn.execute("PRAGMA user_version").fetchone()[0] == 1
        finally:
            bconn.close()
    finally:
        store.close()


def test_backup_creation_failure_prevents_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """5. Backup creation failure prevents migration and leaves database unmodified."""
    db_path = tmp_path / "fail_backup.db"
    _create_v1_database(db_path)

    # Monkeypatch _create_and_verify_migration_backup to simulate I/O or verification failure
    def _failing_backup(self, from_version: int) -> Path:
        raise MigrationBackupError("Simulated disk error during backup creation")

    monkeypatch.setattr(EvidenceStore, "_create_and_verify_migration_backup", _failing_backup)

    with pytest.raises(MigrationBackupError, match="Simulated disk error"):
        EvidenceStore(db_path)

    # Verify original database was NOT migrated
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        conn.close()


def test_migration_failure_preserves_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """6. Migration failure does not silently destroy the only recoverable pre-migration state."""
    db_path = tmp_path / "fail_migration.db"
    _create_v1_database(db_path)

    def _broken_upgrade(self) -> None:
        raise sqlite3.OperationalError("Simulated DDL syntax failure during migration")

    monkeypatch.setattr(EvidenceStore, "_upgrade_schema_v1_to_v2", _broken_upgrade)

    with pytest.raises(MigrationError, match="Simulated DDL syntax failure"):
        EvidenceStore(db_path)

    # Verify backup was created, retained, and is intact
    backup_path = tmp_path / "fail_migration.db.bak"
    assert backup_path.is_file()

    bconn = sqlite3.connect(backup_path)
    try:
        assert bconn.execute("PRAGMA user_version").fetchone()[0] == 1
        assert bconn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        bconn.close()


def test_wal_journal_migration_backup_safety(tmp_path: Path) -> None:
    """7. SQLite WAL/journal scenarios are handled safely."""
    db_path = tmp_path / "wal_case.db"
    _create_v1_database(db_path)

    # Switch to WAL mode and insert dirty uncheckpointed record
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(
        "INSERT INTO events VALUES ('EVT-WAL', 'CASE-HIST-01', '2026-01-01T00:02:00Z', 'sysmon', 'network_connection', 'curl.exe', '101', '100', 'G2', 'curl.exe https://c2.test', NULL, 0, '{}', 0.8, '{}')"
    )
    conn.commit()
    conn.close()

    # Migrate via EvidenceStore
    store = EvidenceStore(db_path)
    try:
        assert store._get_schema_version() == CURRENT_SCHEMA_VERSION
        backup_path = store.last_migration_backup
        assert backup_path is not None and backup_path.is_file()

        # Check that backup contains the uncheckpointed WAL row
        bconn = sqlite3.connect(backup_path)
        try:
            row = bconn.execute("SELECT event_id FROM events WHERE event_id = 'EVT-WAL'").fetchone()
            assert row is not None
            assert row[0] == "EVT-WAL"
            assert bconn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            bconn.close()
    finally:
        store.close()


def test_fresh_database_initialization(tmp_path: Path) -> None:
    """8. Fresh database initialization continues to work seamlessly."""
    db_path = tmp_path / "brand_new.db"
    assert not db_path.exists()

    store = EvidenceStore(db_path)
    try:
        assert db_path.is_file()
        assert store._get_schema_version() == CURRENT_SCHEMA_VERSION
        assert store.last_migration_backup is None
        # Verify core tables exist
        cases = store.list_cases()
        assert cases == []
    finally:
        store.close()


def test_production_database_never_used_by_tests() -> None:
    """9. The production database path is never used by tests and remains untouched."""
    prod_db = Path("data/ransomeye.db")
    assert prod_db.is_file()

    h = hashlib.sha256()
    with open(prod_db, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)

    current_hash = h.hexdigest().upper()
    assert current_hash == BASELINE_PROD_HASH, f"Production DB altered! {current_hash} != {BASELINE_PROD_HASH}"
