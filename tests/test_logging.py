"""Tests for RansomEye structured audit logging system."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ransomeye.logging import write_audit_event


def test_valid_json_written(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(log_file, "database_backup", "success", database="data/test.db", output="backup.db")

    assert log_file.is_file()
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    data = json.loads(lines[0])
    assert data["event"] == "database_backup"
    assert data["outcome"] == "success"
    assert data["database"] == "data/test.db"
    assert data["output"] == "backup.db"


def test_each_write_appends_exactly_one_line(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(log_file, "export_started", "success", case_id="CASE-001")
    write_audit_event(log_file, "export_completed", "success", case_id="CASE-001")

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "export_started"
    assert json.loads(lines[1])["event"] == "export_completed"


def test_timestamp_ends_with_utc_or_offset(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(log_file, "database_integrity_check", "success")

    data = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    ts = data["timestamp_utc"]
    assert "T" in ts
    assert ts.endswith("+00:00") or ts.endswith("Z")


def test_pid_is_present(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(log_file, "lock_inspected", "success")

    data = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert data["pid"] == os.getpid()


def test_nested_sensitive_keys_redacted(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(
        log_file,
        "export_started",
        "success",
        token="supersecrettoken",
        password="secretpassword",
        nested={"api_key": "12345", "safe_field": "visible"},
    )

    data = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert data["token"] == "[REDACTED]"
    assert data["password"] == "[REDACTED]"
    assert data["nested"]["api_key"] == "[REDACTED]"
    assert data["nested"]["safe_field"] == "visible"


def test_evidence_content_fields_redacted(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(
        log_file,
        "export_failed",
        "failure",
        content="raw file contents",
        evidence={"raw_data": "sample"},
    )

    data = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert data["content"] == "[REDACTED]"
    assert data["evidence"] == "[REDACTED]"


def test_success_and_failure_outcomes_preserved(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    write_audit_event(log_file, "lock_removed", "success")
    write_audit_event(log_file, "lock_removed", "rejected")
    write_audit_event(log_file, "lock_removed", "failure")

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["outcome"] == "success"
    assert json.loads(lines[1])["outcome"] == "rejected"
    assert json.loads(lines[2])["outcome"] == "failure"


def test_parent_log_directories_created(tmp_path: Path) -> None:
    nested_log = tmp_path / "logs" / "nested" / "audit.jsonl"
    write_audit_event(nested_log, "database_backup", "success")

    assert nested_log.is_file()


def test_logging_isolated_to_tmp_path(tmp_path: Path) -> None:
    custom_log = tmp_path / "test_isolated.jsonl"
    write_audit_event(custom_log, "export_started", "success", case_id="CASE-ISO")

    assert custom_log.is_file()
    assert "CASE-ISO" in custom_log.read_text(encoding="utf-8")


def test_cli_operations_emit_expected_events(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye.storage import EvidenceStore

    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RANSOMEYE_LOG_PATH", str(audit_log))

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-LOG", "Logging Case")
    store.close()

    # 1. Database check
    from ransomeye.storage import check_database_integrity

    check_database_integrity(db_path)

    # 2. Database backup
    backup_db = tmp_path / "backup.db"
    from ransomeye.storage import backup_database

    backup_database(db_path, backup_db)

    # 3. Case export
    export_out = tmp_path / "export_pkg"
    from ransomeye.export import export_case

    export_case(db_path, "CASE-LOG", export_out)

    assert audit_log.is_file()
    events = [json.loads(line)["event"] for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert "database_integrity_check" in events
    assert "database_backup" in events
    assert "export_started" in events
    assert "export_completed" in events


def test_audit_log_write_failure_does_not_abort_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye.export import export_case, verify_export_package
    from ransomeye.storage import EvidenceStore

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-LOG-FAIL", "Log Failure Test Case")
    store.close()

    # Point RANSOMEYE_LOG_PATH to a directory to force an OSError inside try_write_audit_event
    invalid_log_dir = tmp_path / "invalid_log_dir"
    invalid_log_dir.mkdir()
    monkeypatch.setenv("RANSOMEYE_LOG_PATH", str(invalid_log_dir))

    export_out = tmp_path / "export_pkg"
    result = export_case(db_path, "CASE-LOG-FAIL", export_out)

    assert result == export_out
    assert export_out.is_dir()
    assert verify_export_package(export_out) is True


def test_audit_log_write_failure_does_not_abort_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye.storage import EvidenceStore, backup_database, check_database_integrity

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-LOG-FAIL", "Log Failure Test Case")
    store.close()

    invalid_log_dir = tmp_path / "invalid_log_dir"
    invalid_log_dir.mkdir()
    monkeypatch.setenv("RANSOMEYE_LOG_PATH", str(invalid_log_dir))

    backup_out = tmp_path / "backup.db"
    result = backup_database(db_path, backup_out)

    assert result == backup_out
    assert backup_out.is_file()
    assert check_database_integrity(backup_out) is True


def test_audit_log_write_failure_does_not_alter_evidence_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye.export import export_case, verify_export_package
    from ransomeye.storage import EvidenceStore

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-INTEGRITY", "Integrity Test Case")
    store.save_event("CASE-INTEGRITY", {"event_id": "evt-1", "timestamp": "2026-08-09T12:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.close()

    invalid_log_dir = tmp_path / "invalid_log_dir"
    invalid_log_dir.mkdir()
    monkeypatch.setenv("RANSOMEYE_LOG_PATH", str(invalid_log_dir))

    export_out = tmp_path / "export_pkg"
    export_case(db_path, "CASE-INTEGRITY", export_out)

    assert verify_export_package(export_out) is True
