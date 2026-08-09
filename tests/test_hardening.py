"""Failure path and operational hardening tests for RansomEye."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.export import export_case, verify_export_package
from ransomeye.storage import EvidenceStore


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_missing_database_returns_nonzero(tmp_path: Path) -> None:
    nonexistent_db = tmp_path / "missing.db"
    result = _run_cli(
        ["export", "--database", str(nonexistent_db), "--case", "CASE-001", "--output", str(tmp_path / "out")],
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "Operation failed" in result.stderr or "Case not found" in result.stderr


def test_missing_case_returns_nonzero(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Existing Case")
    store.close()

    result = _run_cli(
        ["export", "--database", str(db_path), "--case", "CASE-999", "--output", str(tmp_path / "out")],
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "Case not found: CASE-999" in result.stderr or "Operation failed: Case not found: CASE-999" in result.stderr


def test_invalid_manifest_returns_nonzero(tmp_path: Path) -> None:
    artifact_path = tmp_path / "report.txt"
    artifact_path.write_text("sample content", encoding="utf-8")
    manifest_path = tmp_path / "manifest.sha256"
    manifest_path.write_text("invalidformat", encoding="utf-8")

    result = _run_cli(
        ["integrity", "verify", "--input", str(artifact_path), "--manifest", str(manifest_path)],
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "Integrity verification failed" in result.stderr


def test_modified_export_is_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Existing Case")
    store.close()

    export_dir = tmp_path / "CASE-001"
    export_case(db_path, "CASE-001", export_dir)

    # Tamper with file
    (export_dir / "case-metadata.json").write_text('{"tampered": true}', encoding="utf-8")
    assert verify_export_package(export_dir) is False


def test_existing_export_is_not_overwritten(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Existing Case")
    store.close()

    export_dir = tmp_path / "CASE-001"
    export_case(db_path, "CASE-001", export_dir)

    original_manifest = (export_dir / "MANIFEST.sha256").read_text(encoding="utf-8")

    # Attempt second export to same output path
    with pytest.raises(FileExistsError, match="Export output already exists"):
        export_case(db_path, "CASE-001", export_dir)

    assert (export_dir / "MANIFEST.sha256").read_text(encoding="utf-8") == original_manifest


def test_failed_export_leaves_no_partial_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye import export

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Existing Case")
    store.close()

    export_dir = tmp_path / "FAILED-EXPORT"

    def mock_write_report(*args, **kwargs):
        raise RuntimeError("Disk full error simulation")

    monkeypatch.setattr(export, "write_case_report", mock_write_report)

    with pytest.raises(RuntimeError, match="Disk full error simulation"):
        export_case(db_path, "CASE-001", export_dir)

    assert not export_dir.exists()


def test_corrupt_database_returns_clear_error(tmp_path: Path) -> None:
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"NOT A SQLITE DATABASE FILE HEADER")

    result = _run_cli(
        ["export", "--database", str(corrupt_db), "--case", "CASE-001", "--output", str(tmp_path / "out")],
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "Operation failed" in result.stderr or "file is not a database" in result.stderr


def test_invalid_case_status_is_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Status Case")

    with pytest.raises(ValueError, match="Unsupported case status"):
        store.update_case_status("CASE-001", "INVALID_STATUS")

    store.close()


def test_duplicate_status_transition_is_handled(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Transition Case")

    store.update_case_status("CASE-001", "OPEN", note="Re-opening open case")
    history = store.get_case_history("CASE-001")
    assert len(history) == 1
    assert history[0]["old_status"] == "OPEN"
    assert history[0]["new_status"] == "OPEN"
    store.close()
