"""Failure path and operational hardening tests for RansomEye."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.export import (
    _reserve_output_path,
    export_case,
    read_export_lock,
    remove_export_lock,
    verify_export_package,
)
from ransomeye.storage import EvidenceStore


def _export_worker(
    database_path: str,
    case_id: str,
    output_path: str,
    result_queue,
) -> None:
    try:
        export_case(
            Path(database_path),
            case_id,
            Path(output_path),
        )
    except Exception as exc:
        result_queue.put((type(exc).__name__, str(exc)))
    else:
        result_queue.put(("success", ""))


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


def test_existing_file_is_not_replaced(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Existing Case")
    store.close()

    output_path = tmp_path / "CASE-001"
    output_path.write_text("do not replace", encoding="utf-8")

    with pytest.raises(FileExistsError):
        export_case(db_path, "CASE-001", output_path)

    assert output_path.is_file()
    assert output_path.read_text(encoding="utf-8") == "do not replace"


def test_concurrent_exports_have_single_winner(tmp_path: Path) -> None:
    import multiprocessing

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Concurrent Case")
    store.close()

    output_dir = tmp_path / "CASE-001"
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()

    processes = [
        context.Process(
            target=_export_worker,
            args=(
                str(db_path),
                "CASE-001",
                str(output_dir),
                result_queue,
            ),
        )
        for _ in range(2)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)

    results = [result_queue.get(timeout=5) for _ in processes]

    assert sum(result[0] == "success" for result in results) == 1
    assert sum(result[0] == "FileExistsError" for result in results) == 1
    assert verify_export_package(output_dir)
    assert not list(tmp_path.glob("ransomeye_export_tmp_*"))
    assert not list(tmp_path.glob(".CASE-001.lock"))


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


def test_export_lock_contains_metadata(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-001"
    lock_path, lock_fd = _reserve_output_path(
        output_path,
        database_path=tmp_path / "test.db",
        case_id="CASE-001",
    )

    try:
        metadata = json.loads(lock_path.read_text(encoding="utf-8"))
        assert metadata["pid"] == os.getpid()
        assert metadata["case_id"] == "CASE-001"
        assert metadata["output"] == str(output_path)
        assert metadata["database"] == str(tmp_path / "test.db")
        assert "created_utc" in metadata
    finally:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)


def test_failed_export_removes_metadata_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ransomeye import export

    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-001", "Failure Case")
    store.close()

    monkeypatch.setattr(
        export,
        "write_case_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("simulated failure")
        ),
    )

    with pytest.raises(RuntimeError, match="simulated failure"):
        export_case(db_path, "CASE-001", tmp_path / "CASE-001")

    assert not (tmp_path / ".CASE-001.lock").exists()


def test_lock_info_reads_metadata(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-001"
    lock_path, lock_fd = _reserve_output_path(
        output_path,
        database_path=tmp_path / "test.db",
        case_id="CASE-001",
    )

    try:
        metadata = read_export_lock(output_path)
        assert metadata["case_id"] == "CASE-001"
        assert metadata["output"] == str(output_path)
    finally:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)


def test_missing_lock_returns_failure(tmp_path: Path) -> None:
    output_path = tmp_path / "NONEXISTENT"
    with pytest.raises(FileNotFoundError, match="No export lock found"):
        read_export_lock(output_path)

    result = _run_cli(["export", "lock-info", "--output", str(output_path)], cwd=tmp_path)
    assert result.returncode != 0
    assert "No export lock found" in result.stderr


def test_malformed_lock_returns_failure(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-CORRUPT"
    lock_path = tmp_path / ".CASE-CORRUPT.lock"
    lock_path.write_text("invalid json content", encoding="utf-8")

    with pytest.raises(ValueError, match="Export lock is invalid"):
        read_export_lock(output_path)

    result = _run_cli(["export", "lock-info", "--output", str(output_path)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Export lock is invalid" in result.stderr


def test_missing_metadata_fields_are_rejected(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-INCOMPLETE"
    lock_path = tmp_path / ".CASE-INCOMPLETE.lock"
    lock_path.write_text(json.dumps({"pid": 1234}), encoding="utf-8")

    with pytest.raises(ValueError, match="Export lock is missing required metadata"):
        read_export_lock(output_path)

    result = _run_cli(["export", "lock-info", "--output", str(output_path)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Export lock is missing required metadata" in result.stderr


def test_unlock_without_force_is_rejected(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-LOCKED"
    lock_path, lock_fd = _reserve_output_path(
        output_path,
        database_path=tmp_path / "test.db",
        case_id="CASE-LOCKED",
    )
    os.close(lock_fd)

    try:
        with pytest.raises(PermissionError, match="Lock removal requires --force"):
            remove_export_lock(output_path, force=False)

        result = _run_cli(["export", "unlock", "--output", str(output_path)], cwd=tmp_path)
        assert result.returncode != 0
        assert "Lock removal requires --force" in result.stderr
        assert lock_path.exists()
    finally:
        lock_path.unlink(missing_ok=True)


def test_unlock_with_force_removes_exact_lock(tmp_path: Path) -> None:
    output_path = tmp_path / "CASE-UNLOCKED"
    lock_path, lock_fd = _reserve_output_path(
        output_path,
        database_path=tmp_path / "test.db",
        case_id="CASE-UNLOCKED",
    )
    os.close(lock_fd)

    removed = remove_export_lock(output_path, force=True)
    assert removed == lock_path
    assert not lock_path.exists()


def test_unlock_one_output_does_not_remove_another(tmp_path: Path) -> None:
    path1 = tmp_path / "CASE-001"
    path2 = tmp_path / "CASE-002"

    lock_path1, lock_fd1 = _reserve_output_path(path1, database_path=tmp_path / "db.db", case_id="CASE-001")
    lock_path2, lock_fd2 = _reserve_output_path(path2, database_path=tmp_path / "db.db", case_id="CASE-002")

    os.close(lock_fd1)
    os.close(lock_fd2)

    try:
        remove_export_lock(path1, force=True)
        assert not lock_path1.exists()
        assert lock_path2.exists()
    finally:
        lock_path2.unlink(missing_ok=True)
