"""Evidence export package creation and verification for RansomEye cases."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ransomeye.integrity import sha256_file
from ransomeye.logging import try_write_audit_event
from ransomeye.report import write_case_report

from ransomeye.storage import EvidenceStore
from ransomeye.timeline import get_case_timeline



class LockOwnerStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNKNOWN = "UNKNOWN"



def verify_export_package(export_dir: Path) -> bool:
    """Verify that all files in the export package match their MANIFEST.sha256 entry."""
    manifest_path = export_dir / "MANIFEST.sha256"
    if not manifest_path.is_file():
        return False

    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest_entries = {}
        for line in manifest_text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                return False
            digest, filename = parts
            manifest_entries[filename] = digest

        # Ensure all listed files exist and match hash
        for filename, expected_hash in manifest_entries.items():
            file_path = export_dir / filename
            if not file_path.is_file():
                return False
            if sha256_file(file_path).lower() != expected_hash.lower():
                return False

        # Ensure no unexpected extra files (other than MANIFEST.sha256 itself)
        exported_files = {
            f.name for f in export_dir.iterdir() if f.name != "MANIFEST.sha256"
        }
        if set(manifest_entries.keys()) != exported_files:
            return False

        return True
    except Exception:
        return False


def get_export_lock_path(output_path: Path) -> Path:
    output_path = Path(output_path)
    return output_path.parent / f".{output_path.name}.lock"


def read_export_lock(output_path: Path) -> dict[str, Any]:
    lock_path = get_export_lock_path(output_path)

    if not lock_path.is_file():
        raise FileNotFoundError(
            f"No export lock found for: {output_path}"
        )

    try:
        metadata = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Export lock is invalid: {lock_path}"
        ) from exc

    required = {
        "pid",
        "created_utc",
        "database",
        "case_id",
        "output",
    }

    if not isinstance(metadata, dict) or not required.issubset(metadata):
        raise ValueError(
            f"Export lock is missing required metadata: {lock_path}"
        )

    return metadata


def remove_export_lock(
    output_path: Path,
    *,
    force: bool = False,
    break_lock: bool = False,
) -> Path:
    log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
    try:
        metadata = read_export_lock(output_path)

        if not force:
            try_write_audit_event(
                log_path,
                "lock_removed",
                "rejected",
                output=str(output_path),
                reason="Missing --force",
            )
            raise PermissionError("Lock removal requires --force")

        owner_status = get_lock_owner_status(metadata)

        if owner_status == LockOwnerStatus.ACTIVE and not break_lock:
            try_write_audit_event(
                log_path,
                "lock_removed",
                "rejected",
                output=str(output_path),
                reason="Active lock owner requires --break-lock",
            )
            raise PermissionError(
                "Export lock owner is active; use --break-lock to override"
            )

        if owner_status == LockOwnerStatus.UNKNOWN and not break_lock:
            try_write_audit_event(
                log_path,
                "lock_removed",
                "rejected",
                output=str(output_path),
                reason="Unknown lock owner requires --break-lock",
            )
            raise PermissionError(
                "Export lock owner status is unknown; use --break-lock to override"
            )

        lock_path = get_export_lock_path(output_path)
        lock_path.unlink()
        try_write_audit_event(
            log_path,
            "lock_removed",
            "success",
            output=str(output_path),
            case_id=metadata.get("case_id"),
        )
        return lock_path
    except Exception as exc:
        if not isinstance(exc, PermissionError):
            try_write_audit_event(
                log_path,
                "lock_removed",
                "failure",
                output=str(output_path),
                error=str(exc),
            )
        raise





def get_lock_owner_status(metadata: dict[str, Any]) -> LockOwnerStatus:
    pid = metadata.get("pid")

    if not isinstance(pid, int) or pid <= 0:
        return LockOwnerStatus.UNKNOWN

    if pid == os.getpid():
        return LockOwnerStatus.ACTIVE

    try:
        if os.name == "nt":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
            )
            output = result.stdout.strip()
            if not output or "No tasks are running" in output:
                return LockOwnerStatus.INACTIVE
            return LockOwnerStatus.ACTIVE

        os.kill(pid, 0)
    except ProcessLookupError:
        return LockOwnerStatus.INACTIVE
    except PermissionError:
        return LockOwnerStatus.ACTIVE
    except (OSError, subprocess.SubprocessError):
        return LockOwnerStatus.UNKNOWN
    else:
        return LockOwnerStatus.ACTIVE




def _reserve_output_path(
    output_path: Path,
    *,
    database_path: Path,
    case_id: str,
) -> tuple[Path, int]:
    lock_path = output_path.parent / f".{output_path.name}.lock"
    metadata = {
        "pid": os.getpid(),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "database": str(database_path),
        "case_id": case_id,
        "output": str(output_path),
    }

    try:
        lock_fd = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
    except FileExistsError as exc:
        raise FileExistsError(
            f"Export output already exists or is being created: {output_path}"
        ) from exc

    try:
        os.write(
            lock_fd,
            (json.dumps(metadata, indent=2) + "\n").encode("utf-8"),
        )
        os.fsync(lock_fd)
    except Exception:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)
        raise


    if output_path.exists():
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)
        raise FileExistsError(
            f"Export output already exists: {output_path}"
        )

    return lock_path, lock_fd


def export_case(
    database_path: Path,
    case_id: str,
    output_path: Path,
) -> Path:
    """Export a RansomEye case to an isolated, self-contained evidence directory package."""
    database_path = Path(database_path)
    output_path = Path(output_path)

    log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
    try_write_audit_event(
        log_path,
        "export_started",
        "success",
        database=str(database_path),
        case_id=case_id,
        output=str(output_path),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_path, lock_fd = _reserve_output_path(
            output_path,
            database_path=database_path,
            case_id=case_id,
        )
    except Exception as exc:
        try_write_audit_event(
            log_path,
            "export_failed",
            "failure",
            database=str(database_path),
            case_id=case_id,
            output=str(output_path),
            error=str(exc),
        )
        raise

    staging_dir: Path | None = Path(
        tempfile.mkdtemp(
            prefix="ransomeye_export_tmp_",
            dir=output_path.parent,
        )
    )

    try:
        store = EvidenceStore(database_path)
        try:
            case = store.get_case(case_id)
            if case is None:
                raise ValueError(f"Case not found: {case_id}")

            findings = store.get_case_findings(case_id)
            history = store.get_case_history(case_id)
            custody = store.get_custody_events(case_id)
            timeline = get_case_timeline(database_path, case_id)
        finally:
            store.close()

        # 1. case-report.txt & case-report.txt.sha256
        report_txt_path = staging_dir / "case-report.txt"
        write_case_report(database_path, case_id, report_txt_path)
        report_hash = sha256_file(report_txt_path)
        report_sha_path = staging_dir / "case-report.txt.sha256"
        report_sha_path.write_text(f"{report_hash}  case-report.txt\n", encoding="utf-8")

        # 2. case-metadata.json
        metadata_path = staging_dir / "case-metadata.json"
        metadata_path.write_text(
            json.dumps(case, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 3. findings.json
        findings_path = staging_dir / "findings.json"
        findings_path.write_text(
            json.dumps(findings, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 4. timeline.json
        timeline_path = staging_dir / "timeline.json"
        timeline_path.write_text(
            json.dumps(timeline, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 5. lifecycle.json
        lifecycle_path = staging_dir / "lifecycle.json"
        lifecycle_path.write_text(
            json.dumps(history, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 6. chain-of-custody.json
        custody_path = staging_dir / "chain-of-custody.json"
        custody_path.write_text(
            json.dumps(custody, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 7. Generate MANIFEST.sha256
        manifest_entries: list[str] = []
        for file_item in sorted(staging_dir.iterdir()):
            if file_item.is_file() and file_item.name != "MANIFEST.sha256":
                file_hash = sha256_file(file_item)
                manifest_entries.append(f"{file_hash}  {file_item.name}")

        manifest_path = staging_dir / "MANIFEST.sha256"
        manifest_path.write_text(
            "\n".join(manifest_entries) + "\n",
            encoding="utf-8",
        )

        # 8. Verify manifest before finalizing
        if not verify_export_package(staging_dir):
            raise RuntimeError("Export manifest verification failed prior to finalization.")

        # 9. Atomic rename/move to target output_path
        os.rename(staging_dir, output_path)
        staging_dir = None

        try_write_audit_event(
            log_path,
            "export_completed",
            "success",
            database=str(database_path),
            case_id=case_id,
            output=str(output_path),
        )
        return output_path
    except Exception as exc:
        if staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        try_write_audit_event(
            log_path,
            "export_failed",
            "failure",
            database=str(database_path),
            case_id=case_id,
            output=str(output_path),
            error=str(exc),
        )
        raise
    finally:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)
