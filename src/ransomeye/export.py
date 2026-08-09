"""Evidence export package creation and verification for RansomEye cases."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ransomeye.integrity import sha256_file
from ransomeye.report import write_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import get_case_timeline


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


def export_case(
    database_path: Path,
    case_id: str,
    output_path: Path,
) -> Path:
    """Export a RansomEye case to an isolated, self-contained evidence directory package."""
    database_path = Path(database_path)
    output_path = Path(output_path)

    if output_path.exists():
        raise FileExistsError(
            f"Export output already exists: {output_path}"
        )

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

    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(prefix="ransomeye_export_tmp_", dir=output_path.parent)
    )

    try:
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
        shutil.move(str(staging_dir), str(output_path))


        return output_path
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise
