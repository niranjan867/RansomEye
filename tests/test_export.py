"""Tests for Milestone 7: Evidence export package creation, verification, and tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ransomeye.storage import EvidenceStore


def test_export_creates_complete_case_package(tmp_path: Path) -> None:
    from ransomeye.export import export_case

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Ransomware Incident", host="HOST-A")
    store.save_event("CASE-001", {"event_id": "evt-1", "timestamp": "2026-08-09T10:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.save_finding("CASE-001", {"type": "SUSPICIOUS_EXECUTION", "score": 80, "confidence": 0.9, "technique": "T1486", "reason": "Mass file modification"})
    store.record_custody_event("CASE-001", "sample.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "created", analyst="Analyst1")

    store.close()

    output_dir = tmp_path / "exports" / "CASE-001"
    exported_path = export_case(database_path, "CASE-001", output_dir)

    assert exported_path == output_dir
    assert output_dir.is_dir()

    expected_files = [
        "case-report.txt",
        "case-report.txt.sha256",
        "case-metadata.json",
        "findings.json",
        "timeline.json",
        "lifecycle.json",
        "chain-of-custody.json",
        "MANIFEST.sha256",
    ]
    for filename in expected_files:
        assert (output_dir / filename).exists(), f"Missing expected file: {filename}"


def test_export_contains_only_requested_case(tmp_path: Path) -> None:
    from ransomeye.export import export_case

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Case One")
    store.create_case(case_id="CASE-002", case_name="Case Two")

    store.save_event("CASE-001", {"event_id": "evt-1", "timestamp": "2026-08-09T10:00:00Z", "source": "sysmon", "event_type": "process_creation"})
    store.save_event("CASE-002", {"event_id": "evt-2", "timestamp": "2026-08-09T10:05:00Z", "source": "sysmon", "event_type": "process_creation"})

    store.save_finding("CASE-001", {"type": "TYPE-1", "score": 50, "confidence": 0.5, "technique": "T1000", "reason": "Reason 1"})
    store.save_finding("CASE-002", {"type": "TYPE-2", "score": 90, "confidence": 0.9, "technique": "T2000", "reason": "Reason 2"})


    store.close()

    output_dir = tmp_path / "CASE-001"
    export_case(database_path, "CASE-001", output_dir)

    metadata = json.loads((output_dir / "case-metadata.json").read_text(encoding="utf-8"))
    assert metadata["case_id"] == "CASE-001"

    timeline = json.loads((output_dir / "timeline.json").read_text(encoding="utf-8"))
    assert len(timeline) == 1
    assert timeline[0]["event_id"] == "evt-1"

    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "TYPE-1"


def test_export_writes_utf8_json(tmp_path: Path) -> None:
    from ransomeye.export import export_case

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(
        case_id="CASE-UNICODE",
        case_name="Café – résumé",
        host="München-01",
    )
    store.save_finding(
        "CASE-UNICODE",
        {
            "type": "SUSP_CHARS",
            "score": 100,
            "confidence": 1.0,
            "technique": "T1486",
            "reason": "Détection réussie – fichier modifié",
        },
    )
    store.close()

    output_dir = tmp_path / "CASE-UNICODE"
    export_case(database_path, "CASE-UNICODE", output_dir)

    metadata = json.loads(
        (output_dir / "case-metadata.json").read_text(encoding="utf-8")
    )
    assert metadata["case_name"] == "Café – résumé"
    assert metadata["host"] == "München-01"

    findings = json.loads(
        (output_dir / "findings.json").read_text(encoding="utf-8")
    )
    assert findings[0]["reason"] == "Détection réussie – fichier modifié"


def test_export_writes_sha256_manifest(tmp_path: Path) -> None:
    from ransomeye.export import export_case


    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Test Case")
    store.close()

    output_dir = tmp_path / "CASE-001"
    export_case(database_path, "CASE-001", output_dir)

    manifest_path = output_dir / "MANIFEST.sha256"
    assert manifest_path.exists()

    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 7

    for line in lines:
        parts = line.strip().split()
        assert len(parts) == 2
        digest, filename = parts
        assert len(digest) == 64
        assert filename != "MANIFEST.sha256"


def test_export_manifest_verifies_successfully(tmp_path: Path) -> None:
    from ransomeye.export import export_case, verify_export_package

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Test Case")
    store.close()

    output_dir = tmp_path / "CASE-001"
    export_case(database_path, "CASE-001", output_dir)

    assert verify_export_package(output_dir) is True


def test_modified_export_artifact_fails_verification(tmp_path: Path) -> None:
    from ransomeye.export import export_case, verify_export_package

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Test Case")
    store.close()

    output_dir = tmp_path / "CASE-001"
    export_case(database_path, "CASE-001", output_dir)

    # Tamper with one artifact file
    metadata_file = output_dir / "case-metadata.json"
    metadata_file.write_text('{"tampered": true}', encoding="utf-8")

    assert verify_export_package(output_dir) is False


def test_missing_case_does_not_create_output(tmp_path: Path) -> None:
    from ransomeye.export import export_case

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Existing")
    store.close()

    output_dir = tmp_path / "NONEXISTENT-CASE"
    with pytest.raises(ValueError, match="Case not found"):
        export_case(database_path, "NONEXISTENT-CASE", output_dir)

    assert not output_dir.exists()


def test_failed_export_leaves_no_partial_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ransomeye import export
    from ransomeye.export import export_case

    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Existing")
    store.close()

    output_dir = tmp_path / "FAILED-EXPORT"

    def mock_write_report(*args, **kwargs):
        raise RuntimeError("Simulated failure during export")

    monkeypatch.setattr(export, "write_case_report", mock_write_report)

    with pytest.raises(RuntimeError, match="Simulated failure during export"):
        export_case(database_path, "CASE-001", output_dir)

    assert not output_dir.exists()
