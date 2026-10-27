"""Regression tests for Forensics & Operations audit repairs."""

import json
from pathlib import Path
import pytest

from ransomeye.commands import write_integrity_manifest, verify_integrity_manifest
from ransomeye.integrity import sha256_file, verify_manifest
from ransomeye.storage import EvidenceStore
from ransomeye.dashboard_server import DashboardHandler
import io


def test_write_integrity_manifest_optional_output(tmp_path):
    artifact = tmp_path / "sample.txt"
    artifact.write_text("Audit evidence content", encoding="utf-8")

    # Call with output_path=None
    manifest_p = write_integrity_manifest(artifact, output_path=None)
    assert manifest_p.is_file()
    assert manifest_p.name == "sample.txt.sha256"
    assert verify_integrity_manifest(artifact, manifest_p) is True


def test_write_integrity_manifest_directory(tmp_path):
    dir_path = tmp_path / "artifacts"
    dir_path.mkdir()
    (dir_path / "file1.bin").write_bytes(b"\x00\x01\x02")
    (dir_path / "file2.txt").write_text("hello world", encoding="utf-8")

    manifest_p = write_integrity_manifest(dir_path, output_path=None)
    assert manifest_p.is_file()
    assert manifest_p.name == "MANIFEST.sha256"

    # Verify directory against manifest
    assert verify_manifest(dir_path, manifest_p) is True

    # Tamper with file2
    (dir_path / "file2.txt").write_text("tampered text", encoding="utf-8")
    assert verify_manifest(dir_path, manifest_p) is False


def test_custody_events_normalization(tmp_path):
    db_file = tmp_path / "test.db"
    store = EvidenceStore(db_file)
    try:
        store.create_case("CASE-TEST-01", "Test Case", "HOST-1")
        test_art = tmp_path / "evidence.raw"
        test_art.write_bytes(b"\x90\x90\x90")
        hash_val = sha256_file(test_art)

        store.record_custody_event(
            "CASE-TEST-01",
            str(test_art),
            hash_val,
            "created",
            "lead_analyst",
            "Initial evidence acquisition note",
        )

        events = store.get_custody_events("CASE-TEST-01")
        assert len(events) == 1
        ev = events[0]
        assert ev["artifact_path"] == str(test_art)
        assert ev["recorded_at"] is not None
        assert ev["note"] == "Initial evidence acquisition note"
    finally:
        store.close()
