import sys
from pathlib import Path

import pytest

from ransomeye.commands import main
from ransomeye.integrity import sha256_file, verify_file, verify_manifest


def test_sha256_is_deterministic(tmp_path):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("RansomEye evidence", encoding="utf-8")

    first = sha256_file(artifact)
    second = sha256_file(artifact)

    assert first == second
    assert len(first) == 64


def test_verify_file_accepts_unchanged_artifact(tmp_path):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")

    digest = sha256_file(artifact)

    assert verify_file(artifact, digest) is True


def test_verify_file_rejects_modified_artifact(tmp_path):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")

    digest = sha256_file(artifact)
    artifact.write_text("modified", encoding="utf-8")

    assert verify_file(artifact, digest) is False


def test_verify_manifest_accepts_unchanged_file(tmp_path):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")

    manifest = tmp_path / "evidence.txt.sha256"
    manifest.write_text(
        f"SHA256  {artifact.name}\n{sha256_file(artifact)}\n",
        encoding="utf-8",
    )

    assert verify_manifest(artifact, manifest) is True


def test_verify_manifest_rejects_modified_file(tmp_path):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")

    manifest = tmp_path / "evidence.txt.sha256"
    manifest.write_text(
        f"SHA256  {artifact.name}\n{sha256_file(artifact)}\n",
        encoding="utf-8",
    )
    artifact.write_text("modified", encoding="utf-8")

    assert verify_manifest(artifact, manifest) is False


def test_integrity_verify_cli_returns_failure_for_modified_file(tmp_path, monkeypatch):
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")

    manifest = tmp_path / "evidence.txt.sha256"
    manifest.write_text(
        f"SHA256  {artifact.name}\n{sha256_file(artifact)}\n",
        encoding="utf-8",
    )
    artifact.write_text("modified", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ransomeye",
            "integrity",
            "verify",
            "--input",
            str(artifact),
            "--manifest",
            str(manifest),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 1
