"""SHA-256 hashing helpers for evidence and report integrity verification."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = sha256()

    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def verify_file(path: Path, expected_hash: str) -> bool:
    return sha256_file(path).lower() == expected_hash.lower()


def verify_manifest(path: Path, manifest_path: Path) -> bool:
    manifest_lines = manifest_path.read_text(encoding="utf-8").splitlines()
    if len(manifest_lines) < 2:
        return False

    expected_hash = manifest_lines[-1].strip()
    return verify_file(path, expected_hash)
