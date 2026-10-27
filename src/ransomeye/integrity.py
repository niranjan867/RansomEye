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
    path = Path(path)
    manifest_path = Path(manifest_path)
    if not path.exists() or not manifest_path.is_file():
        return False

    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except Exception:
        return False

    manifest_lines = [line.strip() for line in manifest_text.splitlines() if line.strip()]
    if not manifest_lines:
        return False

    if path.is_dir():
        for line in manifest_lines:
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            expected_hash, rel_path = parts[0], parts[1]
            target_file = path / rel_path
            if not target_file.is_file():
                return False
            if sha256_file(target_file).lower() != expected_hash.lower():
                return False
        return True

    if len(manifest_lines) >= 2 and manifest_lines[0].startswith("SHA256"):
        expected_hash = manifest_lines[-1].strip()
    else:
        parts = manifest_lines[-1].split()
        expected_hash = parts[0] if parts else ""

    return verify_file(path, expected_hash)
