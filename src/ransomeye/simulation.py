"""Safe synthetic dataset loading and read-only checks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ransomeye.evidence import EvidenceEvent, validate_event_dict

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
NORMAL_ACTIVITY_PATH = SAMPLES_DIR / "normal_activity.json"
RANSOMWARE_LIKE_ACTIVITY_PATH = SAMPLES_DIR / "ransomware_like_activity.json"


@dataclass
class ReadOnlyCheckResult:
    """Result of a read-only file access check."""

    ok: bool
    message: str
    file_path: str
    size_bytes: int
    content_hash: str


@dataclass
class DatasetValidationResult:
    """Validation outcome for a synthetic dataset."""

    ok: bool
    dataset_name: str
    events: list[EvidenceEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        if self.ok:
            return (
                f"Dataset '{self.dataset_name}' is valid "
                f"({len(self.events)} events)."
            )
        return (
            f"Dataset '{self.dataset_name}' failed validation "
            f"with {len(self.errors)} error(s)."
        )


def _dataset_name(path: Path) -> str:
    return path.stem


def check_read_only_access(path: Path) -> ReadOnlyCheckResult:
    """Verify a dataset can be read without modifying the source file."""
    if not path.is_file():
        return ReadOnlyCheckResult(
            ok=False,
            message=f"Dataset file not found: {path}",
            file_path=str(path),
            size_bytes=0,
            content_hash="",
        )

    before_stat = path.stat()
    with path.open("rb") as handle:
        content = handle.read()

    after_stat = path.stat()
    content_hash = hashlib.sha256(content).hexdigest()

    if (
        before_stat.st_size != after_stat.st_size
        or before_stat.st_mtime != after_stat.st_mtime
    ):
        return ReadOnlyCheckResult(
            ok=False,
            message="Input file changed during read-only access.",
            file_path=str(path),
            size_bytes=len(content),
            content_hash=content_hash,
        )

    return ReadOnlyCheckResult(
        ok=True,
        message="Read-only access verified; input file was not modified.",
        file_path=str(path),
        size_bytes=len(content),
        content_hash=content_hash,
    )


def load_raw_dataset(path: Path) -> tuple[dict, ReadOnlyCheckResult]:
    """Load a JSON dataset using read-only checks."""
    read_only_result = check_read_only_access(path)
    if not read_only_result.ok:
        return {}, read_only_result

    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    return payload, read_only_result


def validate_dataset(path: Path) -> DatasetValidationResult:
    """Load and validate a synthetic JSON dataset."""
    payload, read_only_result = load_raw_dataset(path)
    dataset_name = _dataset_name(path)

    if not read_only_result.ok:
        return DatasetValidationResult(
            ok=False,
            dataset_name=dataset_name,
            errors=[read_only_result.message],
        )

    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        return DatasetValidationResult(
            ok=False,
            dataset_name=dataset_name,
            errors=["Dataset must contain an 'events' list."],
        )

    events: list[EvidenceEvent] = []
    errors: list[str] = []

    for index, raw_event in enumerate(raw_events, start=1):
        if not isinstance(raw_event, dict):
            errors.append(f"Event {index}: each event must be a JSON object.")
            continue

        event_errors = validate_event_dict(raw_event, index=index)
        if event_errors:
            errors.extend(event_errors)
            continue

        events.append(EvidenceEvent.from_dict(raw_event))

    return DatasetValidationResult(
        ok=not errors,
        dataset_name=dataset_name,
        events=events,
        errors=errors,
    )


def load_normal_activity() -> DatasetValidationResult:
    """Validate the benign synthetic activity dataset."""
    return validate_dataset(NORMAL_ACTIVITY_PATH)


def load_ransomware_like_activity() -> DatasetValidationResult:
    """Validate the ransomware-like synthetic activity dataset."""
    return validate_dataset(RANSOMWARE_LIKE_ACTIVITY_PATH)
