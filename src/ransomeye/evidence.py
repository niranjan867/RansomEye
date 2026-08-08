"""Common evidence schema for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

ALLOWED_EVENT_TYPES = frozenset(
    {
        "file_create",
        "file_modify",
        "file_delete",
        "file_rename",
        "process_create",
        "process_terminate",
        "network_connect",
        "dns_query",
        "registry_create",
        "registry_modify",
        "registry_delete",
        "image_load",
    }
)


class EvidenceValidationError(ValueError):
    """Raised when an evidence record fails schema validation."""


def _require_non_empty(value: str | None, field_name: str) -> str:
    if value is None or not str(value).strip():
        raise EvidenceValidationError(f"{field_name} is required.")
    return str(value).strip()


def _parse_timestamp(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    if value is None or not str(value).strip():
        raise EvidenceValidationError("timestamp is required.")
    normalized = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceValidationError(
            "timestamp must be a valid ISO-8601 datetime string."
        ) from exc


def _validate_event_type(value: str | None) -> str:
    event_type = _require_non_empty(value, "event_type")
    if event_type not in ALLOWED_EVENT_TYPES:
        allowed = ", ".join(sorted(ALLOWED_EVENT_TYPES))
        raise EvidenceValidationError(
            f"event_type '{event_type}' is invalid. Allowed values: {allowed}."
        )
    return event_type


def _validate_confidence(value: float | None) -> float | None:
    if value is None:
        return None
    if value < 0 or value > 1:
        raise EvidenceValidationError("confidence must be between 0 and 1.")
    return float(value)


def _validate_file_count(value: int | None) -> int | None:
    if value is None:
        return None
    if value < 0:
        raise EvidenceValidationError("file_count must be zero or greater.")
    return int(value)


def _validate_network(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise EvidenceValidationError("network must be a dictionary when provided.")
    return value


def _validate_metadata(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise EvidenceValidationError("metadata must be a dictionary when provided.")
    return value


@dataclass
class EvidenceEvent:
    """Normalized evidence record shared across RansomEye components."""

    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    process_name: str | None = None
    pid: int | None = None
    parent_pid: int | None = None
    process_guid: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_count: int | None = None
    network: dict[str, Any] | None = field(default=None)
    confidence: float | None = None
    metadata: dict[str, Any] | None = field(default=None)

    def __post_init__(self) -> None:
        self.event_id = _require_non_empty(self.event_id, "event_id")
        self.timestamp = _parse_timestamp(self.timestamp)
        self.source = _require_non_empty(self.source, "source")
        self.event_type = _validate_event_type(self.event_type)
        self.confidence = _validate_confidence(self.confidence)
        self.file_count = _validate_file_count(self.file_count)
        self.network = _validate_network(self.network)
        self.metadata = _validate_metadata(self.metadata)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceEvent:
        """Build an evidence event from a raw dictionary."""
        return cls(
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp"),
            source=data.get("source"),
            event_type=data.get("event_type"),
            process_name=data.get("process_name"),
            pid=data.get("pid"),
            parent_pid=data.get("parent_pid"),
            process_guid=data.get("process_guid"),
            command_line=data.get("command_line"),
            file_path=data.get("file_path"),
            file_count=data.get("file_count"),
            network=data.get("network"),
            confidence=data.get("confidence"),
            metadata=data.get("metadata"),
        )


def validate_event_dict(data: dict[str, Any], index: int | None = None) -> list[str]:
    """Return readable validation errors for one raw event dictionary."""
    prefix = f"Event {index}: " if index is not None else "Event: "
    try:
        EvidenceEvent.from_dict(data)
    except EvidenceValidationError as exc:
        return [f"{prefix}{exc}"]
    return []
