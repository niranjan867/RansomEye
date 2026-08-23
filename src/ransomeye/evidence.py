"""Common evidence schema for RansomEye."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Any, Iterable, Mapping

ALLOWED_EVENT_TYPES = frozenset(
    {
        "file_create",
        "file_modify",
        "file_delete",
        "file_rename",
        "file_time_changed",
        "file_stream_hash",
        "process_create",
        "process_creation",
        "process_terminate",
        "process_tampering",
        "process_access",
        "remote_thread",
        "network_connect",
        "dns_query",
        "registry_create",
        "registry_modify",
        "registry_delete",
        "registry_value_set",
        "registry_rename",
        "image_load",
        "image_loaded",
        "driver_loaded",
    }
)

KNOWN_FIELDS = frozenset(
    {
        "event_id",
        "timestamp",
        "source",
        "event_type",
        "process_name",
        "pid",
        "parent_pid",
        "process_guid",
        "parent_process_guid",
        "command_line",
        "image_path",
        "parent_image",
        "parent_command_line",
        "hashes",
        "file_path",
        "file_count",
        "network",
        "network_json",
        "confidence",
        "metadata",
        "metadata_json",
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
    parent_process_guid: str | None = None
    command_line: str | None = None
    image_path: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    hashes: str | None = None
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
    def from_dict(cls, data: dict[str, Any] | Mapping[str, Any]) -> EvidenceEvent:
        """Build an evidence event from a raw dictionary or mapping."""
        if isinstance(data, EvidenceEvent):
            return data

        if not isinstance(data, Mapping):
            raise EvidenceValidationError("Event must be a mapping or EvidenceEvent object.")

        metadata = data.get("metadata")
        if metadata is None and data.get("metadata_json"):
            raw_meta = data.get("metadata_json")
            if isinstance(raw_meta, str):
                try:
                    metadata = json.loads(raw_meta)
                except (json.JSONDecodeError, TypeError):
                    metadata = None
            elif isinstance(raw_meta, dict):
                metadata = raw_meta

        network = data.get("network")
        if network is None and data.get("network_json"):
            raw_net = data.get("network_json")
            if isinstance(raw_net, str):
                try:
                    network = json.loads(raw_net)
                except (json.JSONDecodeError, TypeError):
                    network = None
            elif isinstance(raw_net, dict):
                network = raw_net

        extra_keys = {
            k: v for k, v in data.items()
            if k not in KNOWN_FIELDS
        }
        if extra_keys:
            merged = dict(metadata) if isinstance(metadata, dict) else {}
            for k, v in extra_keys.items():
                if k not in merged:
                    merged[k] = v
            metadata = merged

        return cls(
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp"),
            source=data.get("source"),
            event_type=data.get("event_type"),
            process_name=data.get("process_name"),
            pid=data.get("pid"),
            parent_pid=data.get("parent_pid"),
            process_guid=data.get("process_guid"),
            parent_process_guid=data.get("parent_process_guid"),
            command_line=data.get("command_line"),
            image_path=data.get("image_path"),
            parent_image=data.get("parent_image"),
            parent_command_line=data.get("parent_command_line"),
            hashes=data.get("hashes"),
            file_path=data.get("file_path"),
            file_count=data.get("file_count"),
            network=network,
            confidence=data.get("confidence"),
            metadata=metadata,
        )


def normalize_event(raw_event: Mapping[str, object] | EvidenceEvent) -> EvidenceEvent:
    """Normalize a raw evidence mapping into an EvidenceEvent."""
    return EvidenceEvent.from_dict(raw_event)


def normalize_events(
    raw_events: Iterable[Mapping[str, object] | EvidenceEvent],
) -> list[EvidenceEvent]:
    """Normalize an iterable of raw evidence mappings into a list of EvidenceEvent objects."""
    if raw_events is None:
        raise EvidenceValidationError("raw_events cannot be None.")
    return [normalize_event(event) for event in raw_events]



def validate_event_dict(data: dict[str, Any], index: int | None = None) -> list[str]:
    """Return readable validation errors for one raw event dictionary."""
    prefix = f"Event {index}: " if index is not None else "Event: "
    try:
        EvidenceEvent.from_dict(data)
    except EvidenceValidationError as exc:
        return [f"{prefix}{exc}"]
    return []
