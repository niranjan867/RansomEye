"""File Behavior Engine for detecting patterns of file activity."""

from __future__ import annotations

import collections
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from pathlib import PureWindowsPath
from typing import Any

from ransomeye.rules import (
    MASS_MODIFY_SCORE,
    MASS_MODIFY_THRESHOLD,
    MASS_MODIFY_WINDOW_SECONDS,
    RANSOM_NOTE_SCORE,
    RANSOM_NOTE_KEYWORDS,
)

# Configuration for new behavioral thresholds
MASS_CREATE_THRESHOLD = 100
MASS_DELETE_THRESHOLD = 50
MASS_ACTIVITY_WINDOW_SECONDS = 30
FILE_CHURN_THRESHOLD = 10
FILE_CHURN_WINDOW_SECONDS = 10
FILE_CHURN_SCORE = 15
EXTENSION_CHANGE_SCORE = 15


def _as_dict(event: Any) -> dict[str, Any]:
    if is_dataclass(event):
        return asdict(event)
    if isinstance(event, dict):
        return event
    raise TypeError("Events must be dictionaries or dataclass objects.")


def _parse_timestamp(value: str | datetime) -> datetime:
    """Parse ISO-8601 timestamps from evidence events."""
    if isinstance(value, datetime):
        return value
    normalized = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _try_parse_timestamp(event: dict[str, Any]) -> datetime | None:
    """Attempt to parse an event's timestamp, returning None on failure."""
    ts = event.get("timestamp")
    if ts is None:
        return None
    try:
        return _parse_timestamp(ts)
    except (ValueError, TypeError):
        return None


def _is_ransom_note_path(path: str) -> bool:
    """Check whether a file path matches known ransom note naming patterns."""
    filename = PureWindowsPath(path.replace("/", "\\")).name.upper()
    if not filename:
        return False
    return any(keyword in filename for keyword in RANSOM_NOTE_KEYWORDS)


def _get_process_identity(event: dict[str, Any]) -> str:
    """Return process GUID, fallback to PID, fallback to UNKNOWN."""
    guid = event.get("process_guid")
    if guid:
        return f"GUID:{guid}"
    pid = event.get("pid")
    if pid is not None:
        return f"PID:{pid}"
    return "UNKNOWN"


def _is_file_modify(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_modify", "file_modified", "modify"}


def _is_file_create(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_create", "file_created", "create"}


def _is_file_delete(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_delete", "file_deleted", "delete"}


def _is_file_rename(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_rename", "file_renamed", "rename"}


def _event_path(event: dict) -> str:
    return str(event.get("file_path") or event.get("path") or "")


def _filter_parseable_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only events with valid, parseable timestamps."""
    result = []
    for ev in events:
        if _try_parse_timestamp(ev) is not None:
            result.append(ev)
    return result


def _find_mass_activity_windows(
    events: list[dict[str, Any]],
    threshold: int,
    window_seconds: int
) -> list[list[dict[str, Any]]]:
    """Find discrete sliding windows of activity exceeding the threshold.

    The window boundary is inclusive: an event at exactly start + window_seconds
    is included in the window.
    """
    parseable = _filter_parseable_events(events)
    if not parseable:
        return []

    sorted_events = sorted(parseable, key=lambda e: _parse_timestamp(e["timestamp"]))

    windows = []
    n = len(sorted_events)
    i = 0

    while i < n:
        start_time = _parse_timestamp(sorted_events[i]["timestamp"])
        window_end_time = start_time + timedelta(seconds=window_seconds)

        j = i
        current_window_events = []
        while j < n and _parse_timestamp(sorted_events[j]["timestamp"]) <= window_end_time:
            current_window_events.append(sorted_events[j])
            j += 1

        if len(current_window_events) >= threshold:
            windows.append(current_window_events)
            # Jump past this window to avoid overlapping duplicate findings
            i = j
        else:
            i += 1

    return windows


def detect_mass_modification(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect mass file modification within a sliding time window."""
    findings = []

    process_events: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for ev in events:
        if _is_file_modify(ev):
            process_events[_get_process_identity(ev)].append(ev)

    for proc_id, p_events in sorted(process_events.items()):
        windows = _find_mass_activity_windows(
            p_events, MASS_MODIFY_THRESHOLD, MASS_MODIFY_WINDOW_SECONDS
        )
        for window in windows:
            event_ids = [e["event_id"] for e in window if e.get("event_id")]
            findings.append({
                "type": "mass_file_modification",
                "score": MASS_MODIFY_SCORE,
                "confidence": 0.80,
                "technique": "T1486",
                "process_identity": proc_id,
                "reason": (
                    f"Mass file modification detected: {len(window)} files"
                    f" modified within {MASS_MODIFY_WINDOW_SECONDS} seconds"
                ),
                "event_ids": event_ids,
            })

    return findings


def detect_mass_creation(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect mass file creation within a sliding time window."""
    findings = []
    process_events: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for ev in events:
        if _is_file_create(ev):
            process_events[_get_process_identity(ev)].append(ev)

    for proc_id, p_events in sorted(process_events.items()):
        windows = _find_mass_activity_windows(
            p_events, MASS_CREATE_THRESHOLD, MASS_ACTIVITY_WINDOW_SECONDS
        )
        for window in windows:
            event_ids = [e["event_id"] for e in window if e.get("event_id")]
            findings.append({
                "type": "mass_file_creation",
                "score": 0,
                "confidence": 0.60,
                "technique": "T1486",
                "process_identity": proc_id,
                "reason": (
                    f"High volume file creation: {len(window)} files"
                    f" created within {MASS_ACTIVITY_WINDOW_SECONDS} seconds"
                ),
                "event_ids": event_ids,
            })

    return findings


def detect_mass_deletion(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect mass file deletion within a sliding time window."""
    findings = []
    process_events: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for ev in events:
        if _is_file_delete(ev):
            process_events[_get_process_identity(ev)].append(ev)

    for proc_id, p_events in sorted(process_events.items()):
        windows = _find_mass_activity_windows(
            p_events, MASS_DELETE_THRESHOLD, MASS_ACTIVITY_WINDOW_SECONDS
        )
        for window in windows:
            event_ids = [e["event_id"] for e in window if e.get("event_id")]
            findings.append({
                "type": "mass_file_deletion",
                "score": 0,
                "confidence": 0.60,
                "technique": "T1485",
                "process_identity": proc_id,
                "reason": (
                    f"High volume file deletion: {len(window)} files"
                    f" deleted within {MASS_ACTIVITY_WINDOW_SECONDS} seconds"
                ),
                "event_ids": event_ids,
            })

    return findings


def detect_file_churn(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect rapid create/delete activity within a tight time window.

    Triggers when both create and delete counts independently exceed
    FILE_CHURN_THRESHOLD within FILE_CHURN_WINDOW_SECONDS.
    """
    findings = []
    process_events: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

    for ev in events:
        if _is_file_create(ev) or _is_file_delete(ev):
            process_events[_get_process_identity(ev)].append(ev)

    for proc_id, p_events in sorted(process_events.items()):
        parseable = _filter_parseable_events(p_events)
        sorted_events = sorted(
            parseable, key=lambda e: _parse_timestamp(e["timestamp"])
        )

        i = 0
        n = len(sorted_events)
        while i < n:
            start_time = _parse_timestamp(sorted_events[i]["timestamp"])
            window_end_time = start_time + timedelta(seconds=FILE_CHURN_WINDOW_SECONDS)

            j = i
            window = []
            create_count = 0
            delete_count = 0
            while j < n and _parse_timestamp(sorted_events[j]["timestamp"]) <= window_end_time:
                ev = sorted_events[j]
                window.append(ev)
                if _is_file_create(ev):
                    create_count += 1
                elif _is_file_delete(ev):
                    delete_count += 1
                j += 1

            if create_count >= FILE_CHURN_THRESHOLD and delete_count >= FILE_CHURN_THRESHOLD:
                event_ids = [e["event_id"] for e in window if e.get("event_id")]
                findings.append({
                    "type": "file_churn",
                    "score": FILE_CHURN_SCORE,
                    "confidence": 0.50,
                    "technique": "T1486",
                    "process_identity": proc_id,
                    "reason": (
                        f"Rapid file create/delete churn: {create_count}"
                        f" creates and {delete_count} deletes within"
                        f" {FILE_CHURN_WINDOW_SECONDS} seconds"
                    ),
                    "event_ids": event_ids,
                })
                i = j
            else:
                i += 1

    return findings


def detect_ransom_note(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect creation of files matching known ransom note naming patterns."""
    findings = []
    for ev in events:
        if _is_file_create(ev):
            path = _event_path(ev)
            if _is_ransom_note_path(path):
                event_id = ev.get("event_id")
                findings.append({
                    "type": "ransom_note",
                    "score": RANSOM_NOTE_SCORE,
                    "confidence": 0.90,
                    "technique": "T1486",
                    "process_identity": _get_process_identity(ev),
                    "reason": f"Ransom note creation detected: {path}",
                    "event_ids": [event_id] if event_id else [],
                })
    return findings


def detect_extension_changes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect file renames that change the file extension.

    Requires metadata.old_path to be present. Safely handles missing
    or extensionless filenames without raising.
    """
    findings = []

    for ev in events:
        if _is_file_rename(ev):
            new_path = _event_path(ev)
            metadata = ev.get("metadata") or {}
            if not isinstance(metadata, dict):
                continue
            old_path = str(metadata.get("old_path") or "")

            if not new_path or not old_path:
                continue

            old_ext = old_path.rsplit(".", 1)[-1].lower() if "." in old_path else ""
            new_ext = new_path.rsplit(".", 1)[-1].lower() if "." in new_path else ""

            if old_ext and new_ext and old_ext != new_ext:
                event_id = ev.get("event_id")
                findings.append({
                    "type": "extension_change",
                    "score": EXTENSION_CHANGE_SCORE,
                    "confidence": 0.60,
                    "technique": "T1486",
                    "process_identity": _get_process_identity(ev),
                    "reason": f"Suspicious extension change from .{old_ext} to .{new_ext}",
                    "event_ids": [event_id] if event_id else [],
                })
    return findings


def analyze_file_behavior(events: list[Any]) -> list[dict[str, Any]]:
    """Run all file behavior analysis rules.

    Returns a deterministic list of findings sorted by process identity
    and detection order.
    """
    normalized = [_as_dict(e) for e in events]

    findings = []
    findings.extend(detect_mass_modification(normalized))
    findings.extend(detect_mass_creation(normalized))
    findings.extend(detect_mass_deletion(normalized))
    findings.extend(detect_file_churn(normalized))
    findings.extend(detect_ransom_note(normalized))
    findings.extend(detect_extension_changes(normalized))

    return findings
