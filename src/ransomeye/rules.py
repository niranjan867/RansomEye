"""Safe simulation detection rules for synthetic JSON events."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from pathlib import PureWindowsPath

MASS_MODIFY_THRESHOLD = 50
MASS_MODIFY_WINDOW_SECONDS = 30
MASS_MODIFY_SCORE = 20
RANSOM_NOTE_SCORE = 10
MAX_SCORE = 100

RANSOM_NOTE_KEYWORDS = (
    "DECRYPT",
    "RECOVER",
    "RANSOM",
    "RESTORE_FILES",
    "HOW_TO_DECRYPT",
    "DECRYPT_INSTRUCTIONS",
    "RECOVER-FILES",
    "README_DECRYPT",
)


def _parse_timestamp(value: str | datetime) -> datetime:
    """Parse ISO-8601 timestamps from simulation events."""
    if isinstance(value, datetime):
        return value

    normalized = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _event_dict(event) -> dict:
    """Convert an EvidenceEvent or dictionary into a dictionary."""
    if is_dataclass(event):
        return asdict(event)

    if isinstance(event, dict):
        return event

    raise TypeError("Each event must be a dictionary or EvidenceEvent.")


def _is_file_modify(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_modify", "file_modified", "modify"}


def _is_file_create(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).lower()
    return event_type in {"file_create", "file_created", "create"}


def _event_path(event: dict) -> str:
    return str(event.get("file_path") or event.get("path") or "")


def _is_ransom_note_path(path: str) -> bool:
    filename = PureWindowsPath(path.replace("/", "\\")).name.upper()
    if not filename:
        return False
    return any(keyword in filename for keyword in RANSOM_NOTE_KEYWORDS)


def _max_modifications_in_window(modify_events: list[dict], window_seconds: int) -> int:
    """Return the highest number of file modifications in any sliding window."""
    if not modify_events:
        return 0

    timestamps = sorted(_parse_timestamp(event["timestamp"]) for event in modify_events)
    window = timedelta(seconds=window_seconds)
    max_count = 0
    left = 0

    for right, current_time in enumerate(timestamps):
        while current_time - timestamps[left] > window:
            left += 1
        max_count = max(max_count, right - left + 1)

    return max_count


def _severity_from_score(score: int) -> str:
    if score <= 24:
        return "SAFE"
    if score <= 49:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    if score <= 84:
        return "HIGH"
    return "CRITICAL"


def _confidence_from_signals(
    mass_modify_count: int,
    mass_modify_triggered: bool,
    ransom_note_triggered: bool,
) -> float:
    """Estimate confidence from how strongly each rule matched."""
    if not mass_modify_triggered and not ransom_note_triggered:
        return 0.95

    confidence_values: list[float] = []

    if mass_modify_triggered:
        ratio = mass_modify_count / MASS_MODIFY_THRESHOLD
        confidence_values.append(min(0.99, 0.75 + (ratio - 1) * 0.05))

    if ransom_note_triggered:
        confidence_values.append(0.9)

    return round(max(confidence_values), 2)


def analyze_events(events: list[dict]) -> dict:
    """Score normalized evidence events and return severity details."""
    normalized_events = [_event_dict(event) for event in events]

    modify_events = [
        event for event in normalized_events
        if _is_file_modify(event)
    ]

    create_events = [
        event for event in normalized_events
        if _is_file_create(event)
    ]

    max_mod_count = _max_modifications_in_window(
        modify_events, MASS_MODIFY_WINDOW_SECONDS
    )
    mass_modify_triggered = max_mod_count >= MASS_MODIFY_THRESHOLD

    if len(modify_events) >= MASS_MODIFY_THRESHOLD and not mass_modify_triggered:
        mass_modify_triggered = True
        max_mod_count = max(max_mod_count, len(modify_events))

    ransom_notes = [
        _event_path(event)
        for event in create_events
        if _is_ransom_note_path(_event_path(event))
    ]
    ransom_note_triggered = bool(ransom_notes)

    score = 0
    reasons: list[str] = []

    if mass_modify_triggered:
        score += MASS_MODIFY_SCORE
        reasons.append(
            "Mass file modification detected: "
            f"{max_mod_count} files modified within "
            f"{MASS_MODIFY_WINDOW_SECONDS} seconds (+{MASS_MODIFY_SCORE})"
        )

    if ransom_note_triggered:
        score += RANSOM_NOTE_SCORE
        note_list = ", ".join(ransom_notes)
        reasons.append(
            "Ransom note creation detected: "
            f"{note_list} (+{RANSOM_NOTE_SCORE})"
        )

    if not reasons:
        reasons.append("No suspicious simulation activity detected.")

    score = min(score, MAX_SCORE)
    confidence = _confidence_from_signals(
        max_mod_count, mass_modify_triggered, ransom_note_triggered
    )

    return {
        "score": score,
        "severity": _severity_from_score(score),
        "confidence": confidence,
        "reasons": reasons,
        "mass_modify_triggered": mass_modify_triggered,
        "ransom_note_triggered": ransom_note_triggered,
    }
