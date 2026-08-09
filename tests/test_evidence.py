"""Tests for the normalized evidence model and validation."""

from __future__ import annotations

from datetime import datetime

import pytest

from ransomeye.evidence import (
    EvidenceEvent,
    EvidenceValidationError,
    normalize_event,
    normalize_events,
    validate_event_dict,
)


def _minimal_event_dict() -> dict:
    return {
        "event_id": "evt-100",
        "timestamp": "2026-08-08T12:00:00Z",
        "source": "simulation",
        "event_type": "file_modify",
        "process_name": "simulator.exe",
        "pid": 123,
        "parent_pid": 1,
        "process_guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
        "command_line": "simulator.exe --run",
        "file_path": "C:\\temp\\test.txt",
        "file_count": 1,
        "network": None,
        "confidence": 0.8,
        "metadata": {"scenario": "test"},
    }


def test_from_dict_parses_and_normalizes_fields():
    data = _minimal_event_dict()
    ev = EvidenceEvent.from_dict(data)

    assert ev.event_id == "evt-100"
    assert ev.source == "simulation"
    assert ev.event_type == "file_modify"
    assert ev.process_name == "simulator.exe"
    assert ev.pid == 123
    assert ev.file_path == "C:\\temp\\test.txt"
    assert ev.confidence == 0.8
    assert ev.timestamp.year == 2026


def test_validate_event_dict_reports_missing_required_fields():
    base = _minimal_event_dict()
    for field in ("event_id", "timestamp", "source", "event_type"):
        bad = dict(base)
        bad[field] = None
        errors = validate_event_dict(bad)
        assert errors, f"{field} must trigger a validation error"


def test_invalid_event_type_is_rejected():
    data = _minimal_event_dict()
    data["event_type"] = "not_a_real_type"
    errors = validate_event_dict(data)
    assert errors and "invalid" in errors[0].lower()


@pytest.mark.parametrize(
    "confidence,file_count",
    [
        (-0.1, None),
        (1.5, None),
        (None, -1),
    ],
)
def test_confidence_and_file_count_range_validation(confidence, file_count):
    data = _minimal_event_dict()
    data["confidence"] = confidence
    data["file_count"] = file_count

    errors = validate_event_dict(data)
    assert errors


def test_normalize_event_preserves_parent_fields():
    data = _minimal_event_dict()
    data["parent_process_guid"] = "{parent-guid-123}"
    data["parent_command_line"] = "explorer.exe /select,C:\\"

    ev = normalize_event(data)

    assert isinstance(ev, EvidenceEvent)
    assert ev.parent_process_guid == "{parent-guid-123}"
    assert ev.parent_command_line == "explorer.exe /select,C:\\"


def test_normalize_event_handles_missing_parent_fields_safely():
    data = _minimal_event_dict()
    ev = normalize_event(data)

    assert ev.parent_process_guid is None
    assert ev.parent_command_line is None


def test_normalize_event_preserves_unknown_metadata():
    data = _minimal_event_dict()
    data["custom_field"] = "custom_value"
    data["user_account"] = "admin"

    ev = normalize_event(data)

    assert ev.metadata is not None
    assert ev.metadata.get("scenario") == "test"
    assert ev.metadata.get("custom_field") == "custom_value"
    assert ev.metadata.get("user_account") == "admin"


def test_normalize_events_preserves_input_order():
    raw_list = [
        {**_minimal_event_dict(), "event_id": "evt-1"},
        {**_minimal_event_dict(), "event_id": "evt-2"},
        {**_minimal_event_dict(), "event_id": "evt-3"},
    ]

    events = normalize_events(raw_list)

    assert len(events) == 3
    assert [e.event_id for e in events] == ["evt-1", "evt-2", "evt-3"]
