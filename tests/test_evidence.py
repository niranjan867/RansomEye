"""Tests for the normalized evidence model and validation."""

from __future__ import annotations

from datetime import datetime

import pytest

from ransomeye.evidence import (
    EvidenceEvent,
    EvidenceValidationError,
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
