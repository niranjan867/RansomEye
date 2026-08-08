"""Smoke tests for safe simulation detection."""

from __future__ import annotations

import json
from pathlib import Path

from ransomeye.main import load_events
from ransomeye.rules import analyze_events

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NORMAL_SAMPLE = PROJECT_ROOT / "samples" / "normal_activity.json"
SIMULATION_SAMPLE = PROJECT_ROOT / "samples" / "simulation_activity.json"


def test_normal_activity_is_safe():
    events = load_events(NORMAL_SAMPLE)
    result = analyze_events(events)

    assert result["score"] == 0
    assert result["severity"] == "SAFE"
    assert result["confidence"] >= 0.9
    assert any("No suspicious" in reason for reason in result["reasons"])


def test_simulation_activity_triggers_both_rules():
    events = load_events(SIMULATION_SAMPLE)
    result = analyze_events(events)

    assert result["score"] == 30
    assert result["severity"] == "LOW"
    assert result["confidence"] >= 0.75
    assert any("Mass file modification" in reason for reason in result["reasons"])
    assert any("Ransom note creation" in reason for reason in result["reasons"])


def test_score_is_capped_at_100():
    events = json.loads(SIMULATION_SAMPLE.read_text(encoding="utf-8"))["events"]
    duplicated_events = events + events + events + events
    result = analyze_events(duplicated_events)

    assert result["score"] == 30
    assert result["score"] <= 100


def test_mass_modify_rule_requires_fifty_events_in_thirty_seconds():
    events = [
        {
            "timestamp": f"2026-08-08T12:00:{second:02d}",
            "event_type": "file_modify",
            "file_path": f"C:\\temp\\file_{second}.txt",
        }
        for second in range(49)
    ]
    result = analyze_events(events)

    assert result["score"] == 0
    assert result["severity"] == "SAFE"
