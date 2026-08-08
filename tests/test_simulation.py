"""Tests for safe synthetic dataset loading and read-only checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ransomeye.simulation import (
    load_normal_activity,
    load_ransomware_like_activity,
    check_read_only_access,
    validate_dataset,
    NORMAL_ACTIVITY_PATH,
    RANSOMWARE_LIKE_ACTIVITY_PATH,
)


def test_normal_dataset_is_valid():
    result = load_normal_activity()
    assert result.ok
    assert result.dataset_name == "normal_activity"
    assert len(result.events) > 0


def test_ransomware_like_dataset_is_valid():
    result = load_ransomware_like_activity()
    assert result.ok
    assert result.dataset_name == "ransomware_like_activity"
    assert len(result.events) > 0


def test_read_only_check_verifies_file(NORMAL: None = None):  # simple marker param
    ro = check_read_only_access(NORMAL_ACTIVITY_PATH)
    assert ro.ok
    assert "not modified" in ro.message.lower()


def test_validate_dataset_rejects_bad_payload(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"events": "not a list"}), encoding="utf-8")

    result = validate_dataset(bad)
    assert not result.ok
    assert any("events" in e.lower() for e in result.errors)
