"""Unit tests for CanaryCollector and canary behavioral detection.

Deterministically tests decoy creation, watchdog setup, event generation, and
finding mappings.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Allow running with `python -m pytest tests/` when the package is not installed.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ransomeye.collectors.base import CollectorState
from ransomeye.collectors.canary_collector import (
    CanaryCollector,
    CanaryFileEventHandler,
    _sha256_file,
)
from ransomeye.behavior import analyze_behavior
from ransomeye.evidence import EvidenceEvent


class TestCanaryCollector:

    def test_sha256_helpers(self) -> None:
        assert _sha256_file("") is None
        assert _sha256_file("nonexistent_canary.txt") is None

    def test_decoy_initialization(self, tmp_path: Any) -> None:
        canary_dir = tmp_path / "canary"
        collector = CanaryCollector(
            canary_dir=str(canary_dir),
            canary_names=["test_decoy1.txt", "test_decoy2.xlsx"],
        )

        # Mock watchdog to prevent real start/stop errors during decoy creation testing
        with patch("ransomeye.collectors.canary_collector._WATCHDOG_AVAILABLE", True), \
             patch("ransomeye.collectors.canary_collector.Observer") as mock_obs:
            collector.start()
            assert collector.state == CollectorState.RUNNING

            # Decoy files must exist
            file1 = canary_dir / "test_decoy1.txt"
            file2 = canary_dir / "test_decoy2.xlsx"
            assert file1.exists()
            assert file2.exists()
            assert "Do not modify" in file1.read_text()

            # Hash manifest tracks initial states
            assert "test_decoy1.txt" in collector._initial_hashes
            assert collector._initial_hashes["test_decoy1.txt"] is not None

            collector.stop()
            assert collector.state == CollectorState.STOPPED

    def test_watchdog_unavailable_canary(self) -> None:
        with patch("ransomeye.collectors.canary_collector._WATCHDOG_AVAILABLE", False):
            collector = CanaryCollector(canary_dir="/tmp/canary")
            collector.start()
            assert collector.state == CollectorState.ERROR
            assert "watchdog is not installed" in collector.error_message

    def test_handle_canary_change_evidence(self, tmp_path: Any) -> None:
        received: list[dict] = []
        canary_dir = tmp_path / "canary"
        canary_dir.mkdir()
        
        collector = CanaryCollector(
            canary_dir=str(canary_dir),
            canary_names=["decoy.txt"],
            case_id="CASE-CANARY",
            on_event=received.append,
        )
        
        # Manually initialize manifest hash
        collector._initial_hashes["decoy.txt"] = "old_hash_val"

        # 1. Modify event
        collector.handle_canary_change("file_modify", str(canary_dir / "decoy.txt"))
        assert len(received) == 1
        event = received[0]
        assert event["event_type"] == "file_modify"
        assert event["file_path"] == str(canary_dir / "decoy.txt")
        assert event["case_id"] == "CASE-CANARY"
        assert event["metadata"]["is_canary"] is True
        assert event["metadata"]["tampered"] is True
        assert event["metadata"]["canary_name"] == "decoy.txt"
        assert "pid" not in event  # No process attribution guessed

        # Check EvidenceEvent validation compatibility
        parsed = EvidenceEvent.from_dict(event)
        assert parsed.event_type == "file_modify"
        assert parsed.metadata["is_canary"] is True

    def test_handler_callbacks_routing(self) -> None:
        collector = CanaryCollector(canary_dir="/tmp/canary", canary_names=["decoy.txt"])
        collector.handle_canary_change = MagicMock()  # type: ignore[assignment]
        handler = CanaryFileEventHandler(collector)

        event_mod = MagicMock()
        event_mod.is_directory = False
        event_mod.src_path = "/tmp/canary/decoy.txt"

        handler.on_modified(event_mod)
        collector.handle_canary_change.assert_called_with("file_modify", "/tmp/canary/decoy.txt")

        # Non-canary file changes must be ignored
        collector.handle_canary_change.reset_mock()
        event_other = MagicMock()
        event_other.is_directory = False
        event_other.src_path = "/tmp/canary/normal.txt"

        handler.on_modified(event_other)
        collector.handle_canary_change.assert_not_called()
