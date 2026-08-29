"""Unit tests for ransomeye.collectors.live_file.

Deterministically tests the LiveFileCollector code without requiring a real
active filesystem monitor. Uses stubs/mocking for watchdog if needed.
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
from ransomeye.collectors.live_file import (
    LiveFileCollector,
    _sha256_file,
    RansomEyeFileEventHandler,
)
from ransomeye.evidence import EvidenceEvent


class TestLiveFileCollector:

    def test_sha256_file_errors(self) -> None:
        assert _sha256_file("") is None
        assert _sha256_file("nonexistent_file_path.xyz") is None

    def test_sha256_file_success(self, tmp_path: Any) -> None:
        p = tmp_path / "test.txt"
        p.write_bytes(b"hello world")
        digest = _sha256_file(str(p))
        assert digest == hashlib.sha256(b"hello world").hexdigest()

    def test_event_handler_filtering(self) -> None:
        collector = LiveFileCollector(
            watch_paths=[],
            extensions=[".txt", ".log"],
        )
        handler = RansomEyeFileEventHandler(collector)

        assert handler._is_filtered("test.txt") is False
        assert handler._is_filtered("test.log") is False
        assert handler._is_filtered("test.EXE") is True
        assert handler._is_filtered("test.zip") is True

    def test_event_handler_filtering_empty_is_all(self) -> None:
        collector = LiveFileCollector(watch_paths=[])
        handler = RansomEyeFileEventHandler(collector)
        assert handler._is_filtered("test.exe") is False

    def test_handle_fs_event_fields(self) -> None:
        received: list[dict] = []
        collector = LiveFileCollector(
            watch_paths=[],
            case_id="CASE-123",
            on_event=received.append,
            compute_hash=False,
        )

        collector.handle_fs_event("file_create", "C:/path/to/test.txt")
        assert len(received) == 1
        event = received[0]
        assert event["event_type"] == "file_create"
        assert event["file_path"] == "C:/path/to/test.txt"
        assert event["case_id"] == "CASE-123"
        assert event["source"] == "live_file_collector"
        assert "pid" not in event
        assert "process_name" not in event

        # Verify round-trip parsing
        parsed = EvidenceEvent.from_dict(event)
        assert parsed.event_type == "file_create"
        assert parsed.file_path == "C:/path/to/test.txt"
        assert parsed.pid is None
        assert parsed.process_name is None

    def test_handle_fs_event_rename(self) -> None:
        received: list[dict] = []
        collector = LiveFileCollector(
            watch_paths=[],
            on_event=received.append,
            compute_hash=False,
        )

        collector.handle_fs_event("file_rename", "C:/old.txt", "C:/new.txt")
        assert len(received) == 1
        event = received[0]
        assert event["event_type"] == "file_rename"
        assert event["file_path"] == "C:/new.txt"
        assert event["metadata"]["destination_path"] == "C:/new.txt"
        assert event["metadata"]["watch_path"] == "C:/old.txt"

    def test_event_handler_callbacks(self) -> None:
        collector = LiveFileCollector(watch_paths=[])
        collector.handle_fs_event = MagicMock()  # type: ignore[assignment]
        handler = RansomEyeFileEventHandler(collector)

        # Mock FileSystemEvent class
        event_created = MagicMock()
        event_created.is_directory = False
        event_created.src_path = "test.txt"

        handler.on_created(event_created)
        collector.handle_fs_event.assert_called_with(
            event_type="file_create",
            src_path="test.txt",
        )

    def test_watchdog_unavailable_handling(self) -> None:
        import ransomeye.collectors.live_file as lf_module
        original_avail = lf_module._WATCHDOG_AVAILABLE

        try:
            lf_module._WATCHDOG_AVAILABLE = False
            collector = LiveFileCollector(watch_paths=["/tmp"])
            collector.start()
            assert collector.state == CollectorState.ERROR
            assert "watchdog is not installed" in collector.error_message
        finally:
            lf_module._WATCHDOG_AVAILABLE = original_avail

    def test_watchdog_lifecycle_mocks(self, tmp_path: Any) -> None:
        import ransomeye.collectors.live_file as lf_module
        original_avail = lf_module._WATCHDOG_AVAILABLE
        original_observer = lf_module.Observer

        # Create valid watch directory
        watch_dir = tmp_path / "watchdir"
        watch_dir.mkdir()

        try:
            lf_module._WATCHDOG_AVAILABLE = True
            mock_observer_cls = MagicMock()
            lf_module.Observer = mock_observer_cls

            collector = LiveFileCollector(watch_paths=[str(watch_dir)])
            collector.start()
            assert collector.state == CollectorState.RUNNING

            mock_observer_instance = mock_observer_cls.return_value
            mock_observer_instance.start.assert_called_once()

            collector.stop()
            assert collector.state == CollectorState.STOPPED
            mock_observer_instance.stop.assert_called_once()
            mock_observer_instance.join.assert_called_once()
        finally:
            lf_module._WATCHDOG_AVAILABLE = original_avail
            lf_module.Observer = original_observer
