"""Unit tests for ransomeye.collectors.live_process.

These tests do NOT require a real OS process table.  They use stubs that
inject controlled data so the tests are deterministic and portable.

Coverage:
  - build_process_create_dict: field mapping, hash formatting, timestamps
  - build_process_terminate_dict: minimal required fields
  - LiveProcessCollector.start() / stop() lifecycle
  - LiveProcessCollector.status() counters
  - Detection of new and gone PIDs (_poll_once logic)
  - Per-process AccessDenied / NoSuchProcess handling
  - Missing psutil graceful error
  - on_event callback delivery
  - Synthetic correlation ID format and labelling
  - process_guid is not emitted for live events
  - EvidenceEvent.from_dict() compatibility (round-trip)
"""

from __future__ import annotations

import hashlib
import time
import types
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Allow running with `python -m pytest tests/` when the package is not installed.
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ransomeye.collectors.base import CollectorState
from ransomeye.collectors.live_process import (
    LiveProcessCollector,
    _sha256_file,
    _synthetic_correlation_id,
    build_process_create_dict,
    build_process_terminate_dict,
)
from ransomeye.evidence import EvidenceEvent, ALLOWED_EVENT_TYPES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_dict(**kwargs: Any) -> dict[str, Any]:
    """Return build_process_create_dict with sensible defaults."""
    defaults: dict[str, Any] = dict(
        case_id="CASE-001",
        pid=1234,
        name="test.exe",
        exe="C:/test.exe",
        cmdline="test.exe --flag",
        ppid=4,
        parent_name="explorer.exe",
        username="DOMAIN\\user",
        create_time=1700000000.0,
        exe_hash="aabbcc" * 10 + "aabb",  # 62-char placeholder
    )
    defaults.update(kwargs)
    return build_process_create_dict(**defaults)


# ---------------------------------------------------------------------------
# build_process_create_dict — field validation
# ---------------------------------------------------------------------------

class TestBuildProcessCreateDict:
    def test_event_type_is_process_create(self) -> None:
        d = _create_dict()
        assert d["event_type"] == "process_create"

    def test_event_type_in_allowed(self) -> None:
        d = _create_dict()
        assert d["event_type"] in ALLOWED_EVENT_TYPES

    def test_source_is_live_process_collector(self) -> None:
        d = _create_dict()
        assert d["source"] == "live_process_collector"

    def test_event_id_is_uuid(self) -> None:
        d = _create_dict()
        # Should be parseable as UUID4
        parsed = uuid.UUID(d["event_id"])
        assert parsed.version == 4

    def test_pid_is_preserved(self) -> None:
        d = _create_dict(pid=9999)
        assert d["pid"] == 9999

    def test_parent_pid_is_preserved(self) -> None:
        d = _create_dict(ppid=123)
        assert d["parent_pid"] == 123

    def test_process_name_is_preserved(self) -> None:
        d = _create_dict(name="malware.exe")
        assert d["process_name"] == "malware.exe"

    def test_command_line_is_preserved(self) -> None:
        d = _create_dict(cmdline="cmd /c evil.bat")
        assert d["command_line"] == "cmd /c evil.bat"

    def test_image_path_is_preserved(self) -> None:
        d = _create_dict(exe="C:/Windows/System32/cmd.exe")
        assert d["image_path"] == "C:/Windows/System32/cmd.exe"

    def test_hashes_format_sha256(self) -> None:
        fake_hash = "a" * 64
        d = _create_dict(exe_hash=fake_hash)
        assert d["hashes"] == f"SHA256={fake_hash}"

    def test_hashes_is_none_when_no_hash(self) -> None:
        d = _create_dict(exe_hash=None)
        assert d["hashes"] is None

    def test_case_id_forwarded(self) -> None:
        d = _create_dict(case_id="CASE-XYZ")
        assert d.get("case_id") == "CASE-XYZ"

    def test_no_case_id_not_in_dict(self) -> None:
        d = _create_dict(case_id=None)
        assert "case_id" not in d

    def test_timestamp_is_iso_string(self) -> None:
        d = _create_dict(create_time=1700000000.0)
        ts = datetime.fromisoformat(d["timestamp"])
        assert ts.tzinfo is not None

    def test_timestamp_from_none_create_time(self) -> None:
        d = _create_dict(create_time=None)
        ts = datetime.fromisoformat(d["timestamp"])
        assert ts.tzinfo is not None

    def test_process_guid_is_absent(self) -> None:
        """Live events must NOT carry a process_guid to avoid spoofing Sysmon GUIDs."""
        d = _create_dict()
        assert "process_guid" not in d

    def test_parent_process_guid_is_absent(self) -> None:
        d = _create_dict()
        assert "parent_process_guid" not in d

    def test_metadata_source_collector_label(self) -> None:
        d = _create_dict()
        assert d["metadata"]["source_collector"] == "LiveProcessCollector"

    def test_synthetic_correlation_id_present(self) -> None:
        d = _create_dict()
        assert "synthetic_correlation_id" in d["metadata"]

    def test_synthetic_correlation_id_starts_with_synthetic(self) -> None:
        d = _create_dict()
        assert d["metadata"]["synthetic_correlation_id"].startswith("SYNTHETIC-")

    def test_synthetic_correlation_note_present(self) -> None:
        d = _create_dict()
        note = d["metadata"]["synthetic_correlation_note"]
        assert "NOT a Sysmon ProcessGuid" in note

    def test_metadata_username_preserved(self) -> None:
        d = _create_dict(username="ADMIN")
        assert d["metadata"]["username"] == "ADMIN"

    def test_metadata_parent_name_preserved(self) -> None:
        d = _create_dict(parent_name="svchost.exe")
        assert d["metadata"]["parent_name"] == "svchost.exe"

    def test_round_trip_evidence_event(self) -> None:
        """The raw dict must be parseable by EvidenceEvent.from_dict()."""
        d = _create_dict()
        ev = EvidenceEvent.from_dict(d)
        assert ev.event_type == "process_create"
        assert ev.pid == 1234
        assert ev.process_name == "test.exe"

    def test_empty_cmdline_becomes_none(self) -> None:
        d = _create_dict(cmdline="")
        assert d["command_line"] is None

    def test_none_exe_makes_image_path_none(self) -> None:
        d = _create_dict(exe=None)
        assert d["image_path"] is None

    def test_synthetic_id_deterministic(self) -> None:
        """Same PID + create_time must produce the same synthetic ID."""
        id1 = _synthetic_correlation_id(1234, 1700000000.0)
        id2 = _synthetic_correlation_id(1234, 1700000000.0)
        assert id1 == id2

    def test_synthetic_id_differs_with_different_pid(self) -> None:
        id1 = _synthetic_correlation_id(1234, 1700000000.0)
        id2 = _synthetic_correlation_id(9999, 1700000000.0)
        assert id1 != id2


# ---------------------------------------------------------------------------
# build_process_terminate_dict — field validation
# ---------------------------------------------------------------------------

class TestBuildProcessTerminateDict:
    def test_event_type_is_process_terminate(self) -> None:
        d = build_process_terminate_dict(case_id="CASE-001", pid=42)
        assert d["event_type"] == "process_terminate"

    def test_event_type_in_allowed(self) -> None:
        d = build_process_terminate_dict(case_id=None, pid=1)
        assert d["event_type"] in ALLOWED_EVENT_TYPES

    def test_source_is_live_process_collector(self) -> None:
        d = build_process_terminate_dict(case_id=None, pid=1)
        assert d["source"] == "live_process_collector"

    def test_pid_is_preserved(self) -> None:
        d = build_process_terminate_dict(case_id=None, pid=7777)
        assert d["pid"] == 7777

    def test_event_id_is_uuid(self) -> None:
        d = build_process_terminate_dict(case_id=None, pid=1)
        uuid.UUID(d["event_id"])  # must not raise

    def test_case_id_forwarded(self) -> None:
        d = build_process_terminate_dict(case_id="CASE-T", pid=5)
        assert d.get("case_id") == "CASE-T"

    def test_no_case_id_not_in_dict(self) -> None:
        d = build_process_terminate_dict(case_id=None, pid=5)
        assert "case_id" not in d

    def test_round_trip_evidence_event(self) -> None:
        d = build_process_terminate_dict(case_id="CASE-001", pid=42)
        ev = EvidenceEvent.from_dict(d)
        assert ev.event_type == "process_terminate"
        assert ev.pid == 42


# ---------------------------------------------------------------------------
# _sha256_file
# ---------------------------------------------------------------------------

class TestSha256File:
    def test_returns_none_for_empty_path(self) -> None:
        assert _sha256_file("") is None

    def test_returns_none_for_nonexistent_file(self, tmp_path: Any) -> None:
        missing = str(tmp_path / "does_not_exist.exe")
        assert _sha256_file(missing) is None

    def test_returns_hex_digest_for_real_file(self, tmp_path: Any) -> None:
        f = tmp_path / "sample.bin"
        f.write_bytes(b"\x00" * 1024)
        result = _sha256_file(str(f))
        assert result is not None
        assert len(result) == 64
        expected = hashlib.sha256(b"\x00" * 1024).hexdigest()
        assert result == expected

    def test_returns_none_for_none_path(self) -> None:
        assert _sha256_file(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# LiveProcessCollector — lifecycle
# ---------------------------------------------------------------------------

class TestLiveProcessCollectorLifecycle:

    def _make_collector(self, received: list[dict] | None = None) -> LiveProcessCollector:
        received = received if received is not None else []
        return LiveProcessCollector(
            case_id="CASE-001",
            on_event=received.append,
            poll_interval=0.05,
            compute_exe_hash=False,
        )

    def _psutil_ctx(self):
        """Context manager that stubs out psutil availability for lifecycle tests."""
        import ransomeye.collectors.live_process as lp_module
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            mock_psutil = MagicMock()
            mock_psutil.pids.return_value = []
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})
            orig_avail = lp_module._PSUTIL_AVAILABLE
            orig_psutil = lp_module.psutil
            lp_module._PSUTIL_AVAILABLE = True
            lp_module.psutil = mock_psutil
            try:
                yield
            finally:
                lp_module._PSUTIL_AVAILABLE = orig_avail
                lp_module.psutil = orig_psutil

        return _ctx()

    def test_initial_state_is_stopped(self) -> None:
        c = self._make_collector()
        assert c.state == CollectorState.STOPPED

    def test_start_sets_running(self) -> None:
        with self._psutil_ctx():
            c = self._make_collector()
            try:
                c.start()
                assert c.state == CollectorState.RUNNING
            finally:
                c.stop()

    def test_stop_sets_stopped(self) -> None:
        with self._psutil_ctx():
            c = self._make_collector()
            c.start()
            c.stop()
            assert c.state == CollectorState.STOPPED

    def test_started_at_set_after_start(self) -> None:
        with self._psutil_ctx():
            c = self._make_collector()
            try:
                c.start()
                assert c.started_at is not None
            finally:
                c.stop()

    def test_stopped_at_set_after_stop(self) -> None:
        with self._psutil_ctx():
            c = self._make_collector()
            c.start()
            c.stop()
            assert c.stopped_at is not None

    def test_double_start_is_safe(self) -> None:
        with self._psutil_ctx():
            c = self._make_collector()
            try:
                c.start()
                c.start()  # should not raise
                assert c.state == CollectorState.RUNNING
            finally:
                c.stop()

    def test_stop_without_start_is_safe(self) -> None:
        c = self._make_collector()
        c.stop()  # must not raise

    def test_collect_returns_empty_iterable(self) -> None:
        c = self._make_collector()
        assert list(c.collect()) == []

    def test_status_keys_present(self) -> None:
        c = self._make_collector()
        status = c.status()
        for key in ("name", "state", "events_collected", "events_accepted",
                    "events_rejected", "started_at", "stopped_at", "last_event_at"):
            assert key in status

    def test_name_is_propagated(self) -> None:
        c = LiveProcessCollector(name="MyCollector")
        assert c.status()["name"] == "MyCollector"


# ---------------------------------------------------------------------------
# LiveProcessCollector — psutil unavailable
# ---------------------------------------------------------------------------

class TestLiveProcessCollectorNoPsutil:
    def test_start_without_psutil_sets_error_state(self) -> None:
        import ransomeye.collectors.live_process as lp_module

        original = lp_module._PSUTIL_AVAILABLE
        try:
            lp_module._PSUTIL_AVAILABLE = False
            c = LiveProcessCollector(poll_interval=0.05)
            c.start()
            assert c.state == CollectorState.ERROR
            assert c.error_message is not None
        finally:
            lp_module._PSUTIL_AVAILABLE = original


# ---------------------------------------------------------------------------
# LiveProcessCollector — poll detection with psutil stubs
# ---------------------------------------------------------------------------

def _make_fake_process(pid: int, name: str = "fake.exe",
                        exe: str | None = None,
                        cmdline: list[str] | None = None,
                        ppid: int = 0,
                        username: str = "USER",
                        create_time: float = 1700000000.0) -> MagicMock:
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe or ""
    proc.cmdline.return_value = cmdline or []
    proc.ppid.return_value = ppid
    proc.username.return_value = username
    proc.create_time.return_value = create_time
    # oneshot() context manager
    proc.oneshot.return_value.__enter__ = lambda s: s
    proc.oneshot.return_value.__exit__ = MagicMock(return_value=False)
    return proc


class TestLiveProcessCollectorPolling:
    def test_new_pid_emits_create_event(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id="CASE-P",
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1, 2}

        fake_proc = _make_fake_process(pid=999, name="new.exe")

        import ransomeye.collectors.live_process as lp_module

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 2, 999]
            mock_psutil.Process.side_effect = lambda pid: fake_proc if pid == 999 else MagicMock()
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            c._poll_once()

        assert len(received) == 1
        assert received[0]["event_type"] == "process_create"
        assert received[0]["pid"] == 999

    def test_gone_pid_emits_terminate_event(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id="CASE-P",
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1, 2, 888}

        import ransomeye.collectors.live_process as lp_module

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 2]  # 888 is gone
            mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
            mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})

            c._poll_once()

        assert len(received) == 1
        assert received[0]["event_type"] == "process_terminate"
        assert received[0]["pid"] == 888

    def test_access_denied_increments_rejected_not_crash(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id=None,
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1}

        import ransomeye.collectors.live_process as lp_module

        class FakeAccessDenied(Exception):
            pass

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 55]
            mock_psutil.AccessDenied = FakeAccessDenied
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            # Process(55) raises AccessDenied
            def process_factory(pid: int) -> MagicMock:
                p = MagicMock()
                p.oneshot.return_value.__enter__ = lambda s: (_ for _ in ()).throw(FakeAccessDenied("denied"))
                return p

            mock_psutil.Process.side_effect = process_factory

            c._poll_once()

        assert received == []
        assert c.events_rejected >= 1

    def test_no_such_process_increments_rejected_not_crash(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id=None,
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1}

        import ransomeye.collectors.live_process as lp_module

        class FakeNoSuchProcess(Exception):
            pass

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 66]
            mock_psutil.NoSuchProcess = FakeNoSuchProcess
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            def process_factory(pid: int) -> MagicMock:
                p = MagicMock()
                p.oneshot.return_value.__enter__ = lambda s: (_ for _ in ()).throw(FakeNoSuchProcess())
                return p

            mock_psutil.Process.side_effect = process_factory

            c._poll_once()

        assert received == []
        assert c.events_rejected >= 1

    def test_known_pids_updated_after_poll(self) -> None:
        c = LiveProcessCollector(poll_interval=60, compute_exe_hash=False)
        c._known_pids = {1, 2, 3}

        import ransomeye.collectors.live_process as lp_module

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [2, 3, 4, 5]
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            fake = _make_fake_process(pid=4)
            fake5 = _make_fake_process(pid=5)
            mock_psutil.Process.side_effect = lambda p: fake if p == 4 else fake5

            c._poll_once()

        assert c._known_pids == {2, 3, 4, 5}

    def test_events_accepted_counter_increments(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id=None,
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1}

        import ransomeye.collectors.live_process as lp_module

        fake_proc = _make_fake_process(pid=77)

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 77]
            mock_psutil.Process.side_effect = lambda pid: fake_proc if pid == 77 else MagicMock()
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            c._poll_once()

        assert c.events_accepted == 1
        assert c.last_event_at is not None

    def test_on_event_exception_does_not_crash_collector(self) -> None:
        def bad_callback(ev: dict) -> None:
            raise RuntimeError("callback exploded")

        c = LiveProcessCollector(
            case_id=None,
            on_event=bad_callback,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1}

        import ransomeye.collectors.live_process as lp_module

        fake_proc = _make_fake_process(pid=33)

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 33]
            mock_psutil.Process.side_effect = lambda pid: fake_proc if pid == 33 else MagicMock()
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            # Must not raise
            c._poll_once()

    def test_pids_failure_does_not_crash(self) -> None:
        c = LiveProcessCollector(poll_interval=60, compute_exe_hash=False)
        c._known_pids = {1, 2}

        import ransomeye.collectors.live_process as lp_module

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.side_effect = OSError("access denied")
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            # Must not raise
            c._poll_once()

        # known_pids should be unchanged
        assert c._known_pids == {1, 2}

    def test_create_and_terminate_in_same_poll(self) -> None:
        received: list[dict] = []
        c = LiveProcessCollector(
            case_id=None,
            on_event=received.append,
            poll_interval=60,
            compute_exe_hash=False,
        )
        c._known_pids = {1, 2}  # pid 2 will go, pid 3 will arrive

        import ransomeye.collectors.live_process as lp_module

        fake_proc = _make_fake_process(pid=3, name="arrived.exe")

        with patch.object(lp_module, "psutil") as mock_psutil:
            mock_psutil.pids.return_value = [1, 3]
            mock_psutil.Process.side_effect = lambda pid: fake_proc if pid == 3 else MagicMock()
            mock_psutil.NoSuchProcess = type("NSP", (Exception,), {})
            mock_psutil.AccessDenied = type("AD", (Exception,), {})
            mock_psutil.ZombieProcess = type("ZP", (Exception,), {})

            c._poll_once()

        event_types = {ev["event_type"] for ev in received}
        assert "process_create" in event_types
        assert "process_terminate" in event_types
