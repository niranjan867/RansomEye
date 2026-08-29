"""Live process collector for RansomEye.

Polls the running process table via psutil and emits evidence events for
process creation and termination.

Algorithm adapted from:
    12X-RANSOMWARE-ANALYSIS/SentinelGuard/sentinelguard/monitors/process_monitor.py

Key design decisions
--------------------
* Does NOT import any 12X module.  All logic has been rewritten as a
  RansomEye-native module.
* Does NOT write to any database directly.  Callers supply an
  ``on_event`` callback that receives raw evidence dicts; the
  CollectionPipeline (or test code) is responsible for storing them.
* Does NOT generate Sysmon ProcessGuids.  Live events have no native
  Sysmon GUID.  A lightweight *synthetic* correlation token is stored
  inside ``metadata["synthetic_correlation_id"]`` so the caller can
  optionally use it for intra-session linkage.  It is explicitly labelled
  synthetic and must never overwrite ``process_guid``.
* Does NOT perform autonomous response.
* Handles AccessDenied / NoSuchProcess / ZombieProcess per-process so
  that one inaccessible process cannot crash the collector.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from ransomeye.collectors.base import BaseCollector, CollectorState

logger = logging.getLogger(__name__)

# psutil is an optional runtime dependency.  Guard the import so that
# the module can still be imported (and tested in stub mode) without it.
try:
    import psutil  # type: ignore[import-untyped]

    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


def _sha256_file(path: str) -> str | None:
    """Return the SHA-256 hex-digest of an executable, or None on any error."""
    if not path:
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:  # PermissionError, FileNotFoundError, OSError …
        return None


def _synthetic_correlation_id(pid: int, create_time: float) -> str:
    """Return a stable, *labelled-synthetic* token for intra-session linkage.

    This is NOT a Sysmon ProcessGuid.  It is derived from PID + creation
    timestamp and stored only in ``metadata["synthetic_correlation_id"]``.
    """
    raw = f"live:pid={pid}:ct={create_time:.3f}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"SYNTHETIC-{digest}"


# ---------------------------------------------------------------------------
# Public event-dict builder
# ---------------------------------------------------------------------------

def build_process_create_dict(
    case_id: str | None,
    pid: int,
    name: str,
    exe: str | None,
    cmdline: str,
    ppid: int | None,
    parent_name: str | None,
    username: str | None,
    create_time: float | None,
    exe_hash: str | None,
) -> dict[str, Any]:
    """Build a raw evidence dict for a process-creation event.

    The returned dict is compatible with ``EvidenceEvent.from_dict()`` and
    ``normalize_events()``.  All 12X-specific fields are absent.
    """
    now = _now_utc()
    event_id = str(uuid.uuid4())

    # Represent creation time as ISO-8601 if available; fall back to now.
    if create_time is not None:
        try:
            ts = datetime.fromtimestamp(create_time, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            ts = now
    else:
        ts = now

    # Hashes string follows RansomEye convention: "SHA256=<hex>"
    hashes_str = f"SHA256={exe_hash}" if exe_hash else None

    meta: dict[str, Any] = {
        "source_collector": "LiveProcessCollector",
        "username": username,
        "exe_path": exe,
        "parent_name": parent_name,
        # Explicitly labelled synthetic — must not be used as a Sysmon GUID.
        "synthetic_correlation_id": _synthetic_correlation_id(pid, create_time or 0.0),
        "synthetic_correlation_note": (
            "This token is derived from PID + creation-time by LiveProcessCollector. "
            "It is NOT a Sysmon ProcessGuid and must not be treated as one."
        ),
    }

    raw: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": ts.isoformat(),
        "source": "live_process_collector",
        "event_type": "process_create",
        "process_name": name,
        "pid": pid,
        "parent_pid": ppid,
        # process_guid intentionally absent — no Sysmon GUID available.
        "command_line": cmdline or None,
        "image_path": exe or None,
        "hashes": hashes_str,
        "metadata": meta,
    }

    if case_id:
        raw["case_id"] = case_id

    return raw


def build_process_terminate_dict(
    case_id: str | None,
    pid: int,
) -> dict[str, Any]:
    """Build a raw evidence dict for a process-termination event."""
    event_id = str(uuid.uuid4())

    meta: dict[str, Any] = {
        "source_collector": "LiveProcessCollector",
    }

    raw: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": _now_iso(),
        "source": "live_process_collector",
        "event_type": "process_terminate",
        "pid": pid,
        "metadata": meta,
    }

    if case_id:
        raw["case_id"] = case_id

    return raw


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class LiveProcessCollector(BaseCollector):
    """Polls the live OS process table and emits evidence events.

    Parameters
    ----------
    case_id:
        Optional case identifier forwarded into every emitted event dict.
    on_event:
        Callback invoked synchronously for each emitted raw evidence dict.
        Signature: ``on_event(raw: dict[str, Any]) -> None``.
        The callback must not raise; exceptions are caught and logged.
    poll_interval:
        Seconds between polls.  Default 1.0 s.
    compute_exe_hash:
        If True (default), compute SHA-256 of each new executable.
        Disable when performance matters more than hash coverage.
    """

    def __init__(
        self,
        case_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        poll_interval: float = 1.0,
        compute_exe_hash: bool = True,
        name: str = "LiveProcessCollector",
    ) -> None:
        super().__init__(name=name)
        self.case_id = case_id
        self.on_event = on_event
        self.poll_interval = max(0.1, float(poll_interval))
        self.compute_exe_hash = compute_exe_hash

        self._known_pids: set[int] = set()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background polling thread."""
        if not _PSUTIL_AVAILABLE:
            self.state = CollectorState.ERROR
            self.error_message = "psutil is not installed; LiveProcessCollector requires it."
            logger.error(self.error_message)
            return

        if self.state == CollectorState.RUNNING:
            logger.warning("%s is already running.", self.name)
            return

        self.state = CollectorState.STARTING
        self.started_at = _now_iso()
        self._stop_event.clear()

        # Take an initial snapshot so that all currently-running processes
        # are treated as *known* and do not fire creation events on startup.
        try:
            self._known_pids = set(psutil.pids())
        except Exception as exc:  # pragma: no cover
            logger.warning("Initial PID snapshot failed: %s", exc)
            self._known_pids = set()

        self._thread = threading.Thread(
            target=self._poll_loop,
            name=f"{self.name}-thread",
            daemon=True,
        )
        self._thread.start()
        self.state = CollectorState.RUNNING
        logger.info("%s started (poll_interval=%.2fs).", self.name, self.poll_interval)

    def stop(self) -> None:
        """Signal the polling thread to stop and wait for it to finish."""
        if self.state not in (CollectorState.RUNNING, CollectorState.STARTING):
            return

        self.state = CollectorState.STOPPING
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=self.poll_interval * 3 + 2.0)

        self.state = CollectorState.STOPPED
        self.stopped_at = _now_iso()
        logger.info("%s stopped.", self.name)

    def collect(self) -> Iterable[dict[str, Any]]:
        """Not used in streaming mode; returns an empty iterable.

        In streaming mode events are delivered via the ``on_event``
        callback.  This method satisfies the BaseCollector ABC contract.
        """
        return []

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Main polling loop executed on the background thread."""
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:  # pragma: no cover — defensive
                logger.error("Unexpected error in %s poll loop: %s", self.name, exc)

            self._stop_event.wait(self.poll_interval)

    def _poll_once(self) -> None:
        """Perform one poll iteration: detect new and gone PIDs."""
        try:
            current_pids: set[int] = set(psutil.pids())
        except Exception as exc:
            logger.error("%s: failed to enumerate PIDs: %s", self.name, exc)
            return

        new_pids = current_pids - self._known_pids
        gone_pids = self._known_pids - current_pids

        for pid in new_pids:
            self._emit_process_create(pid)

        for pid in gone_pids:
            self._emit_process_terminate(pid)

        self._known_pids = current_pids

    def _emit_process_create(self, pid: int) -> None:
        """Gather process metadata and emit a process_create event."""
        self.events_collected += 1

        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()

                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, OSError):
                    exe = None

                try:
                    cmdline_parts = proc.cmdline()
                    cmdline = " ".join(cmdline_parts) if cmdline_parts else ""
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    cmdline = ""

                try:
                    ppid: int | None = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = None

                try:
                    parent_proc = psutil.Process(ppid) if ppid else None
                    parent_name: str | None = parent_proc.name() if parent_proc else None
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    parent_name = None

                try:
                    username: str | None = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = None

                try:
                    create_time: float | None = proc.create_time()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    create_time = None

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            logger.debug("%s: cannot inspect PID %d: %s", self.name, pid, exc)
            self.events_rejected += 1
            return
        except Exception as exc:
            logger.warning("%s: unexpected error reading PID %d: %s", self.name, pid, exc)
            self.events_rejected += 1
            return

        exe_hash: str | None = None
        if self.compute_exe_hash and exe:
            exe_hash = _sha256_file(exe)

        raw = build_process_create_dict(
            case_id=self.case_id,
            pid=pid,
            name=name,
            exe=exe,
            cmdline=cmdline,
            ppid=ppid,
            parent_name=parent_name,
            username=username,
            create_time=create_time,
            exe_hash=exe_hash,
        )

        self._deliver(raw)

    def _emit_process_terminate(self, pid: int) -> None:
        """Emit a process_terminate event for a gone PID."""
        self.events_collected += 1
        raw = build_process_terminate_dict(case_id=self.case_id, pid=pid)
        self._deliver(raw)

    def _deliver(self, raw: dict[str, Any]) -> None:
        """Deliver an event dict to the on_event callback."""
        self.events_accepted += 1
        self.last_event_at = _now_iso()

        if self.on_event is not None:
            try:
                self.on_event(raw)
            except Exception as exc:
                logger.error(
                    "%s: on_event callback raised an exception: %s", self.name, exc
                )
