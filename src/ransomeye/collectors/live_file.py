"""Live file collector for RansomEye.

Monitors directories for filesystem activity (creation, modification, deletion,
renaming) using watchdog and generates RansomEye-compatible evidence events.

Algorithm adapted from:
    12X-RANSOMWARE-ANALYSIS/SentinelGuard/sentinelguard/monitors/file_monitor.py

Key design decisions
--------------------
* Does NOT import any 12X modules.
* Does NOT write to any database directly. Calls on_event callback.
* Does NOT perform process attribution, as watchdog does not natively track PIDs.
* Safely computes SHA-256 hashes on creation/modification.
* Cleanly joins the watchdog observer thread on stop().
* Handles missing watchdog package gracefully by shifting to ERROR state.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
import uuid
from typing import Any, Callable, Iterable, Sequence

from ransomeye.collectors.base import BaseCollector, CollectorState

logger = logging.getLogger(__name__)

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
    _WATCHDOG_AVAILABLE = True
except ImportError:
    # Stubs for type checking / when watchdog is not installed
    class FileSystemEventHandler:  # type: ignore
        pass
    class FileSystemEvent:  # type: ignore
        pass
    Observer = None  # type: ignore
    _WATCHDOG_AVAILABLE = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: str) -> str | None:
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Watchdog event handler adapter
# ---------------------------------------------------------------------------

class RansomEyeFileEventHandler(FileSystemEventHandler):
    """Adapts watchdog FileSystemEvents into RansomEye events."""

    def __init__(self, collector: LiveFileCollector) -> None:
        self.collector = collector

    def _is_filtered(self, path: str) -> bool:
        if os.path.isdir(path):
            return True
        if self.collector.extensions:
            _, ext = os.path.splitext(path)
            if ext.lower() not in self.collector.extensions:
                return True
        return False

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._is_filtered(event.src_path):
            return
        self.collector.handle_fs_event(
            event_type="file_create",
            src_path=event.src_path,
        )

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._is_filtered(event.src_path):
            return
        self.collector.handle_fs_event(
            event_type="file_modify",
            src_path=event.src_path,
        )

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._is_filtered(event.src_path):
            return
        self.collector.handle_fs_event(
            event_type="file_delete",
            src_path=event.src_path,
        )

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        
        # Check src
        src_filtered = self._is_filtered(event.src_path)
        dest_filtered = self._is_filtered(event.dest_path)

        if not src_filtered and dest_filtered:
            # Becomes a delete on the source
            self.collector.handle_fs_event(
                event_type="file_delete",
                src_path=event.src_path,
            )
        elif src_filtered and not dest_filtered:
            # Becomes a create on the destination
            self.collector.handle_fs_event(
                event_type="file_create",
                src_path=event.dest_path,
            )
        elif not src_filtered and not dest_filtered:
            # Full rename event
            self.collector.handle_fs_event(
                event_type="file_rename",
                src_path=event.src_path,
                dest_path=event.dest_path,
            )


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class LiveFileCollector(BaseCollector):
    """Monitors specified paths using watchdog and generates filesystem events.

    Parameters
    ----------
    watch_paths:
        Sequence of directory paths to watch.
    case_id:
        Optional case identifier forwarded into every emitted event dict.
    on_event:
        Callback invoked synchronously for each emitted raw evidence dict.
        Signature: ``on_event(raw: dict[str, Any]) -> None``.
    extensions:
        Optional sequence of file extensions to monitor (e.g. ['.exe', '.txt']).
        If empty, all extensions are monitored.
    compute_hash:
        If True (default), compute SHA-256 hash for file_create and file_modify events.
    """

    def __init__(
        self,
        watch_paths: Sequence[str],
        case_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        extensions: Sequence[str] | None = None,
        compute_hash: bool = True,
        name: str = "LiveFileCollector",
    ) -> None:
        super().__init__(name=name)
        self.watch_paths = watch_paths
        self.case_id = case_id
        self.on_event = on_event
        self.extensions = [e.lower() for e in extensions] if extensions else []
        self.compute_hash = compute_hash
        self._observer: Any = None

    def start(self) -> None:
        if not _WATCHDOG_AVAILABLE:
            self.state = CollectorState.ERROR
            self.error_message = "watchdog is not installed; LiveFileCollector requires it."
            logger.error(self.error_message)
            return

        if self.state == CollectorState.RUNNING:
            logger.warning("%s is already running.", self.name)
            return

        self.state = CollectorState.STARTING
        self.started_at = _now_iso()

        self._observer = Observer()
        handler = RansomEyeFileEventHandler(self)

        watch_count = 0
        for path in self.watch_paths:
            resolved = os.path.abspath(os.path.expanduser(path))
            if os.path.exists(resolved) and os.path.isdir(resolved):
                self._observer.schedule(handler, resolved, recursive=True)
                watch_count += 1
            else:
                logger.warning("Watch path does not exist or is not a directory: %s", path)

        if watch_count == 0:
            self.state = CollectorState.ERROR
            self.error_message = "No valid directories to watch."
            logger.error(self.error_message)
            return

        self._observer.start()
        self.state = CollectorState.RUNNING
        logger.info("%s started watching %d directories.", self.name, watch_count)

    def stop(self) -> None:
        if self.state not in (CollectorState.RUNNING, CollectorState.STARTING):
            return

        self.state = CollectorState.STOPPING
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None

        self.state = CollectorState.STOPPED
        self.stopped_at = _now_iso()
        logger.info("%s stopped.", self.name)

    def collect(self) -> Iterable[dict[str, Any]]:
        return []

    def handle_fs_event(self, event_type: str, src_path: str, dest_path: str | None = None) -> None:
        """Process a watchdog filesystem event, generate the event dict, and deliver it."""
        self.events_collected += 1

        file_hash: str | None = None
        if self.compute_hash and event_type in ("file_create", "file_modify", "file_rename"):
            # For rename/moved, compute hash on the destination path if it exists
            target_path = dest_path if dest_path else src_path
            file_hash = _sha256_file(target_path)

        hashes_str = f"SHA256={file_hash}" if file_hash else None

        meta: dict[str, Any] = {
            "source_collector": "LiveFileCollector",
            "watch_path": src_path,
        }
        if dest_path:
            meta["destination_path"] = dest_path

        raw: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source": "live_file_collector",
            "event_type": event_type,
            "file_path": dest_path if event_type == "file_rename" else src_path,
            "hashes": hashes_str,
            "metadata": meta,
        }

        # Watchdog doesn't give process details, so pid and process_name are explicitly absent.
        
        if self.case_id:
            raw["case_id"] = self.case_id

        self.events_accepted += 1
        self.last_event_at = _now_iso()

        if self.on_event:
            try:
                self.on_event(raw)
            except Exception as exc:
                logger.error("%s callback exception: %s", self.name, exc)
