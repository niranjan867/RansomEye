"""Canary collector for RansomEye.

Places decoy canary files in a configurable directory and monitors them using
watchdog. If any canary file is modified, deleted, or renamed, it generates a
RansomEye-compatible filesystem event with specialized canary metadata.

Adapted from:
    12X-RANSOMWARE-ANALYSIS/engine_12x/core/system_guard.py
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

from ransomeye.collectors.base import BaseCollector, CollectorState

logger = logging.getLogger(__name__)

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
    _WATCHDOG_AVAILABLE = True
except ImportError:
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


class CanaryFileEventHandler(FileSystemEventHandler):
    """Monitors the canary directory and handles changes to canary decoy files."""

    def __init__(self, collector: CanaryCollector) -> None:
        self.collector = collector

    def _is_canary_file(self, path: str) -> bool:
        name = os.path.basename(path)
        return name in self.collector.canary_names

    def on_created(self, event: FileSystemEvent) -> None:
        # If a deleted canary file is re-created, we might want to track it
        if event.is_directory or not self._is_canary_file(event.src_path):
            return
        self.collector.handle_canary_change("file_create", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory or not self._is_canary_file(event.src_path):
            return
        self.collector.handle_canary_change("file_modify", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory or not self._is_canary_file(event.src_path):
            return
        self.collector.handle_canary_change("file_delete", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        # If a canary file is renamed/moved away, it counts as a delete/modify
        if self._is_canary_file(event.src_path):
            self.collector.handle_canary_change("file_delete", event.src_path)


class CanaryCollector(BaseCollector):
    """Collector that sets up canary decoy files and monitors their integrity.

    Parameters
    ----------
    canary_dir:
        Directory where decoy files are created and monitored.
    canary_names:
        Sequence of filenames to create as decoys.
    case_id:
        Optional case identifier forwarded into every emitted event dict.
    on_event:
        Callback invoked synchronously for each emitted raw evidence dict.
    """

    def __init__(
        self,
        canary_dir: str,
        canary_names: Sequence[str] = ("canary_doc.txt", "canary_sheet.xlsx"),
        case_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        name: str = "CanaryCollector",
    ) -> None:
        super().__init__(name=name)
        self.canary_dir = os.path.abspath(os.path.expanduser(canary_dir))
        self.canary_names = list(canary_names)
        self.case_id = case_id
        self.on_event = on_event
        self._observer: Any = None
        self._initial_hashes: dict[str, str | None] = {}

    def start(self) -> None:
        if not _WATCHDOG_AVAILABLE:
            self.state = CollectorState.ERROR
            self.error_message = "watchdog is not installed; CanaryCollector requires it."
            logger.error(self.error_message)
            return

        if self.state == CollectorState.RUNNING:
            logger.warning("%s is already running.", self.name)
            return

        self.state = CollectorState.STARTING
        self.started_at = _now_iso()

        # Initialize decoy files
        try:
            os.makedirs(self.canary_dir, exist_ok=True)
            for filename in self.canary_names:
                filepath = os.path.join(self.canary_dir, filename)
                if not os.path.exists(filepath):
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(
                            f"RansomEye Decoy protection file. Do not modify or delete. "
                            f"ID: {uuid.uuid4()}\n"
                        )
                # Compute and store initial hash for integrity manifest
                self._initial_hashes[filename] = _sha256_file(filepath)
        except Exception as exc:
            self.state = CollectorState.ERROR
            self.error_message = f"Failed to initialize canary decoy files: {exc}"
            logger.error(self.error_message)
            return

        self._observer = Observer()
        handler = CanaryFileEventHandler(self)
        self._observer.schedule(handler, self.canary_dir, recursive=False)

        self._observer.start()
        self.state = CollectorState.RUNNING
        logger.info("%s started monitoring decoys in %s.", self.name, self.canary_dir)

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

    def handle_canary_change(self, event_type: str, filepath: str) -> None:
        """Process decoy file changes and emit RansomEye evidence."""
        self.events_collected += 1

        filename = os.path.basename(filepath)
        current_hash = _sha256_file(filepath) if event_type != "file_delete" else None
        initial_hash = self._initial_hashes.get(filename)

        # Confirm actual content change / deletion
        if event_type == "file_modify" and current_hash == initial_hash:
            # Metadata change only, ignore to minimize noise
            return

        hashes_str = f"SHA256={current_hash}" if current_hash else None

        meta: dict[str, Any] = {
            "source_collector": "CanaryCollector",
            "is_canary": True,
            "canary_name": filename,
            "initial_hash": initial_hash,
            "current_hash": current_hash,
            "tampered": True,
        }

        raw: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source": "canary_collector",
            "event_type": event_type,
            "file_path": filepath,
            "hashes": hashes_str,
            "metadata": meta,
        }

        # Do NOT guess process details. Keep it blank as watchdog has no process attribution.

        if self.case_id:
            raw["case_id"] = self.case_id

        self.events_accepted += 1
        self.last_event_at = _now_iso()

        if self.on_event:
            try:
                self.on_event(raw)
            except Exception as exc:
                logger.error("%s callback exception: %s", self.name, exc)
