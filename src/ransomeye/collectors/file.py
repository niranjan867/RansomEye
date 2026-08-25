"""Deterministic local file collector for RansomEye evidence collection."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ransomeye.collectors.base import BaseCollector, CollectorState, _now_iso
from ransomeye.commands import parse_evidence_file


class FileCollector(BaseCollector):
    """Collector that reads pre-existing evidence files (JSON, Sysmon XML, etc.)."""

    def __init__(
        self,
        file_path: str | Path,
        format_type: str = "auto",
        name: str = "FileCollector",
    ):
        super().__init__(name=name)
        self.file_path = Path(file_path)
        self.format_type = format_type
        self._stopped = False

    def start(self) -> None:
        if not self.file_path.is_file():
            self.state = CollectorState.ERROR
            self.error_message = f"Evidence file not found: {self.file_path}"
            raise FileNotFoundError(self.error_message)

        self.state = CollectorState.RUNNING
        self.started_at = _now_iso()
        self._stopped = False
        self.error_message = None

    def stop(self) -> None:
        self.state = CollectorState.STOPPING
        self._stopped = True
        self.stopped_at = _now_iso()
        self.state = CollectorState.STOPPED

    def collect(self) -> Iterable[dict[str, Any]]:
        if self.state != CollectorState.RUNNING:
            raise RuntimeError(f"Collector {self.name} is not running (state={self.state.value})")

        try:
            raw_events, rejected, detected_format = parse_evidence_file(
                self.file_path,
                format_type=self.format_type,
            )
            self.events_rejected += rejected

            for seq, ev in enumerate(raw_events, start=1):
                if self._stopped:
                    break
                self.events_collected += 1
                self.last_event_at = _now_iso()

                yield {
                    "payload": ev,
                    "source": detected_format,
                    "collected_at": self.last_event_at,
                    "collector_name": self.name,
                    "sequence_number": seq,
                }
        except Exception as exc:
            self.state = CollectorState.ERROR
            self.error_message = str(exc)
            raise
