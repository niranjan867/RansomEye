"""Collection pipeline and structured models for RansomEye continuous evidence collection."""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from ransomeye.behavior import analyze_behavior
from ransomeye.collectors.base import BaseCollector, CollectorState
from ransomeye.evidence import EvidenceEvent, normalize_events
from ransomeye.file_behavior import analyze_file_behavior
from ransomeye.storage import EvidenceStore
from ransomeye.threat_assessment import assess_threat

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PipelineState(Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


@dataclass
class CollectionEvent:
    """Structured representation of evidence collected from an endpoint or file source."""

    payload: dict[str, Any] | EvidenceEvent
    source: str = "file"
    collected_at: str | None = None
    collector_name: str = "BaseCollector"
    sequence_number: int = 0


class CollectionPipeline:
    """Pipeline that consumes CollectionEvents, passes them into existing RansomEye ingestion & analysis."""

    def __init__(
        self,
        database_path: str | Path,
        case_id: str,
        collector: BaseCollector | None = None,
        max_queue_size: int = 1000,
        case_name: str | None = None,
        host: str | None = None,
    ):
        self.database_path = Path(database_path)
        self.case_id = case_id
        self.collector = collector
        self.case_name = case_name or case_id
        self.host = host or ""

        self.state = PipelineState.STOPPED
        self.max_queue_size = max_queue_size
        self.queue: queue.Queue[CollectionEvent | None] = queue.Queue(maxsize=max_queue_size)
        self.started_at: str | None = None
        self.stopped_at: str | None = None
        self.last_processed_at: str | None = None

        self.events_collected: int = 0
        self.events_accepted: int = 0
        self.events_rejected: int = 0
        self.duplicates: int = 0
        self.error_message: str | None = None

        self.is_streaming: bool = False
        self.flush_interval: float = 2.0
        self._streaming_thread: threading.Thread | None = None
        self._streaming_stop_event = threading.Event()

        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()

    def attach_collector(self, collector: BaseCollector) -> None:
        """Attach a collector instance to the pipeline."""
        if self.state in (PipelineState.RUNNING, PipelineState.STARTING):
            raise RuntimeError("Cannot attach collector while pipeline is running")
        self.collector = collector

    def start(self, streaming: bool = False, flush_interval: float = 2.0) -> None:
        """Start collector and pipeline processing.

        Parameters
        ----------
        streaming:
            If True, spawn a background worker thread that periodically flushes
            queued events every ``flush_interval`` seconds. Default False (batch mode).
        flush_interval:
            Interval in seconds between streaming flushes. Default 2.0.
        """
        if self.state == PipelineState.RUNNING:
            logger.warning("Pipeline is already running.")
            return

        self.state = PipelineState.STARTING
        self.error_message = None
        self.is_streaming = bool(streaming)
        self.flush_interval = max(0.1, float(flush_interval))

        # Verify/create case in store
        store = EvidenceStore(self.database_path)
        try:
            case = store.get_case(self.case_id)
            if case is None:
                store.create_case(self.case_id, case_name=self.case_name, host=self.host)
        finally:
            store.close()

        if self.collector is not None:
            self.collector.start()

        self.state = PipelineState.RUNNING
        self.started_at = _now_iso()

        if self.is_streaming:
            self._streaming_stop_event.clear()
            self._streaming_thread = threading.Thread(
                target=self._streaming_worker,
                name=f"StreamingPipeline-{self.case_id}",
                daemon=True,
            )
            self._streaming_thread.start()
            logger.info("Pipeline streaming worker started (flush_interval=%.2fs).", self.flush_interval)

    def _streaming_worker(self) -> None:
        """Background worker thread for periodic live flush."""
        while not self._streaming_stop_event.is_set():
            self._streaming_stop_event.wait(self.flush_interval)
            try:
                if not self.queue.empty():
                    self.flush_and_analyze()
            except Exception as exc:
                logger.error("Error during streaming flush: %s", exc)

    def push(self, event: CollectionEvent | dict[str, Any]) -> None:
        """Push collected event into bounded pipeline queue (blocks if full to provide backpressure)."""
        if self.state not in (PipelineState.RUNNING, PipelineState.STOPPING):
            raise RuntimeError(f"Pipeline is not running (state={self.state.value})")

        if isinstance(event, dict) and not isinstance(event, CollectionEvent):
            col_evt = CollectionEvent(
                payload=event.get("payload", event),
                source=event.get("source", "unknown"),
                collected_at=event.get("collected_at") or _now_iso(),
                collector_name=event.get("collector_name", "Collector"),
                sequence_number=event.get("sequence_number", 0),
            )
        elif isinstance(event, CollectionEvent):
            col_evt = event
        else:
            col_evt = CollectionEvent(payload=event, collected_at=_now_iso())

        # Block if queue is full to enforce backpressure without losing events
        self.queue.put(col_evt, block=True, timeout=30.0)
        with self._lock:
            self.events_collected += 1

    def run_batch(self, events: Iterable[CollectionEvent | dict[str, Any]]) -> dict[str, Any]:
        """Synchronously ingest a batch of events through collector and pipeline into existing ingestion."""
        self.start(streaming=False)
        try:
            for item in events:
                self.push(item)
            return self.flush_and_analyze()
        except Exception as exc:
            self.state = PipelineState.ERROR
            self.error_message = str(exc)
            raise
        finally:
            self.stop()

    def flush_and_analyze(self) -> dict[str, Any]:
        """Drain queued events, persist into EvidenceStore, and execute existing RansomEye analysis pipeline."""
        with self._flush_lock:
            pending_events: list[CollectionEvent] = []
            while not self.queue.empty():
                try:
                    item = self.queue.get_nowait()
                    if item is not None:
                        pending_events.append(item)
                except queue.Empty:
                    break

            if not pending_events:
                store = EvidenceStore(self.database_path)
                try:
                    findings = store.get_case_findings(self.case_id)
                    assessment = store.get_latest_assessment(self.case_id) or {}
                    return {
                        "database": str(self.database_path),
                        "case_id": self.case_id,
                        "events_collected": self.events_collected,
                        "events_accepted": self.events_accepted,
                        "events_rejected": self.events_rejected,
                        "duplicates": self.duplicates,
                        "findings_count": len(findings),
                        "correlations_count": len(assessment.get("correlations", [])),
                        "score": assessment.get("score", 0),
                        "severity": assessment.get("severity", "SAFE"),
                    }
                finally:
                    store.close()

            # Extract raw payloads & normalize
            raw_payloads = []
            for ce in pending_events:
                payload = ce.payload
                if isinstance(payload, EvidenceEvent):
                    raw_payloads.append(payload.to_dict())
                elif isinstance(payload, dict):
                    p_copy = dict(payload)
                    if not p_copy.get("source"):
                        p_copy["source"] = ce.source or "unknown"
                    raw_payloads.append(p_copy)
                else:
                    p_copy = dict(payload)
                    if not p_copy.get("source"):
                        p_copy["source"] = ce.source or "unknown"
                    raw_payloads.append(p_copy)

            normalized = normalize_events(raw_payloads)

            store = EvidenceStore(self.database_path)
            try:
                case = store.get_case(self.case_id)
                if case is None:
                    store.create_case(self.case_id, case_name=self.case_name, host=self.host)

                existing_events = store.get_case_events(self.case_id)
                existing_ids = {e["event_id"] for e in existing_events}

                accepted = 0
                dups = 0

                for ev in normalized:
                    if ev.event_id in existing_ids:
                        dups += 1
                    else:
                        accepted += 1
                    store.save_event(self.case_id, ev)
                    existing_ids.add(ev.event_id)

                with self._lock:
                    self.events_accepted += accepted
                    self.duplicates += dups
                    self.last_processed_at = _now_iso()

                # Execute existing analysis engines
                all_case_events = store.get_case_events(self.case_id)
                b_findings = analyze_behavior(all_case_events)
                fb_findings = analyze_file_behavior(all_case_events)
                all_findings = b_findings + fb_findings

                for finding in all_findings:
                    eids = finding.get("event_ids")
                    if not eids and finding.get("event_id"):
                        eids = [str(finding["event_id"])]
                    store.save_finding(self.case_id, finding, event_ids=eids)

                assessment = assess_threat(all_case_events)
                store.save_assessment(self.case_id, assessment)

                return {
                    "database": str(self.database_path),
                    "case_id": self.case_id,
                    "events_collected": self.events_collected,
                    "events_accepted": self.events_accepted,
                    "events_rejected": self.events_rejected,
                    "duplicates": self.duplicates,
                    "findings_count": len(all_findings),
                    "correlations_count": len(assessment.get("correlations", [])),
                    "score": assessment.get("score", 0),
                    "severity": assessment.get("severity", "SAFE"),
                }
            finally:
                store.close()

    def stop(self) -> None:
        """Gracefully stop collector, streaming worker, and pipeline."""
        if self.state not in (PipelineState.RUNNING, PipelineState.STARTING, PipelineState.ERROR):
            return

        self.state = PipelineState.STOPPING

        # 1. Stop collectors first so no further events are produced
        if self.collector and self.collector.state in (CollectorState.RUNNING, CollectorState.STARTING):
            try:
                self.collector.stop()
            except Exception as exc:
                logger.error("Error stopping collector: %s", exc)

        # 2. Stop streaming worker thread
        if self._streaming_thread is not None:
            self._streaming_stop_event.set()
            self._streaming_thread.join(timeout=self.flush_interval * 3 + 2.0)
            self._streaming_thread = None

        # 3. Final drain and flush to ensure all events are persisted and analyzed
        if not self.queue.empty():
            try:
                self.flush_and_analyze()
            except Exception as exc:
                logger.error("Error during final shutdown flush: %s", exc)

        self.is_streaming = False
        self.stopped_at = _now_iso()
        self.state = PipelineState.STOPPED

    def status(self) -> dict[str, Any]:
        """Return truthful status of the pipeline and attached collector."""
        col_status = self.collector.status() if self.collector else None
        return {
            "pipeline_state": self.state.value,
            "is_streaming": self.is_streaming,
            "flush_interval": self.flush_interval,
            "case_id": self.case_id,
            "database": str(self.database_path),
            "events_collected": self.events_collected,
            "events_accepted": self.events_accepted,
            "events_rejected": self.events_rejected,
            "duplicates": self.duplicates,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_processed_at": self.last_processed_at,
            "collector": col_status,
            "error_message": self.error_message,
        }

    def render_status(self) -> str:
        """Render human-readable collection status output."""
        col_name = self.collector.name if self.collector else "None"

        lines = [
            "RANSOMEYE COLLECTION STATUS",
            "===========================",
            "",
            f"Collector: {col_name}",
            f"State: {self.state.value}",
            f"Streaming: {'YES' if self.is_streaming else 'NO'}",
            f"Case: {self.case_id}",
            f"Events collected: {self.events_collected}",
            f"Events accepted: {self.events_accepted}",
            f"Events rejected: {self.events_rejected}",
            f"Duplicates: {self.duplicates}",
        ]
        if self.started_at:
            lines.append(f"Started: {self.started_at}")
        if self.last_processed_at:
            lines.append(f"Last event: {self.last_processed_at}")
        if self.error_message:
            lines.append(f"Error: {self.error_message}")

        return "\n".join(lines)
