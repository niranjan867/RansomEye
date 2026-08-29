"""Tests for CollectionPipeline live streaming mode and graceful shutdown."""

import threading
import time
from pathlib import Path
import pytest
from ransomeye.collection import CollectionEvent, CollectionPipeline, PipelineState
from ransomeye.collectors.base import BaseCollector, CollectorState
from ransomeye.storage import EvidenceStore


class StreamingDummyCollector(BaseCollector):
    def __init__(self, name="StreamingDummyCollector"):
        super().__init__(name=name)

    def start(self) -> None:
        self.state = CollectorState.RUNNING

    def stop(self) -> None:
        self.state = CollectorState.STOPPED

    def collect(self):
        return []


def test_streaming_pipeline_periodic_flush(tmp_path):
    db_path = tmp_path / "streaming_test.db"
    col = StreamingDummyCollector()
    pipeline = CollectionPipeline(
        database_path=db_path,
        case_id="STREAM-CASE-01",
        collector=col,
    )

    # Start in streaming mode with very fast flush interval (0.2s)
    pipeline.start(streaming=True, flush_interval=0.2)
    assert pipeline.state == PipelineState.RUNNING
    assert pipeline.is_streaming is True

    # Push events
    pipeline.push({
        "event_id": "EVT-STREAM-1",
        "timestamp": "2026-08-29T12:00:00Z",
        "source": "live_process",
        "event_type": "process_create",
        "process_name": "cmd.exe",
    })

    # Wait for periodic flush worker to drain queue
    time.sleep(0.5)

    assert pipeline.queue.empty() is True
    assert pipeline.events_accepted >= 1

    # Verify event reached database
    store = EvidenceStore(db_path)
    events = store.get_case_events("STREAM-CASE-01")
    assert len(events) == 1
    assert events[0]["event_id"] == "EVT-STREAM-1"
    store.close()

    pipeline.stop()
    assert pipeline.state == PipelineState.STOPPED
    assert pipeline.is_streaming is False


def test_streaming_pipeline_final_shutdown_flush(tmp_path):
    db_path = tmp_path / "shutdown_flush_test.db"
    col = StreamingDummyCollector()
    pipeline = CollectionPipeline(
        database_path=db_path,
        case_id="SHUTDOWN-CASE-01",
        collector=col,
    )

    # Start with long flush interval so periodic worker doesn't drain immediately
    pipeline.start(streaming=True, flush_interval=10.0)

    # Push event
    pipeline.push({
        "event_id": "EVT-SHUTDOWN-1",
        "timestamp": "2026-08-29T12:00:01Z",
        "source": "live_file",
        "event_type": "file_create",
        "file_path": "C:\\safe\\test.txt",
    })

    # Stop pipeline immediately: shutdown should flush remaining items
    pipeline.stop()
    assert pipeline.state == PipelineState.STOPPED

    store = EvidenceStore(db_path)
    events = store.get_case_events("SHUTDOWN-CASE-01")
    assert len(events) == 1
    assert events[0]["event_id"] == "EVT-SHUTDOWN-1"
    store.close()


def test_streaming_pipeline_concurrent_pushes(tmp_path):
    db_path = tmp_path / "concurrent_pushes.db"
    col = StreamingDummyCollector()
    pipeline = CollectionPipeline(
        database_path=db_path,
        case_id="CONCURRENT-CASE-01",
        collector=col,
    )

    pipeline.start(streaming=True, flush_interval=0.2)

    total_threads = 5
    events_per_thread = 10

    def worker(worker_id: int):
        for i in range(events_per_thread):
            pipeline.push({
                "event_id": f"CONC-EVT-{worker_id}-{i}",
                "timestamp": "2026-08-29T12:00:02Z",
                "source": "worker",
                "event_type": "process_create",
                "process_name": f"worker_{worker_id}.exe",
            })

    threads = [
        threading.Thread(target=worker, args=(t,))
        for t in range(total_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Gracefully stop
    pipeline.stop()

    store = EvidenceStore(db_path)
    events = store.get_case_events("CONCURRENT-CASE-01")
    assert len(events) == total_threads * events_per_thread
    store.close()


def test_streaming_pipeline_status_rendering(tmp_path):
    db_path = tmp_path / "status_test.db"
    col = StreamingDummyCollector()
    pipeline = CollectionPipeline(
        database_path=db_path,
        case_id="STATUS-CASE-01",
        collector=col,
    )

    pipeline.start(streaming=True, flush_interval=1.0)
    status_str = pipeline.render_status()
    assert "Streaming: YES" in status_str
    assert "State: RUNNING" in status_str

    pipeline.stop()
    status_str_stopped = pipeline.render_status()
    assert "Streaming: NO" in status_str_stopped
    assert "State: STOPPED" in status_str_stopped
