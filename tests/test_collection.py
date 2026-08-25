"""Tests for M23.8 Continuous Collection Foundation."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from ransomeye.collection import CollectionEvent, CollectionPipeline, PipelineState
from ransomeye.collectors.base import BaseCollector, CollectorState
from ransomeye.collectors.file import FileCollector
from ransomeye.storage import EvidenceStore


def _run_command(args, cwd=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "ransomeye.commands", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return result


class DummyCollector(BaseCollector):
    """Dummy collector implementation for testing BaseCollector contract."""

    def __init__(self, items=None, name="DummyCollector"):
        super().__init__(name=name)
        self.items = items or []

    def start(self) -> None:
        self.state = CollectorState.RUNNING

    def stop(self) -> None:
        self.state = CollectorState.STOPPED

    def collect(self):
        for idx, item in enumerate(self.items, start=1):
            self.events_collected += 1
            yield CollectionEvent(payload=item, collector_name=self.name, sequence_number=idx)


def test_collector_lifecycle_and_status():
    col = DummyCollector(items=[{"event_id": "EVT-1"}])
    assert col.state == CollectorState.STOPPED
    assert col.status()["state"] == "STOPPED"

    col.start()
    assert col.state == CollectorState.RUNNING
    assert col.status()["state"] == "RUNNING"

    collected = list(col.collect())
    assert len(collected) == 1
    assert col.events_collected == 1

    col.stop()
    assert col.state == CollectorState.STOPPED


def test_file_collector_valid_file(tmp_path):
    sample_file = Path(__file__).resolve().parents[1] / "samples" / "sysmon" / "realistic_ransomware_sequence.xml"
    assert sample_file.is_file()

    col = FileCollector(file_path=sample_file, format_type="sysmon-xml")
    col.start()
    assert col.state == CollectorState.RUNNING

    events = list(col.collect())
    assert len(events) == 7
    assert col.events_collected == 7

    col.stop()
    assert col.state == CollectorState.STOPPED


def test_file_collector_missing_file(tmp_path):
    missing_file = tmp_path / "nonexistent.xml"
    col = FileCollector(file_path=missing_file)

    with pytest.raises(FileNotFoundError):
        col.start()

    assert col.state == CollectorState.ERROR
    assert "not found" in col.error_message


def test_pipeline_delivery_to_existing_ingestion(tmp_path):
    db_path = tmp_path / "collection_test.db"
    sample_file = Path(__file__).resolve().parents[1] / "samples" / "sysmon" / "realistic_ransomware_sequence.xml"

    col = FileCollector(file_path=sample_file, format_type="sysmon-xml")
    pipeline = CollectionPipeline(database_path=db_path, case_id="CASE-COL-01", collector=col)

    summary = pipeline.run_batch(col.collect())

    assert summary["case_id"] == "CASE-COL-01"
    assert summary["events_collected"] == 7
    assert summary["events_accepted"] == 7
    assert summary["findings_count"] == 3
    assert summary["correlations_count"] == 1
    assert summary["score"] == 50
    assert summary["severity"] == "MEDIUM"

    # Verify DB state
    store = EvidenceStore(db_path)
    events = store.get_case_events("CASE-COL-01")
    assert len(events) == 7
    store.close()


def test_pipeline_statistics_and_duplicates(tmp_path):
    db_path = tmp_path / "dups_test.db"
    sample_file = Path(__file__).resolve().parents[1] / "samples" / "sysmon" / "realistic_ransomware_sequence.xml"

    # First run
    col1 = FileCollector(file_path=sample_file)
    p1 = CollectionPipeline(database_path=db_path, case_id="CASE-DUP-01", collector=col1)
    s1 = p1.run_batch(col1.collect())
    assert s1["events_accepted"] == 7
    assert s1["duplicates"] == 0

    # Second run (re-ingesting same file into same case)
    col2 = FileCollector(file_path=sample_file)
    p2 = CollectionPipeline(database_path=db_path, case_id="CASE-DUP-01", collector=col2)
    s2 = p2.run_batch(col2.collect())
    assert s2["events_accepted"] == 0
    assert s2["duplicates"] == 7


def test_bounded_queue_backpressure(tmp_path):
    db_path = tmp_path / "queue_test.db"
    col = DummyCollector()
    pipeline = CollectionPipeline(database_path=db_path, case_id="CASE-Q-01", collector=col, max_queue_size=2)

    pipeline.start()
    pipeline.push({"event_id": "EVT-Q1", "timestamp": "2026-08-08T10:00:00Z", "source": "sysmon", "event_type": "process_creation", "process_name": "a.exe"})
    pipeline.push({"event_id": "EVT-Q2", "timestamp": "2026-08-08T10:00:01Z", "source": "sysmon", "event_type": "process_creation", "process_name": "b.exe"})

    assert pipeline.queue.full() is True
    summary = pipeline.flush_and_analyze()
    assert summary["events_accepted"] == 2
    pipeline.stop()


def test_graceful_shutdown_and_status_rendering(tmp_path):
    db_path = tmp_path / "status_render.db"
    col = DummyCollector(name="CustomCollector")
    pipeline = CollectionPipeline(database_path=db_path, case_id="CASE-STATUS-01", collector=col)

    pipeline.start()
    status_str = pipeline.render_status()
    assert "Collector: CustomCollector" in status_str
    assert "State: RUNNING" in status_str
    assert "Case: CASE-STATUS-01" in status_str

    pipeline.stop()
    assert pipeline.state == PipelineState.STOPPED


def test_cli_collect_file(tmp_path):
    db_path = tmp_path / "cli_collect.db"
    sample_file = Path(__file__).resolve().parents[1] / "samples" / "sysmon" / "realistic_ransomware_sequence.xml"

    cli_res = _run_command([
        "collect", "file",
        "--database", str(db_path),
        "--case", "CASE-CLI-COL",
        "--file", str(sample_file),
    ])

    assert cli_res.returncode == 0
    assert "RansomEye evidence collection complete" in cli_res.stdout
    assert "Collector: FileCollector" in cli_res.stdout
    assert "Events accepted: 7" in cli_res.stdout
    assert "Findings: 3" in cli_res.stdout


def test_cli_collect_status(tmp_path):
    db_path = tmp_path / "cli_status.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-CLI-STAT", "Status Case")
    store.close()

    cli_res = _run_command([
        "collect", "status",
        "--database", str(db_path),
        "--case", "CASE-CLI-STAT",
    ])

    assert cli_res.returncode == 0
    assert "RANSOMEYE COLLECTION STATUS" in cli_res.stdout
    assert "Case: CASE-CLI-STAT" in cli_res.stdout
