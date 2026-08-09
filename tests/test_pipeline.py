from datetime import datetime, timezone

from ransomeye import pipeline


def test_collect_and_store(monkeypatch, tmp_path):
    fake_events = [
        {
            "event_id": "sysmon-1-test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1234",
            "parent_pid": "1000",
            "process_guid": "{TEST-GUID}",
            "command_line": "powershell.exe Get-Date",
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "hashes": "SHA256=TEST",
            "user": "LAB\\Student",
            "metadata": {"rule": "Sysmon Event ID 1"},
        }
    ]

    monkeypatch.setattr(
        pipeline,
        "read_process_creation_events",
        lambda limit: fake_events,
    )

    database_path = tmp_path / "ransomeye.db"

    result = pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-PIPELINE-001",
        case_name="Pipeline Test",
        host="TEST-PC",
        limit=5,
    )

    assert result["case_id"] == "RE-PIPELINE-001"
    assert result["events_collected"] == 1
    assert result["findings_saved"] == 0
    assert result["assessment"]["score"] == 0
    assert result["assessment"]["severity"] == "SAFE"


def test_pipeline_invokes_normalization(monkeypatch, tmp_path):
    fake_events = [
        {
            "event_id": "sysmon-1-norm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
        }
    ]

    normalized_called = False
    original_normalize = pipeline.normalize_events

    def spy_normalize(events):
        nonlocal normalized_called
        normalized_called = True
        return original_normalize(events)

    monkeypatch.setattr(pipeline, "read_process_creation_events", lambda limit: fake_events)
    monkeypatch.setattr(pipeline, "normalize_events", spy_normalize)

    database_path = tmp_path / "ransomeye.db"
    pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-NORM-001",
        case_name="Normalization Test",
        limit=1,
    )

    assert normalized_called is True
