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
