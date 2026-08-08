from datetime import datetime, timezone

from ransomeye import pipeline
from ransomeye.timeline import build_process_tree, get_case_timeline


def test_live_collection_to_timeline_and_tree(monkeypatch, tmp_path):
    events = [
        {
            "event_id": "integration-parent",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1000",
            "parent_pid": "500",
            "process_guid": "guid-parent",
            "command_line": "powershell.exe -NoProfile",
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
        {
            "event_id": "integration-child",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "conhost.exe",
            "pid": "2000",
            "parent_pid": "1000",
            "process_guid": "guid-child",
            "command_line": "conhost.exe",
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
    ]

    monkeypatch.setattr(
        pipeline,
        "read_process_creation_events",
        lambda limit: events,
    )

    database_path = tmp_path / "integration.db"

    result = pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-INTEGRATION-001",
        case_name="Integration Test",
        host="TEST-HOST",
        limit=20,
    )

    assert result["case_id"] == "RE-INTEGRATION-001"
    assert result["events_collected"] == 2
    assert result["assessment"]["severity"] == "SAFE"

    timeline = get_case_timeline(
        database_path,
        "RE-INTEGRATION-001",
    )

    assert len(timeline) == 2
    assert timeline[0]["process_name"] == "powershell.exe"
    assert timeline[1]["process_name"] == "conhost.exe"

    tree = build_process_tree(timeline)

    assert "1000" in tree["nodes"]
    assert "2000" in tree["nodes"]
    assert tree["children"]["1000"] == ["2000"]
