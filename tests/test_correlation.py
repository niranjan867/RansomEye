from datetime import datetime, timezone

from ransomeye.correlation import correlate_events
from ransomeye.evidence import EvidenceEvent


def make_event(
    event_id: str,
    timestamp_second: int,
    process_name: str,
    pid: str,
    parent_pid: str | None = None,
    process_guid: str | None = None,
):
    return EvidenceEvent.from_dict(
        {
            "event_id": event_id,
            "timestamp": datetime(
                2026,
                8,
                8,
                15,
                0,
                timestamp_second,
                tzinfo=timezone.utc,
            ),
            "source": "simulation",
            "event_type": "process_create",
            "process_name": process_name,
            "pid": pid,
            "parent_pid": parent_pid,
            "process_guid": process_guid,
        }
    )


def test_events_with_same_process_guid_are_correlated():
    events = [
        make_event(
            "event-1",
            1,
            "powershell.exe",
            "4532",
            process_guid="{GUID-1}",
        ),
        make_event(
            "event-2",
            2,
            "powershell.exe",
            "4532",
            process_guid="{GUID-1}",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1
    assert incidents[0].process_key == "guid:{GUID-1}"
    assert len(incidents[0].events) == 2


def test_events_with_different_processes_create_separate_incidents():
    events = [
        make_event("event-1", 1, "powershell.exe", "4532"),
        make_event("event-2", 2, "cmd.exe", "6000"),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 2


def test_parent_child_relationship_is_preserved():
    events = [
        make_event(
            "event-1",
            1,
            "powershell.exe",
            "4532",
            parent_pid="1200",
        )
    ]

    incidents = correlate_events(events)

    relationship = incidents[0].parent_relationships[0]

    assert relationship["parent_pid"] == "1200"
    assert relationship["child_pid"] == "4532"
    assert relationship["child_process"] == "powershell.exe"


def test_incident_events_are_sorted_by_timestamp():
    events = [
        make_event("event-2", 5, "powershell.exe", "4532"),
        make_event("event-1", 1, "powershell.exe", "4532"),
    ]

    incidents = correlate_events(events)

    assert incidents[0].events[0]["event_id"] == "event-1"
    assert incidents[0].events[1]["event_id"] == "event-2"
    assert incidents[0].duration_seconds == 4
