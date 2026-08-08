from datetime import datetime, timezone

from ransomeye.storage import EvidenceStore
from ransomeye.timeline import build_process_tree, get_case_timeline


def _write_event(store: EvidenceStore, case_id: str, event_id: str, timestamp: str, process_guid: str | None = None, parent_process_guid: str | None = None, parent_image: str | None = None):
    store.save_event(
        case_id,
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1234",
            "process_guid": process_guid,
            "parent_process_guid": parent_process_guid,
            "parent_image": parent_image,
            "command_line": "powershell.exe -NoProfile",
        },
    )


def test_events_are_returned_in_chronological_order(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-1", case_name="Timeline Test")

    _write_event(store, "CASE-1", "event-2", "2026-08-08T15:00:02Z", "guid-2", "guid-1")
    _write_event(store, "CASE-1", "event-1", "2026-08-08T15:00:01Z", "guid-1")

    timeline = get_case_timeline(database_path, "CASE-1")

    assert [item["event_id"] for item in timeline] == ["event-1", "event-2"]
    store.close()


def test_events_are_filtered_by_case_id(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-1", case_name="Timeline Test")
    store.create_case(case_id="CASE-2", case_name="Timeline Test")

    _write_event(store, "CASE-1", "event-a", "2026-08-08T15:00:01Z", "guid-a")
    _write_event(store, "CASE-2", "event-b", "2026-08-08T15:00:02Z", "guid-b")

    timeline = get_case_timeline(database_path, "CASE-1")

    assert [item["event_id"] for item in timeline] == ["event-a"]
    store.close()


def test_parent_child_relationships_use_process_guids():
    events = [
        {
            "pid": "100",
            "parent_pid": "50",
            "process_name": "powershell.exe",
        },
        {
            "pid": "200",
            "parent_pid": "100",
            "process_name": "conhost.exe",
        },
    ]

    tree = build_process_tree(events)

    assert tree["roots"] == ["100"]
    assert tree["children"]["100"] == ["200"]


def test_missing_parent_processes_do_not_crash_tree_builder():
    tree = build_process_tree([
        {"pid": "200", "parent_pid": "999", "process_name": "wevtutil.exe"},
        {"pid": "300", "parent_pid": None, "process_name": "cmd.exe"},
    ])

    assert tree["roots"] == ["200", "300"]
    assert tree["children"] == {}


def test_empty_cases_return_empty_timeline_and_tree(tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-EMPTY", case_name="Empty")
    store.close()

    timeline = get_case_timeline(database_path, "CASE-EMPTY")
    tree = build_process_tree([])

    assert timeline == []
    assert tree["nodes"] == {}
    assert tree["children"] == {}
    assert tree["roots"] == []


def test_build_process_tree_links_parent_and_child():
    events = [
        {
            "pid": "100",
            "parent_pid": "50",
            "process_name": "powershell.exe",
            "timestamp": "2026-08-08T21:48:01Z",
        },
        {
            "pid": "200",
            "parent_pid": "100",
            "process_name": "conhost.exe",
            "timestamp": "2026-08-08T21:48:02Z",
        },
    ]

    tree = build_process_tree(events)

    assert tree["roots"] == ["100"]
    assert tree["children"]["100"] == ["200"]
    assert tree["nodes"]["200"]["process_name"] == "conhost.exe"


def test_build_process_tree_handles_missing_parent():
    events = [
        {
            "pid": "200",
            "parent_pid": "999",
            "process_name": "wevtutil.exe",
        }
    ]

    tree = build_process_tree(events)

    assert tree["roots"] == ["200"]
    assert tree["children"] == {}
