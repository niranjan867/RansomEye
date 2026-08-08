from pathlib import Path

from ransomeye.commands import print_case_timeline, print_case_tree
from ransomeye.storage import EvidenceStore


def test_print_case_timeline_renders_expected_columns(capsys, tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="RE-LIVE-001", case_name="Timeline View", host="LAPTOP-AKCCFV29")
    store.save_event(
        "RE-LIVE-001",
        {
            "event_id": "event-1",
            "timestamp": "2026-08-08T21:48:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "100",
            "process_guid": "guid-1",
            "parent_process_guid": "guid-parent",
            "parent_image": r"C:\Windows\explorer.exe",
            "command_line": "powershell.exe -NoProfile",
        },
    )
    store.save_event(
        "RE-LIVE-001",
        {
            "event_id": "event-2",
            "timestamp": "2026-08-08T21:48:02Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "conhost.exe",
            "pid": "200",
            "process_guid": "guid-2",
            "parent_process_guid": "guid-1",
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_pid": "100",
            "command_line": "conhost.exe",
        },
    )
    store.close()

    print_case_timeline(database_path, "RE-LIVE-001")
    output = capsys.readouterr().out

    assert "Case: RE-LIVE-001" in output
    assert "Host: LAPTOP-AKCCFV29" in output
    assert "powershell.exe" in output
    assert "conhost.exe" in output
    assert "explorer.exe" in output


def test_print_case_tree_renders_root_and_children(capsys, tmp_path):
    database_path = tmp_path / "ransomeye.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="RE-TREE-001", case_name="Tree View", host="LAPTOP-AKCCFV29")
    store.save_event(
        "RE-TREE-001",
        {
            "event_id": "event-1",
            "timestamp": "2026-08-08T21:48:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "100",
            "command_line": "powershell.exe -NoProfile",
        },
    )
    store.save_event(
        "RE-TREE-001",
        {
            "event_id": "event-2",
            "timestamp": "2026-08-08T21:48:02Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "conhost.exe",
            "pid": "200",
            "parent_pid": "100",
            "command_line": "conhost.exe",
        },
    )
    store.close()

    print_case_tree(database_path, "RE-TREE-001")
    output = capsys.readouterr().out

    assert "Case: RE-TREE-001" in output
    assert "powershell.exe [PID 100]" in output
    assert "conhost.exe [PID 200]" in output
    assert "└──" in output
