import os
import subprocess
import sys
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


def _run_command(args, cwd):
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


def test_custody_record_command_creates_event(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Command")
    store.close()

    result = _run_command(
        [
            "custody",
            "record",
            "--database",
            str(database_path),
            "--case",
            "CASE-001",
            "--artifact",
            "reports/case-report.txt",
            "--hash",
            "a" * 64,
            "--action",
            "created",
            "--analyst",
            "analyst@example.com",
            "--note",
            "Initial report generated",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Recorded custody event for case CASE-001" in result.stdout

    store = EvidenceStore(database_path)
    events = store.get_custody_events("CASE-001")
    store.close()

    assert len(events) == 1
    assert events[0]["action"] == "created"
    assert events[0]["analyst"] == "analyst@example.com"


def test_custody_list_command_prints_history(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Command")
    store.record_custody_event(
        case_id="CASE-001",
        artifact_path="reports/case-report.txt",
        sha256="b" * 64,
        action="created",
        analyst="analyst@example.com",
        note="Initial report generated",
        verification_result=None,
    )
    store.close()

    result = _run_command(
        [
            "custody",
            "list",
            "--database",
            str(database_path),
            "--case",
            "CASE-001",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Artifact: reports/case-report.txt" in result.stdout
    assert "Action: created" in result.stdout
    assert "Analyst: analyst@example.com" in result.stdout


def test_custody_record_rejects_invalid_action(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Command")
    store.close()

    result = _run_command(
        [
            "custody",
            "record",
            "--database",
            str(database_path),
            "--case",
            "CASE-001",
            "--artifact",
            "reports/case-report.txt",
            "--hash",
            "a" * 64,
            "--action",
            "deleted",
            "--analyst",
            "analyst@example.com",
            "--note",
            "",
        ],
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "Invalid custody action" in result.stderr


def test_custody_record_rejects_missing_case(tmp_path):
    database_path = tmp_path / "test.db"

    result = _run_command(
        [
            "custody",
            "record",
            "--database",
            str(database_path),
            "--case",
            "CASE-001",
            "--artifact",
            "reports/case-report.txt",
            "--hash",
            "a" * 64,
            "--action",
            "created",
            "--analyst",
            "analyst@example.com",
            "--note",
            "",
        ],
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "Case not found: CASE-001" in result.stderr


def test_custody_record_rejects_invalid_hash(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-001", case_name="Custody Command")
    store.close()

    result = _run_command(
        [
            "custody",
            "record",
            "--database",
            str(database_path),
            "--case",
            "CASE-001",
            "--artifact",
            "reports/case-report.txt",
            "--hash",
            "deadbeef",
            "--action",
            "created",
            "--analyst",
            "analyst@example.com",
            "--note",
            "",
        ],
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "Invalid SHA-256 digest" in result.stderr


def test_export_command(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.create_case(case_id="CASE-CLI-001", case_name="Export CLI Case")
    store.close()

    output_dir = tmp_path / "exports" / "CASE-CLI-001"

    result = _run_command(
        [
            "export",
            "--database",
            str(database_path),
            "--case",
            "CASE-CLI-001",
            "--output",
            str(output_dir),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Exported case package to" in result.stdout
    assert (output_dir / "MANIFEST.sha256").exists()
