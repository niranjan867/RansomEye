import pytest
from ransomeye.sysmon_reader import parse_process_creation_event, parse_sysmon_event
from ransomeye.evidence import normalize_event

import os

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples", "sysmon")

SAMPLE_EVENT = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-08-08T14:20:00.000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{ABC-123}</Data>
    <Data Name="ProcessId">4532</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentProcessId">1200</Data>
    <Data Name="User">LAB\\Student</Data>
    <Data Name="Hashes">SHA256=TESTHASH</Data>
  </EventData>
</Event>
"""


def test_parse_process_creation_event():
    event = parse_process_creation_event(SAMPLE_EVENT)

    assert event["source"] == "sysmon"
    assert event["event_type"] == "process_creation"
    assert event["process_name"] == "powershell.exe"
    assert event["pid"] == "4532"
    assert event["parent_pid"] == "1200"
    assert event["process_guid"] == "{ABC-123}"
    assert event["user"] == "LAB\\Student"


def test_parse_rejects_non_process_event():
    event = SAMPLE_EVENT.replace("<EventID>1</EventID>", "<EventID>3</EventID>")

    try:
        parse_process_creation_event(event)
    except ValueError as error:
        assert "Expected Sysmon Event ID 1" in str(error)
    else:
        raise AssertionError("Expected ValueError")


def test_process_name_is_extracted_from_full_path():
    event = parse_process_creation_event(SAMPLE_EVENT)

    assert event["process_name"] == "powershell.exe"
    assert event["image_path"].endswith("powershell.exe")


def test_access_denied_message_is_friendly(monkeypatch):
    import subprocess
    from ransomeye import sysmon_reader

    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "Access is denied.\n\nFailed to open event query.\nAccess is denied."

    def fake_run(*args, **kwargs):
        return FakeResult()

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        sysmon_reader.read_process_creation_events(5)
    except sysmon_reader.SysmonReaderError as error:
        assert "Administrator permission is required" in str(error)
    else:
        raise AssertionError("Expected SysmonReaderError")


# --- New Milestone 16 tests below ---

def test_parse_sysmon_event_all_supported_ids():
    event_ids = [1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 22, 23, 25]

    for eid in event_ids:
        # construct filename
        filename = ""
        for f in os.listdir(SAMPLES_DIR):
            if f.startswith(f"event_{eid:02d}_"):
                filename = f
                break

        assert filename, f"Missing fixture for Event ID {eid}"

        with open(os.path.join(SAMPLES_DIR, filename), "r") as f:
            xml_text = f.read()

        parsed = parse_sysmon_event(xml_text)
        assert parsed is not None, f"Failed to parse Event ID {eid}"
        assert parsed["metadata"]["sysmon_event_id"] == str(eid)

        # Verify it can be normalized by EvidenceEvent
        norm = normalize_event(parsed)
        assert norm.event_id is not None
        assert norm.timestamp is not None
        assert norm.event_type is not None

def test_unknown_event_id_handling():
    event = SAMPLE_EVENT.replace("<EventID>1</EventID>", "<EventID>999</EventID>")
    parsed = parse_sysmon_event(event)
    assert parsed is None

def test_malformed_xml():
    assert parse_sysmon_event("<<not_xml") is None

def test_missing_event_id():
    event = SAMPLE_EVENT.replace("<EventID>1</EventID>", "")
    assert parse_sysmon_event(event) is None

def test_metadata_preservation():
    event = SAMPLE_EVENT.replace("<Data Name=\"Hashes\">SHA256=TESTHASH</Data>",
                                 "<Data Name=\"Hashes\">SHA256=TESTHASH</Data><Data Name=\"TerminalSessionId\">1</Data>")
    parsed = parse_sysmon_event(event)
    assert parsed["metadata"]["TerminalSessionId"] == "1"

def test_network_normalization():
    with open(os.path.join(SAMPLES_DIR, "event_03_network_connect.xml"), "r") as f:
        xml_text = f.read()

    parsed = parse_sysmon_event(xml_text)
    assert parsed["event_type"] == "network_connect"
    assert parsed["network"]["destination_ip"] == "8.8.8.8"
    assert parsed["network"]["destination_port"] == "443"
    assert parsed["network"]["protocol"] == "tcp"

def test_dns_normalization():
    with open(os.path.join(SAMPLES_DIR, "event_22_dns_query.xml"), "r") as f:
        xml_text = f.read()

    parsed = parse_sysmon_event(xml_text)
    assert parsed["event_type"] == "dns_query"
    assert parsed["network"]["query_name"] == "malicious.com"
    assert parsed["network"]["query_results"] == "192.168.1.50"

def test_registry_normalization():
    with open(os.path.join(SAMPLES_DIR, "event_12_registry_create.xml"), "r") as f:
        xml_text = f.read()
    parsed = parse_sysmon_event(xml_text)
    assert parsed["event_type"] == "registry_create"
    assert "HKLM" in parsed["registry_path"]