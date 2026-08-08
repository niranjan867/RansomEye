from ransomeye.sysmon_reader import parse_process_creation_event


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