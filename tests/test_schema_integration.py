from datetime import datetime, timezone

from ransomeye.evidence import EvidenceEvent
from ransomeye.rules import analyze_events


def test_process_event_preserves_sysmon_fields():
    event = EvidenceEvent.from_dict(
        {
            "event_id": "sysmon-1-test",
            "timestamp": datetime.now(timezone.utc),
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "4532",
            "parent_pid": "1200",
            "process_guid": "{ABC-123}",
            "command_line": "powershell.exe -NoProfile",
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
            "hashes": "SHA256=TESTHASH",
        }
    )

    assert event.process_name == "powershell.exe"
    assert event.image_path.endswith("powershell.exe")
    assert event.parent_image.endswith("explorer.exe")
    assert event.hashes == "SHA256=TESTHASH"


def test_rules_accept_evidence_events():
    events = []

    for index in range(50):
        events.append(
            EvidenceEvent.from_dict(
                {
                    "event_id": f"file-{index}",
                    "timestamp": datetime(
                        2026,
                        8,
                        8,
                        15,
                        0,
                        0,
                        index * 1000,
                        tzinfo=timezone.utc,
                    ),
                    "source": "simulation",
                    "event_type": "file_modify",
                    "process_name": "test_process.exe",
                    "file_path": f"C:\\Lab\\file{index}.txt",
                }
            )
        )

    result = analyze_events(events)

    assert result["score"] == 20
    assert result["severity"] == "SAFE"
    assert "Mass file modification detected" in result["reasons"][0]
