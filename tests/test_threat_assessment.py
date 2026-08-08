from ransomeye.threat_assessment import assess_threat


def make_file_events(count=50):
    return [
        {
            "event_id": f"file-{index}",
            "timestamp": f"2026-08-08T15:00:00.{index:03d}Z",
            "source": "simulation",
            "event_type": "file_modify",
            "process_name": "test_process.exe",
            "file_path": f"C:\\Lab\\file{index}.encrypted",
        }
        for index in range(count)
    ]


def test_benign_activity_is_safe():
    events = [
        {
            "event_id": "event-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Get-Date",
            "pid": "1000",
        }
    ]

    result = assess_threat(events)

    assert result["score"] == 0
    assert result["severity"] == "SAFE"
    assert result["finding_count"] == 0


def test_correlated_activity_produces_combined_score():
    events = make_file_events()

    events.extend(
        [
            {
                "event_id": "note-1",
                "timestamp": "2026-08-08T15:00:01Z",
                "source": "simulation",
                "event_type": "file_create",
                "process_name": "test_process.exe",
                "file_path": "C:\\Lab\\README_DECRYPT.txt",
            },
            {
                "event_id": "powershell-1",
                "timestamp": "2026-08-08T15:00:02Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand SGVsbG8="
                ),
                "pid": "4532",
            },
            {
                "event_id": "recovery-1",
                "timestamp": "2026-08-08T15:00:03Z",
                "source": "sysmon",
                "event_type": "process_creation",
                "process_name": "vssadmin.exe",
                "command_line": (
                    "vssadmin delete shadows /all /quiet"
                ),
                "pid": "4533",
            },
        ]
    )

    result = assess_threat(events)

    assert result["score"] == 65
    assert result["severity"] == "MEDIUM"
    assert result["finding_count"] == 2
    assert "T1059.001" in result["techniques"]
    assert "T1490" in result["techniques"]
    assert result["confidence"] > 0
