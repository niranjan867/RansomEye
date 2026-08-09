"""Ransomware-related behavioral detections."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

SUSPICIOUS_POWERSHELL_SCORE = 10
SUSPICIOUS_CERTUTIL_SCORE = 12
RECOVERY_INHIBITION_SCORE = 15


def _as_dict(event: Any) -> dict[str, Any]:
    if is_dataclass(event):
        return asdict(event)

    if isinstance(event, dict):
        return event

    raise TypeError("Events must be dictionaries or dataclass objects.")


def _text(event: dict[str, Any]) -> str:
    values = [
        event.get("process_name", ""),
        event.get("command_line", ""),
        event.get("image_path", ""),
    ]

    return " ".join(str(value) for value in values).lower()


def detect_suspicious_powershell(
    events: list[Any],
) -> list[dict[str, Any]]:
    """Detect suspicious PowerShell command-line indicators."""
    findings = []

    indicators = (
        "-enc",
        "-encodedcommand",
        "invoke-expression",
        "iex ",
        "downloadstring",
        "frombase64string",
    )

    for event in events:
        item = _as_dict(event)
        process_name = str(item.get("process_name", "")).lower()
        command_line = str(item.get("command_line", "")).lower()

        if "powershell" not in process_name:
            continue

        matched = [
            indicator for indicator in indicators if indicator in command_line
        ]

        if matched:
            event_id = item.get("event_id")
            finding = {
                "type": "suspicious_powershell",
                "score": SUSPICIOUS_POWERSHELL_SCORE,
                "confidence": 0.80,
                "technique": "T1059.001",
                "process_name": item.get("process_name"),
                "pid": item.get("pid"),
                "event_id": event_id,
                "reason": (
                    "Suspicious PowerShell indicators detected: "
                    + ", ".join(matched)
                ),
            }
            if event_id is not None and str(event_id).strip():
                finding["event_ids"] = [str(event_id).strip()]
            findings.append(finding)

    return findings


def detect_suspicious_certutil(
    events: list[Any],
) -> list[dict[str, Any]]:
    """Detect certutil download/decode indicators."""
    findings = []

    indicators = (
        "-urlcache",
        "-split",
        "-f",
        "-decode",
        "-decodehex",
        "-verifyctl",
    )

    for event in events:
        item = _as_dict(event)
        process_name = str(item.get("process_name", "")).lower()
        command_line = str(item.get("command_line", "")).lower()

        if "certutil" not in process_name:
            continue

        matched = [
            indicator for indicator in indicators if indicator in command_line
        ]

        if matched:
            event_id = item.get("event_id")
            finding = {
                "type": "suspicious_certutil",
                "score": SUSPICIOUS_CERTUTIL_SCORE,
                "confidence": 0.80,
                "technique": "T1105",
                "process_name": item.get("process_name"),
                "pid": item.get("pid"),
                "event_id": event_id,
                "reason": (
                    "Suspicious certutil indicators detected: "
                    + ", ".join(matched)
                ),
            }
            if event_id is not None and str(event_id).strip():
                finding["event_ids"] = [str(event_id).strip()]
            findings.append(finding)

    return findings


def detect_recovery_inhibition(
    events: list[Any],
) -> list[dict[str, Any]]:
    """Detect commands associated with recovery destruction."""
    findings = []

    indicators = (
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "delete shadows",
        "wbadmin delete catalog",
        "recoveryenabled no",
    )

    for event in events:
        item = _as_dict(event)
        text = _text(item)

        matched = [indicator for indicator in indicators if indicator in text]

        if matched:
            event_id = item.get("event_id")
            finding = {
                "type": "recovery_inhibition",
                "score": RECOVERY_INHIBITION_SCORE,
                "confidence": 0.85,
                "technique": "T1490",
                "process_name": item.get("process_name"),
                "pid": item.get("pid"),
                "event_id": event_id,
                "reason": (
                    "Recovery-inhibition indicator detected: "
                    + ", ".join(matched)
                ),
            }
            if event_id is not None and str(event_id).strip():
                finding["event_ids"] = [str(event_id).strip()]
            findings.append(finding)

    return findings


def analyze_behavior(events: list[Any]) -> list[dict[str, Any]]:
    """Run all currently implemented behavior rules."""
    findings = []

    findings.extend(detect_suspicious_powershell(events))
    findings.extend(detect_suspicious_certutil(events))
    findings.extend(detect_recovery_inhibition(events))

    return findings
