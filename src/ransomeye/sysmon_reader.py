from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class SysmonReaderError(RuntimeError):
    """Raised when Sysmon events cannot be read."""


def _local_name(tag: str) -> str:
    """Remove the XML namespace from an element name."""
    return tag.rsplit("}", 1)[-1]


def _event_data(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)
    values: dict[str, str] = {}

    for element in root.iter():
        if _local_name(element.tag) == "Data":
            name = element.attrib.get("Name")
            if name:
                values[name] = element.text or ""

    return values


def parse_process_creation_event(xml_text: str) -> dict[str, Any]:
    """Convert one Sysmon Event ID 1 XML event to normalized evidence."""
    root = ET.fromstring(xml_text)

    event_id = None
    timestamp = None

    for element in root.iter():
        name = _local_name(element.tag)

        if name == "EventID":
            event_id = element.text

        if name == "TimeCreated":
            timestamp = element.attrib.get("SystemTime")

    if event_id != "1":
        raise ValueError(f"Expected Sysmon Event ID 1, received {event_id}")

    data = _event_data(xml_text)

    return {
        "event_id": f"sysmon-1-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}",
        "timestamp": timestamp,
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": data.get("Image", "").split("\\")[-1],
        "pid": data.get("ProcessId", ""),
        "parent_pid": data.get("ParentProcessId", ""),
        "process_guid": data.get("ProcessGuid", ""),
        "command_line": data.get("CommandLine", ""),
        "image_path": data.get("Image", ""),
        "parent_image": data.get("ParentImage", ""),
        "hashes": data.get("Hashes", ""),
        "user": data.get("User", ""),
        "metadata": {
            "rule": "Sysmon Event ID 1",
        },
    }


def sysmon_is_available() -> bool:
    """Return True if the Sysmon event channel is available."""
    if sys.platform != "win32":
        return False

    result = subprocess.run(
        ["wevtutil.exe", "gl", SYSMON_CHANNEL],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.returncode == 0


def read_process_creation_events(limit: int = 20) -> list[dict[str, Any]]:
    """Read recent Sysmon process-creation events without changing the system."""
    if sys.platform != "win32":
        raise SysmonReaderError(
            "Sysmon event reading is available only on Windows."
        )

    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")

    query = "*[System[(EventID=1)]]"

    result = subprocess.run(
        [
            "wevtutil.exe",
            "qe",
            SYSMON_CHANNEL,
            f"/q:{query}",
            "/f:xml",
            f"/c:{limit}",
            "/rd:true",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        message = result.stderr.strip() or "Sysmon event channel could not be read."
        raise SysmonReaderError(message)

    events: list[dict[str, Any]] = []

    for xml_text in result.stdout.split("</Event>"):
        xml_text = xml_text.strip()

        if not xml_text:
            continue

        xml_text += "</Event>"

        try:
            events.append(parse_process_creation_event(xml_text))
        except (ET.ParseError, ValueError):
            continue

    return events