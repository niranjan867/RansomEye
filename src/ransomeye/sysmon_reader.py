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


def parse_sysmon_event(xml_text: str) -> dict[str, Any] | None:
    """Generic parser for Sysmon XML events."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    event_id = None
    timestamp = None
    provider = None
    computer = None
    channel = None
    schema_version = None

    for element in root.iter():
        name = _local_name(element.tag)
        if name == "EventID":
            event_id = element.text
        elif name == "TimeCreated":
            timestamp = element.attrib.get("SystemTime")
        elif name == "Provider":
            provider = element.attrib.get("Name")
        elif name == "Computer":
            computer = element.text
        elif name == "Channel":
            channel = element.text
        elif name == "Version":
            schema_version = element.text

    if not event_id:
        return None

    data = _event_data(xml_text)

    # Core normalization
    result: dict[str, Any] = {
        "source": "sysmon",
        "timestamp": timestamp,
        "metadata": {
            "sysmon_event_id": event_id,
        },
    }

    if provider:
        result["metadata"]["provider"] = provider
    if computer:
        result["metadata"]["computer"] = computer
    if channel:
        result["metadata"]["channel"] = channel
    if schema_version:
        result["metadata"]["schema_version"] = schema_version

    # Map remaining unknown fields to metadata
    for k, v in data.items():
        result["metadata"][k] = v

    # Generic process identity where available
    if "ProcessGuid" in data:
        result["process_guid"] = data["ProcessGuid"]
    if "ProcessId" in data:
        result["pid"] = data["ProcessId"]
    if "Image" in data:
        result["image_path"] = data["Image"]
        result["process_name"] = data["Image"].split("\\")[-1]
    if "User" in data:
        result["user"] = data["User"]

    # Dispatch by Event ID
    if event_id == "1":
        result["event_type"] = "process_creation"
        result["command_line"] = data.get("CommandLine", "")
        if "ParentProcessId" in data:
            result["parent_pid"] = data["ParentProcessId"]
        if "ParentProcessGuid" in data:
            result["parent_process_guid"] = data["ParentProcessGuid"]
        if "ParentImage" in data:
            result["parent_image"] = data["ParentImage"]
        if "Hashes" in data:
            result["hashes"] = data["Hashes"]

        proc_ident = data.get("ProcessGuid", data.get("ProcessId", "unknown"))
        result["event_id"] = f"sysmon-1-{proc_ident}"

    elif event_id == "2":
        result["event_type"] = "file_time_changed"
        result["file_path"] = data.get("TargetFilename", "")
        result["metadata"]["sysmon_event_name"] = "File creation time changed"
        result["event_id"] = f"sysmon-2-{data.get('TargetFilename', 'unknown')}"

    elif event_id == "3":
        result["event_type"] = "network_connect"
        result["metadata"]["sysmon_event_name"] = "Network Connection"
        result["event_id"] = f"sysmon-3-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

        network_data = {}
        if "DestinationIp" in data:
            network_data["destination_ip"] = data["DestinationIp"]
        if "DestinationPort" in data:
            network_data["destination_port"] = data["DestinationPort"]
        if "SourceIp" in data:
            network_data["source_ip"] = data["SourceIp"]
        if "SourcePort" in data:
            network_data["source_port"] = data["SourcePort"]
        if "DestinationHostname" in data:
            network_data["destination_hostname"] = data["DestinationHostname"]
        if "Protocol" in data:
            network_data["protocol"] = data["Protocol"]

        if network_data:
            result["network"] = network_data

    elif event_id == "5":
        result["event_type"] = "process_terminate"
        result["metadata"]["sysmon_event_name"] = "Process Terminated"
        result["event_id"] = f"sysmon-5-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    elif event_id == "6":
        result["event_type"] = "driver_loaded"
        result["metadata"]["sysmon_event_name"] = "Driver Loaded"
        result["file_path"] = data.get("ImageLoaded", "")
        if "Hashes" in data:
            result["hashes"] = data["Hashes"]
        result["event_id"] = f"sysmon-6-{data.get('ImageLoaded', 'unknown')}"

    elif event_id == "7":
        result["event_type"] = "image_loaded"
        result["metadata"]["sysmon_event_name"] = "Image Loaded"
        result["file_path"] = data.get("ImageLoaded", "")
        if "Hashes" in data:
            result["hashes"] = data["Hashes"]
        result["event_id"] = f"sysmon-7-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    elif event_id == "8":
        result["event_type"] = "remote_thread"
        result["metadata"]["sysmon_event_name"] = "CreateRemoteThread"
        # For Event 8, Image is the SourceImage, TargetImage is the target
        if "TargetImage" in data:
            result["metadata"]["TargetImage"] = data["TargetImage"]
        result["event_id"] = f"sysmon-8-{data.get('SourceProcessGuid', data.get('SourceProcessId', 'unknown'))}"

    elif event_id == "10":
        result["event_type"] = "process_access"
        result["metadata"]["sysmon_event_name"] = "Process Access"
        result["event_id"] = f"sysmon-10-{data.get('SourceProcessGuid', data.get('SourceProcessId', 'unknown'))}"

    elif event_id == "11":
        result["event_type"] = "file_create"
        result["metadata"]["sysmon_event_name"] = "File Created"
        result["file_path"] = data.get("TargetFilename", "")
        result["event_id"] = f"sysmon-11-{data.get('TargetFilename', 'unknown')}"

    elif event_id == "12":
        # Registry Create/Delete
        ev_type = data.get("EventType", "")
        if ev_type == "CreateKey":
            result["event_type"] = "registry_create"
        elif ev_type == "DeleteKey":
            result["event_type"] = "registry_delete"
        elif ev_type == "DeleteValue":
            result["event_type"] = "registry_delete"
        else:
            result["event_type"] = "registry_create" # fallback

        result["metadata"]["sysmon_event_name"] = "Registry Event - Create/Delete"
        if "TargetObject" in data:
            result["registry_path"] = data["TargetObject"]
        result["event_id"] = f"sysmon-12-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    elif event_id == "13":
        result["event_type"] = "registry_value_set"
        result["metadata"]["sysmon_event_name"] = "Registry Event - Value Set"
        if "TargetObject" in data:
            result["registry_path"] = data["TargetObject"]
        if "Details" in data:
            result["registry_value"] = data["Details"]
        result["event_id"] = f"sysmon-13-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    elif event_id == "14":
        result["event_type"] = "registry_rename"
        result["metadata"]["sysmon_event_name"] = "Registry Event - Key/Value Rename"
        if "TargetObject" in data:
            result["registry_path"] = data["TargetObject"]
        if "NewName" in data:
            result["metadata"]["NewName"] = data["NewName"]
        result["event_id"] = f"sysmon-14-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    elif event_id == "15":
        result["event_type"] = "file_stream_hash"
        result["metadata"]["sysmon_event_name"] = "FileCreateStreamHash"
        result["file_path"] = data.get("TargetFilename", "")
        if "Hashes" in data:
            result["hashes"] = data["Hashes"]
        result["event_id"] = f"sysmon-15-{data.get('TargetFilename', 'unknown')}"

    elif event_id == "22":
        result["event_type"] = "dns_query"
        result["metadata"]["sysmon_event_name"] = "DNS Query"
        result["event_id"] = f"sysmon-22-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

        network_data = {}
        if "QueryName" in data:
            network_data["query_name"] = data["QueryName"]
        if "QueryStatus" in data:
            network_data["query_status"] = data["QueryStatus"]
        if "QueryResults" in data:
            network_data["query_results"] = data["QueryResults"]
        if network_data:
            result["network"] = network_data

    elif event_id == "23":
        result["event_type"] = "file_delete"
        result["metadata"]["sysmon_event_name"] = "File Delete"
        result["file_path"] = data.get("TargetFilename", "")
        result["event_id"] = f"sysmon-23-{data.get('TargetFilename', 'unknown')}"

    elif event_id == "25":
        result["event_type"] = "process_tampering"
        result["metadata"]["sysmon_event_name"] = "Process Tampering"
        result["event_id"] = f"sysmon-25-{data.get('ProcessGuid', data.get('ProcessId', 'unknown'))}"

    else:
        # Unknown or explicitly skipped
        return None

    return result


def parse_process_creation_event(xml_text: str) -> dict[str, Any]:
    """Compatibility wrapper for Sysmon Event ID 1 XML event parsing."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise ValueError("Invalid XML")

    event_id = None
    for element in root.iter():
        name = _local_name(element.tag)
        if name == "EventID":
            event_id = element.text
            break

    if event_id != "1":
        raise ValueError(f"Expected Sysmon Event ID 1, received {event_id}")

    parsed = parse_sysmon_event(xml_text)
    if not parsed:
        raise ValueError("Failed to parse Event ID 1")
    return parsed


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


def read_sysmon_events(limit: int = 100, event_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """Generic reader for Sysmon events."""
    if sys.platform != "win32":
        raise SysmonReaderError(
            "Sysmon event reading is available only on Windows."
        )

    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")

    if event_ids:
        ids_str = " or ".join(f"EventID={eid}" for eid in event_ids)
        query = f"*[System[({ids_str})]]"
    else:
        query = "*"

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
        stderr = result.stderr.strip().lower()

        if "access is denied" in stderr:
            raise SysmonReaderError(
                "Administrator permission is required to read Sysmon events. "
                "Restart RansomEye as an administrator and try again."
            )

        message = result.stderr.strip() or "Sysmon event channel could not be read."
        raise SysmonReaderError(message)

    events: list[dict[str, Any]] = []

    for xml_text in result.stdout.split("</Event>"):
        xml_text = xml_text.strip()

        if not xml_text:
            continue

        xml_text += "</Event>"

        parsed = parse_sysmon_event(xml_text)
        if parsed is not None:
            events.append(parsed)

    return events


def read_process_creation_events(limit: int = 20) -> list[dict[str, Any]]:
    """Compatibility wrapper to read recent Sysmon process-creation events."""
    return read_sysmon_events(limit=limit, event_ids=[1])