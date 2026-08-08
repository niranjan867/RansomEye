"""Process and timestamp correlation for RansomEye."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from ransomeye.evidence import EvidenceEvent


@dataclass
class CorrelatedIncident:
    """A group of evidence events associated with one process context."""

    incident_id: str
    process_key: str
    start_time: datetime
    end_time: datetime
    events: list[dict[str, Any]]
    processes: list[dict[str, Any]]
    parent_relationships: list[dict[str, Any]]

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


def _as_dict(event: EvidenceEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, EvidenceEvent):
        return asdict(event)

    if isinstance(event, dict):
        return event

    raise TypeError("Events must be EvidenceEvent objects or dictionaries.")


def _process_key(event: dict[str, Any]) -> str:
    process_guid = event.get("process_guid")
    if process_guid:
        return f"guid:{process_guid}"

    pid = event.get("pid")
    if pid not in (None, ""):
        return f"pid:{pid}"

    process_name = event.get("process_name")
    if process_name:
        return f"name:{process_name.lower()}"

    return f"event:{event.get('event_id', 'unknown')}"


def _process_details(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_name": event.get("process_name"),
        "pid": event.get("pid"),
        "process_guid": event.get("process_guid"),
        "image_path": event.get("image_path"),
        "command_line": event.get("command_line"),
    }


def correlate_events(
    events: list[EvidenceEvent | dict[str, Any]],
) -> list[CorrelatedIncident]:
    """Group evidence events by process identity and time."""
    if not events:
        return []

    normalized_events = [_as_dict(event) for event in events]
    groups: dict[str, list[dict[str, Any]]] = {}

    for event in normalized_events:
        key = _process_key(event)
        groups.setdefault(key, []).append(event)

    incidents: list[CorrelatedIncident] = []

    for index, (process_key, group) in enumerate(groups.items(), start=1):
        ordered_events = sorted(
            group,
            key=lambda event: event["timestamp"],
        )

        processes: list[dict[str, Any]] = []
        seen_processes: set[tuple[Any, Any]] = set()

        parent_relationships: list[dict[str, Any]] = []

        for event in ordered_events:
            process_identity = (
                event.get("process_name"),
                event.get("pid"),
            )

            if process_identity not in seen_processes:
                processes.append(_process_details(event))
                seen_processes.add(process_identity)

            if event.get("parent_pid") not in (None, ""):
                parent_relationships.append(
                    {
                        "parent_pid": event.get("parent_pid"),
                        "child_pid": event.get("pid"),
                        "child_process": event.get("process_name"),
                    }
                )

        incidents.append(
            CorrelatedIncident(
                incident_id=f"INC-{index:04d}",
                process_key=process_key,
                start_time=ordered_events[0]["timestamp"],
                end_time=ordered_events[-1]["timestamp"],
                events=ordered_events,
                processes=processes,
                parent_relationships=parent_relationships,
            )
        )

    return incidents
