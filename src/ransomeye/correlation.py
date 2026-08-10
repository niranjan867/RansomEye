"""Cross-behavior correlation engine for RansomEye."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from ransomeye.evidence import EvidenceEvent

CORRELATION_WINDOW_SECONDS: float = 60.0


def _parse_dt(ts: datetime | str | None) -> datetime | None:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class CorrelatedIncident:
    """A deterministic, evidence-backed security incident."""

    incident_id: str
    case_id: str | None = None
    finding_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    process_ids: tuple[str, ...] = ()
    start_time: datetime | None = None
    end_time: datetime | None = None
    correlation_reasons: tuple[str, ...] = ()

    # Backward compatibility attributes
    events: tuple[dict[str, Any], ...] = ()
    processes: tuple[dict[str, Any], ...] = ()
    parent_relationships: tuple[dict[str, Any], ...] = ()
    process_key: str = ""

    @property
    def duration_seconds(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        start = _parse_dt(self.start_time)
        end = _parse_dt(self.end_time)
        if start is None or end is None:
            return 0.0
        return (end - start).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "case_id": self.case_id,
            "finding_ids": list(self.finding_ids),
            "evidence_ids": list(self.evidence_ids),
            "process_ids": list(self.process_ids),
            "start_time": (
                self.start_time.isoformat()
                if isinstance(self.start_time, datetime)
                else (str(self.start_time) if self.start_time else None)
            ),
            "end_time": (
                self.end_time.isoformat()
                if isinstance(self.end_time, datetime)
                else (str(self.end_time) if self.end_time else None)
            ),
            "correlation_reasons": list(self.correlation_reasons),
            "events": [dict(e) for e in self.events],
            "processes": [dict(p) for p in self.processes],
            "parent_relationships": [dict(r) for r in self.parent_relationships],
            "process_key": self.process_key,
        }


def _as_dict(event: EvidenceEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, EvidenceEvent):
        return asdict(event)
    if isinstance(event, dict):
        return event
    raise TypeError("Events must be EvidenceEvent objects or dictionaries.")


def generate_incident_id(
    case_id: str | None,
    finding_ids: tuple[str, ...] | list[str],
    evidence_ids: tuple[str, ...] | list[str],
    process_ids: tuple[str, ...] | list[str],
    start_time: datetime | str | None,
    end_time: datetime | str | None,
) -> str:
    """Generate a deterministic incident ID from a canonical sorted payload."""
    start_str = (
        start_time.isoformat()
        if isinstance(start_time, datetime)
        else (str(start_time) if start_time is not None else "")
    )
    end_str = (
        end_time.isoformat()
        if isinstance(end_time, datetime)
        else (str(end_time) if end_time is not None else "")
    )

    payload = {
        "case_id": case_id or "",
        "evidence_ids": sorted(list(set(evidence_ids))),
        "finding_ids": sorted(list(set(finding_ids))),
        "process_ids": sorted(list(set(process_ids))),
        "start_time": start_str,
        "end_time": end_str,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
    return f"INC-{digest}"


def _get_proc_info(ev: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    guid = ev.get("process_guid")
    pid = str(ev.get("pid")) if ev.get("pid") not in (None, "") else None
    name = ev.get("process_name")
    return guid, pid, name


def _compute_time_delta(
    times_a: list[datetime], times_b: list[datetime]
) -> float | None:
    """Compute the minimum pairwise time delta in seconds between two sets of timestamps."""
    if not times_a or not times_b:
        return None
    min_delta = float("inf")
    for ta in times_a:
        for tb in times_b:
            delta = abs((ta - tb).total_seconds())
            if delta < min_delta:
                min_delta = delta
    return min_delta if min_delta != float("inf") else None


def correlate_findings(
    findings: list[dict[str, Any]],
    evidence: list[EvidenceEvent | dict[str, Any]],
    processes: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> list[CorrelatedIncident]:
    """Correlate findings and evidence into deterministic, evidence-backed incidents."""
    if not findings and not evidence:
        return []

    # Normalize evidence
    normalized_evidence = [_as_dict(e) for e in evidence]
    evidence_by_id: dict[str, dict[str, Any]] = {}
    for ev in normalized_evidence:
        eid = ev.get("event_id")
        if eid:
            evidence_by_id[str(eid)] = ev

    # If findings are provided, treat each finding as a clustering node.
    # If no findings are provided (e.g. raw evidence only), synthesize one finding per event.
    node_findings: list[dict[str, Any]] = []
    if findings:
        for idx, f in enumerate(findings):
            fid = f.get("finding_id") or f.get("id") or f"finding-{idx+1}"
            raw_eids = f.get("event_ids") or []
            if not raw_eids and f.get("event_id"):
                raw_eids = [f["event_id"]]
            eids = [str(x) for x in raw_eids]
            case_id = f.get("case_id")
            node_findings.append({
                "finding_id": str(fid),
                "event_ids": eids,
                "case_id": case_id,
                "raw_finding": f,
            })
    else:
        for idx, ev in enumerate(normalized_evidence):
            eid = str(ev.get("event_id", f"ev-{idx+1}"))
            node_findings.append({
                "finding_id": f"finding-{eid}",
                "event_ids": [eid],
                "case_id": ev.get("case_id"),
                "raw_finding": ev,
            })

    n = len(node_findings)
    if n == 0:
        return []

    # Extract metadata per node
    node_guids: list[set[str]] = []
    node_pids: list[set[str]] = []
    node_parent_guids: list[set[str]] = []
    node_parent_pids: list[set[str]] = []
    node_timestamps: list[list[datetime]] = []
    node_case_ids: list[str | None] = []

    for nf in node_findings:
        guids: set[str] = set()
        pids: set[str] = set()
        parent_guids: set[str] = set()
        parent_pids: set[str] = set()
        timestamps: list[datetime] = []
        case_id = nf.get("case_id")

        for eid in nf["event_ids"]:
            ev = evidence_by_id.get(eid)
            if ev:
                if not case_id and ev.get("case_id"):
                    case_id = ev.get("case_id")
                guid, pid, _ = _get_proc_info(ev)
                if guid:
                    guids.add(guid)
                if pid:
                    pids.add(pid)
                pguid = ev.get("parent_process_guid")
                if pguid:
                    parent_guids.add(pguid)
                ppid = ev.get("parent_pid")
                if ppid not in (None, ""):
                    parent_pids.add(str(ppid))
                dt = _parse_dt(ev.get("timestamp"))
                if dt is not None:
                    timestamps.append(dt)

        node_guids.append(guids)
        node_pids.append(pids)
        node_parent_guids.append(parent_guids)
        node_parent_pids.append(parent_pids)
        node_timestamps.append(timestamps)
        node_case_ids.append(case_id)

    # Process creation relations from all evidence and processes parameter
    spawn_relations: list[tuple[str | None, str | None, str | None, str | None, datetime | None]] = []
    for ev in normalized_evidence:
        if ev.get("event_type") in ("process_creation", "process_create"):
            p_guid = ev.get("parent_process_guid")
            p_pid = str(ev.get("parent_pid")) if ev.get("parent_pid") not in (None, "") else None
            c_guid = ev.get("process_guid")
            c_pid = str(ev.get("pid")) if ev.get("pid") not in (None, "") else None
            t_spawn = _parse_dt(ev.get("timestamp"))
            spawn_relations.append((p_guid, p_pid, c_guid, c_pid, t_spawn))

    if isinstance(processes, list):
        for proc in processes:
            p_guid = proc.get("parent_process_guid")
            p_pid = str(proc.get("parent_pid")) if proc.get("parent_pid") not in (None, "") else None
            c_guid = proc.get("process_guid")
            c_pid = str(proc.get("pid")) if proc.get("pid") not in (None, "") else None
            t_spawn = _parse_dt(proc.get("start_time") or proc.get("timestamp"))
            spawn_relations.append((p_guid, p_pid, c_guid, c_pid, t_spawn))

    # Disjoint Set Union (Union-Find)
    parent_map = list(range(n))
    component_reasons: dict[int, set[str]] = {i: set() for i in range(n)}

    def find(i: int) -> int:
        if parent_map[i] == i:
            return i
        parent_map[i] = find(parent_map[i])
        return parent_map[i]

    def union(i: int, j: int, reason: str) -> None:
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent_map[root_i] = root_j
            component_reasons[root_j].update(component_reasons[root_i])
            component_reasons[root_j].add(reason)
        else:
            component_reasons[root_i].add(reason)

    # Check pairwise relationships
    for i in range(n):
        for j in range(i + 1, n):
            eids_i = set(node_findings[i]["event_ids"])
            eids_j = set(node_findings[j]["event_ids"])

            # Rule 4: Shared evidence
            if eids_i and eids_j and (eids_i & eids_j):
                union(i, j, "shared_evidence")
                continue

            # Rule 1: Same ProcessGuid
            if node_guids[i] and node_guids[j] and (node_guids[i] & node_guids[j]):
                union(i, j, "same_process_guid")
                continue

            # Rule 2: Controlled PID fallback within temporal window (only when ProcessGuid unavailable)
            if not node_guids[i] and not node_guids[j] and (node_pids[i] & node_pids[j]):
                delta = _compute_time_delta(node_timestamps[i], node_timestamps[j])
                if delta is not None and 0.0 <= delta <= CORRELATION_WINDOW_SECONDS:
                    union(i, j, "pid_fallback_within_window")
                    continue

            # Rule 3: Parent/Child ancestry within temporal window
            is_parent_child = False

            # Check direct evidence parent annotations
            # i is parent of j
            if (
                (node_guids[i] and node_parent_guids[j] and (node_guids[i] & node_parent_guids[j]))
                or (not node_guids[i] and not node_parent_guids[j] and node_pids[i] and node_parent_pids[j] and (node_pids[i] & node_parent_pids[j]))
            ):
                is_parent_child = True

            # j is parent of i
            if (
                (node_guids[j] and node_parent_guids[i] and (node_guids[j] & node_parent_guids[i]))
                or (not node_guids[j] and not node_parent_guids[i] and node_pids[j] and node_parent_pids[i] and (node_pids[j] & node_parent_pids[i]))
            ):
                is_parent_child = True

            # Check spawn relations table
            if not is_parent_child:
                for p_guid, p_pid, c_guid, c_pid, _ in spawn_relations:
                    parent_match_i = (p_guid and p_guid in node_guids[i]) or (not p_guid and p_pid and p_pid in node_pids[i])
                    child_match_j = (c_guid and c_guid in node_guids[j]) or (not c_guid and c_pid and c_pid in node_pids[j])
                    if parent_match_i and child_match_j:
                        is_parent_child = True
                        break

                    parent_match_j = (p_guid and p_guid in node_guids[j]) or (not p_guid and p_pid and p_pid in node_pids[j])
                    child_match_i = (c_guid and c_guid in node_guids[i]) or (not c_guid and c_pid and c_pid in node_pids[i])
                    if parent_match_j and child_match_i:
                        is_parent_child = True
                        break

            if is_parent_child:
                delta = _compute_time_delta(node_timestamps[i], node_timestamps[j])
                if delta is not None and 0.0 <= delta <= CORRELATION_WINDOW_SECONDS:
                    union(i, j, "parent_child_within_window")
                    continue

    # Group nodes by root component
    clusters: dict[int, list[int]] = {}
    for idx in range(n):
        r = find(idx)
        clusters.setdefault(r, []).append(idx)

    incidents: list[CorrelatedIncident] = []

    for root, node_indices in clusters.items():
        comp_finding_ids: list[str] = []
        comp_evidence_ids_set: set[str] = set()
        comp_case_id: str | None = None

        for idx in node_indices:
            comp_finding_ids.append(node_findings[idx]["finding_id"])
            comp_evidence_ids_set.update(node_findings[idx]["event_ids"])
            if not comp_case_id and node_case_ids[idx]:
                comp_case_id = node_case_ids[idx]

        sorted_finding_ids = tuple(sorted(list(set(comp_finding_ids))))
        sorted_evidence_ids = tuple(sorted(list(comp_evidence_ids_set)))

        # Gather and order all evidence events
        events_list: list[dict[str, Any]] = []
        for eid in sorted_evidence_ids:
            if eid in evidence_by_id:
                events_list.append(evidence_by_id[eid])

        def _ev_sort_key(ev: dict[str, Any]) -> datetime:
            dt = _parse_dt(ev.get("timestamp"))
            return dt if dt is not None else datetime.min.replace(tzinfo=timezone.utc)

        ordered_events = sorted(events_list, key=_ev_sort_key)

        # Collect timestamps
        all_timestamps: list[datetime] = []
        for ev in ordered_events:
            dt = _parse_dt(ev.get("timestamp"))
            if dt is not None:
                all_timestamps.append(dt)

        start_time = min(all_timestamps) if all_timestamps else None
        end_time = max(all_timestamps) if all_timestamps else None

        # Build process IDs and details
        proc_ids_set: set[str] = set()
        processes_list: list[dict[str, Any]] = []
        seen_processes: set[tuple[Any, Any]] = set()
        parent_relationships: list[dict[str, Any]] = []

        for ev in ordered_events:
            guid, pid, name = _get_proc_info(ev)
            if guid:
                proc_ids_set.add(f"guid:{guid}")
            if pid:
                proc_ids_set.add(f"pid:{pid}")

            p_ident = (ev.get("process_name"), ev.get("pid"))
            if p_ident not in seen_processes and (ev.get("process_name") or ev.get("pid")):
                processes_list.append({
                    "process_name": ev.get("process_name"),
                    "pid": ev.get("pid"),
                    "process_guid": ev.get("process_guid"),
                    "image_path": ev.get("image_path") or ev.get("file_path"),
                    "command_line": ev.get("command_line"),
                })
                seen_processes.add(p_ident)

            if ev.get("parent_pid") not in (None, ""):
                parent_relationships.append({
                    "parent_pid": ev.get("parent_pid"),
                    "child_pid": ev.get("pid"),
                    "child_process": ev.get("process_name"),
                })

        sorted_process_ids = tuple(sorted(list(proc_ids_set)))
        reasons = tuple(sorted(list(component_reasons[root])))

        # Derive process_key for backward compatibility
        if ordered_events:
            primary_event = ordered_events[0]
            guid, pid, name = _get_proc_info(primary_event)
            if guid:
                process_key = f"guid:{guid}"
            elif pid:
                process_key = f"pid:{pid}"
            elif name:
                process_key = f"name:{name.lower()}"
            else:
                process_key = f"event:{primary_event.get('event_id', 'unknown')}"
        else:
            process_key = "unknown"

        incident_id = generate_incident_id(
            case_id=comp_case_id,
            finding_ids=sorted_finding_ids,
            evidence_ids=sorted_evidence_ids,
            process_ids=sorted_process_ids,
            start_time=start_time,
            end_time=end_time,
        )

        incidents.append(
            CorrelatedIncident(
                incident_id=incident_id,
                case_id=comp_case_id,
                finding_ids=sorted_finding_ids,
                evidence_ids=sorted_evidence_ids,
                process_ids=sorted_process_ids,
                start_time=start_time,
                end_time=end_time,
                correlation_reasons=reasons,
                events=tuple(ordered_events),
                processes=tuple(processes_list),
                parent_relationships=tuple(parent_relationships),
                process_key=process_key,
            )
        )

    def _incident_sort_key(inc: CorrelatedIncident) -> tuple[datetime, str]:
        st = inc.start_time if inc.start_time is not None else datetime.min.replace(tzinfo=timezone.utc)
        return (st, inc.incident_id)

    return sorted(incidents, key=_incident_sort_key)


def correlate_events(
    events: list[EvidenceEvent | dict[str, Any]],
) -> list[CorrelatedIncident]:
    """Legacy compatibility adapter: Group evidence events by process identity and time."""
    if not events:
        return []
    return correlate_findings(findings=[], evidence=events)
