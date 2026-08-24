"""Command-line helpers for inspecting stored RansomEye cases."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ransomeye.behavior import analyze_behavior
from ransomeye.evidence import normalize_events, EvidenceValidationError
from ransomeye.file_behavior import analyze_file_behavior
from ransomeye.integrity import sha256_file, verify_manifest
from ransomeye.report import write_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.sysmon_reader import parse_sysmon_event
from ransomeye.threat_assessment import assess_threat
from ransomeye.timeline import (
    build_process_tree,
    get_case_timeline,
)
from ransomeye.investigation import load_investigation, get_investigation_summary


def parse_evidence_file(
    file_path: str | Path,
    format_type: str = "auto",
) -> tuple[list[dict[str, Any]], int, str]:
    """Parse raw evidence from JSON or Sysmon XML file.

    Returns a tuple of (raw_events_list, rejected_count, detected_format_name).
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    # Maximum file size check (50 MB)
    max_size = 50 * 1024 * 1024
    if path.stat().st_size > max_size:
        raise ValueError(f"Evidence file exceeds maximum allowed size of {max_size} bytes")

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Failed to read {path.name} as UTF-8: {exc}") from exc

    stripped = content.strip()
    if not stripped:
        raise ValueError("Evidence file is empty")

    norm_format = format_type.lower().strip()
    if norm_format not in ("auto", "json", "sysmon-xml", "xml"):
        raise ValueError(f"Unsupported format: {format_type}. Expected auto, json, or sysmon-xml.")

    resolved_format = norm_format
    if resolved_format == "auto":
        if path.suffix.lower() == ".json" or stripped.startswith(("{", "[")):
            resolved_format = "json"
        elif path.suffix.lower() == ".xml" or stripped.startswith("<"):
            resolved_format = "sysmon-xml"
        else:
            raise ValueError(f"Could not automatically determine format for: {path.name}")

    if resolved_format == "json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path.name}: {exc}") from exc

        if isinstance(payload, dict):
            if "events" in payload and isinstance(payload["events"], list):
                raw_events = payload["events"]
            else:
                raw_events = [payload]
        elif isinstance(payload, list):
            raw_events = payload
        else:
            raise ValueError("JSON must contain an event object, a list of events, or an object with an 'events' list.")

        return raw_events, 0, "json"

    elif resolved_format in ("sysmon-xml", "xml"):
        from ransomeye.sysmon_reader import iter_sysmon_events
        events = []
        rejected = 0

        for item in iter_sysmon_events(content):
            if item["error"] is None and item["parsed"] is not None:
                events.append(item["parsed"])
            else:
                rejected += 1

        if not events and rejected == 0:
            raise ValueError(f"No valid Sysmon XML events found in {path.name}")
        elif not events and rejected > 0:
            raise ValueError(f"No valid Sysmon XML events found in {path.name} (rejected {rejected} malformed/unsupported events)")

        return events, rejected, "sysmon-xml"

    else:
        raise ValueError(f"Unsupported format: {format_type}")

def ingest_evidence(
    database_path: str | Path,
    case_id: str,
    file_path: str | Path,
    format_type: str = "auto",
    case_name: str | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    """Ingest evidence from file into a case, normalize, store, and assess threat."""
    raw_events, rejected_count, detected_format = parse_evidence_file(file_path, format_type=format_type)

    if not raw_events:
        raise ValueError("No events found to ingest")

    normalized_events = normalize_events(raw_events)

    store = EvidenceStore(database_path)
    try:
        case = store.get_case(case_id)
        if case is None:
            c_name = case_name or case_id
            c_host = host or ""
            store.create_case(case_id=case_id, case_name=c_name, host=c_host)

        existing_events = store.get_case_events(case_id)
        existing_ids = {e["event_id"] for e in existing_events}

        accepted_count = 0
        duplicate_count = 0

        for event in normalized_events:
            if event.event_id in existing_ids:
                duplicate_count += 1
            else:
                accepted_count += 1
            store.save_event(case_id, event)
            existing_ids.add(event.event_id)

        # Run behavioral analysis & threat assessment on all case events
        all_case_events = store.get_case_events(case_id)
        behavior_findings = analyze_behavior(all_case_events)
        file_behavior_findings = analyze_file_behavior(all_case_events)
        all_findings = behavior_findings + file_behavior_findings

        for finding in all_findings:
            event_ids = finding.get("event_ids")
            if not event_ids and finding.get("event_id"):
                event_ids = [str(finding["event_id"])]
            store.save_finding(case_id, finding, event_ids=event_ids)

        assessment = assess_threat(all_case_events)
        store.save_assessment(case_id, assessment)

        events_read = accepted_count + duplicate_count + rejected_count

        return {
            "database": str(database_path),
            "case_id": case_id,
            "input_file": Path(file_path).name,
            "format": detected_format,
            "events_read": events_read,
            "events_accepted": accepted_count,
            "events_rejected": rejected_count,
            "duplicates": duplicate_count,
            "findings_count": len(all_findings),
            "correlations_count": len(assessment.get("correlations", [])),
            "score": assessment.get("score", 0),
            "severity": assessment.get("severity", "SAFE"),
        }
    finally:
        store.close()

def show_investigation(database_path: str | Path, case_id: str) -> None:
    """Load and print an investigation summary."""
    try:
        investigation = load_investigation(database_path, case_id)
        print(get_investigation_summary(investigation))
    except ValueError as e:
        print(e)


def show_investigation_graph(database_path: str | Path, case_id: str) -> None:
    """Load investigation, build and print investigation evidence graph summary."""
    try:
        investigation = load_investigation(database_path, case_id)
        from ransomeye.investigation_graph import build_investigation_graph

        graph = build_investigation_graph(investigation)
        print(graph.summary(case_id))
    except ValueError as e:
        print(e)


def show_investigation_incident(database_path: str | Path, case_id: str, incident_id: str) -> None:
    """Isolate and print a specific investigation incident."""
    store = EvidenceStore(database_path)
    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            sys.exit(1)

        assessment = store.get_latest_assessment(case_id)
        if assessment is None or not assessment.get("correlations"):
            print(f"Incident not found in latest assessment: {incident_id}")
            sys.exit(1)

        target_incident = None
        for corr in assessment["correlations"]:
            if corr.get("incident_id") == incident_id:
                target_incident = corr
                break

        if not target_incident:
            print(f"Incident not found in latest assessment: {incident_id}")
            sys.exit(1)

        print("RANSOMEYE INCIDENT REPORT")
        print("=========================\n")
        print(f"Incident ID: {incident_id}")
        print(f"Case: {case_id}")

        severity = assessment.get("severity", "None")
        score = assessment.get("score", "None")
        print(f"Severity: {severity}")
        print(f"Score: {score}")

        start_time = target_incident.get("start_time")
        end_time = target_incident.get("end_time")
        print(f"Timeframe: {start_time} -> {end_time}")

        if "duration_seconds" in target_incident:
            print(f"Duration: {target_incident['duration_seconds']}")
        if "process_key" in target_incident:
            print(f"Process Key: {target_incident['process_key']}")

        corr_finding_ids = target_incident.get("finding_ids", [])
        print(f"\n--- FINDINGS ({len(corr_finding_ids)}) ---")
        if not corr_finding_ids:
            print("None")
        else:
            all_case_findings = store.get_case_findings(case_id)
            import hashlib
            import json
            for f in all_case_findings:
                ftype = str(f.get("finding_type", "finding"))
                if ftype == "unknown":
                    ftype = "finding"
                sorted_eids = sorted(list(set(str(e) for e in (f.get("event_ids") or []))))
                technique = str(f.get("technique") or "")
                reason = str(f.get("reason") or "")

                payload = {
                    "event_ids": sorted_eids,
                    "reason": reason,
                    "technique": technique,
                    "type": ftype,
                }
                canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
                f["computed_hash"] = f"F-{digest}"

            for f_id in corr_finding_ids:
                matching_finding = next((f for f in all_case_findings if f.get("computed_hash") == str(f_id)), None)
                if not matching_finding:
                    print(f"Finding not available: {f_id}")
                else:
                    ftype = matching_finding.get("finding_type", "unknown")
                    tech = matching_finding.get("technique") or "unavailable"
                    fscore = matching_finding.get("score")
                    if fscore is None:
                        fscore = "unavailable"
                    conf = matching_finding.get("confidence")
                    if conf is None:
                        conf = "unavailable"
                    reason = matching_finding.get("reason") or "unavailable"

                    print(f"- Finding ID: {f_id}")
                    print(f"  Type: {ftype}")
                    print(f"  Technique: {tech}")
                    print(f"  Score: {fscore}")
                    print(f"  Confidence: {conf}")
                    print(f"  Reason: {reason}")

        evidence_ids = target_incident.get("evidence_ids", target_incident.get("evidence_event_ids", []))
        print(f"\n--- EVIDENCE ({len(evidence_ids)}) ---")
        if not evidence_ids:
            print("None")
        else:
            events = []
            missing = []
            for eid in evidence_ids:
                ev = store.get_event(case_id, eid)
                if ev:
                    events.append(ev)
                else:
                    missing.append(eid)

            events.sort(key=lambda e: (e.get("timestamp") or "", e.get("event_id") or ""))

            for m in missing:
                print(f"Evidence not available: {m}")

            if events:
                print(f"{'Timestamp':<25} {'Event ID':<21} {'Event Type':<19} {'Summary'}")
                print(f"{'-'*9:<25} {'-'*8:<21} {'-'*10:<19} {'-'*7}")
                for event in events:
                    ts = (event.get("timestamp") or "").replace("T", " ").replace("Z", "")
                    eid = event.get("event_id") or ""
                    etype = (event.get("event_type") or "")[:18]

                    summary = ""
                    if event.get("process_name"):
                        summary = event["process_name"].split("\\")[-1]
                        if event.get("network_json"):
                            net = event["network_json"]
                            if net.get("DestinationIp"):
                                summary += f" -> {net.get('DestinationIp')}:{net.get('DestinationPort', '')}"
                    elif event.get("file_path"):
                        summary = event["file_path"].split("\\")[-1]
                    elif event.get("network_json"):
                        net = event["network_json"]
                        if net.get("QueryName"):
                            summary = net["QueryName"]
                    elif event.get("command_line"):
                        summary = event["command_line"][:50]

                    if len(eid) > 21:
                        short_eid = eid[:18] + "..."
                        print(f"{ts:<25} {short_eid:<21} {etype:<19} {summary}")
                        print(f"{'':<25} {eid}")
                    else:
                        print(f"{ts:<25} {eid:<21} {etype:<19} {summary}")
    except (ValueError, KeyError, sqlite3.Error, OSError) as exc:
        print(f"Incident report failed: {exc}")
        sys.exit(1)
    finally:
        store.close()



def show_investigation_process(database_path: str | Path, case_id: str, process_query: str) -> None:
    """Isolate and print a specific process profile."""
    try:
        from ransomeye.investigation_graph import build_investigation_graph
        investigation = load_investigation(database_path, case_id)
        graph = build_investigation_graph(investigation)

        process_nodes = graph.get_process_nodes()
        matched_nodes = []

        target_id = f"PROCESS:{process_query}"
        node = graph.get_node(target_id)
        if node:
            matched_nodes = [node]
        else:
            for n in process_nodes:
                if str(n.attributes.get("pid")) == str(process_query):
                    matched_nodes.append(n)

        if not matched_nodes:
            print(f"Process not found in case: {process_query}")
            sys.exit(1)

        if len(matched_nodes) > 1:
            print(f"Multiple processes matched PID: {process_query}")
            for n in matched_nodes:
                guid = n.node_id.replace("PROCESS:", "") if not n.node_id.startswith("PROCESS:PID:") else "N/A"
                ts = "unknown"
                for ev in investigation.evidence:
                    if str(ev.pid) == str(process_query) and (guid == "N/A" or ev.process_guid == guid):
                        if ev.timestamp:
                            ts = str(ev.timestamp)
                            break
                print(f"- {n.node_id} at {ts}")
            sys.exit(1)

        target_node = matched_nodes[0]

        process_name = target_node.label
        pid = target_node.attributes.get("pid", "unavailable")
        guid = target_node.node_id.replace("PROCESS:", "") if not target_node.node_id.startswith("PROCESS:PID:") else "unavailable"
        image_path = target_node.attributes.get("image") or target_node.attributes.get("image_path") or "unavailable"
        command_line = target_node.attributes.get("command_line") or "unavailable"
        timestamp = "unavailable"

        for ev in investigation.evidence:
            if ev.process_guid == guid or (str(ev.pid) == str(pid) and (guid == "unavailable" or ev.process_guid == guid)):
                if getattr(ev, "image_path", None) and image_path == "unavailable":
                    image_path = ev.image_path
                if ev.command_line and command_line == "unavailable":
                    command_line = ev.command_line
                if ev.timestamp and timestamp == "unavailable":
                    timestamp = str(ev.timestamp)
                if image_path != "unavailable" and command_line != "unavailable" and timestamp != "unavailable":
                    break
        print(f"DEBUG: after loop image_path={image_path}")
        print("RANSOMEYE PROCESS PROFILE")
        print("=========================\n")
        print(f"Case: {case_id}")
        print(f"Process: {process_name}")
        print(f"PID: {pid}")
        print(f"GUID: {guid}")
        print(f"Image: {image_path}")
        print(f"Command Line: {command_line}")
        print(f"Timestamp: {timestamp}")
        print("")

        incoming_spawned = [e for e in graph.get_edges_for_node(target_node.node_id) if e.target_id == target_node.node_id and e.relationship == "SPAWNED"]
        outgoing_spawned = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id and e.relationship == "SPAWNED"]

        print("--- PARENT ---")
        parent_str = "unavailable"
        if incoming_spawned:
            parent_node = graph.get_node(incoming_spawned[0].source_id)
            if parent_node:
                p_pid = parent_node.attributes.get("pid", "unknown")
                p_guid = parent_node.node_id.replace("PROCESS:", "") if not parent_node.node_id.startswith("PROCESS:PID:") else "N/A"
                parent_str = f"{parent_node.label} (PID {p_pid})"
                if p_guid != "N/A":
                    parent_str += f" [{p_guid}]"
        print(f"Parent: {parent_str}")
        print("")

        children = []
        for edge in outgoing_spawned:
            child_node = graph.get_node(edge.target_id)
            if child_node:
                c_pid = child_node.attributes.get("pid", "unknown")
                c_guid = child_node.node_id.replace("PROCESS:", "") if not child_node.node_id.startswith("PROCESS:PID:") else "N/A"

                ts = ""
                if edge.evidence_ids:
                    ev_id = edge.evidence_ids[0]
                    for ev in investigation.evidence:
                        if ev.event_id == ev_id:
                            ts = str(ev.timestamp or "")
                            break

                children.append({
                    "name": child_node.label,
                    "pid": c_pid,
                    "guid": c_guid,
                    "rel": edge.relationship,
                    "ts": ts
                })

        children.sort(key=lambda x: (x["ts"], x["guid"]))

        print(f"--- CHILDREN ({len(children)}) ---")
        if not children:
            print("None")
        else:
            for child in children:
                c_guid_str = f" [{child['guid']}]" if child['guid'] != "N/A" else ""
                print(f"- {child['name']} (PID {child['pid']}){c_guid_str} - {child['rel']}")

        print("")

        files_edges = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id and e.relationship in ("CREATED", "MODIFIED", "DELETED", "RENAMED")]
        files_edges.sort(key=lambda e: (e.relationship, graph.get_node(e.target_id).attributes.get("file_path", "") if graph.get_node(e.target_id) else ""))

        print(f"--- FILES TOUCHED ({len(files_edges)}) ---")
        if not files_edges:
            print("None")
        else:
            for edge in files_edges:
                f_node = graph.get_node(edge.target_id)
                if f_node:
                    f_path = f_node.attributes.get("file_path", f_node.label)
                    print(f"- {edge.relationship}: {f_path}")

        print("")

        network_edges = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id and graph.get_node(e.target_id) and graph.get_node(e.target_id).node_type == "NETWORK"]

        net_items = []
        for edge in network_edges:
            n_node = graph.get_node(edge.target_id)
            if n_node:
                ts = ""
                if edge.evidence_ids:
                    ev_id = edge.evidence_ids[0]
                    for ev in investigation.evidence:
                        if ev.event_id == ev_id:
                            ts = str(ev.timestamp or "")
                            break
                proto = n_node.attributes.get("protocol") or n_node.attributes.get("Protocol") or ""
                proto_str = f" [{proto}]" if proto else ""
                rel_str = edge.relationship if edge.relationship != "CONNECTED_TO" else "CONNECTED"

                # Check for DNS
                if n_node.attributes.get("QueryName"):
                    rel_str = "DNS QUERY"
                    label = n_node.attributes.get("QueryName")
                    proto_str = ""
                else:
                    label = n_node.label

                net_items.append({
                    "ts": ts,
                    "label": label,
                    "rel": rel_str,
                    "proto": proto_str
                })

        net_items.sort(key=lambda x: (x["ts"], x["label"]))
        print(f"--- NETWORK CONNECTIONS ({len(net_items)}) ---")
        if not net_items:
            print("None")
        else:
            for n in net_items:
                print(f"- {n['rel']}: {n['label']}{n['proto']}")

        print("")

        # Associated Findings
        # A finding is associated if there is a SUPPORTS edge from an EVIDENCE node to the FINDING node,
        # AND that EVIDENCE node has an INVOLVED edge from the PROCESS node.
        # Or, since we only need associated findings, we can just look at findings whose evidence contains the process.

        # We can just look for FINDING nodes in the graph where a SUPPORTS edge comes from an EVIDENCE node that is connected to our PROCESS node.
        # Wait, the graph builder in investigation_graph.py links FINDINGS.
        associated_finding_ids = set()

        # First find all EVIDENCE nodes connected to this PROCESS
        ev_edges = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id or e.target_id == target_node.node_id]
        process_ev_ids = set()
        for e in ev_edges:
            if e.evidence_ids:
                process_ev_ids.update(e.evidence_ids)

        # Now find findings connected to these evidence IDs
        finding_nodes = graph.get_finding_nodes()
        associated_findings = []
        for fn in finding_nodes:
            # check if any SUPPORTS edge from evidence to finding matches process_ev_ids
            supports_edges = [e for e in graph.get_edges_for_node(fn.node_id) if e.target_id == fn.node_id and e.relationship == "SUPPORTS"]
            is_associated = False
            for se in supports_edges:
                ev_id = se.source_id.replace("EVIDENCE:", "")
                if ev_id in process_ev_ids:
                    is_associated = True
                    break
            if is_associated:
                associated_findings.append(fn)

        associated_findings.sort(key=lambda fn: fn.node_id)
        print(f"--- ASSOCIATED FINDINGS ({len(associated_findings)}) ---")
        if not associated_findings:
            print("None")
        else:
            for fn in associated_findings:
                fid = fn.node_id.replace("FINDING:", "")
                ftype = fn.attributes.get("finding_type", "unknown")
                tech = fn.attributes.get("technique", "unavailable")
                score = fn.attributes.get("score", "unavailable")
                reason = fn.attributes.get("reason", "unavailable")

                print(f"- {fid} ({ftype})")
                print(f"  Technique: {tech}")
                print(f"  Score: {score}")
                print(f"  Reason: {reason}")

    except ValueError as e:
        print(e)
        sys.exit(1)


def show_attack_reconstruction(database_path: str | Path, case_id: str) -> None:
    """Load investigation, build graph, reconstruct and print attack sequence."""
    try:
        investigation = load_investigation(database_path, case_id)
        from ransomeye.investigation_graph import build_investigation_graph
        from ransomeye.reconstruction import reconstruct_attack

        graph = build_investigation_graph(investigation)
        sequence = reconstruct_attack(investigation, graph)
        print(sequence.summary())
    except ValueError as e:
        print(e)


def show_advanced_timeline(database_path: str | Path, case_id: str) -> None:
    """Load investigation, build graph and attack sequence, and print advanced timeline."""
    try:
        investigation = load_investigation(database_path, case_id)
        from ransomeye.investigation_graph import build_investigation_graph
        from ransomeye.reconstruction import reconstruct_attack
        from ransomeye.advanced_timeline import build_advanced_timeline

        graph = build_investigation_graph(investigation)
        sequence = reconstruct_attack(investigation, graph)
        timeline = build_advanced_timeline(investigation, sequence, graph)
        print(timeline.render())
    except ValueError as e:
        print(e)


def print_case_timeline(
    database_path: str | Path,
    case_id: str,
    advanced: bool = False,
) -> None:
    """Print an analyst-friendly timeline for a stored case."""
    if advanced:
        show_advanced_timeline(database_path, case_id)
        return

    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        print(f"Case: {case['case_id']}")
        print(f"Host: {case.get('host', '')}")
        print()
        print("Time                  Process             Parent")

        timeline = get_case_timeline(database_path, case_id)

        process_names_by_pid = {
            str(entry.get("pid")): str(entry.get("process_name") or "")
            for entry in timeline
            if entry.get("pid") is not None
        }

        for entry in timeline:
            timestamp = str(entry.get("timestamp", ""))

            if timestamp and "T" in timestamp:
                timestamp = timestamp.replace("T", " ")
                if "." in timestamp:
                    timestamp = timestamp.split(".")[0]
                if timestamp.endswith("Z"):
                    timestamp = timestamp[:-1]

            process_name = str(entry.get("process_name") or "")
            parent_name = ""

            if entry.get("parent_image"):
                parent_name = str(entry["parent_image"]).split("\\")[-1]
            elif entry.get("parent_pid") is not None:
                parent_pid_text = str(entry["parent_pid"])
                parent_name = process_names_by_pid.get(
                    parent_pid_text,
                    f"PID {parent_pid_text}",
                )
            else:
                parent_name = ""

            print(f"{timestamp:<20} {process_name:<18} {parent_name}")
    finally:
        store.close()


def print_case_tree(database_path: str | Path, case_id: str) -> None:
    """Print a process tree for a stored case."""
    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        timeline = get_case_timeline(database_path, case_id)
        tree = build_process_tree(timeline)

        print(f"Case: {case['case_id']}")
        print(f"Host: {case.get('host', '')}")
        print()

        nodes = tree.get("nodes", {})
        children = tree.get("children", {})

        child_ids = {
            child_id
            for child_list in children.values()
            for child_id in child_list
        }

        roots = [
            process_id
            for process_id in nodes
            if process_id not in child_ids
        ]

        def render(
            process_id: str,
            prefix: str = "",
            connector: str = "",
        ) -> None:
            node = nodes[process_id]
            name = node.get("process_name") or "[unknown]"
            pid = node.get("pid") or process_id

            print(f"{prefix}{connector}{name} [PID {pid}]")

            child_list = children.get(process_id, [])

            if connector == "├── ":
                child_prefix = prefix + "│   "
            elif connector == "└── ":
                child_prefix = prefix + "    "
            else:
                child_prefix = prefix

            for index, child_id in enumerate(child_list):
                last = index == len(child_list) - 1
                branch = "└── " if last else "├── "

                render(
                    child_id,
                    prefix=child_prefix,
                    connector=branch,
                )

        for root_id in roots:
            render(root_id)
            print()
    finally:
        store.close()


def show_case_status(database_path: str | Path, case_id: str) -> None:
    store = EvidenceStore(database_path)

    try:
        case = store.get_case(case_id)
        if case is None:
            print(f"Case not found: {case_id}")
            return

        print(f"Case: {case['case_id']}")
        print(f"Status: {case.get('status', 'OPEN')}")
    finally:
        store.close()


def update_case_status(
    database_path: str | Path,
    case_id: str,
    status: str,
    note: str = "",
) -> None:
    store = EvidenceStore(database_path)

    try:
        store.update_case_status(case_id, status, note=note)
        print(f"Updated case {case_id} to {status.upper()}")
    finally:
        store.close()


def print_case_history(database_path: str | Path, case_id: str) -> None:
    store = EvidenceStore(database_path)

    try:
        history = store.get_case_history(case_id)
        if not history:
            print(f"No history found for case {case_id}")
            return

        print(f"Case history: {case_id}")
        for entry in history:
            note = entry.get("note") or ""
            print(
                f"{entry['changed_at']} {entry['old_status'] or '-'} -> {entry['new_status']}"
                + (f" :: {note}" if note else "")
            )
    finally:
        store.close()


def write_integrity_manifest(input_path: str | Path, output_path: str | Path) -> Path:
    input_file = Path(input_path)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    digest = sha256_file(input_file)
    output_file.write_text(
        f"SHA256  {input_file.name}\n{digest}\n",
        encoding="utf-8",
    )
    return output_file


def verify_integrity_manifest(artifact_path: str | Path, manifest_path: str | Path) -> bool:
    return verify_manifest(Path(artifact_path), Path(manifest_path))


def main() -> None:
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="ransomeye",
        description="Inspect stored RansomEye cases.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    timeline_parser = subparsers.add_parser(
        "timeline",
        help="Print a case timeline.",
    )
    timeline_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    timeline_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    timeline_parser.add_argument(
        "--advanced",
        action="store_true",
        default=False,
        help="Print advanced analyst timeline.",
    )

    tree_parser = subparsers.add_parser(
        "tree",
        help="Print a process tree.",
    )
    tree_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    tree_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Write a case report to disk.",
    )
    report_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    report_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    report_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write the report text file.",
    )

    case_parser = subparsers.add_parser(
        "case",
        help="Manage case lifecycle state.",
    )
    case_subparsers = case_parser.add_subparsers(dest="case_command", required=True)

    case_status_parser = case_subparsers.add_parser(
        "status",
        help="Show the current case status.",
    )
    case_status_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_status_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    case_update_parser = case_subparsers.add_parser(
        "update",
        help="Update the case status and record a note.",
    )
    case_update_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_update_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    case_update_parser.add_argument(
        "--status",
        required=True,
        help="New case status.",
    )
    case_update_parser.add_argument(
        "--note",
        default="",
        help="Analyst note to record with the status change.",
    )

    case_history_parser = case_subparsers.add_parser(
        "history",
        help="Show the lifecycle history for a case.",
    )
    case_history_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    case_history_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    custody_parser = subparsers.add_parser(
        "custody",
        help="Record or inspect case chain-of-custody events.",
    )
    custody_subparsers = custody_parser.add_subparsers(dest="custody_command", required=True)

    custody_record_parser = custody_subparsers.add_parser(
        "record",
        help="Record a custody event for a case.",
    )
    custody_record_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    custody_record_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    custody_record_parser.add_argument(
        "--artifact",
        required=True,
        dest="artifact_path",
        help="Path to the artifact within the case.",
    )
    custody_record_parser.add_argument(
        "--hash",
        required=True,
        dest="sha256",
        help="SHA-256 digest of the artifact.",
    )
    custody_record_parser.add_argument(
        "--action",
        required=True,
        help="Custody action: created, verified, exported, reviewed.",
    )
    custody_record_parser.add_argument(
        "--analyst",
        required=True,
        help="Analyst name or email recording the event.",
    )
    custody_record_parser.add_argument(
        "--note",
        default="",
        help="Optional note about the custody event.",
    )

    custody_list_parser = custody_subparsers.add_parser(
        "list",
        help="List custody history for a case.",
    )
    custody_list_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    custody_list_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Create integrity manifests for evidence and reports.",
    )
    integrity_subparsers = integrity_parser.add_subparsers(dest="integrity_command", required=True)

    integrity_hash_parser = integrity_subparsers.add_parser(
        "hash",
        help="Write a SHA-256 manifest for a file.",
    )
    integrity_hash_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the evidence or report file to hash.",
    )
    integrity_hash_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write the SHA-256 manifest.",
    )

    verify_parser = integrity_subparsers.add_parser(
        "verify",
        help="Verify an artifact against a SHA-256 manifest.",
    )
    verify_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Artifact to verify.",
    )
    verify_parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="SHA-256 manifest file.",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Export case evidence package.",
    )
    export_subparsers = export_parser.add_subparsers(dest="export_command")

    # Standard export arguments when no subcommand (lock-info / unlock) is passed
    export_parser.add_argument(
        "--database",
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    export_parser.add_argument(
        "--case",
        dest="case_id",
        help="Case identifier.",
    )
    export_parser.add_argument(
        "--output",
        type=Path,
        help="Output directory path for the export package.",
    )

    lock_info_parser = export_subparsers.add_parser(
        "lock-info",
        help="Inspect export lock file metadata.",
    )
    lock_info_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )

    lock_status_parser = export_subparsers.add_parser(
        "lock-status",
        help="Inspect export lock file status and owner PID.",
    )
    lock_status_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )

    unlock_parser = export_subparsers.add_parser(
        "unlock",
        help="Remove export lock file.",
    )
    unlock_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory path of the export package.",
    )
    unlock_parser.add_argument(
        "--force",
        action="store_true",
        help="Force removal of the lock file.",
    )
    unlock_parser.add_argument(
        "--break-lock",
        action="store_true",
        help="Override active or unknown lock-owner status.",
    )

    database_parser = subparsers.add_parser(
        "database",
        help="Database management operations.",
    )
    database_subparsers = database_parser.add_subparsers(dest="database_command", required=True)

    db_check_parser = database_subparsers.add_parser(
        "check",
        help="Check SQLite database integrity.",
    )
    db_check_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )

    db_backup_parser = database_subparsers.add_parser(
        "backup",
        help="Create a safe SQLite database backup.",
    )
    db_backup_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the source SQLite database.",
    )
    db_backup_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination path for the backup.",
    )

    db_restore_parser = database_subparsers.add_parser(
        "restore",
        help="Restore a SQLite database from a backup.",
    )
    db_restore_parser.add_argument(
        "--backup",
        required=True,
        type=Path,
        help="Path to the SQLite backup.",
    )
    db_restore_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination path for the restored database.",
    )

    investigation_parser = subparsers.add_parser(
        "investigation",
        help="Investigation domain model operations.",
    )
    investigation_subparsers = investigation_parser.add_subparsers(dest="investigation_command", required=True)

    investigation_show_parser = investigation_subparsers.add_parser(
        "show",
        help="Show investigation summary.",
    )
    investigation_show_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_show_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    investigation_graph_parser = investigation_subparsers.add_parser(
        "graph",
        help="Show investigation evidence graph summary.",
    )
    investigation_graph_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_graph_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    investigation_reconstruct_parser = investigation_subparsers.add_parser(
        "reconstruct",
        help="Reconstruct chronological attack sequence.",
    )
    investigation_reconstruct_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_reconstruct_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    investigation_timeline_parser = investigation_subparsers.add_parser(
        "timeline",
        help="Show advanced investigation timeline.",
    )
    investigation_timeline_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_timeline_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )

    investigation_incident_parser = investigation_subparsers.add_parser(
        "incident",
        help="Show investigation incident drill-down.",
    )
    investigation_incident_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_incident_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    investigation_incident_parser.add_argument(
        "--incident",
        required=True,
        dest="incident_id",
        help="Incident identifier.",
    )

    investigation_process_parser = investigation_subparsers.add_parser(
        "process",
        help="View a specific process profile.",
    )
    investigation_process_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    investigation_process_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    investigation_process_parser.add_argument(
        "--process",
        required=True,
        dest="process_query",
        help="Process GUID or PID.",
    )

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest JSON or Sysmon XML evidence into a case.",
    )
    ingest_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    ingest_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    ingest_parser.add_argument(
        "--file",
        required=True,
        dest="file_path",
        type=Path,
        help="Path to the evidence file to ingest.",
    )
    ingest_parser.add_argument(
        "--format",
        default="auto",
        dest="format_type",
        choices=["auto", "json", "sysmon-xml", "xml"],
        help="Evidence format (auto, json, sysmon-xml).",
    )
    ingest_parser.add_argument(
        "--case-name",
        dest="case_name",
        default=None,
        help="Optional case name if creating a new case.",
    )
    ingest_parser.add_argument(
        "--host",
        dest="host",
        default=None,
        help="Optional host name if creating a new case.",
    )

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Interrogate and search case evidence.",
    )
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command", required=True)

    evidence_search_parser = evidence_subparsers.add_parser(
        "search",
        help="Search events for a specific query string.",
    )
    evidence_search_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    evidence_search_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    evidence_search_parser.add_argument(
        "--query",
        required=True,
        help="Search indicator or text fragment.",
    )

    evidence_inspect_parser = evidence_subparsers.add_parser(
        "inspect",
        help="Inspect a specific event by ID.",
    )
    evidence_inspect_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    evidence_inspect_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    evidence_inspect_parser.add_argument(
        "--event",
        required=True,
        dest="event_id",
        help="Event identifier.",
    )

    evidence_trace_parser = evidence_subparsers.add_parser(
        "trace",
        help="Pivot and trace analytical context for an event.",
    )
    evidence_trace_parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the RansomEye SQLite database.",
    )
    evidence_trace_parser.add_argument(
        "--case",
        required=True,
        dest="case_id",
        help="Case identifier.",
    )
    evidence_trace_parser.add_argument(
        "--event",
        required=True,
        dest="event_id",
        help="Event identifier.",
    )

    args = parser.parse_args()

    if args.command == "ingest":
        try:
            summary = ingest_evidence(
                database_path=args.database,
                case_id=args.case_id,
                file_path=args.file_path,
                format_type=args.format_type,
                case_name=args.case_name,
                host=args.host,
            )
            print("RansomEye evidence ingestion complete\n")
            print(f"Database: {summary['database']}")
            print(f"Case: {summary['case_id']}")
            print(f"Input: {summary['input_file']}")
            print(f"Format: {summary['format']}\n")
            print(f"Events read: {summary['events_read']}")
            print(f"Events accepted: {summary['events_accepted']}")
            print(f"Events rejected: {summary['events_rejected']}")
            print(f"Duplicates: {summary['duplicates']}")
            print(f"Findings: {summary['findings_count']}")
            print(f"Correlations: {summary['correlations_count']}")
            print(f"Score: {summary['score']}")
            print(f"Severity: {summary['severity']}")
        except (FileNotFoundError, ValueError, EvidenceValidationError, sqlite3.Error, OSError) as exc:
            parser.exit(1, f"Ingestion failed: {exc}\n")
    elif args.command == "investigation":
        if args.investigation_command == "show":
            show_investigation(
                database_path=args.database,
                case_id=args.case_id,
            )
        elif args.investigation_command == "incident":
            show_investigation_incident(
                database_path=args.database,
                case_id=args.case_id,
                incident_id=args.incident_id,
            )
        elif args.investigation_command == "process":
            show_investigation_process(
                database_path=args.database,
                case_id=args.case_id,
                process_query=args.process_query,
            )
        elif args.investigation_command == "graph":
            show_investigation_graph(
                database_path=args.database,
                case_id=args.case_id,
            )
        elif args.investigation_command == "reconstruct":
            show_attack_reconstruction(
                database_path=args.database,
                case_id=args.case_id,
            )
        elif args.investigation_command == "timeline":
            show_advanced_timeline(
                database_path=args.database,
                case_id=args.case_id,
            )
    elif args.command == "timeline":

        print_case_timeline(
            database_path=args.database,
            case_id=args.case_id,
            advanced=getattr(args, "advanced", False),
        )
    elif args.command == "tree":
        print_case_tree(
            database_path=args.database,
            case_id=args.case_id,
        )
    elif args.command == "report":
        output_path = write_case_report(
            database_path=args.database,
            case_id=args.case_id,
            output_path=args.output,
        )
        print(f"Report written to {output_path}")
    elif args.command == "case":
        if args.case_command == "status":
            show_case_status(
                database_path=args.database,
                case_id=args.case_id,
            )
        elif args.case_command == "update":
            update_case_status(
                database_path=args.database,
                case_id=args.case_id,
                status=args.status,
                note=args.note,
            )
        elif args.case_command == "history":
            print_case_history(
                database_path=args.database,
                case_id=args.case_id,
            )
    elif args.command == "custody":
        if args.custody_command == "record":
            try:
                store = EvidenceStore(args.database)
                try:
                    store.record_custody_event(
                        case_id=args.case_id,
                        artifact_path=args.artifact_path,
                        sha256=args.sha256,
                        action=args.action,
                        analyst=args.analyst,
                        note=args.note,
                    )
                    print(
                        f"Recorded custody event for case {args.case_id}"
                    )
                finally:
                    store.close()
            except (ValueError, KeyError) as exc:
                parser.exit(1, f"{exc}\n")
        elif args.custody_command == "list":
            try:
                store = EvidenceStore(args.database)
                try:
                    case = store.get_case(args.case_id)
                    if case is None:
                        parser.exit(1, f"Case not found: {args.case_id}\n")

                    events = store.get_custody_events(args.case_id)
                    if not events:
                        print(f"No custody records for case {args.case_id}")
                        return

                    for event in events:
                        verification = "N/A"
                        if event["verification_result"] is not None:
                            verification = "Yes" if event["verification_result"] else "FAILED"

                        print(f"{event['recorded_at']} {event['action']}")
                        print(f"Artifact: {event['artifact_path']}")
                        print(f"Action: {event['action']}")
                        print(f"Analyst: {event['analyst']}")
                        print(f"SHA-256: {event['sha256']}")
                        print(f"Note: {event['note'] or 'N/A'}")
                        print(f"Verification: {verification}")
                        print()
                finally:
                    store.close()
            except (ValueError, KeyError) as exc:
                parser.exit(1, f"{exc}\n")
    elif args.command == "integrity":
        if args.integrity_command == "hash":
            manifest_path = write_integrity_manifest(
                input_path=args.input,
                output_path=args.output,
            )
            print(f"Manifest written to {manifest_path}")
        elif args.integrity_command == "verify":
            verified = verify_integrity_manifest(
                artifact_path=args.input,
                manifest_path=args.manifest,
            )
            if not verified:
                parser.exit(1, "Integrity verification failed\n")
            print("Integrity verified")
    elif args.command == "export":
        from ransomeye.export import (
            export_case,
            read_export_lock,
            remove_export_lock,
        )

        if args.export_command == "lock-info":
            try:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                metadata = read_export_lock(args.output)
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "success",
                    output=str(args.output),
                    case_id=metadata.get("case_id"),
                )
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
            except (FileNotFoundError, ValueError, OSError) as exc:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "failure",
                    output=str(args.output),
                    error=str(exc),
                )
                parser.exit(1, f"{exc}\n")
        elif args.export_command == "lock-status":
            try:
                from ransomeye.export import get_lock_owner_status
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                metadata = read_export_lock(args.output)
                owner_status = get_lock_owner_status(metadata)
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "success",
                    output=str(args.output),
                    case_id=metadata.get("case_id"),
                    owner_status=owner_status.value,
                )
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
                print(f"  Owner status: {owner_status.value}")

            except (FileNotFoundError, ValueError, OSError) as exc:
                from ransomeye.logging import try_write_audit_event

                log_path = os.environ.get("RANSOMEYE_LOG_PATH", "logs/audit.jsonl")
                try_write_audit_event(
                    log_path,
                    "lock_inspected",
                    "failure",
                    output=str(args.output),
                    error=str(exc),
                )
                parser.exit(1, f"{exc}\n")



        elif args.export_command == "unlock":
            try:
                metadata = read_export_lock(args.output)
                print("Export lock:")
                print(f"  PID: {metadata.get('pid')}")
                print(f"  Created UTC: {metadata.get('created_utc')}")
                print(f"  Case: {metadata.get('case_id')}")
                print(f"  Database: {metadata.get('database')}")
                print(f"  Output: {metadata.get('output')}")
                removed_lock = remove_export_lock(
                    args.output,
                    force=args.force,
                    break_lock=args.break_lock,
                )
                print(f"Removed export lock: {removed_lock}")

            except (FileNotFoundError, ValueError, PermissionError, OSError) as exc:
                parser.exit(1, f"{exc}\n")
        else:
            if not args.database or not args.case_id or not args.output:
                parser.exit(2, "export requires --database, --case, and --output\n")
            try:
                exported_path = export_case(
                    database_path=args.database,
                    case_id=args.case_id,
                    output_path=args.output,
                )
                print(f"Exported case package to {exported_path}")
            except FileExistsError as exc:
                parser.exit(1, f"{exc}\n")
            except (OSError, sqlite3.Error, ValueError) as exc:
                parser.exit(1, f"Operation failed: {exc}\n")
    elif args.command == "database":
        if args.database_command == "check":
            try:
                from ransomeye.storage import check_database_integrity

                is_ok = check_database_integrity(args.database)
                if is_ok:
                    print("Database integrity: OK")
                else:
                    parser.exit(1, "Database integrity check failed: Integrity check returned non-ok result\n")
            except (FileNotFoundError, sqlite3.DatabaseError, sqlite3.Error, OSError) as exc:
                parser.exit(1, f"Database integrity check failed: {exc}\n")
        elif args.database_command == "backup":
            try:
                from ransomeye.storage import backup_database

                backup_path = backup_database(
                    args.database,
                    args.output,
                )
                print(f"Database backup created: {backup_path}")
            except (FileExistsError, FileNotFoundError, OSError, sqlite3.Error) as exc:
                parser.exit(1, f"Database backup failed: {exc}\n")
        elif args.database_command == "restore":
            try:
                from ransomeye.storage import restore_database

                restored_path = restore_database(
                    args.backup,
                    args.output,
                )
                print(f"Database restored: {restored_path}")
            except (FileExistsError, FileNotFoundError, OSError, sqlite3.Error) as exc:
                parser.exit(1, f"Database restore failed: {exc}\n")
    elif args.command == "evidence":
        store = EvidenceStore(args.database)
        try:
            case = store.get_case(args.case_id)
            if not case:
                parser.exit(1, f"Case not found: {args.case_id}\n")

            if args.evidence_command == "search":
                if not args.query:
                    parser.exit(1, "Query cannot be empty\n")

                events = store.search_events(args.case_id, args.query)

                print("RANSOMEYE EVIDENCE SEARCH")
                print("=========================\n")
                print(f"Case: {args.case_id}")
                print(f"Query: {args.query}")
                print(f"Matches: {len(events)}\n")

                if not events:
                    print("No matching evidence found.")
                else:
                    print(f"{'Timestamp':<25} {'Event ID':<21} {'Event Type':<17} {'Summary'}")
                    print(f"{'-'*9:<25} {'-'*8:<21} {'-'*10:<17} {'-'*7}")
                    for event in events:
                        ts = (event.get("timestamp") or "").replace("T", " ").replace("Z", "")
                        eid = event.get("event_id") or ""
                        if len(eid) > 20:
                            eid = eid[:17] + "..."
                        etype = (event.get("event_type") or "")[:16]

                        summary = ""
                        if event.get("process_name"):
                            summary = event["process_name"].split("\\")[-1]
                            if event.get("network_json"):
                                net = event["network_json"]
                                if net.get("DestinationIp"):
                                    summary += f" -> {net.get('DestinationIp')}:{net.get('DestinationPort', '')}"
                        elif event.get("file_path"):
                            summary = event["file_path"].split("\\")[-1]
                        elif event.get("network_json"):
                            net = event["network_json"]
                            if net.get("QueryName"):
                                summary = net["QueryName"]
                        elif event.get("command_line"):
                            summary = event["command_line"][:50]

                        print(f"{ts:<25} {eid:<21} {etype:<17} {summary}")

            elif args.evidence_command == "inspect":
                event = store.get_event(args.case_id, args.event_id)
                if not event:
                    parser.exit(1, f"Event not found\n")
                print(json.dumps(event, indent=2, ensure_ascii=False))

            elif args.evidence_command == "trace":
                event = store.get_event(args.case_id, args.event_id)
                if not event:
                    parser.exit(1, f"Event not found\n")

                print("RANSOMEYE EVIDENCE TRACE")
                print("=========================\n")
                print("Event")
                print(f"Event ID: {event.get('event_id')}")
                print(f"Timestamp: {event.get('timestamp')}")
                print(f"Event Type: {event.get('event_type')}")
                print(f"Summary: {event.get('command_line') or event.get('process_name') or event.get('file_path') or '-'}")

                print("\n--- Process Lineage ---")
                from ransomeye.timeline import get_case_timeline, build_process_tree
                timeline = get_case_timeline(args.database, args.case_id)
                processes = build_process_tree(timeline)
                nodes = processes.get("nodes", {})

                current_process = None
                parent_process = None

                pid_val = str(event.get("pid")) if event.get("pid") is not None else None
                if pid_val and pid_val in nodes:
                    current_process = nodes[pid_val]

                if current_process:
                    parent_pid = current_process.get("parent_pid")
                    if parent_pid and parent_pid in nodes:
                        parent_process = nodes[parent_pid]

                if parent_process:
                    name = parent_process.get("process_name", "Unknown")
                    pid = parent_process.get("pid", "?")
                    guid = event.get("parent_process_guid") or "?"
                    cmd = parent_process.get("command_line", "-")
                    print(f"Parent: {name} [PID {pid}] ({guid})")
                    print(f"        -> {cmd}")
                else:
                    print("Parent: Unknown")

                if current_process:
                    name = current_process.get("process_name", "Unknown")
                    pid = current_process.get("pid", "?")
                    guid = event.get("process_guid") or "?"
                    print(f"Current: {name} [PID {pid}] ({guid})")
                else:
                    print("Current: Unknown")

                print("\n--- Findings ---")
                findings = store.get_event_findings(args.case_id, args.event_id)
                finding_ids = []
                if not findings:
                    print("None")
                else:
                    for f in findings:
                        fid = f['finding_id']
                        finding_ids.append(str(fid))
                        print(f"Finding ID: {fid}")
                        print(f"Type / Technique: {f.get('finding_type')} / {f.get('technique') or '-'}")
                        print(f"Reason: {f.get('reason')}")
                        print(f"Evidence IDs: {', '.join(f.get('event_ids', []))}\n")

                print("--- Correlations / Incidents ---")
                assessment = store.get_latest_assessment(args.case_id)
                matched_correlations = []
                if assessment and assessment.get("correlations"):
                    for corr in assessment["correlations"]:
                        corr_finding_ids = [str(x) for x in corr.get("finding_ids", [])]
                        if any(fid in corr_finding_ids for fid in finding_ids) or \
                           (args.event_id in corr.get("evidence_ids", [])):
                           matched_correlations.append(corr)

                if not matched_correlations:
                    print("None")
                else:
                    for corr in matched_correlations:
                        print(f"Incident ID: {corr.get('incident_id')}")
                        print(f"Related Finding IDs: {', '.join(str(x) for x in corr.get('finding_ids', []))}")
                        print(f"Related Evidence IDs: {', '.join(corr.get('evidence_ids', []))}")
                        print(f"Start / End Time: {corr.get('start_time')} / {corr.get('end_time')}\n")

        except (ValueError, KeyError, sqlite3.Error, OSError) as exc:
            parser.exit(1, f"{exc}\n")
        finally:
            store.close()

if __name__ == "__main__":
    main()
