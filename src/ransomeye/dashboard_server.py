"""RansomEye Analyst Dashboard HTTP Server."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ransomeye.advanced_timeline import build_advanced_timeline
from ransomeye.collection import CollectionPipeline
from ransomeye.commands import (
    ingest_evidence,
    run_collect_file_command,
    verify_integrity_manifest,
    write_integrity_manifest,
)
from ransomeye.export import (
    export_case,
    get_lock_owner_status,
    read_export_lock,
    remove_export_lock,
)
from ransomeye.integrity import sha256_file
from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.investigation_validation import validate_investigation
from ransomeye.ioc_extractor import (
    IocAnalysisError,
    IocExtractor,
    ingest_ioc_finding,
)
from ransomeye.pcap_analyzer import (
    PcapAnalysisError,
    PcapAnalyzer,
    ingest_pcap_finding,
)
from ransomeye.phishing import MessagePayload, PhishingDetector, ingest_phishing_finding
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.report import generate_case_report
from ransomeye.script_analyzer import (
    ScriptAnalysisError,
    ScriptAnalyzer,
    ingest_script_finding,
)
from ransomeye.static_analyzer import StaticAnalyzer, ingest_static_finding
from ransomeye.storage import (
    EvidenceStore,
    backup_database,
    check_database_integrity,
    restore_database,
)
from ransomeye.timeline import build_process_tree, get_case_timeline

logger = logging.getLogger(__name__)

DB_PATH: Path | None = None
MAX_COLLECTION_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
SAFE_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-]+$")


def _get_store() -> EvidenceStore:
    """Return a fresh EvidenceStore connection to avoid multi-threading issues."""
    if not DB_PATH or not DB_PATH.is_file():
        raise FileNotFoundError("Database not configured or file does not exist.")
    return EvidenceStore(DB_PATH)


def _validate_safe_id(identifier: str, name: str = "Identifier") -> None:
    """Validate string identifier to prevent path traversal or SQL injection."""
    if not identifier or not SAFE_ID_REGEX.match(identifier):
        raise ValueError(f"Invalid {name}: '{identifier}'. Must contain only letters, numbers, underscores, or hyphens.")


def json_response(handler: BaseHTTPRequestHandler, status: int, data: Any) -> None:
    """Send JSON response with CORS headers."""
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(json.dumps(data, default=str).encode("utf-8"))


def error_response(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    """Send JSON error response."""
    json_response(handler, status, {"error": message})


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for RansomEye Analyst Console."""

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle HTTP GET requests for static UI assets and API endpoints."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/" or path == "":
            self.serve_file("index.html", "text/html")
        elif path.startswith("/api/"):
            self.handle_api_get(path, parsed_path)
        else:
            self.serve_file(path.lstrip("/"), self.guess_type(path))

    def do_POST(self) -> None:
        """Handle HTTP POST requests for API actions."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path.startswith("/api/"):
            self.handle_api_post(path, parsed_path)
        else:
            self.send_error(404, "Endpoint not found")

    def guess_type(self, path: str) -> str:
        """Guess MIME type for static files."""
        if path.endswith(".css"):
            return "text/css"
        if path.endswith(".js"):
            return "application/javascript"
        if path.endswith(".png"):
            return "image/png"
        if path.endswith(".jpg") or path.endswith(".jpeg"):
            return "image/jpeg"
        if path.endswith(".svg"):
            return "image/svg+xml"
        return "text/plain"

    def serve_file(self, filename: str, content_type: str) -> None:
        """Serve static files from the static/ directory."""
        filepath = (Path(__file__).parent / "static" / filename).resolve()
        static_dir = (Path(__file__).parent / "static").resolve()
        if static_dir not in filepath.parents and filepath != static_dir:
            self.send_error(403, "Access denied")
            return

        if not filepath.is_file():
            self.send_error(404, f"File not found: {filename}")
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        with open(filepath, "rb") as f:
            self.wfile.write(f.read())

    def handle_api_get(self, path: str, parsed_path: Any) -> None:
        """Route GET API requests."""
        parts = [unquote(p) for p in path.split("/")[2:]]  # Drop ['', 'api']

        try:
            if parts[0] == "cases":
                if not DB_PATH or not DB_PATH.is_file():
                    json_response(self, 200, {"cases": []})
                    return
                store = _get_store()
                try:
                    cases = store.connection.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
                    case_list = []
                    for c in cases:
                        cd = dict(c)
                        cid = cd.get("case_id")
                        try:
                            ev_c = store.connection.execute("SELECT COUNT(*) FROM events WHERE case_id = ?", (cid,)).fetchone()[0]
                            fn_c = store.connection.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (cid,)).fetchone()[0]
                            ass = store.get_latest_assessment(cid)
                            inc_c = len(ass.get("correlations", [])) if ass else 0
                            cd["events_count"] = ev_c
                            cd["findings_count"] = fn_c
                            cd["incidents_count"] = inc_c
                        except Exception:
                            cd["events_count"] = 0
                            cd["findings_count"] = 0
                            cd["incidents_count"] = 0
                        case_list.append(cd)
                    json_response(self, 200, {"cases": case_list})
                finally:
                    store.close()
                return

            if parts[0] == "collect" and len(parts) > 1 and parts[1] == "status":
                query_params = parse_qs(parsed_path.query)
                case_id = query_params.get("case_id", [""])[0]
                if not case_id:
                    json_response(self, 200, {
                        "status": {
                            "pipeline_state": "STOPPED",
                            "collector": None,
                        },
                        "rendered": "RANSOMEYE COLLECTION STATUS\n===========================\n\nCollector: None\nState: STOPPED"
                    })
                    return

                _validate_safe_id(case_id, "case_id")
                if not DB_PATH or not DB_PATH.is_file():
                    return error_response(self, 400, "Database not configured")

                pipeline = CollectionPipeline(database_path=DB_PATH, case_id=case_id)
                store = _get_store()
                try:
                    events = store.get_case_events(case_id)
                    pipeline.events_collected = len(events)
                    pipeline.events_accepted = len(events)
                finally:
                    store.close()

                json_response(self, 200, {
                    "status": pipeline.status(),
                    "rendered": pipeline.render_status()
                })
                return

            # All remaining endpoints require configured DB file
            if not DB_PATH or not DB_PATH.is_file():
                return error_response(self, 400, "Database not configured or file missing")

            store = _get_store()

            if parts[0] == "case" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                if len(parts) > 2 and parts[2] == "history":
                    history_rows = store.get_case_history(case_id)
                    history = []
                    for h in history_rows:
                        item = dict(h)
                        item["status"] = h.get("new_status")
                        item["timestamp"] = h.get("changed_at")
                        item["notes"] = h.get("note")
                        history.append(item)
                    return json_response(self, 200, {"case_id": case_id, "history": history})

                case = store.connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                assessment = store.get_latest_assessment(case_id)
                events_count = store.connection.execute("SELECT COUNT(*) FROM events WHERE case_id = ?", (case_id,)).fetchone()[0]
                incidents_count = len(assessment.get("correlations", [])) if assessment else 0
                findings = store.get_case_findings(case_id)

                json_response(self, 200, {
                    "case": dict(case),
                    "assessment": assessment,
                    "stats": {
                        "events": events_count,
                        "incidents": incidents_count,
                        "findings": len(findings),
                    }
                })

            elif parts[0] == "incidents" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                assessment = store.get_latest_assessment(case_id)
                incidents = assessment.get("correlations", []) if assessment else []
                json_response(self, 200, {"incidents": incidents})

            elif parts[0] == "findings" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                findings = store.get_case_findings(case_id)
                json_response(self, 200, {"findings": findings})

            elif parts[0] == "recent_activity" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                events = store.connection.execute(
                    "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp DESC LIMIT 10",
                    (case_id,)
                ).fetchall()
                json_response(self, 200, {"activity": [dict(e) for e in events]})

            elif parts[0] == "search" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                query = parse_qs(parsed_path.query).get("q", [""])[0]
                if not query:
                    results = store.get_case_events(case_id)
                else:
                    results = store.search_events(case_id, query)
                json_response(self, 200, {"results": results[:100]})

            elif parts[0] == "inspect" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                query_params = parse_qs(parsed_path.query)
                event_id = query_params.get("event_id", [None])[0]
                if not event_id:
                    return error_response(self, 400, "event_id query parameter is required")

                event = store.get_event(case_id, event_id)
                if not event:
                    return error_response(self, 404, f"Event not found in case {case_id}: {event_id}")

                investigation = load_investigation(DB_PATH, case_id)
                graph = build_investigation_graph(investigation)

                ev_node_id = f"EVIDENCE:{event_id}"
                findings = []
                for e in graph.get_edges_for_node(ev_node_id):
                    if e.relationship == "SUPPORTS" and e.source_id == ev_node_id:
                        fn = graph.get_node(e.target_id)
                        if fn:
                            findings.append(fn.attributes)

                incidents = []
                for fn_attr in findings:
                    fn_node_id = f"FINDING:{fn_attr.get('finding_id')}"
                    for e in graph.get_edges_for_node(fn_node_id):
                        if e.relationship == "ASSOCIATED_WITH" and e.source_id == fn_node_id:
                            inc_node = graph.get_node(e.target_id)
                            if inc_node and inc_node.attributes not in incidents:
                                incidents.append(inc_node.attributes)

                processes = []
                for e in graph.get_edges_for_node(ev_node_id):
                    if e.relationship == "INVOLVED" and e.target_id == ev_node_id:
                        p_node = graph.get_node(e.source_id)
                        if p_node:
                            processes.append(p_node.attributes)

                json_response(self, 200, {
                    "event": event,
                    "trace": {
                        "findings": findings,
                        "incidents": incidents,
                        "processes": processes,
                    }
                })

            elif parts[0] == "evidence" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                if len(parts) > 2 and parts[2] == "search":
                    qp = parse_qs(parsed_path.query)
                    q = qp.get("q", [""])[0]
                    etype = qp.get("event_type", [""])[0]
                    pname = qp.get("process_name", [""])[0]
                    pid_val = qp.get("pid", [""])[0]
                    pguid = qp.get("process_guid", [""])[0]

                    if q:
                        results = store.search_events(case_id, q)
                    else:
                        results = store.get_case_events(case_id)

                    if etype:
                        results = [e for e in results if str(e.get("event_type", "")).lower() == etype.lower()]
                    if pname:
                        results = [e for e in results if pname.lower() in str(e.get("process_name", "")).lower()]
                    if pid_val:
                        results = [e for e in results if str(e.get("pid", "")) == str(pid_val)]
                    if pguid:
                        results = [e for e in results if pguid.strip("{}").lower() in str(e.get("process_guid", "")).strip("{}").lower()]

                    return json_response(self, 200, {"results": results[:200]})

                elif len(parts) > 3 and parts[3] == "trace":
                    event_id = parts[2]
                    event = store.get_event(case_id, event_id)
                    if not event:
                        return error_response(self, 404, f"Event not found in case {case_id}: {event_id}")

                    timeline = get_case_timeline(DB_PATH, case_id)
                    proc_tree = build_process_tree(timeline)
                    nodes = proc_tree.get("nodes", {})

                    pid_v = str(event.get("pid")) if event.get("pid") is not None else None
                    current_p = nodes.get(pid_v) if pid_v else None
                    parent_p = None
                    if current_p and current_p.get("parent_pid"):
                        parent_p = nodes.get(str(current_p.get("parent_pid")))

                    findings = store.get_event_findings(case_id, event_id)
                    finding_ids = [str(f.get("finding_id")) for f in findings]
                    assessment = store.get_latest_assessment(case_id)
                    matched_corrs = []
                    if assessment and assessment.get("correlations"):
                        for corr in assessment["correlations"]:
                            corr_fids = [str(x) for x in corr.get("finding_ids", [])]
                            if any(fid in corr_fids for fid in finding_ids) or (event_id in corr.get("evidence_ids", [])):
                                matched_corrs.append(corr)

                    return json_response(self, 200, {
                        "event": event,
                        "trace": {
                            "parent_process": parent_p,
                            "current_process": current_p,
                            "findings": findings,
                            "incidents": matched_corrs,
                        }
                    })

                elif len(parts) > 2:
                    event_id = parts[2]
                    event = store.get_event(case_id, event_id)
                    if not event:
                        return error_response(self, 404, f"Event not found in case {case_id}: {event_id}")
                    return json_response(self, 200, {"event": event})

                results = store.get_case_events(case_id)
                return json_response(self, 200, {"results": results[:200]})

            elif parts[0] == "process" and len(parts) > 2:
                case_id, process_query = parts[1], parts[2].strip()
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                investigation = load_investigation(DB_PATH, case_id)
                graph = build_investigation_graph(investigation)

                cleaned_query = process_query
                if cleaned_query.startswith("PROCESS:"):
                    cleaned_query = cleaned_query[8:]
                elif cleaned_query.startswith("guid:"):
                    cleaned_query = cleaned_query[5:]
                elif cleaned_query.startswith("PID:"):
                    cleaned_query = cleaned_query[4:]

                target_node = None
                for cand in [
                    process_query,
                    f"PROCESS:{process_query}",
                    f"PROCESS:{cleaned_query}",
                    f"PROCESS:PID:{cleaned_query}",
                    f"PROCESS:{{{cleaned_query.strip('{}')}}}",
                    f"PROCESS:{cleaned_query.strip('{}')}",
                ]:
                    target_node = graph.get_node(cand)
                    if target_node:
                        break

                if not target_node:
                    process_nodes = graph.get_process_nodes()
                    for n in process_nodes:
                        if str(n.attributes.get("pid")) == cleaned_query:
                            target_node = n
                            break
                    if not target_node:
                        norm_q = cleaned_query.strip("{}").lower()
                        for n in process_nodes:
                            node_guid = n.node_id.replace("PROCESS:", "").strip("{}").lower()
                            attr_guid = str(n.attributes.get("guid", "")).strip("{}").lower()
                            if node_guid == norm_q or attr_guid == norm_q:
                                target_node = n
                                break

                if not target_node:
                    return error_response(self, 404, f"Process not found in case {case_id}: {process_query}")

                pid = target_node.attributes.get("pid")
                guid = target_node.node_id.replace("PROCESS:", "") if not target_node.node_id.startswith("PROCESS:PID:") else "unavailable"

                image_path = target_node.attributes.get("image") or target_node.attributes.get("image_path") or "unavailable"
                command_line = target_node.attributes.get("command_line") or "unavailable"
                if target_node.attributes.get("process_name") and image_path == "unavailable":
                    image_path = target_node.attributes.get("process_name")

                norm_node_guid = guid.strip("{}").lower() if guid != "unavailable" else None

                for ev in investigation.evidence:
                    ev_guid = ev.process_guid.strip("{}").lower() if ev.process_guid else None
                    matches_guid = bool(norm_node_guid and ev_guid and ev_guid == norm_node_guid)
                    matches_pid = bool(pid is not None and str(ev.pid) == str(pid))

                    if matches_guid or (matches_pid and (guid == "unavailable" or matches_guid)):
                        if getattr(ev, "image_path", None) and image_path == "unavailable":
                            image_path = ev.image_path
                        elif getattr(ev, "process_name", None) and image_path == "unavailable":
                            image_path = ev.process_name
                        if ev.command_line and command_line == "unavailable":
                            command_line = ev.command_line

                incoming = [e for e in graph.get_edges_for_node(target_node.node_id) if e.target_id == target_node.node_id and e.relationship == "SPAWNED"]
                parent = None
                if incoming:
                    p_node = graph.get_node(incoming[0].source_id)
                    if p_node:
                        parent = {"name": p_node.label, "pid": p_node.attributes.get("pid"), "guid": p_node.node_id.replace("PROCESS:", "")}

                outgoing = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id and e.relationship == "SPAWNED"]
                children = []
                for e in outgoing:
                    c_node = graph.get_node(e.target_id)
                    if c_node:
                        children.append({"name": c_node.label, "pid": c_node.attributes.get("pid"), "guid": c_node.node_id.replace("PROCESS:", "")})

                files = []
                for e in graph.get_edges_for_node(target_node.node_id):
                    if e.source_id == target_node.node_id and e.relationship in ("CREATED", "MODIFIED", "DELETED", "RENAMED"):
                        f_node = graph.get_node(e.target_id)
                        if f_node:
                            files.append({"rel": e.relationship, "path": f_node.attributes.get("file_path", f_node.label)})

                network = []
                for e in graph.get_edges_for_node(target_node.node_id):
                    if e.source_id == target_node.node_id and e.relationship == "CONNECTED_TO":
                        n_node = graph.get_node(e.target_id)
                        if n_node:
                            network.append(n_node.attributes)

                ev_edges = [e for e in graph.get_edges_for_node(target_node.node_id) if e.source_id == target_node.node_id or e.target_id == target_node.node_id]
                process_ev_ids = {eid for e in ev_edges if e.evidence_ids for eid in e.evidence_ids}

                associated_findings = []
                for fn in graph.get_finding_nodes():
                    supports = [e for e in graph.get_edges_for_node(fn.node_id) if e.target_id == fn.node_id and e.relationship == "SUPPORTS"]
                    if any(se.source_id.replace("EVIDENCE:", "") in process_ev_ids for se in supports):
                        associated_findings.append(fn.attributes)

                json_response(self, 200, {
                    "process": {
                        "name": target_node.label,
                        "pid": pid,
                        "guid": guid,
                        "image_path": image_path,
                        "command_line": command_line,
                    },
                    "parent": parent,
                    "children": children,
                    "files": files,
                    "network": network,
                    "findings": associated_findings,
                })

            elif parts[0] == "timeline" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                investigation = load_investigation(DB_PATH, case_id)
                graph = build_investigation_graph(investigation)
                sequence = reconstruct_attack(investigation, graph)
                timeline = build_advanced_timeline(investigation, sequence, graph)
                json_response(self, 200, {
                    "timeline": [
                        {
                            "timestamp": t.timestamp,
                            "description": t.description,
                            "process_name": t.attributes.get("process_name", ""),
                            "pid": t.pid,
                            "process_guid": t.attributes.get("process_guid", ""),
                        }
                        for t in timeline.entries
                    ]
                })

            elif parts[0] == "tree" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")
                timeline = get_case_timeline(DB_PATH, case_id)
                proc_tree = build_process_tree(timeline)
                json_response(self, 200, {"tree": proc_tree})

            elif parts[0] == "reconstruction" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                investigation = load_investigation(DB_PATH, case_id)
                graph = build_investigation_graph(investigation)
                sequence = reconstruct_attack(investigation, graph)

                status_str = "OK" if sequence.stages else "UNAVAILABLE"
                stages_json = []
                for s in sequence.stages:
                    stages_json.append({
                        "stage_id": s.stage_id,
                        "timestamp": s.timestamp,
                        "stage_type": s.stage_type,
                        "title": s.title,
                        "description": s.description,
                        "evidence_ids": list(s.evidence_ids),
                        "finding_ids": list(s.finding_ids),
                        "correlation_ids": list(s.correlation_ids),
                    })
                json_response(self, 200, {"stages": stages_json, "status": status_str})

            elif parts[0] == "validation" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                val_res = validate_investigation(DB_PATH, case_id)
                json_response(self, 200, {
                    "case_id": case_id,
                    "case_exists": val_res.case_exists,
                    "assessment_available": val_res.assessment_available,
                    "assessment_score": val_res.assessment_score,
                    "assessment_severity": val_res.assessment_severity,
                    "findings_count": val_res.findings_count,
                    "findings_with_evidence": f"{val_res.findings_with_evidence}/{val_res.findings_total}",
                    "incidents_count": val_res.incidents_count,
                    "incidents_with_findings": f"{val_res.incidents_with_findings}/{val_res.incidents_total}",
                    "incident_evidence_valid": f"{val_res.incident_evidence_valid}/{val_res.incident_evidence_total}",
                    "evidence_count": val_res.evidence_count,
                    "evidence_traceable": f"{val_res.evidence_traceable}/{val_res.evidence_total}",
                    "process_nodes_ok": val_res.process_nodes_ok,
                    "process_relationships_ok": val_res.process_relationships_ok,
                    "timeline_ok": val_res.timeline_ok,
                    "reconstruction_status": val_res.reconstruction_status,
                    "cross_case_references": val_res.cross_case_references,
                    "passed": val_res.passed,
                    "rendered": val_res.render(),
                    "issues": [{"category": i.category, "message": i.message, "severity": i.severity} for i in val_res.issues],
                })

            elif parts[0] == "investigation" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                investigation = load_investigation(DB_PATH, case_id)
                if len(parts) > 2 and parts[2] == "graph":
                    graph = build_investigation_graph(investigation)
                    nodes = [{"node_id": n.node_id, "node_type": n.node_type, "label": n.label, "attributes": n.attributes} for n in graph.nodes.values()]
                    edges = [{"edge_id": e.edge_id, "source_id": e.source_id, "target_id": e.target_id, "relationship": e.relationship, "evidence_ids": list(e.evidence_ids)} for e in graph.edges]
                    return json_response(self, 200, {"nodes": nodes, "edges": edges})
                elif len(parts) > 2 and parts[2] == "tree":
                    tree = build_process_tree(investigation.timeline)
                    return json_response(self, 200, {"tree": tree})
                elif len(parts) > 2 and parts[2] == "validation":
                    val_res = validate_investigation(DB_PATH, case_id)
                    return json_response(self, 200, {
                        "case_id": case_id,
                        "passed": val_res.passed,
                        "validation": {
                            "valid": val_res.passed,
                            "passed": val_res.passed,
                            "checks_performed": "Complete",
                            "errors": [i.message for i in val_res.issues if i.severity == "ERROR"],
                            "issues": [{"category": i.category, "message": i.message, "severity": i.severity} for i in val_res.issues],
                        },
                        "rendered": val_res.render(),
                        "issues": [{"category": i.category, "message": i.message, "severity": i.severity} for i in val_res.issues],
                    })

                s = investigation.summary
                json_response(self, 200, {
                    "case_id": s.case_id,
                    "summary": {
                        "case_id": s.case_id,
                        "case_name": s.case_name,
                        "host": s.host,
                        "status": s.status,
                        "total_nodes": s.process_count + s.evidence_count,
                        "total_edges": s.correlation_count + s.finding_count,
                        "evidence_count": s.evidence_count,
                        "finding_count": s.finding_count,
                        "correlation_count": s.correlation_count,
                        "process_count": s.process_count,
                        "threat_score": s.threat_score,
                        "severity": s.severity,
                        "confidence": s.confidence,
                    },
                    "investigation": {
                        "case_id": s.case_id,
                        "case_name": s.case_name,
                        "host": s.host,
                        "status": s.status,
                        "evidence_count": s.evidence_count,
                        "finding_count": s.finding_count,
                        "correlation_count": s.correlation_count,
                        "process_count": s.process_count,
                        "threat_score": s.threat_score,
                        "severity": s.severity,
                        "confidence": s.confidence,
                        "first_activity": s.first_activity,
                        "last_activity": s.last_activity,
                    }
                })

            elif parts[0] == "custody" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")
                events = store.get_custody_events(case_id)
                json_response(self, 200, {"case_id": case_id, "custody_events": events, "entries": events})

            elif parts[0] == "export" and len(parts) > 1 and parts[1] == "lock":
                qs = parse_qs(parsed_path.query)
                output_param = qs.get("output", [""])[0] or qs.get("output_dir", [""])[0] or qs.get("case_id", [""])[0] or "exports"
                try:
                    lock_info = read_export_lock(Path(output_param))
                    owner_status = get_lock_owner_status(lock_info)
                    json_response(self, 200, {"locked": lock_info is not None, "lock": lock_info, "owner_status": owner_status.value})
                except FileNotFoundError:
                    json_response(self, 200, {"locked": False, "lock": None, "owner_status": "NONE"})

            elif parts[0] == "database" and len(parts) > 1 and parts[1] in ("check", "status"):
                is_ok = check_database_integrity(DB_PATH)
                json_response(self, 200, {
                    "status": "OK" if is_ok else "CORRUPTED",
                    "ok": is_ok,
                    "database": str(DB_PATH.resolve()),
                })

            else:
                error_response(self, 404, "Unknown API endpoint")

        except ValueError as exc:
            error_response(self, 400, str(exc))
        except Exception as exc:
            logger.exception("API Error")
            error_response(self, 500, str(exc))
        finally:
            if "store" in locals():
                store.close()

    def handle_api_post(self, path: str, parsed_path: Any) -> None:
        """Route POST API requests."""
        parts = [unquote(p) for p in path.split("/")[2:]]  # Drop ['', 'api']

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            body = json.loads(post_data) if post_data.strip() else {}
        except Exception:
            body = {}

        try:
            if parts[0] == "report" and len(parts) > 1:
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")

                if not DB_PATH or not DB_PATH.is_file():
                    return error_response(self, 400, "Database not configured")

                store = _get_store()
                try:
                    case = store.get_case(case_id)
                    if not case:
                        return error_response(self, 404, f"Case not found: {case_id}")
                finally:
                    store.close()

                report_text = generate_case_report(DB_PATH, case_id)
                reports_dir = Path("reports").resolve()
                reports_dir.mkdir(exist_ok=True)

                out_path = (reports_dir / f"{case_id}_report.txt").resolve()
                if reports_dir not in out_path.parents and out_path != reports_dir:
                    return error_response(self, 400, "Path traversal rejected in report path")

                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(report_text)

                json_response(self, 200, {
                    "message": "Report generated",
                    "path": str(out_path),
                    "content": report_text,
                })

            elif parts[0] == "collect":
                case_id = body.get("case_id")
                file_path = body.get("file_path")
                format_type = body.get("format_type", "auto")

                if not case_id or not file_path:
                    return error_response(self, 400, "case_id and file_path are required parameters")

                _validate_safe_id(case_id, "case_id")

                if not DB_PATH or not DB_PATH.is_file():
                    return error_response(self, 400, "Database not configured")

                store = _get_store()
                try:
                    case = store.get_case(case_id)
                    if not case:
                        return error_response(self, 404, f"Case not found: {case_id}")
                finally:
                    store.close()

                target_file = Path(file_path).resolve()
                if not target_file.is_file():
                    return error_response(self, 400, f"Evidence file not found or is a directory: {file_path}")

                if target_file.suffix.lower() not in (".xml", ".json"):
                    return error_response(self, 400, f"Unsupported file type: '{target_file.suffix}'. Only .xml and .json evidence files are allowed.")

                if target_file.stat().st_size > MAX_COLLECTION_FILE_SIZE:
                    return error_response(self, 400, f"Evidence file exceeds maximum allowed size of 50 MB ({target_file.stat().st_size} bytes)")

                summary = run_collect_file_command(
                    database_path=DB_PATH,
                    case_id=case_id,
                    file_path=target_file,
                    format_type=format_type,
                )
                json_response(self, 200, {
                    "message": "Collection complete",
                    "summary": summary,
                })

            elif parts[0] == "cases" or (parts[0] == "case" and len(parts) > 1 and parts[1] == "create"):
                if not DB_PATH:
                    return error_response(self, 400, "Database not configured")
                case_id = body.get("case_id")
                case_name = body.get("case_name")
                host = body.get("host")
                if not case_id:
                    return error_response(self, 400, "case_id is required")
                _validate_safe_id(case_id, "case_id")
                store = EvidenceStore(DB_PATH)
                try:
                    existing = store.get_case(case_id)
                    if existing:
                        return error_response(self, 400, f"Case already exists: {case_id}")
                    store.create_case(case_id, case_name, host)
                    created = store.get_case(case_id)
                finally:
                    store.close()
                json_response(self, 201, {"message": "Case created", "case": created})

            elif parts[0] == "case" and len(parts) > 2 and parts[2] in ("status", "update"):
                if not DB_PATH or not DB_PATH.is_file():
                    return error_response(self, 400, "Database not configured")
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                status = body.get("status")
                note = body.get("notes") or body.get("note")
                if not status:
                    return error_response(self, 400, "status is required")
                status_raw = str(status).upper().strip()
                status_map = {
                    "IN_PROGRESS": "TRIAGED",
                    "INVESTIGATING": "TRIAGED",
                    "ARCHIVED": "CLOSED",
                }
                status_normalized = status_map.get(status_raw, status_raw)
                store = _get_store()
                try:
                    store.update_case_status(case_id, status_normalized, note or "")
                    updated = store.get_case(case_id)
                finally:
                    store.close()
                json_response(self, 200, {"message": "Case status updated", "case": updated, "status": status_normalized})

            elif parts[0] == "ingest":
                if not DB_PATH:
                    return error_response(self, 400, "Database not configured")
                case_id = body.get("case_id")
                file_path = body.get("file_path")
                format_type = body.get("format_type", "auto")
                case_name = body.get("case_name")
                host = body.get("host")
                if not case_id or not file_path:
                    return error_response(self, 400, "case_id and file_path are required")
                _validate_safe_id(case_id, "case_id")
                target_file = Path(file_path).resolve()
                if not target_file.is_file():
                    return error_response(self, 400, f"Evidence file not found: {file_path}")
                summary = ingest_evidence(
                    database_path=DB_PATH,
                    case_id=case_id,
                    file_path=target_file,
                    format_type=format_type,
                    case_name=case_name,
                    host=host,
                )
                events_ingested = summary.get("events_accepted", summary.get("events_read", summary.get("events_ingested", 0))) if isinstance(summary, dict) else 0
                findings_generated = summary.get("findings_count", summary.get("findings_generated", 0)) if isinstance(summary, dict) else 0
                incidents_correlated = summary.get("correlations_count", summary.get("incidents_correlated", 0)) if isinstance(summary, dict) else 0
                json_response(self, 200, {
                    "message": "Ingestion complete",
                    "summary": summary,
                    "events_ingested": events_ingested,
                    "findings_generated": findings_generated,
                    "incidents_correlated": incidents_correlated,
                })

            elif parts[0] == "custody" and len(parts) > 1:
                if not DB_PATH or not DB_PATH.is_file():
                    return error_response(self, 400, "Database not configured")
                case_id = parts[1]
                _validate_safe_id(case_id, "case_id")
                artifact_path = body.get("artifact_path") or body.get("artifact")
                sha256 = body.get("sha256")
                act_raw = (body.get("action") or "created").lower().strip()
                action = act_raw if act_raw in ("created", "verified", "exported", "reviewed") else (
                    "created" if act_raw in ("collected", "create", "new") else
                    "reviewed" if act_raw in ("transferred", "transfer", "analyzed") else
                    "exported" if act_raw in ("archived", "archive", "export") else "created"
                )
                analyst = body.get("analyst", "analyst")
                note = body.get("notes") or body.get("note")
                if not artifact_path:
                    return error_response(self, 400, "artifact_path is required")
                art_p = Path(artifact_path).resolve()
                if not sha256:
                    if art_p.is_file():
                        sha256 = sha256_file(art_p)
                    else:
                        sha256 = "0" * 64
                store = _get_store()
                try:
                    store.record_custody_event(case_id, str(art_p), sha256, action, analyst, note or "")
                finally:
                    store.close()
                entry_dict = {
                    "case_id": case_id,
                    "artifact": str(art_p),
                    "action": body.get("action", action),
                    "action_db": action,
                    "analyst": analyst,
                    "sha256": sha256,
                    "notes": note,
                }
                json_response(self, 201, {"message": "Custody event recorded", "entry": entry_dict})

            elif parts[0] == "integrity" and len(parts) > 1:
                if parts[1] == "hash":
                    input_path = body.get("input_path") or body.get("target_path")
                    output_path = body.get("output_path") or body.get("manifest_path")
                    if not input_path:
                        return error_response(self, 400, "input_path is required")
                    in_p = Path(input_path).resolve()
                    if not in_p.exists():
                        return error_response(self, 400, f"Input path not found: {input_path}")
                    out_p = Path(output_path).resolve() if output_path else None
                    manifest_path = write_integrity_manifest(in_p, out_p)
                    content = Path(manifest_path).read_text(encoding="utf-8")
                    json_response(self, 200, {"manifest_path": str(manifest_path), "content": content})
                elif parts[1] == "verify":
                    artifact_path = body.get("artifact_path") or body.get("target_path")
                    manifest_path = body.get("manifest_path")
                    if not artifact_path or not manifest_path:
                        return error_response(self, 400, "artifact_path and manifest_path are required")
                    art_p = Path(artifact_path).resolve()
                    man_p = Path(manifest_path).resolve()
                    if not art_p.exists():
                        return error_response(self, 400, f"Artifact not found: {artifact_path}")
                    if not man_p.is_file():
                        return error_response(self, 400, f"Manifest not found: {manifest_path}")
                    verified = verify_integrity_manifest(art_p, man_p)
                    json_response(self, 200, {
                        "verified": verified,
                        "artifact": str(art_p),
                        "manifest": str(man_p),
                        "status": "MATCHED" if verified else "FAILED",
                    })
                else:
                    error_response(self, 404, "Unknown integrity endpoint")

            elif parts[0] == "export":
                if len(parts) > 1 and parts[1] == "unlock":
                    output_path = body.get("output_path") or body.get("output_dir") or "exports"
                    force = bool(body.get("force", True))
                    break_lock = bool(body.get("break_lock", True))
                    try:
                        removed = remove_export_lock(Path(output_path), force=force, break_lock=break_lock)
                    except FileNotFoundError:
                        removed = False
                    json_response(self, 200, {"message": "Export lock removed", "removed_lock": removed})
                else:
                    if not DB_PATH or not DB_PATH.is_file():
                        return error_response(self, 400, "Database not configured")
                    case_id = body.get("case_id")
                    output_path = body.get("output_path") or body.get("output_dir")
                    if not case_id or not output_path:
                        return error_response(self, 400, "case_id and output_path are required")
                    _validate_safe_id(case_id, "case_id")
                    exported = export_case(DB_PATH, case_id, Path(output_path))
                    json_response(self, 200, {
                        "message": "Export completed successfully",
                        "export_path": str(exported),
                        "exported_path": str(exported),
                    })

            elif parts[0] == "database" and len(parts) > 1:
                if not DB_PATH:
                    return error_response(self, 400, "Database not configured")
                if parts[1] == "check":
                    if not DB_PATH.is_file():
                        EvidenceStore(DB_PATH).close()
                    is_ok = check_database_integrity(DB_PATH)
                    json_response(self, 200, {"status": "OK" if is_ok else "CORRUPTED", "ok": is_ok, "database": str(DB_PATH.resolve())})
                elif parts[1] == "backup":
                    if not DB_PATH.is_file():
                        EvidenceStore(DB_PATH).close()
                    output_path = body.get("output_path") or body.get("backup_path")
                    out_p = Path(output_path) if output_path else None
                    backup_p = backup_database(DB_PATH, out_p)
                    json_response(self, 200, {"message": "Database backup created", "backup_path": str(backup_p)})
                elif parts[1] == "restore":
                    confirm = bool(body.get("confirm", True))
                    if not confirm:
                        return error_response(self, 400, "Database restore requires explicit confirmation (confirm: true)")
                    backup_path = body.get("backup_path")
                    target_path = body.get("target_path")
                    if not backup_path:
                        return error_response(self, 400, "backup_path is required")
                    b_p = Path(backup_path).resolve()
                    if not b_p.is_file():
                        return error_response(self, 400, f"Backup file not found: {backup_path}")
                    t_p = Path(target_path).resolve() if target_path else DB_PATH
                    restored_p = restore_database(b_p, t_p)
                    json_response(self, 200, {"message": "Database restored successfully", "status": "OK", "restored_path": str(restored_p)})
                else:
                    error_response(self, 404, "Unknown database endpoint")

            elif parts[0] == "static" and len(parts) > 1 and parts[1] == "analyze":
                file_path = body.get("file_path")
                case_id = body.get("case_id")
                if not file_path:
                    return error_response(self, 400, "file_path is required")
                f_p = Path(file_path).resolve()
                if not f_p.is_file():
                    return error_response(self, 400, f"Target file not found: {file_path}")
                analyzer = StaticAnalyzer()
                res = analyzer.analyze_file(f_p)
                res_dict = res.to_dict()
                finding_id = None
                if case_id and DB_PATH and DB_PATH.is_file():
                    _validate_safe_id(case_id, "case_id")
                    store = _get_store()
                    try:
                        finding_id = ingest_static_finding(store, case_id, res)
                    finally:
                        store.close()
                json_response(self, 200, {"analysis": res_dict, "finding_id": finding_id})

            elif parts[0] == "phishing" and len(parts) > 1 and parts[1] == "analyze":
                text = body.get("text") or body.get("body") or ""
                sender = body.get("sender") or ""
                subject = body.get("subject") or ""
                file_path = body.get("file_path")
                case_id = body.get("case_id")
                if file_path:
                    f_p = Path(file_path).resolve()
                    if not f_p.is_file():
                        return error_response(self, 400, f"Message file not found: {file_path}")
                    raw = f_p.read_text(encoding="utf-8", errors="replace")
                    if f_p.suffix.lower() == ".eml":
                        payload = MessagePayload.from_eml(raw, sender=sender)
                    else:
                        payload = MessagePayload.from_text(raw, sender=sender)
                else:
                    if not text and not subject:
                        return error_response(self, 400, "text or file_path is required")
                    payload = MessagePayload.from_dict({"text": str(text), "sender": sender, "subject": subject})
                detector = PhishingDetector()
                res = detector.analyze(payload)
                res_dict = res.to_dict()
                res_dict["threat_level"] = (res_dict.get("risk_level") or "LOW").upper()
                finding_id = None
                if case_id and DB_PATH and DB_PATH.is_file():
                    _validate_safe_id(case_id, "case_id")
                    store = _get_store()
                    try:
                        source = f_p.name if file_path else "analyst_console_text"
                        finding_id = ingest_phishing_finding(store, case_id, res, source)
                    finally:
                        store.close()
                json_response(self, 200, {"analysis": res_dict, "assessment": res_dict, "finding_id": finding_id})

            elif parts[0] == "script" and len(parts) > 1 and parts[1] == "analyze":
                file_path = body.get("file_path")
                text = body.get("text")
                event_id = body.get("event_id")
                case_id = body.get("case_id")
                language = body.get("language")

                provided = [
                    name for name, value in
                    (("file_path", file_path), ("text", text), ("event_id", event_id)) if value
                ]
                if len(provided) != 1:
                    return error_response(self, 400, "Provide exactly one of file_path, text, or event_id")

                analyzer = ScriptAnalyzer()
                finding_ids = None

                if event_id:
                    if not case_id:
                        return error_response(self, 400, "event_id requires case_id")
                    _validate_safe_id(case_id, "case_id")
                    if not DB_PATH or not DB_PATH.is_file():
                        return error_response(self, 400, "Database not configured")
                    store = _get_store()
                    try:
                        if store.get_case(case_id) is None:
                            return error_response(self, 404, f"Case not found: {case_id}")
                        event = store.get_event(case_id, event_id)
                        if event is None:
                            return error_response(self, 404, f"Event not found in case {case_id}: {event_id}")
                        command_line = event.get("command_line")
                        if not command_line or not str(command_line).strip():
                            return error_response(self, 400, f"Event {event_id} has no command line to analyze")
                        try:
                            res = analyzer.analyze_text(str(command_line), file_name=event_id, language=language)
                        except ScriptAnalysisError as exc:
                            return error_response(self, 400, str(exc))
                        finding_ids = ingest_script_finding(store, case_id, res, event_id=event_id)
                    finally:
                        store.close()

                elif file_path:
                    try:
                        res = analyzer.analyze_file(file_path, language=language)
                    except ScriptAnalysisError as exc:
                        return error_response(self, 400, str(exc))
                    except FileNotFoundError:
                        return error_response(self, 400, f"Script file not found: {file_path}")
                    if case_id:
                        _validate_safe_id(case_id, "case_id")
                        if not DB_PATH or not DB_PATH.is_file():
                            return error_response(self, 400, "Database not configured")
                        store = _get_store()
                        try:
                            if store.get_case(case_id) is None:
                                return error_response(self, 404, f"Case not found: {case_id}")
                            finding_ids = ingest_script_finding(store, case_id, res)
                        finally:
                            store.close()

                else:  # text
                    if case_id:
                        return error_response(
                            self, 400,
                            "Pasted text cannot be added to a case; analyze a file or stored event instead",
                        )
                    try:
                        res = analyzer.analyze_text(str(text), language=language)
                    except ScriptAnalysisError as exc:
                        return error_response(self, 400, str(exc))

                json_response(self, 200, {"analysis": res.to_dict(), "finding_ids": finding_ids})

            elif parts[0] == "ioc" and len(parts) > 1 and parts[1] == "analyze":
                file_path = body.get("file_path")
                case_id = body.get("case_id")

                if not file_path or not str(file_path).strip():
                    return error_response(self, 400, "file_path is required")

                extractor = IocExtractor()
                try:
                    res = extractor.analyze_file(file_path)
                except IocAnalysisError as exc:
                    return error_response(self, 400, str(exc))
                except FileNotFoundError:
                    return error_response(self, 404, f"IOC input file not found: {file_path}")

                finding_ids = None
                if case_id:
                    _validate_safe_id(case_id, "case_id")
                    if not DB_PATH or not DB_PATH.is_file():
                        return error_response(self, 400, "Database not configured")
                    store = _get_store()
                    try:
                        if store.get_case(case_id) is None:
                            return error_response(self, 404, f"Case not found: {case_id}")
                        finding_ids = ingest_ioc_finding(store, case_id, res)
                    finally:
                        store.close()

                json_response(self, 200, {"analysis": res.to_dict(), "finding_ids": finding_ids})

            elif parts[0] == "pcap" and len(parts) > 1 and parts[1] == "analyze":
                file_path = body.get("file_path")
                case_id = body.get("case_id")

                if not file_path or not str(file_path).strip():
                    return error_response(self, 400, "file_path is required")

                analyzer = PcapAnalyzer()
                try:
                    res = analyzer.analyze_file(file_path)
                except PcapAnalysisError as exc:
                    return error_response(self, 400, str(exc))
                except FileNotFoundError:
                    return error_response(self, 404, f"PCAP file not found: {file_path}")

                finding_ids = None
                if case_id:
                    _validate_safe_id(case_id, "case_id")
                    if not DB_PATH or not DB_PATH.is_file():
                        return error_response(self, 400, "Database not configured")
                    store = _get_store()
                    try:
                        if store.get_case(case_id) is None:
                            return error_response(self, 404, f"Case not found: {case_id}")
                        finding_ids = ingest_pcap_finding(store, case_id, res)
                    finally:
                        store.close()

                json_response(self, 200, {"analysis": res.to_dict(), "finding_ids": finding_ids})

            else:
                error_response(self, 404, "Unknown API POST endpoint")

        except ValueError as exc:
            error_response(self, 400, str(exc))
        except FileNotFoundError as exc:
            error_response(self, 404, str(exc))
        except FileExistsError as exc:
            error_response(self, 409, str(exc))
        except Exception as exc:
            logger.exception("API POST Error")
            error_response(self, 500, str(exc))


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the HTTP dashboard server securely on specified host and port."""
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, DashboardHandler)
    db_msg = f"Using database: {DB_PATH.absolute()}" if DB_PATH else "WARNING: No database configured. Dashboard will show empty state."
    display_host = "localhost" if host in ("127.0.0.1", "") else host
    print(f"Starting RansomEye dashboard on http://{display_host}:{port}")
    print(db_msg)
    httpd.serve_forever()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RansomEye Analyst Dashboard")
    parser.add_argument("--database", "-d", help="Path to the RansomEye SQLite database")
    parser.add_argument("--host", "-H", default="127.0.0.1", help="Host address to bind the dashboard server (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to run the dashboard on (default: 8080)")
    args = parser.parse_args()

    if args.database:
        DB_PATH = Path(args.database)
    elif os.environ.get("RANSOMEYE_DB"):
        DB_PATH = Path(os.environ["RANSOMEYE_DB"])

    run_server(host=args.host, port=args.port)
