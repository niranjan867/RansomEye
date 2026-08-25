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
from ransomeye.commands import run_collect_file_command
from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.investigation_validation import validate_investigation
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.report import generate_case_report
from ransomeye.storage import EvidenceStore

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
        parts = path.split("/")[2:]  # Drop ['', 'api']

        try:
            if parts[0] == "cases":
                if not DB_PATH or not DB_PATH.is_file():
                    json_response(self, 200, {"cases": []})
                    return
                store = _get_store()
                cases = store.connection.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
                json_response(self, 200, {"cases": [dict(c) for c in cases]})
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

            elif parts[0] == "process" and len(parts) > 2:
                case_id, process_query = parts[1], parts[2]
                _validate_safe_id(case_id, "case_id")
                case = store.get_case(case_id)
                if not case:
                    return error_response(self, 404, f"Case not found: {case_id}")

                investigation = load_investigation(DB_PATH, case_id)
                graph = build_investigation_graph(investigation)

                target_id = f"PROCESS:{process_query}"
                node = graph.get_node(target_id)
                matched_nodes = [node] if node else [n for n in graph.get_process_nodes() if str(n.attributes.get("pid")) == str(process_query)]

                if not matched_nodes:
                    return error_response(self, 404, f"Process not found in case {case_id}: {process_query}")

                target_node = matched_nodes[0]
                pid = target_node.attributes.get("pid")
                guid = target_node.node_id.replace("PROCESS:", "") if not target_node.node_id.startswith("PROCESS:PID:") else "unavailable"

                image_path = target_node.attributes.get("image") or target_node.attributes.get("image_path") or "unavailable"
                command_line = target_node.attributes.get("command_line") or "unavailable"

                for ev in investigation.evidence:
                    if ev.process_guid == guid or (str(ev.pid) == str(pid) and (guid == "unavailable" or ev.process_guid == guid)):
                        if getattr(ev, "image_path", None) and image_path == "unavailable":
                            image_path = ev.image_path
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
        parts = path.split("/")[2:]  # Drop ['', 'api']

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

            else:
                error_response(self, 404, "Unknown API POST endpoint")

        except ValueError as exc:
            error_response(self, 400, str(exc))
        except Exception as exc:
            logger.exception("API POST Error")
            error_response(self, 500, str(exc))


def run_server(port: int = 8080) -> None:
    """Run the HTTP dashboard server."""
    server_address = ("", port)
    httpd = ThreadingHTTPServer(server_address, DashboardHandler)
    db_msg = f"Using database: {DB_PATH.absolute()}" if DB_PATH else "WARNING: No database configured. Dashboard will show empty state."
    print(f"Starting RansomEye dashboard on http://localhost:{port}")
    print(db_msg)
    httpd.serve_forever()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RansomEye Analyst Dashboard")
    parser.add_argument("--database", "-d", help="Path to the RansomEye SQLite database")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to run the dashboard on")
    args = parser.parse_args()

    if args.database:
        DB_PATH = Path(args.database)
    elif os.environ.get("RANSOMEYE_DB"):
        DB_PATH = Path(os.environ["RANSOMEYE_DB"])

    run_server(args.port)
