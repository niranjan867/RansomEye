"""Investigation completeness and integrity validator for RansomEye."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import get_case_timeline


@dataclass
class ValidationIssue:
    category: str
    message: str
    severity: str = "ERROR"


@dataclass
class InvestigationValidationResult:
    case_id: str
    case_exists: bool = False
    assessment_available: bool = False
    assessment_score: int | None = None
    assessment_severity: str | None = None
    assessment_confidence: float | None = None
    findings_count: int = 0
    findings_with_evidence: int = 0
    findings_total: int = 0
    incidents_count: int = 0
    incidents_with_findings: int = 0
    incidents_total: int = 0
    incident_evidence_valid: int = 0
    incident_evidence_total: int = 0
    evidence_count: int = 0
    evidence_traceable: int = 0
    evidence_total: int = 0
    process_nodes_ok: bool = True
    process_relationships_ok: bool = True
    timeline_ok: bool = True
    reconstruction_status: str = "UNAVAILABLE"
    cross_case_references: int = 0
    passed: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)

    def render(self) -> str:
        """Render formatted investigation validation report."""
        if not self.case_exists:
            db_issue = next((i for i in self.issues if i.category == "DATABASE"), None)
            if db_issue:
                return f"Validation failed: {db_issue.message}"
            return f"Case not found: {self.case_id}"

        def _dot(label: str, val: Any, width: int = 27) -> str:
            dots_len = max(1, width - len(str(label)))
            return f"{label} {'.' * dots_len} {val}"

        lines = [
            "RANSOMEYE INVESTIGATION VALIDATION",
            "==================================",
            "",
            f"Case: {self.case_id}",
            "",
            "CASE",
            "----",
            _dot("Case exists", "PASS"),
            "",
            "ASSESSMENT",
            "----------",
        ]

        if self.assessment_available:
            score_str = str(self.assessment_score) if self.assessment_score is not None else "N/A"
            sev_str = self.assessment_severity or "N/A"
            conf_str = f"{self.assessment_confidence:.2f}" if self.assessment_confidence is not None else "N/A"
            lines.extend([
                _dot("Assessment", "AVAILABLE"),
                _dot("Score", score_str),
                _dot("Severity", sev_str),
                _dot("Confidence", conf_str),
            ])
        else:
            lines.append(_dot("Assessment", "UNAVAILABLE"))

        lines.extend([
            "",
            "TRACEABILITY",
            "------------",
            _dot("Findings", self.findings_count),
            _dot("Findings with evidence", f"{self.findings_with_evidence}/{self.findings_total}"),
            _dot("Incidents", self.incidents_count),
            _dot("Incidents with findings", f"{self.incidents_with_findings}/{self.incidents_total}"),
            _dot("Incident evidence", f"{self.incident_evidence_valid}/{self.incident_evidence_total}"),
            _dot("Evidence traceable", f"{self.evidence_traceable}/{self.evidence_total}"),
            "",
            "PROCESS INTEGRITY",
            "-----------------",
            _dot("Process nodes", "OK" if self.process_nodes_ok else "FAIL"),
            _dot("Parent/child relationships", "OK" if self.process_relationships_ok else "FAIL"),
            "",
            "TIMELINE",
            "--------",
            _dot("Timeline", "OK" if self.timeline_ok else "FAIL"),
            "",
            "RECONSTRUCTION",
            "--------------",
            _dot("Reconstruction", self.reconstruction_status),
            "",
            "CASE ISOLATION",
            "--------------",
            _dot("Cross-case references", self.cross_case_references),
            "",
            "RESULT",
            "------",
            "PASS" if self.passed else "FAIL",
        ])

        if self.issues:
            lines.extend(["", "Problems:"])
            for issue in self.issues:
                lines.append(f"* {issue.message}")

        return "\n".join(lines)


def _compute_deterministic_finding_id(f: dict[str, Any]) -> str:
    """Compute deterministic F-<digest> finding ID matching threat_assessment.py logic."""
    ftype = str(f.get("finding_type") or f.get("type", "finding"))
    eids = sorted(list(set(str(e) for e in (f.get("event_ids") or []))))
    technique = str(f.get("technique") or "")
    reason = str(f.get("reason") or "")

    payload = {
        "event_ids": eids,
        "reason": reason,
        "technique": technique,
        "type": ftype,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
    return f"F-{digest}"


def validate_investigation(database_path: str | Path, case_id: str) -> InvestigationValidationResult:
    """Validate completeness and integrity of a stored investigation."""
    result = InvestigationValidationResult(case_id=case_id)
    db_file = Path(database_path)

    if not db_file.is_file():
        result.case_exists = False
        result.passed = False
        result.issues.append(ValidationIssue("DATABASE", f"Database not found: {database_path}"))
        return result

    try:
        store = EvidenceStore(database_path)
    except (sqlite3.Error, ValueError, OSError) as exc:
        result.case_exists = False
        result.passed = False
        result.issues.append(ValidationIssue("DATABASE", f"Invalid database: {exc}"))
        return result

    try:
        case = store.get_case(case_id)
        if case is None:
            result.case_exists = False
            result.passed = False
            result.issues.append(ValidationIssue("CASE", f"Case not found: {case_id}"))
            return result

        result.case_exists = True

        # 1. Assessment
        assessment = store.get_latest_assessment(case_id)
        if assessment:
            result.assessment_available = True
            result.assessment_score = assessment.get("score")
            result.assessment_severity = assessment.get("severity")
            result.assessment_confidence = assessment.get("confidence")

        # 2. Findings -> Evidence & Deterministic ID Check
        findings = store.get_case_findings(case_id)
        result.findings_count = len(findings)
        result.findings_total = len(findings)

        case_event_ids = {e["event_id"] for e in store.get_case_events(case_id)}
        case_finding_ids: set[str] = set()

        for f in findings:
            fid = f["finding_id"]
            fid_str = str(fid)
            case_finding_ids.add(fid_str)
            det_id = _compute_deterministic_finding_id(f)
            case_finding_ids.add(det_id)

            if fid_str.startswith("F-") and fid_str != det_id:
                result.issues.append(ValidationIssue(
                    "DETERMINISTIC_ID",
                    f"Finding {fid_str} ID mismatch: expected {det_id}, found {fid_str}"
                ))
            elif f.get("id") and str(f["id"]).startswith("F-") and str(f["id"]) != det_id:
                result.issues.append(ValidationIssue(
                    "DETERMINISTIC_ID",
                    f"Finding {f['id']} ID mismatch: expected {det_id}, found {f['id']}"
                ))

            if f.get("case_id") and f["case_id"] != case_id:
                result.cross_case_references += 1
                result.issues.append(ValidationIssue(
                    "ISOLATION",
                    f"Finding {fid} belongs to case {f['case_id']}, not {case_id}"
                ))

            ev_ids = store.get_finding_event_ids(fid)
            if not ev_ids:
                result.issues.append(ValidationIssue(
                    "FINDING_EVIDENCE",
                    f"Finding {fid} ({f.get('finding_type')}) has no supporting evidence"
                ))

            ev_valid = True
            for eid in ev_ids:
                if eid not in case_event_ids:
                    ev_valid = False
                    other_case = store.connection.execute(
                        "SELECT case_id FROM events WHERE event_id = ?", (eid,)
                    ).fetchone()
                    if other_case:
                        result.cross_case_references += 1
                        result.issues.append(ValidationIssue(
                            "ISOLATION",
                            f"Finding {fid} references evidence {eid} from another case ({other_case[0]})"
                        ))
                    else:
                        result.issues.append(ValidationIssue(
                            "FINDING_EVIDENCE",
                            f"Finding {fid} references missing evidence {eid}"
                        ))

            if ev_ids and ev_valid:
                result.findings_with_evidence += 1

        # 3. Incident -> Findings & Incident -> Evidence
        correlations = assessment.get("correlations", []) if assessment else []
        result.incidents_count = len(correlations)
        result.incidents_total = len(correlations)

        for inc in correlations:
            inc_id = inc.get("incident_id", "unknown")
            if inc.get("case_id") and inc["case_id"] != case_id:
                result.cross_case_references += 1
                result.issues.append(ValidationIssue(
                    "ISOLATION",
                    f"Incident {inc_id} belongs to another case ({inc['case_id']})"
                ))

            ref_findings = [str(x) for x in inc.get("finding_ids", [])]
            inc_ev_ids = set(inc.get("evidence_ids", []) or inc.get("evidence_event_ids", []))

            assoc_findings = []
            for f in findings:
                f_str = str(f["finding_id"])
                d_id = _compute_deterministic_finding_id(f)
                f_evs = set(f.get("event_ids", []))

                if (f_str in ref_findings) or (d_id in ref_findings) or (f_evs and inc_ev_ids and f_evs.intersection(inc_ev_ids)):
                    assoc_findings.append(f)

            if not assoc_findings and (ref_findings or inc_ev_ids):
                result.issues.append(ValidationIssue(
                    "INCIDENT_FINDINGS",
                    f"Incident {inc_id} has no supporting findings"
                ))

            for rfid in ref_findings:
                if rfid not in case_finding_ids:
                    other_f = store.connection.execute(
                        "SELECT case_id FROM findings WHERE finding_id = ?", (rfid,)
                    ).fetchone()
                    if other_f:
                        result.cross_case_references += 1
                        result.issues.append(ValidationIssue(
                            "ISOLATION",
                            f"Incident {inc_id} references finding {rfid} from another case ({other_f[0]})"
                        ))
                    else:
                        result.issues.append(ValidationIssue(
                            "INCIDENT_FINDINGS",
                            f"Incident {inc_id} references missing finding {rfid}"
                        ))

            if assoc_findings:
                result.incidents_with_findings += 1

            ref_ev = inc.get("evidence_ids", []) or inc.get("evidence_event_ids", [])
            result.incident_evidence_total += len(ref_ev)
            for eid in ref_ev:
                if eid in case_event_ids:
                    result.incident_evidence_valid += 1
                else:
                    other_e = store.connection.execute(
                        "SELECT case_id FROM events WHERE event_id = ?", (eid,)
                    ).fetchone()
                    if other_e:
                        result.cross_case_references += 1
                        result.issues.append(ValidationIssue(
                            "ISOLATION",
                            f"Incident {inc_id} references evidence {eid} from another case ({other_e[0]})"
                        ))
                    else:
                        result.issues.append(ValidationIssue(
                            "INCIDENT_EVIDENCE",
                            f"Incident {inc_id} references missing evidence {eid}"
                        ))

        # 4. Evidence Traceability
        case_events = store.get_case_events(case_id)
        result.evidence_count = len(case_events)
        result.evidence_total = len(case_events)

        for ev in case_events:
            eid = ev["event_id"]
            if ev.get("case_id") and ev["case_id"] != case_id:
                result.cross_case_references += 1
                result.issues.append(ValidationIssue(
                    "ISOLATION",
                    f"Evidence event {eid} belongs to case {ev['case_id']}, not {case_id}"
                ))

            if store.get_event(case_id, eid) is not None:
                result.evidence_traceable += 1
            else:
                result.issues.append(ValidationIssue(
                    "EVIDENCE_TRACE",
                    f"Evidence event {eid} not traceable in case {case_id}"
                ))

        # 5. Process Relationships & Investigation Graph
        try:
            investigation = load_investigation(database_path, case_id)
            graph = build_investigation_graph(investigation)

            process_nodes = graph.get_nodes("PROCESS")
            if not process_nodes and len(case_events) > 0:
                result.process_nodes_ok = False
                result.issues.append(ValidationIssue("PROCESS", "No process nodes found in investigation graph"))

            for edge in graph.edges:
                source_node = graph.get_node(edge.source_id)
                target_node = graph.get_node(edge.target_id)
                if not source_node:
                    result.process_relationships_ok = False
                    result.issues.append(ValidationIssue(
                        "GRAPH",
                        f"Graph edge {edge.edge_id} references missing source node {edge.source_id}"
                    ))
                if not target_node:
                    result.process_relationships_ok = False
                    result.issues.append(ValidationIssue(
                        "GRAPH",
                        f"Graph edge {edge.edge_id} references missing target node {edge.target_id}"
                    ))

                if source_node and source_node.attributes.get("case_id") and source_node.attributes["case_id"] != case_id:
                    result.cross_case_references += 1
                    result.process_relationships_ok = False
                    result.issues.append(ValidationIssue(
                        "ISOLATION",
                        f"Graph node {source_node.node_id} belongs to another case ({source_node.attributes['case_id']})"
                    ))

                if target_node and target_node.attributes.get("case_id") and target_node.attributes["case_id"] != case_id:
                    result.cross_case_references += 1
                    result.process_relationships_ok = False
                    result.issues.append(ValidationIssue(
                        "ISOLATION",
                        f"Graph node {target_node.node_id} belongs to another case ({target_node.attributes['case_id']})"
                    ))

                for eid in edge.evidence_ids:
                    if eid not in case_event_ids:
                        result.process_relationships_ok = False
                        result.issues.append(ValidationIssue(
                            "GRAPH",
                            f"Graph edge {edge.edge_id} references missing evidence {eid}"
                        ))

            # 6. Timeline Consistency
            timeline_entries = get_case_timeline(database_path, case_id)
            for entry in timeline_entries:
                eid = entry.get("event_id")
                if eid and eid not in case_event_ids:
                    result.timeline_ok = False
                    result.issues.append(ValidationIssue(
                        "TIMELINE",
                        f"Timeline entry references missing evidence {eid}"
                    ))
                if entry.get("case_id") and entry["case_id"] != case_id:
                    result.cross_case_references += 1
                    result.timeline_ok = False
                    result.issues.append(ValidationIssue(
                        "ISOLATION",
                        f"Timeline entry belongs to another case ({entry['case_id']})"
                    ))
                for fid in entry.get("finding_ids", []):
                    if str(fid) not in case_finding_ids:
                        result.timeline_ok = False
                        result.issues.append(ValidationIssue(
                            "TIMELINE",
                            f"Timeline entry references missing finding {fid}"
                        ))

            # 7. Reconstruction Consistency
            try:
                sequence = reconstruct_attack(investigation, graph)
                if not sequence or not sequence.stages:
                    result.reconstruction_status = "UNAVAILABLE"
                else:
                    reconstruction_ok = True
                    for stage in sequence.stages:
                        for eid in stage.evidence_ids:
                            if eid not in case_event_ids:
                                reconstruction_ok = False
                                result.issues.append(ValidationIssue(
                                    "RECONSTRUCTION",
                                    f"Reconstruction stage {stage.stage_id} references missing evidence {eid}"
                                ))
                        for fid in stage.finding_ids:
                            if str(fid) not in case_finding_ids:
                                reconstruction_ok = False
                                result.issues.append(ValidationIssue(
                                    "RECONSTRUCTION",
                                    f"Reconstruction stage {stage.stage_id} references missing finding {fid}"
                                ))
                    result.reconstruction_status = "OK" if reconstruction_ok else "FAIL"
            except Exception as exc:
                result.reconstruction_status = "FAIL"
                result.issues.append(ValidationIssue(
                    "RECONSTRUCTION",
                    f"Reconstruction processing exception: {exc}"
                ))

        except Exception as exc:
            result.issues.append(ValidationIssue("GRAPH", f"Investigation graph failure: {exc}"))

        # Final evaluation
        error_issues = [i for i in result.issues if i.severity == "ERROR"]
        if error_issues or result.cross_case_references > 0 or not result.process_relationships_ok or not result.timeline_ok or result.reconstruction_status == "FAIL":
            result.passed = False
        else:
            result.passed = True

        return result
    finally:
        store.close()
