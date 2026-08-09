"""Investigation domain model and loader for RansomEye."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ransomeye.evidence import EvidenceEvent, normalize_events
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import build_process_tree, get_case_timeline


@dataclass
class InvestigationSummary:
    """Summary of a RansomEye investigation."""
    case_id: str
    case_name: str
    host: str
    status: str
    evidence_count: int
    finding_count: int
    correlation_count: int
    process_count: int
    threat_score: int | None
    severity: str | None
    confidence: float | None
    first_activity: str | None
    last_activity: str | None


@dataclass
class Investigation:
    """The root context of a RansomEye investigation."""
    case: dict[str, Any]
    evidence: list[EvidenceEvent]
    findings: list[dict[str, Any]]
    correlations: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    processes: dict[str, Any]
    assessment: dict[str, Any] | None

    @property
    def summary(self) -> InvestigationSummary:
        """Return a formatted summary of the investigation."""
        threat_score = None
        severity = None
        confidence = None

        if self.assessment:
            threat_score = self.assessment.get("score")
            severity = self.assessment.get("severity")
            confidence = self.assessment.get("confidence")

        first_activity = None
        last_activity = None
        if self.timeline:
            first_activity = self.timeline[0].get("timestamp")
            last_activity = self.timeline[-1].get("timestamp")

        process_count = len(self.processes.get("nodes", {}))

        return InvestigationSummary(
            case_id=self.case.get("case_id", ""),
            case_name=self.case.get("case_name", ""),
            host=self.case.get("host", ""),
            status=self.case.get("status", ""),
            evidence_count=len(self.evidence),
            finding_count=len(self.findings),
            correlation_count=len(self.correlations),
            process_count=process_count,
            threat_score=threat_score,
            severity=severity,
            confidence=confidence,
            first_activity=first_activity,
            last_activity=last_activity,
        )


def get_investigation_summary(investigation: Investigation) -> str:
    """Return a formatted string of the investigation summary."""
    summary = investigation.summary

    score_display = f"{summary.threat_score}/100" if summary.threat_score is not None else "None"
    confidence_display = str(summary.confidence) if summary.confidence is not None else "None"

    return "\n".join([
        "RANSOMEYE INVESTIGATION",
        "=======================",
        "",
        "Case:",
        summary.case_id,
        "",
        "Host:",
        summary.host or "N/A",
        "",
        "Status:",
        summary.status or "N/A",
        "",
        "Evidence:",
        str(summary.evidence_count),
        "",
        "Findings:",
        str(summary.finding_count),
        "",
        "Correlations:",
        str(summary.correlation_count),
        "",
        "Processes:",
        str(summary.process_count),
        "",
        "Threat Assessment:",
        summary.severity or "None",
        "",
        "Threat Score:",
        score_display,
        "",
        "Confidence:",
        confidence_display,
        "",
        "First Activity:",
        summary.first_activity or "N/A",
        "",
        "Last Activity:",
        summary.last_activity or "N/A",
    ])


def load_investigation(database_path: str | Path, case_id: str) -> Investigation:
    """Load a complete investigation from the storage layer.

    Does NOT modify the database, recalculate assessments, or run detection rules.
    """
    store = EvidenceStore(database_path)
    try:
        case = store.connection.execute(
            """
            SELECT case_id, case_name, host, status, severity, created_at
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if case is None:
            raise ValueError(f"Case not found: {case_id}")

        case_dict = dict(case)

        timeline = get_case_timeline(database_path, case_id)
        evidence = normalize_events(timeline)

        findings = store.get_case_findings(case_id)
        for finding in findings:
            finding["event_ids"] = store.get_finding_event_ids(finding["finding_id"])

        db_assessment = store.connection.execute(
            """
            SELECT *
            FROM assessments
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()

        assessment = None
        correlations = []
        if db_assessment:
            db_assessment_dict = dict(db_assessment)

            reasons = []
            if db_assessment_dict.get("reasons_json"):
                try:
                    reasons = json.loads(db_assessment_dict["reasons_json"])
                except json.JSONDecodeError:
                    reasons = []

            techniques = []
            if db_assessment_dict.get("techniques_json"):
                try:
                    techniques = json.loads(db_assessment_dict["techniques_json"])
                except json.JSONDecodeError:
                    techniques = []

            assessment = {
                "score": db_assessment_dict["score"],
                "severity": db_assessment_dict["severity"],
                "confidence": db_assessment_dict["confidence"],
                "reasons": reasons,
                "techniques": techniques,
            }

            if db_assessment_dict.get("correlations_json"):
                try:
                    correlations = json.loads(db_assessment_dict["correlations_json"])
                    assessment["correlations"] = correlations
                except json.JSONDecodeError:
                    pass

        processes = build_process_tree(timeline)

        return Investigation(
            case=case_dict,
            evidence=evidence,
            findings=findings,
            correlations=correlations,
            timeline=timeline,
            processes=processes,
            assessment=assessment,
        )
    finally:
        store.close()
