"""Unified threat assessment for RansomEye."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from ransomeye.behavior import analyze_behavior
from ransomeye.correlation import correlate_findings
from ransomeye.rules import analyze_events, MASS_MODIFY_SCORE, RANSOM_NOTE_SCORE
from ransomeye.file_behavior import analyze_file_behavior


def _severity_from_score(score: int) -> str:
    if score <= 24:
        return "SAFE"
    if score <= 49:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    if score <= 84:
        return "HIGH"
    return "CRITICAL"


def _combine_confidence(
    base_result: dict[str, Any],
    behavior_findings: list[dict[str, Any]],
    score: int,
) -> float:
    if score == 0:
        return 0.95

    values: list[float] = []

    if base_result["score"] > 0:
        values.append(float(base_result["confidence"]))

    values.extend(
        float(finding["confidence"])
        for finding in behavior_findings
        if finding.get("confidence") is not None
    )

    if not values:
        return 0.50

    return round(sum(values) / len(values), 2)


def _ensure_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure all findings have deterministic finding_ids and event_ids independent of input ordering."""
    normalized = []
    for f in findings:
        f_copy = dict(f)
        if not f_copy.get("event_ids") and f_copy.get("event_id"):
            f_copy["event_ids"] = [str(f_copy["event_id"])]

        if not f_copy.get("finding_id"):
            fid = f_copy.get("id")
            if not fid:
                ftype = str(f_copy.get("type", "finding"))
                sorted_eids = sorted(str(e) for e in (f_copy.get("event_ids") or []))
                fevts = "-".join(sorted_eids)
                content = f"{ftype}|{fevts}"
                digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:8]
                fid = f"FND-{ftype}-{digest}"
            f_copy["finding_id"] = str(fid)
        normalized.append(f_copy)
    return normalized


def assess_threat(
    events: list[Any],
    processes: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Combine all current findings into one explainable assessment."""
    base_result = analyze_events(events)
    behavior_findings = analyze_behavior(events)
    file_behavior_findings = analyze_file_behavior(events)

    # Prevent double counting: if file_behavior detected the same pattern
    # that rules.py scored, subtract the legacy contribution using the
    # structured trigger flags rather than fragile reason-string matching.
    has_mass_mod = any(
        f.get("type") == "mass_file_modification"
        for f in file_behavior_findings
    )
    has_ransom_note = any(
        f.get("type") == "ransom_note"
        for f in file_behavior_findings
    )

    if has_mass_mod and base_result.get("mass_modify_triggered"):
        base_result["score"] = max(0, base_result["score"] - MASS_MODIFY_SCORE)

    if has_ransom_note and base_result.get("ransom_note_triggered"):
        base_result["score"] = max(0, base_result["score"] - RANSOM_NOTE_SCORE)

    raw_all_findings = behavior_findings + file_behavior_findings
    all_findings = _ensure_finding_ids(raw_all_findings)

    if all_findings:
        incidents = correlate_findings(
            findings=all_findings,
            evidence=events,
            processes=processes,
        )
    else:
        incidents = []

    file_behavior_score = sum(int(f.get("score", 0)) for f in file_behavior_findings)
    behavior_score = sum(int(f.get("score", 0)) for f in behavior_findings)

    correlation_bonus = 0
    # Use (base_result + file_behavior_score) to see if we have baseline suspicious activity
    if (base_result["score"] + file_behavior_score) > 0 and behavior_findings:
        correlation_bonus = 10

    total_score = min(base_result["score"] + file_behavior_score + behavior_score + correlation_bonus, 100)

    # Apply aggressive behavior floor ONLY to the original behavior findings (powershell, certutil, etc.)
    if behavior_findings:
        behavior_floor = 25
        if len(behavior_findings) > 1:
            behavior_floor = 50
        if total_score < behavior_floor:
            total_score = behavior_floor

    reasons = []

    if base_result["score"] > 0:
        reasons.extend(base_result["reasons"])

    reasons.extend(
        f"{finding['reason']} (+{finding.get('score', 0)})"
        for finding in all_findings
    )

    techniques = sorted({
        finding["technique"]
        for finding in all_findings
        if finding.get("technique")
    })

    if not reasons:
        reasons.append("No suspicious activity detected.")

    correlations_data: list[dict[str, Any]] = []
    for inc in incidents:
        start_t = (
            inc.start_time.isoformat()
            if isinstance(inc.start_time, datetime)
            else (str(inc.start_time) if inc.start_time is not None else None)
        )
        end_t = (
            inc.end_time.isoformat()
            if isinstance(inc.end_time, datetime)
            else (str(inc.end_time) if inc.end_time is not None else None)
        )
        correlations_data.append(
            {
                "incident_id": inc.incident_id,
                "case_id": inc.case_id,
                "finding_ids": list(inc.finding_ids),
                "evidence_ids": list(inc.evidence_ids),
                "evidence_event_ids": list(inc.evidence_ids),
                "process_ids": list(inc.process_ids),
                "process_key": inc.process_key,
                "start_time": start_t,
                "end_time": end_t,
                "duration": inc.duration_seconds,
                "correlation_reasons": list(inc.correlation_reasons),
                "processes": [dict(p) for p in inc.processes],
                "parent_relationships": [dict(r) for r in inc.parent_relationships],
            }
        )

    return {
        "score": total_score,
        "severity": _severity_from_score(total_score),
        "confidence": _combine_confidence(
            base_result,
            all_findings,
            total_score,
        ),
        "reasons": reasons,
        "techniques": techniques,
        "finding_count": len(all_findings),
        "correlation_count": len(correlations_data),
        "correlations": correlations_data,
    }
