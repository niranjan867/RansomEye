"""Unified threat assessment for RansomEye."""

from __future__ import annotations

import hashlib
import json
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


def _coerce_confidence(val: Any) -> float:
    """Coerce numeric or qualitative confidence strings into [0.0, 1.0] float."""
    if val is None:
        return 0.50
    if isinstance(val, (int, float)):
        return max(0.0, min(1.0, float(val)))
    s = str(val).strip().lower()
    return {"low": 0.50, "medium": 0.75, "high": 0.90}.get(s, 0.50)


def _is_informational_ioc_finding(finding: dict[str, Any]) -> bool:
    """Return True if finding is an ordinary informational IOC observation."""
    ftype = str(finding.get("finding_type") or finding.get("type", "")).lower()
    if ftype.startswith("ioc_observation_"):
        return True
    reason = str(finding.get("reason", "")).lower()
    if "[ioc-obs-" in reason and "[ioc-obs-lolbin]" not in reason:
        return True
    return False


def _is_forensic_finding(finding: dict[str, Any]) -> bool:
    """Return True if finding is an authorized forensic analyzer finding."""
    ftype = str(finding.get("finding_type") or finding.get("type", "")).lower()
    if ftype.startswith("script_"):
        return True
    if ftype.startswith("phishing_") or ftype == "phishing_detection":
        return True
    if ftype.startswith("pcap_"):
        return True
    if ftype in ("static_file_analysis", "static_binary_analysis") or ftype.startswith("static_"):
        return True
    if ftype in ("ioc_contextual_lolbin", "ioc_lolbin") or "ioc-obs-lolbin" in str(finding.get("reason", "")).lower():
        return True
    return False


def _combine_confidence(
    base_result: dict[str, Any],
    contributing_findings: list[dict[str, Any]],
    score: int,
) -> float:
    if score == 0:
        return 0.95

    values: list[float] = []

    if base_result.get("score", 0) > 0:
        values.append(float(base_result["confidence"]))

    for finding in contributing_findings:
        if finding.get("confidence") is not None:
            values.append(_coerce_confidence(finding["confidence"]))

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

        ftype = str(f_copy.get("type") or f_copy.get("finding_type", "finding"))
        f_copy["type"] = ftype
        if "finding_type" not in f_copy:
            f_copy["finding_type"] = ftype

        if not f_copy.get("finding_id") and f_copy.get("id"):
            f_copy["finding_id"] = str(f_copy["id"])

        if not f_copy.get("finding_id"):
            sorted_eids = sorted(list(set(str(e) for e in (f_copy.get("event_ids") or []))))
            technique = str(f_copy.get("technique") or "")
            reason = str(f_copy.get("reason") or "")

            payload = {
                "event_ids": sorted_eids,
                "reason": reason,
                "technique": technique,
                "type": ftype,
            }
            canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
            f_copy["finding_id"] = f"F-{digest}"
        else:
            f_copy["finding_id"] = str(f_copy["finding_id"])

        normalized.append(f_copy)
    return normalized


def assess_threat(
    events: list[Any],
    processes: dict[str, Any] | list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Combine all current findings into one explainable assessment."""
    base_result = analyze_events(events)
    dyn_behavior_findings = analyze_behavior(events)
    dyn_file_behavior_findings = analyze_file_behavior(events)

    # Prevent double counting: if file_behavior detected the same pattern
    # that rules.py scored, subtract the legacy contribution using the
    # structured trigger flags rather than fragile reason-string matching.
    has_mass_mod = any(
        f.get("type") == "mass_file_modification"
        for f in dyn_file_behavior_findings
    )
    has_ransom_note = any(
        f.get("type") == "ransom_note"
        for f in dyn_file_behavior_findings
    )

    if has_mass_mod and base_result.get("mass_modify_triggered"):
        base_result["score"] = max(0, base_result["score"] - MASS_MODIFY_SCORE)

    if has_ransom_note and base_result.get("ransom_note_triggered"):
        base_result["score"] = max(0, base_result["score"] - RANSOM_NOTE_SCORE)

    # Initialize finding categories
    behavior_findings: list[dict[str, Any]] = list(dyn_behavior_findings)
    file_behavior_findings: list[dict[str, Any]] = list(dyn_file_behavior_findings)
    forensic_findings: list[dict[str, Any]] = []
    informational_findings: list[dict[str, Any]] = []

    # Process and deduplicate any supplied stored findings
    if findings:
        def _finding_sig(f: dict[str, Any]) -> tuple[str, tuple[str, ...], str]:
            ftype = str(f.get("type") or f.get("finding_type", ""))
            eids = tuple(sorted(str(e) for e in (f.get("event_ids") or ([] if not f.get("event_id") else [f["event_id"]]))))
            reason = str(f.get("reason", ""))
            return (ftype, eids, reason)

        seen_sigs = {_finding_sig(f) for f in behavior_findings + file_behavior_findings}
        seen_finding_ids = {str(f.get("finding_id")) for f in behavior_findings + file_behavior_findings if f.get("finding_id")}

        for f in findings:
            fid = str(f.get("finding_id")) if f.get("finding_id") is not None else None
            sig = _finding_sig(f)

            if fid and fid in seen_finding_ids:
                continue
            if sig in seen_sigs:
                continue

            if _is_informational_ioc_finding(f):
                informational_findings.append(f)
                seen_sigs.add(sig)
                if fid:
                    seen_finding_ids.add(fid)
            elif _is_forensic_finding(f):
                forensic_findings.append(f)
                seen_sigs.add(sig)
                if fid:
                    seen_finding_ids.add(fid)
            else:
                ftype = str(f.get("type") or f.get("finding_type", ""))
                if ftype in ("suspicious_powershell", "suspicious_certutil", "recovery_inhibition"):
                    behavior_findings.append(f)
                    seen_sigs.add(sig)
                    if fid:
                        seen_finding_ids.add(fid)
                elif ftype in ("mass_file_modification", "ransom_note", "mass_file_creation", "mass_file_deletion", "file_churn", "suspicious_extension"):
                    file_behavior_findings.append(f)
                    seen_sigs.add(sig)
                    if fid:
                        seen_finding_ids.add(fid)
                else:
                    forensic_findings.append(f)
                    seen_sigs.add(sig)
                    if fid:
                        seen_finding_ids.add(fid)

    contributing_findings = behavior_findings + file_behavior_findings + forensic_findings
    raw_all_findings = contributing_findings + informational_findings
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
    forensic_score = sum(int(f.get("score", 0)) for f in forensic_findings)

    correlation_bonus = 0
    # Use (base_result + file_behavior_score) to see if we have baseline suspicious activity
    if (base_result["score"] + file_behavior_score) > 0 and behavior_findings:
        correlation_bonus = 10

    total_score = min(base_result["score"] + file_behavior_score + behavior_score + forensic_score + correlation_bonus, 100)

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
        for finding in contributing_findings
        if int(finding.get("score", 0)) > 0
    )

    techniques = sorted({
        finding["technique"]
        for finding in contributing_findings
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
            contributing_findings,
            total_score,
        ),
        "reasons": reasons,
        "techniques": techniques,
        "finding_count": len(all_findings),
        "correlation_count": len(correlations_data),
        "correlations": correlations_data,
    }


def assess_case(store: Any, case_id: str) -> dict[str, Any]:
    """Authoritative case assessment lifecycle: load events and findings, assess, and persist."""
    events = store.get_case_events(case_id)
    findings = store.get_case_findings(case_id)
    assessment = assess_threat(events=events, findings=findings)
    store.save_assessment(case_id, assessment)
    return assessment
