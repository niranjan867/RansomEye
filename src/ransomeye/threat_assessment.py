"""Unified threat assessment for RansomEye."""

from __future__ import annotations

from typing import Any

from ransomeye.behavior import analyze_behavior
from ransomeye.rules import analyze_events


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


def assess_threat(events: list[Any]) -> dict[str, Any]:
    """Combine all current findings into one explainable assessment."""
    base_result = analyze_events(events)
    behavior_findings = analyze_behavior(events)

    behavior_score = sum(
        int(finding.get("score", 0))
        for finding in behavior_findings
    )

    correlation_bonus = 0
    if base_result["score"] > 0 and behavior_findings:
        correlation_bonus = 10

    total_score = min(base_result["score"] + behavior_score + correlation_bonus, 100)

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
        f"{finding['reason']} (+{finding['score']})"
        for finding in behavior_findings
    )

    techniques = sorted({
        finding["technique"]
        for finding in behavior_findings
        if finding.get("technique")
    })

    if not reasons:
        reasons.append("No suspicious activity detected.")

    return {
        "score": total_score,
        "severity": _severity_from_score(total_score),
        "confidence": _combine_confidence(
            base_result,
            behavior_findings,
            total_score,
        ),
        "reasons": reasons,
        "techniques": techniques,
        "finding_count": len(behavior_findings),
    }
