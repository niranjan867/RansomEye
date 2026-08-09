"""RansomEye live collection and storage pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ransomeye.behavior import analyze_behavior
from ransomeye.evidence import normalize_events
from ransomeye.storage import EvidenceStore
from ransomeye.sysmon_reader import read_process_creation_events
from ransomeye.threat_assessment import assess_threat


def collect_and_store(
    database_path: str | Path,
    case_id: str,
    case_name: str,
    host: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Collect live Sysmon events and save the complete assessment."""
    store = EvidenceStore(database_path)

    try:
        store.create_case(
            case_id=case_id,
            case_name=case_name,
            host=host,
        )

        raw_events = read_process_creation_events(limit)
        evidence_events = normalize_events(raw_events)

        for event in evidence_events:
            store.save_event(case_id, event)


        findings = analyze_behavior(evidence_events)

        for finding in findings:
            store.save_finding(case_id, finding)

        assessment = assess_threat(evidence_events)
        store.save_assessment(case_id, assessment)

        return {
            "case_id": case_id,
            "events_collected": len(evidence_events),
            "findings_saved": len(findings),
            "assessment": assessment,
        }

    finally:
        store.close()
