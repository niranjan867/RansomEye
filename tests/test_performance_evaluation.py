"""Performance metrics, evaluation, and investigation verification tests.

This module validates the evaluation methodology for RansomEye using strictly
controlled synthetic fixtures and deterministic test scenarios.

Safety Guarantees:
- Never executes real malware or ransomware binaries.
- Never encrypts, modifies, or deletes real user files.
- Operates exclusively in isolated temporary directories (tmp_path) and memory.
- Uses read-only access checks for static dataset fixtures.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ransomeye.advanced_timeline import build_advanced_timeline
from ransomeye.behavior import analyze_behavior
from ransomeye.correlation import correlate_events
from ransomeye.evidence import EvidenceEvent, normalize_events
from ransomeye.file_behavior import analyze_file_behavior
from ransomeye.integrity import sha256_file, verify_file, verify_manifest
from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.investigation_validation import validate_investigation
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.report import generate_case_report
from ransomeye.simulation import (
    check_read_only_access,
    load_normal_activity,
    load_ransomware_like_activity,
    NORMAL_ACTIVITY_PATH,
    RANSOMWARE_LIKE_ACTIVITY_PATH,
)
from ransomeye.storage import EvidenceStore
from ransomeye.threat_assessment import assess_threat
from ransomeye.timeline import get_case_timeline


def _get_all_findings(events: list[EvidenceEvent]) -> list[dict]:
    return analyze_behavior(events) + analyze_file_behavior(events)


def test_safety_guarantees_and_read_only_isolation():
    """Verify that evaluation datasets are accessed read-only and not mutated."""
    normal_ro = check_read_only_access(NORMAL_ACTIVITY_PATH)
    assert normal_ro.ok, f"Normal dataset check failed: {normal_ro.message}"

    ransom_ro = check_read_only_access(RANSOMWARE_LIKE_ACTIVITY_PATH)
    assert ransom_ro.ok, f"Ransomware-like dataset check failed: {ransom_ro.message}"


def test_positive_ransomware_like_scenarios_detection(tmp_path: Path):
    """Evaluate detection capabilities against deterministic ransomware-like scenarios."""
    db_path = tmp_path / "eval_positive.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-POS-001"
    store.create_case(case_id=case_id, case_name="Evaluation Positive Ransomware Scenario")

    # Ingest synthetic ransomware-like dataset
    ds_result = load_ransomware_like_activity()
    assert ds_result.ok, f"Dataset load failed: {ds_result.errors}"
    assert len(ds_result.events) > 0

    saved_event_ids = set()
    for event in ds_result.events:
        store.save_event(case_id, event)
        saved_event_ids.add(event.event_id)

    # Execute behavioral analysis
    all_findings = _get_all_findings(ds_result.events)

    for finding in all_findings:
        f_eids = []
        if finding.get("event_ids"):
            f_eids = [eid for eid in finding["event_ids"] if eid in saved_event_ids]
        elif finding.get("event_id") and str(finding["event_id"]) in saved_event_ids:
            f_eids = [str(finding["event_id"])]
        store.save_finding(case_id, finding, event_ids=f_eids)

    # Perform threat assessment
    assessment = assess_threat(ds_result.events)
    store.save_assessment(case_id, assessment)
    store.close()

    # Verification: Positive ransomware-like behavior produces findings and non-safe threat
    assert len(all_findings) > 0, "Expected positive behavioral findings for ransomware scenario"
    assert assessment["score"] > 0, "Assessment score must be positive"
    assert assessment["severity"] != "SAFE", f"Expected non-SAFE severity, got {assessment['severity']}"
    assert len(assessment["techniques"]) > 0, "Expected MITRE ATT&CK techniques mapped"


def test_negative_benign_scenarios_false_positive_control(tmp_path: Path):
    """Evaluate false positive resistance against benign baseline activity."""
    db_path = tmp_path / "eval_negative.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-NEG-001"
    store.create_case(case_id=case_id, case_name="Evaluation Benign Baseline Scenario")

    ds_result = load_normal_activity()
    assert ds_result.ok, f"Dataset load failed: {ds_result.errors}"
    assert len(ds_result.events) > 0

    saved_event_ids = set()
    for event in ds_result.events:
        store.save_event(case_id, event)
        saved_event_ids.add(event.event_id)

    all_findings = _get_all_findings(ds_result.events)

    for finding in all_findings:
        f_eids = []
        if finding.get("event_ids"):
            f_eids = [eid for eid in finding["event_ids"] if eid in saved_event_ids]
        elif finding.get("event_id") and str(finding["event_id"]) in saved_event_ids:
            f_eids = [str(finding["event_id"])]
        store.save_finding(case_id, finding, event_ids=f_eids)

    assessment = assess_threat(ds_result.events)
    store.save_assessment(case_id, assessment)
    store.close()

    # Verification: Benign activity should yield SAFE classification and no high-severity findings
    assert assessment["severity"] == "SAFE", f"Expected SAFE for benign dataset, got {assessment['severity']}"
    assert assessment["score"] == 0, f"Expected 0 score for benign dataset, got {assessment['score']}"


def test_detection_latency_measurement_capability(tmp_path: Path):
    """Verify ability to measure execution and detection latency on event sequences."""
    db_path = tmp_path / "eval_latency.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-LATENCY-001"
    store.create_case(case_id=case_id, case_name="Evaluation Latency Measurement")

    events_raw = [
        {
            "event_id": f"evt-lat-{i}",
            "timestamp": "2026-08-08T12:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "pid": str(1000 + i),
        }
        for i in range(10)
    ]
    evidence_events = normalize_events(events_raw)
    saved_event_ids = set()
    for evt in evidence_events:
        store.save_event(case_id, evt)
        saved_event_ids.add(evt.event_id)

    start_perf = time.perf_counter()
    findings = _get_all_findings(evidence_events)
    assessment = assess_threat(evidence_events)
    elapsed_seconds = time.perf_counter() - start_perf

    for f in findings:
        f_eids = []
        if f.get("event_ids"):
            f_eids = [eid for eid in f["event_ids"] if eid in saved_event_ids]
        elif f.get("event_id") and str(f["event_id"]) in saved_event_ids:
            f_eids = [str(f["event_id"])]
        store.save_finding(case_id, f, event_ids=f_eids)
    store.save_assessment(case_id, assessment)
    store.close()

    assert elapsed_seconds >= 0.0, "Latency measurement must be non-negative"
    assert len(findings) > 0, "Findings should be generated"
    assert assessment["score"] > 0


def test_evidence_traceability_and_junction_integrity(tmp_path: Path):
    """Verify that every finding is linked to its source evidence in SQLite finding_evidence."""
    db_path = tmp_path / "eval_traceability.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-TRACE-001"
    store.create_case(case_id=case_id, case_name="Evidence Traceability Evaluation")

    event_payload = {
        "event_id": "EVT-SRC-999",
        "timestamp": "2026-08-08T14:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "pid": "4400",
    }
    store.save_event(case_id, event_payload)

    fid = store.save_finding(
        case_id=case_id,
        finding={
            "type": "obfuscated_powershell",
            "score": 35,
            "confidence": 0.9,
            "technique": "T1059.001",
            "reason": "Encoded PowerShell execution detected",
        },
        event_ids=["EVT-SRC-999"],
    )

    # Query junction table
    linked_event_ids = store.get_finding_event_ids(fid)
    assert linked_event_ids == ["EVT-SRC-999"], "Finding must resolve precisely to source event ID"

    store.close()

    # Run investigation validation
    validation = validate_investigation(db_path, case_id)
    assert validation.passed, f"Validation failed with issues: {[i.message for i in validation.issues]}"
    assert validation.findings_with_evidence == 1
    assert validation.evidence_traceable == 1


def test_investigation_completeness_and_correlations(tmp_path: Path):
    """Verify investigation graph, timeline, attack reconstruction, and forensic report."""
    db_path = tmp_path / "eval_investigation.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-INV-001"
    store.create_case(case_id=case_id, case_name="Investigation Completeness Evaluation")

    events = [
        {
            "event_id": "EVT-INV-1",
            "timestamp": "2026-08-08T10:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "pid": "1000",
            "parent_pid": "500",
            "command_line": "cmd.exe /c start",
        },
        {
            "event_id": "EVT-INV-2",
            "timestamp": "2026-08-08T10:01:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "vssadmin.exe",
            "pid": "1001",
            "parent_pid": "1000",
            "command_line": "vssadmin delete shadows /all /quiet",
        },
        {
            "event_id": "EVT-INV-3",
            "timestamp": "2026-08-08T10:02:00Z",
            "source": "live_file",
            "event_type": "file_modify",
            "file_path": r"C:\Data\finance.xlsx.locked",
            "file_count": 1,
            "pid": "1001",
            "metadata": {"entropy": 7.95},
        },
    ]

    normalized = normalize_events(events)
    saved_event_ids = set()
    for evt in normalized:
        store.save_event(case_id, evt)
        saved_event_ids.add(evt.event_id)

    findings = _get_all_findings(normalized)
    for f in findings:
        f_eids = []
        if f.get("event_ids"):
            f_eids = [eid for eid in f["event_ids"] if eid in saved_event_ids]
        elif f.get("event_id") and str(f["event_id"]) in saved_event_ids:
            f_eids = [str(f["event_id"])]
        store.save_finding(case_id, f, event_ids=f_eids)

    assessment = assess_threat(normalized)
    store.save_assessment(case_id, assessment)
    store.close()

    # 1. Timeline verification
    timeline = get_case_timeline(db_path, case_id)
    assert len(timeline) == 3, "Timeline should contain all 3 events in order"
    assert timeline[0]["event_id"] == "EVT-INV-1"
    assert timeline[2]["event_id"] == "EVT-INV-3"

    # 2. Investigation data load
    inv = load_investigation(db_path, case_id)
    assert inv.case["case_id"] == case_id
    assert len(inv.evidence) == 3

    # 3. Investigation Graph verification
    graph = build_investigation_graph(inv)
    assert len(graph.get_nodes()) > 0, "Investigation graph must contain nodes"
    assert len(graph.get_edges()) > 0, "Investigation graph must contain edges"

    # 4. Attack Reconstruction verification
    recon = reconstruct_attack(inv, graph)
    assert recon is not None
    assert len(recon.stages) > 0, "Reconstruction must identify stages"
    assert "ATTACK RECONSTRUCTION" in recon.summary()

    # 5. Forensic Report generation verification
    report_text = generate_case_report(db_path, case_id)
    assert "RANSOMEYE CASE REPORT" in report_text
    assert case_id in report_text
    assert "TIMELINE" in report_text
    assert "FINDINGS" in report_text

    # 6. Investigation validator
    val = validate_investigation(db_path, case_id)
    assert val.passed is True, f"Investigation validation failed: {[i.message for i in val.issues]}"


def test_integrity_and_chain_of_custody_verification(tmp_path: Path):
    """Verify SHA-256 integrity functions and custody log tracking."""
    evidence_file = tmp_path / "evidence_sample.json"
    evidence_content = b'{"event_id": "EVT-001", "type": "process_create"}'
    evidence_file.write_bytes(evidence_content)

    # SHA-256 calculation and verification
    computed_hash = sha256_file(evidence_file)
    assert len(computed_hash) == 64
    assert verify_file(evidence_file, computed_hash) is True
    assert verify_file(evidence_file, "0" * 64) is False

    # Manifest verification
    manifest_file = tmp_path / "evidence_sample.json.sha256"
    manifest_file.write_text(f"evidence_sample.json\n{computed_hash}\n", encoding="utf-8")
    assert verify_manifest(evidence_file, manifest_file) is True

    # Chain of Custody logging
    db_path = tmp_path / "eval_custody.db"
    store = EvidenceStore(db_path)
    case_id = "CASE-EVAL-CUSTODY-001"
    store.create_case(case_id=case_id, case_name="Custody Evaluation Case")

    store.record_custody_event(
        case_id=case_id,
        artifact_path=str(evidence_file),
        sha256=computed_hash,
        action="created",
        analyst="analyst_1",
        note="Case initiated",
    )
    store.record_custody_event(
        case_id=case_id,
        artifact_path=str(evidence_file),
        sha256=computed_hash,
        action="verified",
        analyst="analyst_2",
        note="Evidence hash verified",
        verification_result=True,
    )
    store.record_custody_event(
        case_id=case_id,
        artifact_path=str(evidence_file),
        sha256=computed_hash,
        action="exported",
        analyst="analyst_1",
        note="Evidence bundle exported",
    )

    custody_logs = store.get_custody_events(case_id)
    assert len(custody_logs) >= 3
    actions = [log["action"] for log in custody_logs]
    assert "created" in actions
    assert "verified" in actions
    assert "exported" in actions
    store.close()
