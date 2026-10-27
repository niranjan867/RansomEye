"""Test for the competition prepared ransomware case generation and validation."""

from __future__ import annotations

from pathlib import Path

from ransomeye.investigation import load_investigation, get_investigation_summary
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.investigation_validation import validate_investigation
from ransomeye.prepared_case import (
    PREPARED_CASE_ID,
    PREPARED_CASE_NAME,
    PREPARED_HOST,
    seed_prepared_case,
)
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.report import generate_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import build_process_tree, get_case_timeline


def test_seed_prepared_case_end_to_end(tmp_path: Path):
    db_path = tmp_path / "prepared_test.db"
    art_dir = tmp_path / "artifacts"

    # Step 1: Seed the case
    result = seed_prepared_case(db_path, artifacts_dir=art_dir)

    assert result["case_id"] == PREPARED_CASE_ID
    assert result["case_name"] == PREPARED_CASE_NAME
    assert result["host"] == PREPARED_HOST
    assert result["events_count"] >= 60
    assert result["findings_count"] >= 6
    assert result["score"] >= 60
    assert result["severity"] in ("HIGH", "CRITICAL")
    assert result["correlations_count"] >= 1
    assert result["custody_count"] >= 4

    # Step 2: Storage verification
    store = EvidenceStore(db_path)
    try:
        case = store.get_case(PREPARED_CASE_ID)
        assert case["case_name"] == PREPARED_CASE_NAME
        assert case["status"] == "OPEN"

        findings = store.get_case_findings(PREPARED_CASE_ID)
        finding_types = {f.get("finding_type") or f.get("type") for f in findings}
        assert "suspicious_powershell" in finding_types
        assert "suspicious_certutil" in finding_types
        assert "recovery_inhibition" in finding_types
        assert "mass_file_modification" in finding_types
        assert "ransom_note" in finding_types

        custody = store.get_custody_events(PREPARED_CASE_ID)
        assert len(custody) >= 4
    finally:
        store.close()

    # Step 3: Investigation Domain Model & Graph
    investigation = load_investigation(db_path, PREPARED_CASE_ID)
    summary = get_investigation_summary(investigation)
    assert PREPARED_CASE_ID in summary
    assert "Threat Score:" in summary

    graph = build_investigation_graph(investigation)
    proc_nodes = graph.get_process_nodes()
    assert len(proc_nodes) >= 4
    proc_labels = {p.label for p in proc_nodes}
    assert "powershell.exe" in proc_labels
    assert "certutil.exe" in proc_labels
    assert "update_agent.exe" in proc_labels
    assert "vssadmin.exe" in proc_labels

    # Step 4: Process Tree & Timeline
    timeline_events = get_case_timeline(db_path, PREPARED_CASE_ID)
    assert len(timeline_events) >= 60
    tree = build_process_tree(timeline_events)
    assert "nodes" in tree

    # Step 5: Attack Reconstruction
    attack_sequence = reconstruct_attack(investigation, graph)
    assert len(attack_sequence.stages) >= 3

    # Step 6: Investigation Validation
    val_res = validate_investigation(db_path, PREPARED_CASE_ID)
    assert val_res.case_exists is True
    assert val_res.assessment_available is True
    assert val_res.passed is True

    # Step 7: Case Report Generation
    report = generate_case_report(db_path, PREPARED_CASE_ID)
    assert PREPARED_CASE_ID in report
    assert PREPARED_CASE_NAME in report
    assert "powershell.exe" in report
    assert "certutil.exe" in report
    assert "vssadmin.exe" in report
    assert "CHAIN OF CUSTODY" in report
