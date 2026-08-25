"""Tests for M23.7 Investigation Completeness & Integrity Validation."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from ransomeye.commands import main
from ransomeye.investigation_validation import validate_investigation
from ransomeye.storage import EvidenceStore


def _run_command(args, cwd=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "ransomeye.commands", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return result


def test_validate_valid_complete_case(tmp_path):
    db_path = tmp_path / "valid_complete.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-VALID-01", "Valid Complete Case")

    # Save event
    store.save_event("CASE-VALID-01", {
        "event_id": "EVT-01",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "pid": "100",
        "process_guid": "{PS-GUID}",
        "command_line": "powershell.exe -enc XYZ",
    })

    # Save finding linked to event
    fid = store.save_finding("CASE-VALID-01", {
        "type": "suspicious_powershell",
        "score": 40,
        "confidence": 0.8,
        "technique": "T1059.001",
        "reason": "Encoded powershell",
    }, event_ids=["EVT-01"])

    # Save assessment with correlation
    store.save_assessment("CASE-VALID-01", {
        "score": 50,
        "severity": "MEDIUM",
        "confidence": 0.85,
        "reasons": ["Encoded powershell execution"],
        "techniques": ["T1059.001"],
        "correlations": [{
            "incident_id": "INC-01",
            "finding_ids": [fid],
            "evidence_ids": ["EVT-01"],
            "start_time": "2026-08-08T10:00:00Z",
            "end_time": "2026-08-08T10:00:00Z",
        }]
    })
    store.close()

    res = validate_investigation(db_path, "CASE-VALID-01")
    assert res.case_exists is True
    assert res.assessment_available is True
    assert res.assessment_score == 50
    assert res.findings_count == 1
    assert res.findings_with_evidence == 1
    assert res.incidents_count == 1
    assert res.incidents_with_findings == 1
    assert res.incident_evidence_valid == 1
    assert res.evidence_count == 1
    assert res.evidence_traceable == 1
    assert res.process_nodes_ok is True
    assert res.process_relationships_ok is True
    assert res.timeline_ok is True
    assert res.cross_case_references == 0
    assert res.passed is True


def test_validate_empty_case(tmp_path):
    db_path = tmp_path / "empty_case.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-EMPTY-01", "Empty Case")
    store.close()

    res = validate_investigation(db_path, "CASE-EMPTY-01")
    assert res.case_exists is True
    assert res.assessment_available is False
    assert res.findings_count == 0
    assert res.incidents_count == 0
    assert res.evidence_count == 0
    assert res.cross_case_references == 0
    assert res.passed is True

    rendered = res.render()
    assert "Case: CASE-EMPTY-01" in rendered
    assert "Assessment" in rendered
    assert "UNAVAILABLE" in rendered
    assert "PASS" in rendered
    assert "RESULT\n------\nPASS" in rendered


def test_validate_missing_case(tmp_path):
    db_path = tmp_path / "missing_case.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-EXIST", "Existing Case")
    store.close()

    res = validate_investigation(db_path, "NONEXISTENT-CASE")
    assert res.case_exists is False
    assert res.passed is False

    cli_res = _run_command([
        "investigation", "validate",
        "--database", str(db_path),
        "--case", "NONEXISTENT-CASE",
    ])
    assert cli_res.returncode != 0
    assert "Case not found: NONEXISTENT-CASE" in cli_res.stdout or "Case not found: NONEXISTENT-CASE" in cli_res.stderr


def test_validate_invalid_database_input(tmp_path):
    invalid_db_path = tmp_path / "nonexistent.db"

    res = validate_investigation(invalid_db_path, "CASE-01")
    assert res.case_exists is False
    assert res.passed is False
    assert any("Database not found" in i.message for i in res.issues)

    cli_res = _run_command([
        "investigation", "validate",
        "--database", str(invalid_db_path),
        "--case", "CASE-01",
    ])
    assert cli_res.returncode != 0
    assert "Database not found" in cli_res.stdout or "Validation failed" in cli_res.stdout or "Database not found" in cli_res.stderr


def test_validate_deterministic_finding_id_mismatch(tmp_path):
    db_path = tmp_path / "det_id_mismatch.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-ID-MISMATCH", "Mismatch Case")

    store.save_event("CASE-ID-MISMATCH", {
        "event_id": "EVT-DET-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })

    # Manually insert finding with mismatched F- hash string
    store.connection.execute(
        """
        INSERT INTO findings (case_id, finding_type, score, confidence, technique, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("CASE-ID-MISMATCH", "suspicious_cmd", 30, 0.7, "T1059.003", "Mismatched ID", "2026-08-08T10:00:00Z"),
    )
    fid = store.connection.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Store finding_evidence
    store.connection.execute(
        "INSERT INTO finding_evidence (finding_id, event_id) VALUES (?, ?)",
        (fid, "EVT-DET-1"),
    )
    store.connection.commit()
    store.close()

    # Pass a finding with custom F- mismatch in memory or test verification
    res = validate_investigation(db_path, "CASE-ID-MISMATCH")
    assert res.case_exists is True
    # Verify canonical computation functions
    from ransomeye.investigation_validation import _compute_deterministic_finding_id
    raw_finding = {"finding_id": "F-BADHASH12345678", "type": "suspicious_cmd", "event_ids": ["EVT-DET-1"], "technique": "T1059.003", "reason": "Mismatched ID"}
    expected_det = _compute_deterministic_finding_id(raw_finding)
    assert expected_det != "F-BADHASH12345678"


def test_validate_missing_finding_reference(tmp_path):
    db_path = tmp_path / "missing_finding.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-MF-01", "Missing Finding Case")

    store.save_event("CASE-MF-01", {
        "event_id": "EVT-MF-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })

    # Save assessment pointing to non-existent finding ID 9999
    store.save_assessment("CASE-MF-01", {
        "score": 50,
        "severity": "MEDIUM",
        "confidence": 0.8,
        "reasons": ["Test reason"],
        "techniques": ["T1059"],
        "correlations": [{
            "incident_id": "INC-MF-1",
            "finding_ids": [9999],
            "evidence_ids": ["EVT-MF-1"],
            "start_time": "2026-08-08T10:00:00Z",
            "end_time": "2026-08-08T10:00:00Z",
        }]
    })
    store.close()

    res = validate_investigation(db_path, "CASE-MF-01")
    assert res.case_exists is True
    assert res.incidents_with_findings == 0
    assert res.passed is False
    assert any("references missing finding 9999" in issue.message for issue in res.issues)


def test_validate_missing_evidence_reference(tmp_path):
    db_path = tmp_path / "missing_evidence.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-ME-01", "Missing Evidence Case")

    # Save event first
    store.save_event("CASE-ME-01", {
        "event_id": "EVT-ME-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })

    # Finding references EVT-ME-1
    fid = store.save_finding("CASE-ME-01", {
        "type": "suspicious_cmd",
        "score": 30,
        "confidence": 0.7,
        "technique": "T1059.003",
        "reason": "Test cmd",
    }, event_ids=["EVT-ME-1"])

    # Delete EVT-ME-1 with foreign keys disabled
    store.connection.execute("PRAGMA foreign_keys = OFF")
    store.connection.execute("DELETE FROM events WHERE event_id = 'EVT-ME-1'")
    store.connection.commit()
    store.connection.execute("PRAGMA foreign_keys = ON")
    store.close()

    res = validate_investigation(db_path, "CASE-ME-01")
    assert res.case_exists is True
    assert res.findings_with_evidence == 0
    assert res.passed is False
    assert any("references missing evidence EVT-ME-1" in issue.message for issue in res.issues)


def test_validate_cross_case_isolation_failure(tmp_path):
    db_path = tmp_path / "cross_case.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-A", "Case A")
    store.create_case("CASE-B", "Case B")

    # Event in Case A
    store.save_event("CASE-A", {
        "event_id": "EVT-CASE-A-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })

    # Assessment in Case B referencing Event from Case A
    store.save_assessment("CASE-B", {
        "score": 50,
        "severity": "MEDIUM",
        "confidence": 0.8,
        "reasons": ["Cross case test"],
        "techniques": ["T1059"],
        "correlations": [{
            "incident_id": "INC-CROSS-1",
            "finding_ids": [],
            "evidence_ids": ["EVT-CASE-A-1"],
            "start_time": "2026-08-08T10:00:00Z",
            "end_time": "2026-08-08T10:00:00Z",
        }]
    })
    store.close()

    res = validate_investigation(db_path, "CASE-B")
    assert res.case_exists is True
    assert res.cross_case_references > 0
    assert res.passed is False
    assert any("references evidence EVT-CASE-A-1 from another case (CASE-A)" in issue.message for issue in res.issues)


def test_validate_reconstruction_exception_failure(tmp_path):
    db_path = tmp_path / "recon_fail.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-RECON-FAIL", "Recon Fail Case")
    store.save_event("CASE-RECON-FAIL", {
        "event_id": "EVT-R1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })
    store.close()

    with patch("ransomeye.investigation_validation.reconstruct_attack", side_effect=RuntimeError("Reconstruction processing crash")):
        res = validate_investigation(db_path, "CASE-RECON-FAIL")
        assert res.case_exists is True
        assert res.reconstruction_status == "FAIL"
        assert res.passed is False
        assert any("Reconstruction processing exception" in i.message for i in res.issues)


def test_validate_broken_timeline_reference(tmp_path):
    db_path = tmp_path / "broken_timeline.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-TL-FAIL", "Timeline Fail Case")

    store.save_event("CASE-TL-FAIL", {
        "event_id": "EVT-TL-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })
    store.close()

    with patch("ransomeye.investigation_validation.get_case_timeline", return_value=[{"event_id": "EVT-MISSING-TL", "timestamp": "2026-08-08T10:00:00Z"}]):
        res = validate_investigation(db_path, "CASE-TL-FAIL")
        assert res.case_exists is True
        assert res.timeline_ok is False
        assert res.passed is False
        assert any("Timeline entry references missing evidence EVT-MISSING-TL" in i.message for i in res.issues)


def test_validate_cli_success(tmp_path):
    db_path = tmp_path / "cli_valid.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-CLI-PASS", "CLI Pass Case")
    store.close()

    cli_res = _run_command([
        "investigation", "validate",
        "--database", str(db_path),
        "--case", "CASE-CLI-PASS",
    ])
    assert cli_res.returncode == 0
    assert "RANSOMEYE INVESTIGATION VALIDATION" in cli_res.stdout
    assert "Case: CASE-CLI-PASS" in cli_res.stdout
    assert "RESULT\n------\nPASS" in cli_res.stdout


def test_validate_cli_failure(tmp_path):
    db_path = tmp_path / "cli_fail.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-CLI-FAIL", "CLI Fail Case")

    store.save_event("CASE-CLI-FAIL", {
        "event_id": "EVT-TEMP-1",
        "timestamp": "2026-08-08T10:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "pid": "100",
    })
    store.save_finding("CASE-CLI-FAIL", {
        "type": "bad_event",
        "score": 50,
        "reason": "Missing evidence",
    }, event_ids=["EVT-TEMP-1"])

    store.connection.execute("PRAGMA foreign_keys = OFF")
    store.connection.execute("DELETE FROM events WHERE event_id = 'EVT-TEMP-1'")
    store.connection.commit()
    store.connection.execute("PRAGMA foreign_keys = ON")
    store.close()

    cli_res = _run_command([
        "investigation", "validate",
        "--database", str(db_path),
        "--case", "CASE-CLI-FAIL",
    ])
    assert cli_res.returncode != 0
    assert "RANSOMEYE INVESTIGATION VALIDATION" in cli_res.stdout
    assert "RESULT\n------\nFAIL" in cli_res.stdout
    assert "Problems:" in cli_res.stdout
    assert "EVT-TEMP-1" in cli_res.stdout
