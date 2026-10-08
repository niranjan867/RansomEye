"""Phase 2C.2 — Static analyzer deterministic-evidence integration tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ransomeye.report import generate_case_report
from ransomeye.static_analyzer import (
    STATIC_FINDING_TYPE,
    STATIC_SOURCE,
    StaticAnalyzer,
    ingest_static_finding,
    static_event_id,
)
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import get_case_timeline


def _write_artifact(tmp_path: Path, name: str, body: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(body)
    return p


def _make_case(tmp_path: Path, case_id: str) -> tuple[EvidenceStore, Path]:
    db = tmp_path / "static.db"
    store = EvidenceStore(db)
    store.create_case(case_id, "static evidence test")
    return store, db


# --------------------------------------------------------------------------- #
# Deterministic event id
# --------------------------------------------------------------------------- #

def test_event_id_is_sha256_prefix():
    sha = "a" * 64
    eid = static_event_id(sha)
    assert eid == "EVT-STATIC-" + "a" * 20
    assert len(eid) == len("EVT-STATIC-") + 20


def test_event_id_is_deterministic_across_runs(tmp_path):
    artifact = _write_artifact(tmp_path, "sample.bin", b"malware payload bytes" * 100)
    r1 = StaticAnalyzer().analyze_file(artifact)
    r2 = StaticAnalyzer().analyze_file(artifact)
    assert r1.sha256 == r2.sha256
    assert static_event_id(r1.sha256) == static_event_id(r2.sha256)


def test_event_id_differs_for_different_artifacts(tmp_path):
    a1 = _write_artifact(tmp_path, "a.bin", b"content one")
    a2 = _write_artifact(tmp_path, "b.bin", b"content two")
    r1 = StaticAnalyzer().analyze_file(a1)
    r2 = StaticAnalyzer().analyze_file(a2)
    assert static_event_id(r1.sha256) != static_event_id(r2.sha256)


def test_event_id_is_not_a_random_uuid(tmp_path):
    """Regression: the previous implementation used uuid.uuid4().hex[:12];
    the new id must be the SHA-256 prefix of the artifact bytes."""
    artifact = _write_artifact(tmp_path, "sample.bin", b"deterministic input")
    result = StaticAnalyzer().analyze_file(artifact)
    expected_prefix = result.sha256[:20]
    eid = static_event_id(result.sha256)
    assert eid == f"EVT-STATIC-{expected_prefix}"
    # And it reproduces exactly from the hash we can compute ourselves.
    manual_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert eid == f"EVT-STATIC-{manual_hash[:20]}"


# --------------------------------------------------------------------------- #
# Persistence + finding_evidence linkage
# --------------------------------------------------------------------------- #

def test_ingest_persists_evidence_event_with_deterministic_id(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-STATIC-01")
    artifact = _write_artifact(tmp_path, "x.bin", b"persist me")
    result = StaticAnalyzer().analyze_file(artifact)
    fid = ingest_static_finding(store, "CASE-STATIC-01", result)
    assert fid is not None

    expected_event_id = static_event_id(result.sha256)
    ev = store.get_event("CASE-STATIC-01", expected_event_id)
    assert ev is not None
    assert ev["source"] == STATIC_SOURCE
    assert ev["event_type"] == "file_stream_hash"
    # SHA-256 travels in metadata (events table has no hashes column).
    meta = ev.get("metadata_json") or {}
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta.get("sha256") == result.sha256
    store.close()


def test_finding_links_to_deterministic_event(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-STATIC-LINK")
    artifact = _write_artifact(tmp_path, "link.bin", b"link test")
    result = StaticAnalyzer().analyze_file(artifact)
    fid = ingest_static_finding(store, "CASE-STATIC-LINK", result)

    findings = store.get_case_findings("CASE-STATIC-LINK")
    static_findings = [f for f in findings if f["finding_type"] == STATIC_FINDING_TYPE]
    assert len(static_findings) == 1
    assert static_findings[0]["finding_id"] == fid
    assert static_findings[0]["event_ids"] == [static_event_id(result.sha256)]
    store.close()


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #

def test_repeated_analysis_is_idempotent(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-STATIC-IDEM")
    artifact = _write_artifact(tmp_path, "idem.bin", b"same bytes")
    result = StaticAnalyzer().analyze_file(artifact)

    f1 = ingest_static_finding(store, "CASE-STATIC-IDEM", result)
    f2 = ingest_static_finding(store, "CASE-STATIC-IDEM", result)
    f3 = ingest_static_finding(store, "CASE-STATIC-IDEM", result)
    assert f1 == f2 == f3

    findings = store.get_case_findings("CASE-STATIC-IDEM")
    static_findings = [f for f in findings if f["finding_type"] == STATIC_FINDING_TYPE]
    assert len(static_findings) == 1, "idempotent ingest must not duplicate findings"

    # Exactly one static evidence event in the case.
    events = store.get_case_events("CASE-STATIC-IDEM")
    static_events = [e for e in events if e["source"] == STATIC_SOURCE]
    assert len(static_events) == 1, "idempotent ingest must not create duplicate events"
    store.close()


def test_different_artifacts_create_distinct_findings(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-STATIC-DIFF")
    a = _write_artifact(tmp_path, "a.bin", b"artifact A")
    b = _write_artifact(tmp_path, "b.bin", b"artifact B")
    ra = StaticAnalyzer().analyze_file(a)
    rb = StaticAnalyzer().analyze_file(b)

    fa = ingest_static_finding(store, "CASE-STATIC-DIFF", ra)
    fb = ingest_static_finding(store, "CASE-STATIC-DIFF", rb)
    assert fa != fb

    findings = store.get_case_findings("CASE-STATIC-DIFF")
    assert sum(1 for f in findings if f["finding_type"] == STATIC_FINDING_TYPE) == 2
    store.close()


# --------------------------------------------------------------------------- #
# Traceability (timeline, report)
# --------------------------------------------------------------------------- #

def test_timeline_contains_static_evidence(tmp_path):
    store, db = _make_case(tmp_path, "CASE-STATIC-TL")
    artifact = _write_artifact(tmp_path, "tl.bin", b"timeline")
    result = StaticAnalyzer().analyze_file(artifact)
    ingest_static_finding(store, "CASE-STATIC-TL", result)
    store.close()

    events = get_case_timeline(db, "CASE-STATIC-TL")
    assert any(e["source"] == STATIC_SOURCE for e in events)
    assert any(e["event_id"].startswith("EVT-STATIC-") for e in events)


def test_report_includes_static_evidence(tmp_path):
    store, db = _make_case(tmp_path, "CASE-STATIC-RPT")
    artifact = _write_artifact(tmp_path, "r.bin", b"report")
    result = StaticAnalyzer().analyze_file(artifact)
    ingest_static_finding(store, "CASE-STATIC-RPT", result)
    store.close()

    text = generate_case_report(db, "CASE-STATIC-RPT")
    assert STATIC_FINDING_TYPE in text
    assert "EVT-STATIC-" in text
    assert STATIC_SOURCE in text


# --------------------------------------------------------------------------- #
# No process attribution fabricated
# --------------------------------------------------------------------------- #

def test_static_event_never_fabricates_process_attribution(tmp_path):
    store, db = _make_case(tmp_path, "CASE-STATIC-NP")
    artifact = _write_artifact(tmp_path, "np.bin", b"no process metadata")
    result = StaticAnalyzer().analyze_file(artifact)
    ingest_static_finding(store, "CASE-STATIC-NP", result)
    store.close()
    for ev in get_case_timeline(db, "CASE-STATIC-NP"):
        if ev["source"] == STATIC_SOURCE:
            assert not ev.get("process_name")
            assert not ev.get("command_line")
            assert not ev.get("process_guid")
            assert not ev.get("parent_pid")


# --------------------------------------------------------------------------- #
# Custody uses the real artifact SHA-256
# --------------------------------------------------------------------------- #

def test_custody_hash_matches_artifact_sha256(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-STATIC-CUST")
    artifact = _write_artifact(tmp_path, "c.bin", b"custody bytes")
    result = StaticAnalyzer().analyze_file(artifact)
    ingest_static_finding(store, "CASE-STATIC-CUST", result)

    custody = store.get_custody_events("CASE-STATIC-CUST")
    static_custody = [c for c in custody if "static-analyzer" in (c.get("analyst") or "")]
    assert static_custody
    assert static_custody[0]["sha256"] == result.sha256
    store.close()
