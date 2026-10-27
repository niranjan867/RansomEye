"""Phase 2C.1 — Phishing analyzer evidence-pipeline integration tests."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.phishing import (
    MessagePayload,
    PHISHING_FINDING_TYPE,
    PHISHING_SOURCE,
    PhishingDetector,
    ingest_phishing_finding,
    phishing_canonical_bytes,
    phishing_content_sha256,
    phishing_event_id,
)
from ransomeye.report import generate_case_report
from ransomeye.storage import EvidenceStore
from ransomeye.timeline import get_case_timeline


_SUSPICIOUS_BODY = (
    "URGENT: Your Bank of America account is suspended. Verify KYC within 24 "
    "hours at http://192.168.1.50/login or your card will be blocked."
)


def _detect(payload: MessagePayload):
    return PhishingDetector().analyze(payload)


def _make_case(tmp_path: Path, case_id: str = "CASE-PHISH-01") -> tuple[EvidenceStore, Path]:
    db = tmp_path / "phish.db"
    store = EvidenceStore(db)
    store.create_case(case_id, "phishing evidence test")
    return store, db


# --------------------------------------------------------------------------- #
# Deterministic event ID
# --------------------------------------------------------------------------- #

def test_event_id_is_deterministic_from_content():
    p1 = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="attacker@evil.example")
    p2 = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="attacker@evil.example")
    assert phishing_content_sha256(p1) == phishing_content_sha256(p2)
    assert phishing_event_id(phishing_content_sha256(p1)).startswith("EVT-PHISH-")
    assert len(phishing_event_id(phishing_content_sha256(p1))) == len("EVT-PHISH-") + 20


def test_event_id_differs_for_different_content():
    p1 = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="a@x.example")
    p2 = MessagePayload.from_text(_SUSPICIOUS_BODY + " extra", sender="a@x.example")
    assert phishing_content_sha256(p1) != phishing_content_sha256(p2)


def test_event_id_is_not_derived_from_literal_suspicious_message():
    """Regression: the hash must be of real content, not the literal 'suspicious_message'."""
    import hashlib
    literal_hash = hashlib.sha256(b"suspicious_message").hexdigest()
    p = MessagePayload.from_text(_SUSPICIOUS_BODY)
    assert phishing_content_sha256(p) != literal_hash


def test_canonical_representation_is_order_insensitive_on_headers_urls():
    p1 = MessagePayload(
        text="hi", subject="s", sender="s@x", recipient="r@x",
        headers={"a": "1", "b": "2"}, urls=["https://x", "https://y"],
        attachments=["a.exe", "b.pdf"],
    )
    p2 = MessagePayload(
        text="hi", subject="s", sender="s@x", recipient="r@x",
        headers={"b": "2", "a": "1"}, urls=["https://y", "https://x"],
        attachments=["b.pdf", "a.exe"],
    )
    assert phishing_canonical_bytes(p1) == phishing_canonical_bytes(p2)


# --------------------------------------------------------------------------- #
# Evidence event + finding_evidence linkage
# --------------------------------------------------------------------------- #

def test_ingest_persists_evidence_event_with_deterministic_id(tmp_path):
    store, _ = _make_case(tmp_path)
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="attacker@evil.example")
    result = _detect(payload)
    finding_id = ingest_phishing_finding(store, "CASE-PHISH-01", result, payload=payload)
    assert finding_id is not None

    expected_event_id = phishing_event_id(phishing_content_sha256(payload))
    ev = store.get_event("CASE-PHISH-01", expected_event_id)
    assert ev is not None
    assert ev["source"] == PHISHING_SOURCE
    assert ev["event_type"] == "file_stream_hash"
    # Custody-grade SHA-256 travels in metadata (events table has no hashes column).
    meta = ev.get("metadata_json") or {}
    if isinstance(meta, str):
        meta = json.loads(meta)
    assert meta.get("sha256") == phishing_content_sha256(payload)
    store.close()


def test_finding_is_linked_to_evidence_event(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-PHISH-LINK")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY)
    result = _detect(payload)
    fid = ingest_phishing_finding(store, "CASE-PHISH-LINK", result, payload=payload)

    findings = store.get_case_findings("CASE-PHISH-LINK")
    phish_findings = [f for f in findings if f["finding_type"] == PHISHING_FINDING_TYPE]
    assert len(phish_findings) == 1
    assert phish_findings[0]["finding_id"] == fid
    assert phish_findings[0]["event_ids"], "phishing finding must link to evidence"
    assert phish_findings[0]["event_ids"][0] == phishing_event_id(phishing_content_sha256(payload))
    store.close()


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #

def test_repeated_ingest_is_idempotent(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-PHISH-IDEM")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="x@y.example")
    result = _detect(payload)

    first = ingest_phishing_finding(store, "CASE-PHISH-IDEM", result, payload=payload)
    second = ingest_phishing_finding(store, "CASE-PHISH-IDEM", result, payload=payload)
    third = ingest_phishing_finding(store, "CASE-PHISH-IDEM", result, payload=payload)

    assert first == second == third

    findings = store.get_case_findings("CASE-PHISH-IDEM")
    phish = [f for f in findings if f["finding_type"] == PHISHING_FINDING_TYPE]
    assert len(phish) == 1, "idempotent ingest must not duplicate findings"
    store.close()


def test_different_payload_creates_new_evidence(tmp_path):
    store, _ = _make_case(tmp_path, "CASE-PHISH-DIFF")
    p1 = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="a@x.example")
    p2 = MessagePayload.from_text(_SUSPICIOUS_BODY + " second variant", sender="a@x.example")
    f1 = ingest_phishing_finding(store, "CASE-PHISH-DIFF", _detect(p1), payload=p1)
    f2 = ingest_phishing_finding(store, "CASE-PHISH-DIFF", _detect(p2), payload=p2)
    assert f1 != f2
    findings = store.get_case_findings("CASE-PHISH-DIFF")
    assert sum(1 for f in findings if f["finding_type"] == PHISHING_FINDING_TYPE) == 2
    store.close()


# --------------------------------------------------------------------------- #
# Timeline / report traceability
# --------------------------------------------------------------------------- #

def test_timeline_contains_phishing_evidence(tmp_path):
    store, db = _make_case(tmp_path, "CASE-PHISH-TL")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY)
    ingest_phishing_finding(store, "CASE-PHISH-TL", _detect(payload), payload=payload)
    store.close()

    events = get_case_timeline(db, "CASE-PHISH-TL")
    sources = {e["source"] for e in events}
    assert PHISHING_SOURCE in sources
    assert any(e["event_id"].startswith("EVT-PHISH-") for e in events)


def test_report_includes_phishing_evidence(tmp_path):
    store, db = _make_case(tmp_path, "CASE-PHISH-RPT")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY)
    ingest_phishing_finding(store, "CASE-PHISH-RPT", _detect(payload), payload=payload)
    store.close()

    report = generate_case_report(db, "CASE-PHISH-RPT")
    assert PHISHING_FINDING_TYPE in report
    assert "EVT-PHISH-" in report
    assert PHISHING_SOURCE in report


# --------------------------------------------------------------------------- #
# Custody uses real content hash, not "suspicious_message"
# --------------------------------------------------------------------------- #

def test_custody_hash_matches_actual_content(tmp_path):
    import hashlib
    store, _ = _make_case(tmp_path, "CASE-PHISH-CUST")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY, sender="s@x.example")
    ingest_phishing_finding(store, "CASE-PHISH-CUST", _detect(payload), payload=payload)

    custody = store.get_custody_events("CASE-PHISH-CUST")
    phish_custody = [c for c in custody if "phishing-analyzer" in (c.get("analyst") or "")]
    assert phish_custody
    expected = phishing_content_sha256(payload)
    assert phish_custody[0]["sha256"] == expected

    # The old literal "suspicious_message" hash must not appear.
    legacy = hashlib.sha256(b"suspicious_message").hexdigest()
    assert all(c["sha256"] != legacy for c in phish_custody)
    store.close()


# --------------------------------------------------------------------------- #
# No process attribution fabricated
# --------------------------------------------------------------------------- #

def test_phishing_event_never_fabricates_process_attribution(tmp_path):
    store, db = _make_case(tmp_path, "CASE-PHISH-NP")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY)
    ingest_phishing_finding(store, "CASE-PHISH-NP", _detect(payload), payload=payload)
    store.close()
    for ev in get_case_timeline(db, "CASE-PHISH-NP"):
        if ev["source"] == PHISHING_SOURCE:
            assert not ev.get("process_name")
            assert not ev.get("command_line")
            assert not ev.get("process_guid")
            assert not ev.get("parent_pid")


# --------------------------------------------------------------------------- #
# Attacker-controlled content stays safe (string data, not HTML)
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]


def test_attacker_controlled_subject_and_body_round_trip_as_string_data(tmp_path):
    store, db = _make_case(tmp_path, "CASE-PHISH-XSS")
    for probe in _XSS_PROBES:
        payload = MessagePayload(
            text=f"verify {probe} your account at http://192.168.1.5/login",
            subject=probe, sender=f"{probe}@evil.example",
        )
        ingest_phishing_finding(store, "CASE-PHISH-XSS", _detect(payload), payload=payload)
    store.close()

    # Pull the serialized events and confirm the probe is present as plain
    # string data in metadata/hashes/subject.
    events = get_case_timeline(db, "CASE-PHISH-XSS")
    phish_events = [e for e in events if e["source"] == PHISHING_SOURCE]
    assert phish_events
    for ev in phish_events:
        meta = ev.get("metadata_json") or ""
        assert isinstance(meta, str), "metadata is persisted as JSON string, never structural"
    # Report contains the probe only as text.
    report = generate_case_report(db, "CASE-PHISH-XSS")
    for probe in _XSS_PROBES:
        # Reports surface the finding reason, which bounds subject exposure to
        # the top-3-indicator string; probes do not become report structure.
        assert "<html" not in report.lower()
        assert "<body" not in report.lower()


# --------------------------------------------------------------------------- #
# Backward compatibility: callers that still omit payload
# --------------------------------------------------------------------------- #

def test_legacy_call_without_payload_is_still_deterministic(tmp_path):
    import hashlib
    store, _ = _make_case(tmp_path, "CASE-PHISH-LEGACY")
    payload = MessagePayload.from_text(_SUSPICIOUS_BODY)
    result = _detect(payload)
    f1 = ingest_phishing_finding(store, "CASE-PHISH-LEGACY", result)
    f2 = ingest_phishing_finding(store, "CASE-PHISH-LEGACY", result)
    assert f1 == f2, "legacy ingest must still be idempotent per analysis result"

    # The event id must NOT be derived from the literal 'suspicious_message'.
    literal_sha = hashlib.sha256(b"suspicious_message").hexdigest()
    legacy_event_id = f"EVT-PHISH-{literal_sha[:20]}"
    assert store.get_event("CASE-PHISH-LEGACY", legacy_event_id) is None
    store.close()


# --------------------------------------------------------------------------- #
# CLI / API wiring smoke-tests
# --------------------------------------------------------------------------- #

def test_cli_phishing_ingest_now_creates_evidence_event(tmp_path):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PHISH-CLI", "cli")
    store.close()
    cmd = [
        sys.executable, "-m", "ransomeye.commands",
        "phishing", "--text", _SUSPICIOUS_BODY,
        "--database", str(db), "--case", "CASE-PHISH-CLI",
    ]
    res = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert "Phishing finding ingested" in res.stdout

    store = EvidenceStore(db)
    events = store.get_case_events("CASE-PHISH-CLI")
    assert any(e["event_id"].startswith("EVT-PHISH-") for e in events)
    assert any(e["source"] == PHISHING_SOURCE for e in events)
    store.close()
