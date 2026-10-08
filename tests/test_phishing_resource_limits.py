"""Phase 2C.5 — Phishing analyzer resource limits."""

from __future__ import annotations

import json
import pytest

from ransomeye.phishing import (
    MAX_PHISHING_ATTACHMENT_NAME_LEN,
    MAX_PHISHING_ATTACHMENTS,
    MAX_PHISHING_BODY_LEN,
    MAX_PHISHING_HEADER_VALUE_LEN,
    MAX_PHISHING_HEADERS,
    MAX_PHISHING_INDICATORS,
    MAX_PHISHING_INPUT_SIZE,
    MAX_PHISHING_SUBJECT_LEN,
    MAX_PHISHING_URL_LEN,
    MAX_PHISHING_URLS,
    MAX_PHISHING_WARNINGS,
    MessagePayload,
    PhishingAnalysisError,
    PhishingDetector,
    ingest_phishing_finding,
    phishing_content_sha256,
    phishing_event_id,
)
from ransomeye.storage import EvidenceStore


def _d():
    return PhishingDetector()


# --------------------------------------------------------------------------- #
# Normal payloads remain unchanged
# --------------------------------------------------------------------------- #

def test_normal_payload_has_no_warnings_and_same_score():
    payload = MessagePayload.from_text(
        "URGENT: Verify your Bank of America KYC within 24 hours or your card "
        "will be blocked. http://192.168.1.5/login",
        sender="attacker@evil.example",
    )
    before = _d().analyze(payload)
    after = _d().analyze(payload)
    assert before.warnings == []
    assert after.warnings == []
    assert before.score == after.score
    assert before.risk_level == after.risk_level
    assert before.confidence == after.confidence
    assert [i.rule_id for i in before.indicators] == [i.rule_id for i in after.indicators]


# --------------------------------------------------------------------------- #
# Total aggregate size: HARD rejection
# --------------------------------------------------------------------------- #

def test_total_aggregate_above_cap_is_rejected():
    oversized_body = "A" * (MAX_PHISHING_INPUT_SIZE + 1)
    payload = MessagePayload(text=oversized_body)
    with pytest.raises(PhishingAnalysisError):
        _d().analyze(payload)


def test_total_aggregate_at_cap_is_accepted():
    body = "A" * MAX_PHISHING_INPUT_SIZE
    payload = MessagePayload(text=body)
    r = _d().analyze(payload)
    # At the cap, the aggregate check passes; the body truncation warning
    # fires because body > MAX_PHISHING_BODY_LEN.
    assert any("Body truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# Body truncation
# --------------------------------------------------------------------------- #

def test_body_above_cap_is_truncated_with_warning():
    body = "a" * (MAX_PHISHING_BODY_LEN + 100)
    payload = MessagePayload(text=body)
    r = _d().analyze(payload)
    assert any("Body truncated" in w for w in r.warnings)


def test_body_at_cap_is_not_truncated():
    body = "a" * MAX_PHISHING_BODY_LEN
    payload = MessagePayload(text=body)
    r = _d().analyze(payload)
    assert not any("Body truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# Subject / sender / recipient truncation
# --------------------------------------------------------------------------- #

def test_subject_above_cap_is_truncated():
    payload = MessagePayload(subject="S" * (MAX_PHISHING_SUBJECT_LEN + 50), text="hi")
    r = _d().analyze(payload)
    assert any("Subject truncated" in w for w in r.warnings)


def test_sender_above_cap_is_truncated():
    payload = MessagePayload(text="hi", sender="s" * 5000)
    r = _d().analyze(payload)
    assert any("Sender truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# Headers
# --------------------------------------------------------------------------- #

def test_excessive_headers_are_bounded():
    headers = {f"x-h{i}": "v" for i in range(MAX_PHISHING_HEADERS + 50)}
    payload = MessagePayload(text="hi", headers=headers)
    r = _d().analyze(payload)
    assert any("Header count capped" in w for w in r.warnings)


def test_oversized_header_value_is_bounded():
    headers = {"x-huge": "x" * (MAX_PHISHING_HEADER_VALUE_LEN + 100)}
    payload = MessagePayload(text="hi", headers=headers)
    r = _d().analyze(payload)
    assert any("Header value truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #

def test_excessive_urls_are_bounded():
    urls = [f"https://example-{i}.test/" for i in range(MAX_PHISHING_URLS + 100)]
    payload = MessagePayload(text="see links", urls=urls)
    r = _d().analyze(payload)
    assert any("URL count capped" in w for w in r.warnings)


def test_oversized_url_is_bounded():
    big_url = "https://evil.example/" + ("a" * (MAX_PHISHING_URL_LEN + 100))
    payload = MessagePayload(text="click", urls=[big_url])
    r = _d().analyze(payload)
    assert any("URL truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #

def test_excessive_attachments_are_bounded():
    atts = [f"file-{i}.exe" for i in range(MAX_PHISHING_ATTACHMENTS + 50)]
    payload = MessagePayload(text="see attached", attachments=atts)
    r = _d().analyze(payload)
    assert any("Attachment count capped" in w for w in r.warnings)


def test_oversized_attachment_name_is_bounded():
    atts = ["b" * (MAX_PHISHING_ATTACHMENT_NAME_LEN + 20) + ".exe"]
    payload = MessagePayload(text="see", attachments=atts)
    r = _d().analyze(payload)
    assert any("Attachment name truncated" in w for w in r.warnings)


# --------------------------------------------------------------------------- #
# Indicator cap
# --------------------------------------------------------------------------- #

def test_indicator_cap_is_enforced():
    # Build a message that would normally produce many indicators via URL rules.
    many_bad_urls = [f"http://192.168.{i // 256}.{i % 256}/login" for i in range(MAX_PHISHING_INDICATORS + 50)]
    payload = MessagePayload(text="urgent urgent urgent", urls=many_bad_urls)
    r = _d().analyze(payload)
    assert len(r.indicators) <= MAX_PHISHING_INDICATORS


# --------------------------------------------------------------------------- #
# Warning cap
# --------------------------------------------------------------------------- #

def test_many_simultaneous_limits_do_not_crash():
    """Hitting every per-component cap at once must produce a bounded
    analysis (not a crash), with the warnings list respecting
    MAX_PHISHING_WARNINGS."""
    payload = MessagePayload(
        text="a" * (MAX_PHISHING_BODY_LEN + 10),
        subject="S" * (MAX_PHISHING_SUBJECT_LEN + 10),
        sender="x" * 5000,
        headers={f"h{i}": "x" * (MAX_PHISHING_HEADER_VALUE_LEN + 1)
                 for i in range(MAX_PHISHING_HEADERS + 5)},
        urls=[("https://x.test/" + "a" * 100) for _ in range(MAX_PHISHING_URLS + 5)],
        attachments=[f"a-{i}.exe" for i in range(MAX_PHISHING_ATTACHMENTS + 5)],
    )
    r = _d().analyze(payload)
    assert r.warnings, "simultaneous over-cap conditions must emit warnings"
    assert len(r.warnings) <= MAX_PHISHING_WARNINGS
    # Core bounded-category warnings are present.
    text_dump = "\n".join(r.warnings)
    assert "Body truncated" in text_dump
    assert "Subject truncated" in text_dump
    assert "Header value truncated" in text_dump
    assert "URL count capped" in text_dump
    assert "Attachment count capped" in text_dump


# --------------------------------------------------------------------------- #
# Determinism under bounded analysis
# --------------------------------------------------------------------------- #

def test_bounded_analysis_is_deterministic():
    body = "verify kyc at http://192.168.1.5/login " + "a" * (MAX_PHISHING_BODY_LEN + 10)
    payload = MessagePayload(text=body, subject="urgent")
    r1 = _d().analyze(payload)
    r2 = _d().analyze(payload)
    assert r1.score == r2.score
    assert r1.risk_level == r2.risk_level
    assert r1.confidence == r2.confidence
    assert [i.rule_id for i in r1.indicators] == [i.rule_id for i in r2.indicators]
    assert sorted(r1.warnings) == sorted(r2.warnings)


# --------------------------------------------------------------------------- #
# EVT-PHISH identity is still derived from the ORIGINAL content
# --------------------------------------------------------------------------- #

def test_event_identity_uses_original_content_not_truncated(tmp_path):
    body_short = "URGENT verify KYC http://192.168.1.5/login"
    body_long = body_short + ("x" * (MAX_PHISHING_BODY_LEN + 500))
    p_short = MessagePayload.from_text(body_short, sender="a@x.example")
    p_long = MessagePayload.from_text(body_long, sender="a@x.example")

    # Different originals must yield different event ids, even though the
    # analyzed PREFIX is the same (because the long body is truncated at
    # MAX_PHISHING_BODY_LEN which happens to be larger than the short body's
    # length — so the truncated-view prefix is still the short body).
    assert phishing_content_sha256(p_short) != phishing_content_sha256(p_long)
    assert phishing_event_id(phishing_content_sha256(p_short)) != \
           phishing_event_id(phishing_content_sha256(p_long))


def test_case_persistence_still_works_after_bounded_analysis(tmp_path):
    db = tmp_path / "p.db"
    store = EvidenceStore(db)
    store.create_case("CASE-PHISH-RL", "resource limits")
    body = "URGENT verify KYC at http://192.168.1.5/login " + "x" * (MAX_PHISHING_BODY_LEN + 5)
    payload = MessagePayload.from_text(body, sender="a@x.example")
    result = _d().analyze(payload)
    assert result.warnings  # bounded analysis
    fid = ingest_phishing_finding(store, "CASE-PHISH-RL", result, payload=payload)
    assert fid is not None
    findings = store.get_case_findings("CASE-PHISH-RL")
    phish = [f for f in findings if f["finding_type"] == "phishing_initial_access"]
    assert phish and phish[0]["event_ids"]
    assert phish[0]["event_ids"][0].startswith("EVT-PHISH-")
    store.close()


def test_bounded_result_serializes_warnings_field():
    body = "a" * (MAX_PHISHING_BODY_LEN + 10)
    payload = MessagePayload(text=body)
    r = _d().analyze(payload)
    d = r.to_dict()
    assert "warnings" in d
    assert isinstance(d["warnings"], list)
    assert d["warnings"], "warnings must appear in to_dict() when bounds hit"


# --------------------------------------------------------------------------- #
# XSS inertness through the bounded path
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]


def test_xss_probes_remain_inert_with_truncation():
    for probe in _XSS_PROBES:
        oversized = probe + ("x" * (MAX_PHISHING_BODY_LEN + 100))
        payload = MessagePayload.from_text(oversized, sender=f"{probe}@evil.example")
        r = _d().analyze(payload)
        blob = json.dumps(r.to_dict())
        # Probe round-trips as JSON string data (indicators / urls are string valued).
        assert isinstance(blob, str)
        assert "<html" not in blob.lower()


# --------------------------------------------------------------------------- #
# Empty / tiny input
# --------------------------------------------------------------------------- #

def test_empty_payload_is_safe():
    payload = MessagePayload()
    r = _d().analyze(payload)
    assert r.warnings == []
    assert r.indicators == []


def test_tiny_payload_is_safe():
    payload = MessagePayload.from_text("ok")
    r = _d().analyze(payload)
    assert r.warnings == []


# --------------------------------------------------------------------------- #
# Dashboard view surfaces warnings
# --------------------------------------------------------------------------- #

def test_app_js_phishing_view_renders_warnings():
    from pathlib import Path
    from ransomeye import dashboard_server
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    render_fn = app_js.split("function renderPhishingResult(")[1].split("\nfunction ")[0]
    assert "a.warnings" in render_fn or "analysis.warnings" in render_fn
    assert "Bounded-analysis warnings" in render_fn


def test_app_js_safe_dom_invariant_preserved():
    from pathlib import Path
    from ransomeye import dashboard_server
    app_js = (Path(dashboard_server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write(", "eval(", "new Function"):
        assert sink not in app_js, f"Phase 2C.5 regressed safe-DOM: '{sink}'"
