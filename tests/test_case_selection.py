"""Phase 2C.4 — Static / Phishing dashboard case selection and backend validation."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ransomeye import dashboard_server
from ransomeye.storage import EvidenceStore


# --------------------------------------------------------------------------- #
# HTTP fixtures
# --------------------------------------------------------------------------- #

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_server(tmp_path):
    port = _find_free_port()
    dashboard_server.DB_PATH = tmp_path / "cases.db"
    store = EvidenceStore(dashboard_server.DB_PATH)
    store.create_case("CASE-SEL-001", "Case selector demo")
    store.create_case("CASE-SEL-002", "Second case")
    store.close()
    httpd = dashboard_server.HTTPServer(("127.0.0.1", port), dashboard_server.DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _get_json(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _post_json(url: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# Case list is reachable to both case selectors
# --------------------------------------------------------------------------- #

def test_case_list_endpoint_returns_cases(running_server):
    code, res = _get_json(f"{running_server}/api/cases")
    assert code == 200
    ids = {c["case_id"] for c in res.get("cases", [])}
    assert "CASE-SEL-001" in ids
    assert "CASE-SEL-002" in ids


# --------------------------------------------------------------------------- #
# Static Analysis — case selector backend validation
# --------------------------------------------------------------------------- #

def _write_artifact(tmp_path: Path, name: str, content: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


def test_static_api_rejects_unknown_case(running_server, tmp_path):
    artifact = _write_artifact(tmp_path, "a.bin", b"content")
    code, res = _post_json(
        f"{running_server}/api/static/analyze",
        {"file_path": str(artifact), "case_id": "CASE-DOES-NOT-EXIST"},
    )
    assert code == 404
    assert "Case not found" in (res.get("error") or res.get("message", ""))


def test_static_api_rejects_malformed_case(running_server, tmp_path):
    artifact = _write_artifact(tmp_path, "a2.bin", b"content")
    code, res = _post_json(
        f"{running_server}/api/static/analyze",
        {"file_path": str(artifact), "case_id": "../../etc/passwd"},
    )
    assert code == 400


def test_static_api_persists_evidence_under_selected_case(running_server, tmp_path):
    artifact = _write_artifact(tmp_path, "sel.bin", b"persisted bytes")
    code, res = _post_json(
        f"{running_server}/api/static/analyze",
        {"file_path": str(artifact), "case_id": "CASE-SEL-001"},
    )
    assert code == 200, res
    assert res["case_id"] == "CASE-SEL-001"
    assert res["finding_id"] is not None

    store = EvidenceStore(dashboard_server.DB_PATH)
    try:
        # Finding belongs to the selected case.
        findings = store.get_case_findings("CASE-SEL-001")
        static_findings = [f for f in findings if f["finding_type"] == "static_file_analysis"]
        assert static_findings, "static finding must be stored under selected case"
        # finding_evidence rows reference the finding we just made.
        f = static_findings[0]
        assert f["event_ids"], "finding_evidence must link to the static evidence event"
        # The linked evidence event itself is owned by the selected case.
        ev = store.get_event("CASE-SEL-001", f["event_ids"][0])
        assert ev is not None
        assert ev["event_id"].startswith("EVT-STATIC-")
        # The other case must NOT see this finding or event.
        other_findings = store.get_case_findings("CASE-SEL-002")
        assert all(ff["finding_type"] != "static_file_analysis" for ff in other_findings), \
            "static finding leaked into the wrong case"
        assert store.get_event("CASE-SEL-002", f["event_ids"][0]) is None
    finally:
        store.close()


def test_static_api_is_idempotent_per_case(running_server, tmp_path):
    artifact = _write_artifact(tmp_path, "idem.bin", b"idempotent bytes")
    _, r1 = _post_json(
        f"{running_server}/api/static/analyze",
        {"file_path": str(artifact), "case_id": "CASE-SEL-001"},
    )
    _, r2 = _post_json(
        f"{running_server}/api/static/analyze",
        {"file_path": str(artifact), "case_id": "CASE-SEL-001"},
    )
    assert r1["finding_id"] == r2["finding_id"], "repeated analysis must be idempotent"

    store = EvidenceStore(dashboard_server.DB_PATH)
    try:
        findings = store.get_case_findings("CASE-SEL-001")
        static_findings = [f for f in findings if f["finding_type"] == "static_file_analysis"
                           and str(r1["finding_id"]) == str(f["finding_id"])]
        assert len(static_findings) == 1
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# Phishing Analysis — case selector backend validation
# --------------------------------------------------------------------------- #

_PHISH_TEXT = (
    "URGENT: Your bank account is suspended. Verify KYC within 24 hours at "
    "http://192.168.1.5/login or your card will be blocked."
)


def test_phishing_api_rejects_unknown_case(running_server):
    code, res = _post_json(
        f"{running_server}/api/phishing/analyze",
        {"body": _PHISH_TEXT, "case_id": "CASE-DOES-NOT-EXIST"},
    )
    assert code == 404
    assert "Case not found" in (res.get("error") or res.get("message", ""))


def test_phishing_api_rejects_malformed_case(running_server):
    code, res = _post_json(
        f"{running_server}/api/phishing/analyze",
        {"body": _PHISH_TEXT, "case_id": "bad id with spaces"},
    )
    assert code == 400


def test_phishing_api_persists_under_selected_case(running_server):
    code, res = _post_json(
        f"{running_server}/api/phishing/analyze",
        {"body": _PHISH_TEXT, "subject": "verify", "sender": "x@y.example",
         "case_id": "CASE-SEL-002"},
    )
    assert code == 200, res
    assert res["case_id"] == "CASE-SEL-002"
    assert res["finding_id"] is not None

    store = EvidenceStore(dashboard_server.DB_PATH)
    try:
        findings = store.get_case_findings("CASE-SEL-002")
        phish_findings = [f for f in findings if f["finding_type"] == "phishing_initial_access"]
        assert phish_findings
        linked = phish_findings[0]["event_ids"]
        assert linked
        ev = store.get_event("CASE-SEL-002", linked[0])
        assert ev is not None
        assert ev["event_id"].startswith("EVT-PHISH-")
        # Other case must not see it.
        other = store.get_case_findings("CASE-SEL-001")
        assert all(ff["finding_type"] != "phishing_initial_access" for ff in other)
    finally:
        store.close()


def test_phishing_api_is_idempotent_per_case(running_server):
    body = {"body": _PHISH_TEXT, "subject": "same", "sender": "attacker@evil.example",
            "case_id": "CASE-SEL-001"}
    _, r1 = _post_json(f"{running_server}/api/phishing/analyze", body)
    _, r2 = _post_json(f"{running_server}/api/phishing/analyze", body)
    assert r1["finding_id"] == r2["finding_id"]

    store = EvidenceStore(dashboard_server.DB_PATH)
    try:
        findings = store.get_case_findings("CASE-SEL-001")
        phish_findings = [f for f in findings
                          if f["finding_type"] == "phishing_initial_access"
                          and str(f["finding_id"]) == str(r1["finding_id"])]
        assert len(phish_findings) == 1
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# Static UI: template exposes a required case selector
# --------------------------------------------------------------------------- #

def _static_dir() -> Path:
    return Path(dashboard_server.__file__).parent / "static"


def test_static_template_has_case_selector():
    html = (_static_dir() / "index.html").read_text(encoding="utf-8")
    static_section = html.split("tpl-static")[1].split("</template>")[0]
    assert 'id="static-case"' in static_section
    assert 'data-case-selector="required"' in static_section
    assert 'id="static-case-status"' in static_section


def test_phishing_template_has_case_selector():
    html = (_static_dir() / "index.html").read_text(encoding="utf-8")
    phishing_section = html.split("tpl-phishing")[1].split("</template>")[0]
    assert 'id="phishing-case"' in phishing_section
    assert 'data-case-selector="required"' in phishing_section
    assert 'id="phishing-case-status"' in phishing_section


# --------------------------------------------------------------------------- #
# app.js: shared helper + required case plumbing
# --------------------------------------------------------------------------- #

def test_app_js_defines_shared_case_selector_helper():
    app_js = (_static_dir() / "app.js").read_text(encoding="utf-8")
    assert "function populateCaseSelector(" in app_js


def test_app_js_static_and_phishing_require_case_selection():
    app_js = (_static_dir() / "app.js").read_text(encoding="utf-8")
    static_fn = app_js.split("function initStatic(")[1].split("\nfunction ")[0]
    phishing_fn = app_js.split("function initPhishing(")[1].split("\nfunction ")[0]

    assert "populateCaseSelector(caseSel, { required: true" in static_fn, \
        "static view must mount a required case selector"
    assert "populateCaseSelector(caseSel, { required: true" in phishing_fn, \
        "phishing view must mount a required case selector"
    assert "case_id: cid" in static_fn
    assert "case_id: cid" in phishing_fn
    assert "Select a case before running analysis" in static_fn
    assert "Select a case before running analysis" in phishing_fn


def test_app_js_safe_dom_invariant_preserved():
    app_js = (_static_dir() / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write(", "eval(", "new Function"):
        assert sink not in app_js, f"Phase 2C.4 regressed safe-DOM: '{sink}'"


# --------------------------------------------------------------------------- #
# XSS invariant through the case selector path
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]


def test_phishing_case_selection_rejects_malformed_ids_with_markup(running_server):
    """Attacker-supplied case_id with HTML markup must be rejected safely."""
    for probe in _XSS_PROBES:
        code, res = _post_json(
            f"{running_server}/api/phishing/analyze",
            {"body": _PHISH_TEXT, "case_id": probe},
        )
        assert code == 400
        # The error message contains the probe only as text; the body is JSON.
        err = res.get("error") or res.get("message", "")
        assert isinstance(err, str)
