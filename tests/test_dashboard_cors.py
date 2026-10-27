"""Focused tests for Dashboard CORS Hardening in RansomEye."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import pytest

from ransomeye import dashboard_server
from ransomeye.storage import EvidenceStore


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a temporary populated database for dashboard CORS tests."""
    db_file = tmp_path / "dashboard_cors_test.db"
    store = EvidenceStore(db_file)
    store.create_case("CASE-CORS-01", "CORS Test Case", "SEC-HOST")
    store.close()
    return db_file


@pytest.fixture
def running_server(test_db: Path):
    """Start an ephemeral background dashboard server."""
    # Reset allowed origins to empty default
    dashboard_server.set_allowed_origins(None)
    dashboard_server.DB_PATH = test_db

    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    httpd = HTTPServer(("127.0.0.1", port), dashboard_server.DashboardHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    time.sleep(0.1)

    yield base_url

    httpd.shutdown()
    httpd.server_close()
    dashboard_server.set_allowed_origins(None)


def test_normal_same_origin_requests_work(running_server: str) -> None:
    """1. Normal dashboard requests continue to work and return valid data."""
    req = urllib.request.Request(f"{running_server}/api/cases")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "cases" in data
        assert len(data["cases"]) == 1
        assert data["cases"][0]["case_id"] == "CASE-CORS-01"


def test_no_wildcard_cors_header_emitted(running_server: str) -> None:
    """2. No wildcard (*) CORS header is ever emitted."""
    # Same origin / missing origin
    req = urllib.request.Request(f"{running_server}/api/cases")
    with urllib.request.urlopen(req) as resp:
        assert resp.headers.get("Access-Control-Allow-Origin") is None

    # Request with arbitrary origin
    req_with_origin = urllib.request.Request(
        f"{running_server}/api/cases",
        headers={"Origin": "http://evil-attacker.test"},
    )
    with urllib.request.urlopen(req_with_origin) as resp:
        assert resp.headers.get("Access-Control-Allow-Origin") != "*"
        assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_untrusted_origin_not_granted_access(running_server: str) -> None:
    """3. An untrusted Origin is not granted cross-origin access."""
    req = urllib.request.Request(
        f"{running_server}/api/case/CASE-CORS-01",
        headers={"Origin": "http://malicious.site.com:8080"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        # Access-Control-Allow-Origin must be absent
        assert resp.headers.get("Access-Control-Allow-Origin") is None
        assert resp.headers.get("Vary") is None


def test_approved_origin_receives_exact_header(running_server: str) -> None:
    """4. An approved Origin receives the exact matching origin header."""
    trusted_origin = "http://127.0.0.1:3000"
    dashboard_server.set_allowed_origins([trusted_origin])

    req = urllib.request.Request(
        f"{running_server}/api/cases",
        headers={"Origin": trusted_origin},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == trusted_origin
        assert resp.headers.get("Vary") == "Origin"


def test_missing_origin_handled_cleanly(running_server: str) -> None:
    """5. Missing Origin header is handled correctly without emitting CORS header."""
    dashboard_server.set_allowed_origins(["http://trusted.local"])

    req = urllib.request.Request(f"{running_server}/api/cases")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_options_preflight_obeys_policy(running_server: str) -> None:
    """6. OPTIONS/preflight requests obey the configured policy."""
    trusted_origin = "http://127.0.0.1:3000"
    dashboard_server.set_allowed_origins([trusted_origin])

    # 6a. Trusted preflight -> 200 OK with exact origin
    req_trusted = urllib.request.Request(
        f"{running_server}/api/cases",
        headers={
            "Origin": trusted_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
        method="OPTIONS",
    )
    with urllib.request.urlopen(req_trusted) as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == trusted_origin
        assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")

    # 6b. Untrusted preflight -> 403 Forbidden without CORS header
    req_untrusted = urllib.request.Request(
        f"{running_server}/api/cases",
        headers={
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "POST",
        },
        method="OPTIONS",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_untrusted)
    assert exc_info.value.code == 403
    assert exc_info.value.headers.get("Access-Control-Allow-Origin") is None


def test_error_responses_follow_same_cors_policy(running_server: str) -> None:
    """7. Error responses follow the exact same CORS policy."""
    trusted_origin = "http://127.0.0.1:3000"
    dashboard_server.set_allowed_origins([trusted_origin])

    # 7a. Error with trusted origin -> returns exact origin
    req_err_trusted = urllib.request.Request(
        f"{running_server}/api/case/NON_EXISTENT_CASE",
        headers={"Origin": trusted_origin},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_err_trusted)
    assert exc_info.value.code == 404
    assert exc_info.value.headers.get("Access-Control-Allow-Origin") == trusted_origin

    # 7b. Error with untrusted origin -> no CORS header
    req_err_untrusted = urllib.request.Request(
        f"{running_server}/api/case/NON_EXISTENT_CASE",
        headers={"Origin": "http://untrusted-site.test"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_err_untrusted)
    assert exc_info.value.code == 404
    assert exc_info.value.headers.get("Access-Control-Allow-Origin") is None
