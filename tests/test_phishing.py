"""Tests for RansomEye phishing and financial fraud detection module."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ransomeye.phishing import (
    MessagePayload,
    PhishingDetector,
    extract_urls_from_text,
    ingest_phishing_finding,
)
from ransomeye.storage import EvidenceStore


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


# --- Unit Tests: URL Extraction ---

def test_extract_urls_from_text() -> None:
    text = (
        "Check this link: https://login.example.com/auth. Also visit "
        "http://192.168.1.100/verify and www.malicious-domain.xyz/download?ref=123."
    )
    urls = extract_urls_from_text(text)
    assert len(urls) == 3
    assert "https://login.example.com/auth" in urls
    assert "http://192.168.1.100/verify" in urls
    assert "www.malicious-domain.xyz/download?ref=123" in urls


# --- Unit Tests: Benign Messages ---

def test_benign_business_message() -> None:
    payload = MessagePayload.from_text(
        "Hi John,\nPlease review the attached quarterly project status report when you have time.\nThanks,\nAlice",
        sender="alice@examplecorp.com",
    )
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score <= 19
    assert result.risk_level == "benign"
    assert len(result.indicators) == 0


# --- Unit Tests: Banking KYC & Coercion Scams ---

def test_banking_kyc_suspension_scam() -> None:
    message = (
        "URGENT: Your Bank of America netbanking account is suspended. Immediate action required. "
        "Please update your KYC and verify your bank details within 24 hours at http://192.168.1.50/login "
        "or your debit card will be blocked permanently."
    )
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score >= 70
    assert result.risk_level in ("high", "critical")
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "URG-001" in rule_ids  # Urgent Account Suspension Threat
    assert "FRD-KYC-001" in rule_ids  # Banking KYC
    assert "URL-IP-001" in rule_ids  # Direct IP Hostname
    assert "T1566.002" in result.mitre_techniques


# --- Unit Tests: Tech Support & Fake Invoice Scams ---

def test_fake_invoice_tech_support_scam() -> None:
    message = (
        "Thank you for your order! Your Geek Squad subscription auto-renewal of $499.99 has been processed. "
        "If you did not authorize this charge, call our support at toll-free 1-800-555-0199 immediately to cancel."
    )
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score >= 30
    assert any(ind.rule_id == "FRD-TECH-003" for ind in result.indicators)


# --- Unit Tests: Cryptocurrency & Advance Fee Scams ---

def test_crypto_investment_fraud() -> None:
    message = (
        "Special VIP Invitation! Earn guaranteed profit with daily return of 15%. "
        "Send BTC to our liquidity pool wallet to double your bitcoin today. Register: http://crypto-pool.xyz/join"
    )
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score >= 40
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "FRD-CRYPTO-004" in rule_ids
    assert "URL-TLD-005" in rule_ids  # .xyz TLD


def test_advance_fee_lottery_scam() -> None:
    message = (
        "Official Notification: You have won $2,500,000 in the International Lottery Award! "
        "You are the sole beneficiary of unclaimed funds. Provide your one-time password and identity proof to claim."
    )
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score >= 50
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "FRD-LOTTERY-005" in rule_ids
    assert "FRD-OTP-002" in rule_ids


# --- Unit Tests: URL & Domain Spoofing ---

def test_brand_subdomain_impersonation() -> None:
    message = "Please verify your account: https://paypal.com.account-update.xyz/signin"
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert any(ind.rule_id == "URL-SPOOF-002" for ind in result.indicators)


def test_url_shortener_smishing() -> None:
    message = "FedEx: Your package delivery has a security alert. Final warning: verify your address at https://bit.ly/3xSecAlert"
    payload = MessagePayload.from_text(message)
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert any(ind.rule_id == "URL-SHORT-004" for ind in result.indicators)
    assert any(ind.rule_id == "URG-001" for ind in result.indicators)


# --- Unit Tests: Attachment Inspection ---

def test_dangerous_attachments() -> None:
    payload = MessagePayload(
        text="Please see attached statement.",
        attachments=["statement_march.pdf.exe", "macro_sheet.docm"],
    )
    detector = PhishingDetector()
    result = detector.analyze(payload)

    assert result.score >= 70
    assert result.risk_level in ("high", "critical")
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "ATT-EVASION-001" in rule_ids  # Double extension
    assert "ATT-EXECUTABLE-002" in rule_ids  # Dangerous format (.docm)
    assert "T1566.001" in result.mitre_techniques


# --- Unit Tests: Header Authentication (SPF/DMARC) ---

def test_email_header_authentication_failure() -> None:
    payload = MessagePayload(
        text="Payroll details attached.",
        sender="it-support@gmail.com",
        headers={
            "received-spf": "spf=fail (google.com: domain does not designate IP)",
            "authentication-results": "spf=fail; dmarc=fail action=none",
            "reply-to": "hacker@evilcorp.org",
        },
    )
    detector = PhishingDetector()
    result = detector.analyze(payload)

    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "HDR-SPF-001" in rule_ids
    assert "HDR-DMARC-002" in rule_ids
    assert "HDR-SPOOF-003" in rule_ids
    assert "HDR-REPLYTO-004" in rule_ids


# --- Unit Tests: EML File Parsing ---

def test_eml_file_parsing(tmp_path: Path) -> None:
    eml_content = (
        "From: IT Security <security@freemail.com>\n"
        "To: employee@company.com\n"
        "Subject: Security Alert: Account Suspended\n"
        "Received-SPF: spf=fail\n"
        "\n"
        "Immediate action required. Your account is locked. Verify at http://192.168.1.200/auth\n"
    )
    eml_file = tmp_path / "phish.eml"
    eml_file.write_text(eml_content, encoding="utf-8")

    payload = MessagePayload.from_email_file(eml_file)
    assert payload.subject == "Security Alert: Account Suspended"
    assert "192.168.1.200" in payload.urls[0]

    detector = PhishingDetector()
    result = detector.analyze(payload)
    assert result.risk_level in ("high", "critical")


# --- Unit Tests: Case Ingestion into EvidenceStore ---

def test_ingest_phishing_finding_into_case(tmp_path: Path) -> None:
    db_path = tmp_path / "case_test.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-PHISH-01", "Phishing Vector Test")

    payload = MessagePayload.from_text(
        "Immediate action required: Your account is suspended. Verify KYC at http://192.168.1.1/login"
    )
    detector = PhishingDetector()
    result = detector.analyze(payload)

    finding_id = ingest_phishing_finding(store, "CASE-PHISH-01", result, "email_attachment.eml")
    assert finding_id is not None

    findings = store.get_case_findings("CASE-PHISH-01")
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "phishing_initial_access"
    assert "Phishing/Scam Analysis" in findings[0]["reason"]
    assert findings[0]["technique"] in ("T1566.002", "T1566.001", "T1566.003", "T1598")

    custody = store.get_custody_events("CASE-PHISH-01")
    assert any(c["action"] == "reviewed" for c in custody)
    store.close()


# --- CLI Tests ---

def test_cli_phishing_text(tmp_path: Path) -> None:
    cmd = [
        "phishing",
        "--text",
        "URGENT: Your account is suspended. Verify KYC at http://192.168.1.10/login immediately.",
    ]
    res = _run_cli(cmd, cwd=tmp_path)
    assert res.returncode == 0
    assert "RANSOMEYE PHISHING & SCAM FORENSIC VERDICT" in res.stdout
    assert "Risk Score" in res.stdout
    assert "URG-001" in res.stdout


def test_cli_phishing_json_and_export(tmp_path: Path) -> None:
    export_file = tmp_path / "report.json"
    cmd = [
        "phishing",
        "--text",
        "URGENT: Verify your bank details within 24 hours.",
        "--json",
        "--export",
        str(export_file),
    ]
    res = _run_cli(cmd, cwd=tmp_path)
    assert res.returncode == 0
    parsed = json.loads(res.stdout)
    assert "score" in parsed
    assert "risk_level" in parsed
    assert export_file.is_file()
    file_json = json.loads(export_file.read_text(encoding="utf-8"))
    assert file_json["score"] == parsed["score"]


def test_cli_phishing_case_ingest(tmp_path: Path) -> None:
    db_path = tmp_path / "test_case.db"
    store = EvidenceStore(db_path)
    store.create_case("CASE-CLI-01", "CLI Case")
    store.close()

    cmd = [
        "phishing",
        "--text",
        "URGENT: Update your KYC or account will be suspended within 24 hours.",
        "--database",
        str(db_path),
        "--case",
        "CASE-CLI-01",
    ]
    res = _run_cli(cmd, cwd=tmp_path)
    assert res.returncode == 0
    assert "[+] Phishing finding ingested into case CASE-CLI-01" in res.stdout

    store = EvidenceStore(db_path)
    findings = store.get_case_findings("CASE-CLI-01")
    assert len(findings) == 1
    store.close()


# --------------------------------------------------------------------------- #
# XSS hardening: attacker-controlled markup must be preserved as inert string
# data by the analyzer. The dashboard renders it via textContent / safe DOM
# construction, never as HTML, so none of these probes can create live DOM.
# --------------------------------------------------------------------------- #

_XSS_PROBES = [
    "<u>x</u>",
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


def test_attachment_filename_markup_preserved_as_data():
    """Markup in an attachment filename round-trips verbatim as string data."""
    for probe in _XSS_PROBES:
        fname = f"{probe}.exe"
        payload = MessagePayload.from_dict({"text": "see attached", "attachments": [fname]})
        result = PhishingDetector().analyze(payload)
        names = [a["filename"] for a in result.attachment_findings]
        assert fname in names
        # Serializes (as the dashboard server does) with the bytes preserved.
        assert fname in json.dumps(result.to_dict(), default=str)


def test_extracted_url_is_string_data():
    """Extracted URLs are returned as plain strings (the view renders them inert)."""
    payload = MessagePayload.from_dict({
        "text": "verify your kyc at http://evil.example.xyz/login now",
    })
    result = PhishingDetector().analyze(payload)
    urls = result.to_dict()["extracted_urls"]
    assert urls
    assert all(isinstance(u["url"], str) for u in urls)


def test_message_fields_of_pure_markup_analyze_to_structured_data():
    """A message whose subject/sender/body are attacker markup analyzes cleanly."""
    for probe in _XSS_PROBES:
        payload = MessagePayload.from_dict({
            "subject": probe,
            "sender": f"{probe}@evil.example",
            "text": f"{probe} verify your account {probe}",
        })
        result = PhishingDetector().analyze(payload)
        d = result.to_dict()
        # Structured, serializable result -- no markup becomes structure.
        assert isinstance(json.dumps(d, default=str), str)
        assert isinstance(d["indicators"], list)
        assert isinstance(d["extracted_urls"], list)
