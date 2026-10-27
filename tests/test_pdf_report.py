"""Automated tests for RansomEye PDF forensic report generation and dashboard endpoints."""

import io
import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pypdf
import pytest

from ransomeye.commands import main as cli_main
from ransomeye.pdf_report import generate_case_pdf_report, write_case_pdf_report
from ransomeye.report import generate_case_report, write_case_report
from ransomeye.storage import EvidenceStore


@pytest.fixture
def temp_db(tmp_path: Path):
    """Fixture providing an isolated SQLite database with schema initialized."""
    db_file = tmp_path / "test_ransomeye.db"
    store = EvidenceStore(db_file)
    store.close()
    return db_file


@pytest.fixture
def seeded_db(tmp_path: Path):
    """Fixture providing an isolated SQLite database seeded with the prepared case."""
    from ransomeye.prepared_case import seed_prepared_case

    db_file = tmp_path / "seeded_case.db"
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    seed_prepared_case(database_path=db_file, artifacts_dir=artifacts_dir)
    return db_file


def test_pdf_report_generation_for_prepared_case(seeded_db: Path):
    """Verify that a valid PDF is generated for the prepared case with expected size and pages."""
    pdf_bytes = generate_case_pdf_report(seeded_db, "CASE-2026-ENC-01")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 50000  # Multi-page PDF with embedded logo

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) >= 5

    # Check first page content
    page1_text = reader.pages[0].extract_text()
    assert "Digital Forensics & Incident Investigation Report" in page1_text
    assert "CASE-2026-ENC-01" in page1_text
    assert "SEC-CORP-EP01" in page1_text
    assert "Page 1 of" in page1_text


def test_pdf_report_logo_and_footer_on_every_page(seeded_db: Path):
    """Verify that the official logo and dynamic Page X of Y footer appear on every page."""
    pdf_bytes = generate_case_pdf_report(seeded_db, "CASE-2026-ENC-01")
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    total_pages = len(reader.pages)
    assert total_pages > 1

    for idx, page in enumerate(reader.pages):
        page_num = idx + 1
        # Each page must contain images (the header logo)
        assert len(page.images) >= 1, f"Page {page_num} is missing header logo image"
        page_text = page.extract_text()
        # Footer check
        expected_footer = f"Page {page_num} of {total_pages}"
        assert expected_footer in page_text, f"Footer '{expected_footer}' not found on page {page_num}"


def test_pdf_report_extractable_sections_and_findings(seeded_db: Path):
    """Verify that key DFIR report sections and case data are searchable and extractable."""
    pdf_bytes = generate_case_pdf_report(seeded_db, "CASE-2026-ENC-01")
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    full_text = "\n".join(p.extract_text() for p in reader.pages)

    # Verify standard sections
    assert "1. Executive Summary" in full_text or "Executive Summary" in full_text
    assert "2. Case Overview" in full_text
    assert "3. Threat Assessment" in full_text
    assert "4. Forensic Findings" in full_text
    assert "5. Evidence Inventory" in full_text
    assert "6. Chronological Investigation Timeline" in full_text
    assert "7. Process Relationships" in full_text
    assert "8. Chain of Custody" in full_text
    assert "9. Investigation Limitations" in full_text
    assert "10. Conclusion" in full_text

    # Verify specific case findings and techniques
    assert "T1486" in full_text or "T1490" in full_text or "T1059" in full_text
    assert "CONFIDENTIAL // TLP:AMBER" in full_text


def test_pdf_report_special_characters_and_safety(temp_db: Path, tmp_path: Path):
    """Verify that untrusted input with XML special characters does not crash ReportLab."""
    store = EvidenceStore(temp_db)
    try:
        case_id = "CASE-SPECIAL-CHARS"
        store.create_case(case_id, "Test <script>alert(1)</script> & Special Characters", "HOST<>&'\"")
        store.save_event(
            case_id,
            {
                "event_id": "EVT-001",
                "timestamp": "2026-10-09T01:00:00Z",
                "source": "sysmon",
                "event_type": "process_create",
                "process_name": "cmd.exe <test>",
                "pid": 1234,
                "command_line": "powershell.exe -enc <payload>&foo=bar>out.txt",
            },
        )
        store.save_finding(
            case_id,
            {
                "finding_type": "INJECTION_<TEST>",
                "score": 75,
                "confidence": 0.85,
                "technique": "T1059 <XML>",
                "reason": "Detected <malicious> pattern & unsafe bytes",
            },
        )
    finally:
        store.close()

    out_pdf = tmp_path / "special_chars_report.pdf"
    result_path = write_case_pdf_report(temp_db, case_id, out_pdf)
    assert result_path.is_file()
    assert result_path.stat().st_size > 5000

    reader = pypdf.PdfReader(str(result_path))
    text = reader.pages[0].extract_text()
    assert "CASE-SPECIAL-CHARS" in text


def test_pdf_report_empty_case_handling(temp_db: Path, tmp_path: Path):
    """Verify that an empty case with no findings or events generates without error."""
    store = EvidenceStore(temp_db)
    try:
        case_id = "CASE-EMPTY-001"
        store.create_case(case_id, "Empty Case", "HOST-EMPTY")
    finally:
        store.close()

    out_pdf = tmp_path / "empty_case_report.pdf"
    result_path = write_case_pdf_report(temp_db, case_id, out_pdf)
    assert result_path.is_file()
    assert result_path.stat().st_size > 5000

    reader = pypdf.PdfReader(str(result_path))
    assert len(reader.pages) >= 1
    text = reader.pages[0].extract_text()
    assert "CASE-EMPTY-001" in text
    assert "HOST-EMPTY" in text


def test_pdf_report_cli_export(seeded_db: Path, tmp_path: Path):
    """Verify CLI report command with --format pdf."""
    out_pdf = tmp_path / "cli_report.pdf"
    with patch("sys.argv", [
        "ransomeye",
        "report",
        "--database", str(seeded_db),
        "--case", "CASE-2026-ENC-01",
        "--format", "pdf",
        "--output", str(out_pdf),
    ]):
        cli_main()

    assert out_pdf.is_file()
    assert out_pdf.stat().st_size > 50000
    reader = pypdf.PdfReader(str(out_pdf))
    assert len(reader.pages) >= 5


def test_text_report_preserved(seeded_db: Path, tmp_path: Path):
    """Verify that existing text report export format remains completely intact."""
    out_txt = tmp_path / "report.txt"
    write_case_report(seeded_db, "CASE-2026-ENC-01", out_txt, format="text")
    assert out_txt.is_file()
    content = out_txt.read_text(encoding="utf-8")
    assert "RANSOMEYE CASE REPORT" in content
    assert "CASE-2026-ENC-01" in content
    assert "FINDINGS" in content


def test_dashboard_pdf_download_and_post_api(seeded_db: Path, tmp_path: Path):
    """Verify live dashboard GET /api/report/<id>/pdf and POST /api/report/<id> using an ephemeral server."""
    import socket
    import threading
    import time
    import urllib.request
    import urllib.error
    from ransomeye import dashboard_server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    old_db = dashboard_server.DB_PATH
    dashboard_server.DB_PATH = seeded_db

    server_address = ("127.0.0.1", port)
    httpd = dashboard_server.HTTPServer(server_address, dashboard_server.DashboardHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.15)
    base_url = f"http://127.0.0.1:{port}"
    try:
        # Test GET PDF download
        req = urllib.request.Request(f"{base_url}/api/report/CASE-2026-ENC-01/pdf")
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200
            assert r.headers.get("Content-Type") == "application/pdf"
            assert 'filename="RansomEye_CASE-2026-ENC-01_Report.pdf"' in r.headers.get("Content-Disposition", "")
            data = r.read()
            assert len(data) > 50000

        # Test POST PDF generation
        post_data = json.dumps({"format": "pdf"}).encode("utf-8")
        req_post = urllib.request.Request(
            f"{base_url}/api/report/CASE-2026-ENC-01",
            data=post_data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_post, timeout=5) as r:
            assert r.status == 200
            res = json.loads(r.read())
            assert res.get("filename") == "RansomEye_CASE-2026-ENC-01_Report.pdf"
            assert res.get("download_url") == "/api/report/CASE-2026-ENC-01/pdf"

        # Test 404 for unknown case
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/api/report/UNKNOWN-CASE-999/pdf", timeout=5)
        assert exc_info.value.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()
        server_thread.join(timeout=2)
        dashboard_server.DB_PATH = old_db


def test_pdf_report_available_flag():
    """Verify is_pdf_available reports status accurately."""
    from ransomeye.pdf_report import is_pdf_available
    from ransomeye.report import is_pdf_report_available

    assert is_pdf_available() is True
    assert is_pdf_report_available() is True


def test_pdf_report_unavailable_simulation(seeded_db: Path, tmp_path: Path):
    """Verify graceful handling when ReportLab is unavailable without uninstalling packages."""
    from unittest.mock import patch
    from ransomeye import pdf_report
    from ransomeye import dashboard_server
    from ransomeye.report import write_case_report

    with patch.object(pdf_report, "_REPORTLAB_AVAILABLE", False):
        assert pdf_report.is_pdf_available() is False

        # Direct generation raises PdfDependencyError
        with pytest.raises(pdf_report.PdfDependencyError) as exc_info:
            pdf_report.generate_case_pdf_report(seeded_db, "CASE-2026-ENC-01")
        assert "requires 'reportlab' and 'pillow'" in str(exc_info.value)

        # write_case_report with format='pdf' raises PdfDependencyError
        out_pdf = tmp_path / "should_fail.pdf"
        with pytest.raises(pdf_report.PdfDependencyError):
            write_case_report(seeded_db, "CASE-2026-ENC-01", out_pdf, format="pdf")

        # Text report still works completely fine
        out_txt = tmp_path / "works.txt"
        write_case_report(seeded_db, "CASE-2026-ENC-01", out_txt, format="text")
        assert out_txt.is_file()

        # Ephemeral server returns HTTP 501
        import socket
        import threading
        import time
        import urllib.request
        import urllib.error

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        old_db = dashboard_server.DB_PATH
        dashboard_server.DB_PATH = seeded_db

        server_address = ("127.0.0.1", port)
        httpd = dashboard_server.HTTPServer(server_address, dashboard_server.DashboardHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        time.sleep(0.15)
        base_url = f"http://127.0.0.1:{port}"
        try:
            # GET /api/report/<id>/pdf should return 501
            with pytest.raises(urllib.error.HTTPError) as http_err:
                urllib.request.urlopen(f"{base_url}/api/report/CASE-2026-ENC-01/pdf", timeout=5)
            assert http_err.value.code == 501

            # POST /api/report/<id> with format=pdf should return 501
            post_data = json.dumps({"format": "pdf"}).encode("utf-8")
            req_post = urllib.request.Request(
                f"{base_url}/api/report/CASE-2026-ENC-01",
                data=post_data,
                headers={"Content-Type": "application/json"},
            )
            with pytest.raises(urllib.error.HTTPError) as http_err2:
                urllib.request.urlopen(req_post, timeout=5)
            assert http_err2.value.code == 501
        finally:
            httpd.shutdown()
            httpd.server_close()
            server_thread.join(timeout=2)
            dashboard_server.DB_PATH = old_db
