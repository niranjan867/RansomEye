# RansomEye Release Audit — Phase 2E

**Audit Date:** October 26, 2026  
**Auditor:** Senior Windows Software Release Engineer & DFIR Product Architect  
**Target Repository:** `D:\nira\project\RansomEye`  
**Branch:** `integration/12x-capabilities`  
**Git HEAD:** `da617241d4e8a597b556869e5bf59575955935af`  
**Artifact Evaluated:** `dist_isolated\RansomEye.exe` (`21,095,724 bytes`, SHA-256: `49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E`)

---

## 1. Overview and Architecture

RansomEye is a local-first Digital Forensics and Incident Response (DFIR) platform engineered to transition investigation workflows "from ransomware signal to forensic proof." The platform packages:
- A CLI management and interrogation interface (`ransomeye.commands`).
- An embedded HTTP analyst console (`ransomeye.dashboard_server`).
- Local SQLite evidence and case custody ledger (`ransomeye.storage`).
- Non-executing static PE analysis (`ransomeye.static_analyzer`).
- PowerShell/script AST deobfuscation and bounded emulation (`ransomeye.script_analyzer`).
- Libpcap network stream analysis (`ransomeye.pcap_analyzer`).
- Normalized threat indicator extraction (`ransomeye.ioc_extractor`).
- Phishing and financial fraud analysis (`ransomeye.phishing`).
- End-to-end incident reconstruction and graph correlation (`ransomeye.reconstruction`, `ransomeye.investigation_graph`).
- High-fidelity text and ReportLab-based PDF case reporting (`ransomeye.report`, `ransomeye.pdf_report`).

This audit evaluates the packaging fidelity, dependency boundaries, path traversal security, report disclosures, and runtime safety of the compiled standalone distribution.

---

## 2. Packaging Assumptions and Dependency Boundaries

### 2.1 PyInstaller Bundle Specification (`scripts/ransomeye.spec`)
- **Bundle Mode:** Onefile standalone executable (`EXE` archive bundling PYZ, binaries, scripts, and runtime assets).
- **Python Runtime:** Python 3.13.15 64-bit (AMD64).
- **PyInstaller Version:** `6.22.3` (with `pyinstaller-hooks-contrib 2026.9`).
- **Included Assets (`datas`):**
  - `src/ransomeye/static` $\rightarrow$ `ransomeye/static` (Web dashboard HTML, JS, CSS).
  - `THIRD_PARTY_NOTICES.md` $\rightarrow$ `.` (License disclosures).
  - ReportLab data files (Type 1 fonts, AFM tables, XML resource definitions via `collect_data_files("reportlab")`).
- **Excluded Modules:** `tkinter`, `matplotlib`, `numpy`, `torch`.
- **Runtime Temporary Directory:** Default bootloader unpacks to `%LOCALAPPDATA%\Temp\_MEIxxxxxx`.

### 2.2 Dependency Audit
| Package | Version in `.venv` | License | Packaging Handling | Runtime Fallback Verified |
| :--- | :---: | :--- | :--- | :---: |
| `reportlab` | 5.0.1 | BSD | Bundled in `dist_isolated` | Yes (`is_pdf_available()` guards) |
| `pillow` | 12.3.0 | HPND / PIL | Bundled in `dist_isolated` | Yes (guarded in `pdf_report.py`) |
| `pypdf` | 6.19.0 | BSD-3-Clause | Test/Validation only | N/A (not in PyInstaller bundle) |
| `watchdog` | - | Apache 2.0 | Optional collector | Safe lazy import in `live_file.py` |
| `psutil` | - | BSD-3-Clause | Optional collector | Safe lazy import in `live_process.py` |
| `setuptools` | 84.2.1 | MIT | Build-time dependency | Build tool only |

**Finding:** The packaging specification correctly separates mandatory build-time requirements from optional runtime extensions. The binary contains all code necessary for core triage, static analysis, script inspection, PCAP dissection, and PDF generation without runtime host dependencies.

---

## 3. Runtime Paths and Static Asset Loading

### 3.1 Asset Discovery in Onefile Mode
In PyInstaller onefile mode, files bundled in `datas` are extracted to the temporary folder pointed to by `sys._MEIPASS`.
In `src/ransomeye/dashboard_server.py`:
```python
filepath = (Path(__file__).parent / "static" / filename).resolve()
static_dir = (Path(__file__).parent / "static").resolve()
```
When running frozen, `__file__` resolves to `_MEIxxxxxx\ransomeye\dashboard_server.pyc`. `Path(__file__).parent / "static"` accurately targets the unpacked web assets.
- **Live Verification:** Executing `dist_isolated\RansomEye.exe dashboard --port 8999` and retrieving `GET /` successfully loaded `index.html` (51,990 bytes) and related CSS/JS files without disk lookup failures.

### 3.2 Path Traversal Defenses
The dashboard HTTP server strictly restricts static asset serving:
```python
if static_dir not in filepath.parents and filepath != static_dir:
    self.send_error(403, "Access denied")
    return
```
- Path canonicalization via `.resolve()` eliminates directory traversal payloads (e.g. `GET /../../Windows/win.ini`).
- API routes validate parameters with `_validate_safe_id(case_id, "case_id")` enforcing regex `^[A-Za-z0-9_\-]+$`, preventing directory traversal in database lookups.

---

## 4. Dashboard Startup and Network Binding

### 4.1 Binding Defaults
- **CLI Declaration (`commands.py`):**
  ```python
  dashboard_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind dashboard server (default: 127.0.0.1).")
  dashboard_parser.add_argument("--port", type=int, default=8080, help="Port to serve the analyst console (default: 8080).")
  ```
- **Server Implementation (`dashboard_server.py`):**
  ```python
  def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
      server_address = (host, port)
      httpd = ThreadingHTTPServer(server_address, DashboardHandler)
  ```
- **Security Assessment:** The server defaults strictly to loopback (`127.0.0.1`). It never binds to `0.0.0.0` or public network adapters unless explicitly instructed by the operator via `--host 0.0.0.0`.
- **CORS Configuration (Hardened in Phase 2F):** The previous wildcard `Access-Control-Allow-Origin: *` policy has been completely removed. Same-origin and local direct requests receive zero CORS headers. Cross-origin requests are checked against an explicit allowlist (`ALLOWED_ORIGINS` / `--allowed-origin` / `RANSOMEYE_ALLOWED_ORIGINS`). Untrusted cross-origin preflight requests receive HTTP 403 Forbidden without CORS headers.

---

## 5. CLI Error Handling and Diagnostic Safety

- When malformed input or unhandled exceptions occur in CLI commands, errors are intercepted through structured `try/except` blocks in `commands.py`:
  - `FileNotFoundError`, `ValueError`, `KeyError`, and `sqlite3.Error` exit with code `1` and clean console messages via `parser.exit(1, ...)`.
  - Raw Python stack traces are suppressed in user-facing CLI paths unless unhandled system-level faults emerge.
- In `ransomeye report`, when PDF generation dependencies are absent, `PdfDependencyError` is caught and outputs:
  ```text
  [!] PDF report generation is unavailable: ReportLab is not installed.
      Install reporting dependencies or generate a text report with '--format text'.
  ```
  Exits cleanly with returncode `1`.

---

## 6. PDF Generation and Dependency Fallback

- **ReportLab Import Isolation:**
  `src/ransomeye/pdf_report.py` wraps all canvas, platypus, and style imports in conditional blocks:
  ```python
  try:
      from reportlab.lib import colors
      from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, ...
      HAS_REPORTLAB = True
  except ImportError:
      HAS_REPORTLAB = False
  ```
- **Packaged Executable Behavior:**
  Because ReportLab 5.0.1 and Pillow 12.3.0 are bundled inside `dist_isolated\RansomEye.exe`, PDF report generation succeeds natively with zero external dependencies (ST-06 generated a 10-page forensic report, 589,590 bytes).
- **Graceful API Fallback:**
  When ReportLab is absent, `dashboard_server.py` and `report.py` return HTTP 501 / text fallback, preventing server crashes.

---

## 7. Evidence and Report Output Safety

- **Non-Destructive Export (`_export_report_no_overwrite`):**
  In `commands.py`, writing reports to an export destination uses low-level file creation flags:
  ```python
  fd = os.open(export_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
  ```
  This guarantees that existing forensic evidence files, previous case exports, or symlinked system files cannot be overwritten silently (`O_EXCL` throws `FileExistsError`).
- **Database Immutability:**
  `case_custody` SQLite table enforces append-only rules via SQL triggers:
  ```sql
  CREATE TRIGGER IF NOT EXISTS prevent_custody_update BEFORE UPDATE ON case_custody
  BEGIN SELECT RAISE(ABORT, 'case custody records are append-only'); END;

  CREATE TRIGGER IF NOT EXISTS prevent_custody_delete BEFORE DELETE ON case_custody
  BEGIN SELECT RAISE(ABORT, 'case custody records are append-only'); END;
  ```
- **Database Migration Safeguard (Hardened in Phase 2F):**
  When opening historical SQLite databases (Schema versions 1 through 5), `EvidenceStore` automatically performs a transactionally consistent online backup (`connection.backup`) before applying any DDL schema upgrades. The backup path (`<db>.bak` or unique timestamped variant) is created exclusively without overwriting pre-existing backups, its readability and pre-migration schema version are validated prior to executing migration DDL, and migration failures safely halt without destroying the pre-migration state.
- **Sensitive Data in Reports:**
  Case reports include process names, command-lines, hashes, IP addresses, and user accounts associated with forensic events. They do not redact command-line arguments (such as inline passwords or tokens) by default. A recommendation is noted in the security findings for token masking.

---

## 8. Audit Summary & Conclusion

The packaging implementation is sound and meets all release hardening criteria:
1. All core capabilities operate inside the standalone executable.
2. Clean-machine compatibility is established.
3. Path traversal attacks against the embedded web console are blocked.
4. Database custody history is protected by append-only database triggers.
5. Accidental file overwrites are prevented by exclusive file descriptors (`O_CREAT | O_EXCL`).
6. Pre-migration database backups protect historical forensic databases against corruption.
7. Dashboard CORS wildcard is eliminated, enforcing strict origin allowlisting.
