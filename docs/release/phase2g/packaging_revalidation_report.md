# RansomEye Phase 2G — Isolated Packaging Re-validation Report

**Date:** October 26, 2026  
**Auditor / Roles:** Senior Windows Release Engineer, Python Security Engineer, DFIR QA Lead  
**Target Repository:** `D:\nira\project\RansomEye`  
**Branch:** `integration/12x-capabilities`  
**Git HEAD:** `da617241d4e8a597b556869e5bf59575955935af`  

---

## 1. Executive Summary & Verdict

**Phase 2G Verdict:** **`PASS WITH CONDITIONS`**

The RansomEye standalone Windows distribution was re-compiled from the verified Phase 2F source tree into an isolated, protected build directory (`dist_phase2g_rc\`) using PyInstaller 6.22.3 on Python 3.13.15. The resulting executable (`dist_phase2g_rc\RansomEye.exe`) successfully incorporates both Phase 2F security improvements (safe pre-migration SQLite backup creation and strict CORS origin allowlisting with preflight rejection).

All 31 packaged empirical validation scenarios passed with 100% success rate:
- **6/6** Database migration safety scenarios passed.
- **10/10** Dashboard CORS hardening & API scenarios passed.
- **12/12** Packaged forensic and incident response capability scenarios passed.
- **3/3** Clean-environment (stripped PATH, 0 Python environment variables) scenarios passed.
- **1,000 / 1,000** Pytest unit and integration tests passed across all 36 test modules in 162.43s.

**Condition for Release:** The candidate executable remains Authenticode **unsigned** (`NotSigned`). Code signing with an enterprise EV certificate (as detailed in `docs/release/phase2e/code_signing_plan.md`) is mandatory before external deployment or end-user distribution to bypass Windows SmartScreen warnings.

---

## 2. Release Candidate Binary Provenance

| Metric | Details |
| :--- | :--- |
| **Output Path** | `dist_phase2g_rc\RansomEye.exe` |
| **Compilation Workspace** | `build_phase2g_rc\` |
| **File Size** | `21,100,919 bytes` (20.12 MB) |
| **SHA-256 Hash** | `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871` |
| **Authenticode Status** | `NotSigned` (Expected prior to Phase 3 signing stage) |
| **Build Toolchain** | PyInstaller 6.22.3 (contrib hooks: 2026.9), Python 3.13.15 64-bit |
| **Host Environment** | Windows 11 Enterprise (10.0.26300) |
| **Build Exit Code** | `0` (Success, runtime ~37 seconds) |
| **Build Automation** | `scripts/build_release_candidate.ps1 -DistPath dist_phase2g_rc -WorkPath build_phase2g_rc` |

---

## 3. Cryptographic Baseline Invariant Verification

Before and after the isolated compilation and empirical validation, SHA-256 checksums were calculated for all protected project assets:

| Protected Asset | Absolute Path | Baseline SHA-256 | Post-Validation SHA-256 | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Production Database** | `data\ransomeye.db` | `9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB` | `9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB` | **INTACT** |
| **Baseline Executable** | `dist\RansomEye.exe` | `65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542` | `65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542` | **INTACT** |
| **Phase 2D Isolated Executable** | `dist_isolated\RansomEye.exe` | `49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E` | `49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E` | **INTACT** |
| **Build Directories** | `build\`, `build_isolated\` | Existing content preserved | Existing content preserved | **INTACT** |

---

## 4. Empirical Packaged Security Fix Validation

All tests were performed exclusively against `dist_phase2g_rc\RansomEye.exe` using isolated temporary databases and forensic fixtures. The production database was never accessed.

### 4.1 Database Migration Safety Verification (6 Scenarios)

| Scenario ID | Test Description | Packaged Binary Invocation | Expected Behavior | Actual Empirical Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **PKG-MIG-01** | Current-Schema Opening | `RansomEye.exe case list --database <v6_db>` | Open v6 DB without creating `.bak` file | Exit code `0`; 0 `.bak` files created | **PASS** |
| **PKG-MIG-02** | Historical-Schema Migration | `RansomEye.exe case list --database <v1_db>` | Create verified backup before upgrading to v6 | Exit code `0`; backup created at v1; original migrated to v6 | **PASS** |
| **PKG-MIG-03** | Collision Handling | `RansomEye.exe case list --database <v1_col_db>` | Pre-existing `.bak` preserved byte-for-byte | Exit code `0`; canary intact; `v1_collision.db.v1.bak` created | **PASS** |
| **PKG-MIG-04** | Backup Failure Halts Migration | `RansomEye.exe case list --database <unwritable_db>` | Write-denied dir halts migration; DB untouched | Exit code `1`; DB unmodified at schema v1 | **PASS** |
| **PKG-MIG-05** | Migration Failure Retains Backup | `RansomEye.exe case list --database <failing_db>` | Aborted DDL mid-migration leaves valid backup | Exit code `1`; backup verified readable at v1 | **PASS** |
| **PKG-MIG-06** | Fresh Database Initialization | `RansomEye.exe case list --database <fresh_db>` | Brand-new file initializes at v6 with 0 backups | Exit code `0`; fresh DB created at v6; 0 backups | **PASS** |

### 4.2 Dashboard CORS Hardening Verification (10 Scenarios)

The packaged executable was launched as:  
`RansomEye.exe dashboard --host 127.0.0.1 --port 8989 --database <dash_db> --allowed-origin http://trusted-console.internal`

| Scenario ID | Test Description | HTTP Request | Expected Response | Actual Empirical Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **PKG-CORS-01** | Same-Origin HTML | `GET /` | HTTP 200, HTML body, no CORS | HTTP `200 OK`, HTML served, `Access-Control-Allow-Origin: None` | **PASS** |
| **PKG-CORS-02** | Same-Origin API | `GET /api/cases` | HTTP 200, JSON body, no CORS | HTTP `200 OK`, JSON served, `Access-Control-Allow-Origin: None` | **PASS** |
| **PKG-CORS-03** | Wildcard Removal | Across `/`, `/api/cases`, `/api/case/<id>` | No `*` header emitted | `Access-Control-Allow-Origin: *` was absent across all routes | **PASS** |
| **PKG-CORS-04** | Untrusted Preflight | `OPTIONS /api/cases` (`Origin: http://evil.attacker.com`) | HTTP 403 Forbidden | HTTP `403 Forbidden`, CORS headers rejected | **PASS** |
| **PKG-CORS-05** | Untrusted GET | `GET /api/cases` (`Origin: http://evil.attacker.com`) | Data served, no CORS header | HTTP `200 OK`, `Access-Control-Allow-Origin: None` | **PASS** |
| **PKG-CORS-06** | Approved Preflight | `OPTIONS /api/cases` (`Origin: http://trusted-console.internal`) | HTTP 200, matching CORS origin | HTTP `200 OK`, `Access-Control-Allow-Origin: http://trusted-console.internal` | **PASS** |
| **PKG-CORS-07** | Approved GET | `GET /api/cases` (`Origin: http://trusted-console.internal`) | HTTP 200, matching CORS + Vary | HTTP `200 OK`, matching origin + `Vary: Origin` | **PASS** |
| **PKG-CORS-08** | Direct Request | `GET /api/cases` (no `Origin` header) | HTTP 200, no CORS header | HTTP `200 OK`, no CORS headers emitted | **PASS** |
| **PKG-CORS-09** | PDF Report API | `GET /api/report/CASE-2026-ENC-01/pdf` | HTTP 200, `application/pdf`, CORS | HTTP `200 OK`, `589,583 bytes` valid PDF, matching origin | **PASS** |
| **PKG-CORS-10** | Clean Shutdown | Process `terminate()` / `SIGTERM` | Process exits within 5s | Clean termination (Exit Code `0`) | **PASS** |

---

## 5. Packaged Forensic Capability Regression (12 Workflows)

All 12 capability workflows were executed directly against `dist_phase2g_rc\RansomEye.exe`:

| Workflow ID | Command Line | Verification Criteria | Empirical Output | Status |
| :--- | :--- | :--- | :--- | :---: |
| **CAP-01** | `RansomEye.exe --help` | Exit 0, display 17 subcommands | Exit code `0`; all subcommands displayed | **PASS** |
| **CAP-02** | `RansomEye.exe static --file update_agent.exe` | Non-executing PE entropy & string parsing | Exit code `0`; entropy `7.5271`, flagged `HOW_TO_DECRYPT` | **PASS** |
| **CAP-03** | `RansomEye.exe script --file verify_token.ps1` | PowerShell AST analysis without execution | Exit code `0`; detected download rule `PS-DL-004` (T1105) | **PASS** |
| **CAP-04** | `RansomEye.exe pcap --file network_traffic.pcap` | Dissect Ethernet/TCP/UDP packets | Exit code `0`; parsed 2 packets (DNS beacon + TCP C2 stream) | **PASS** |
| **CAP-05** | `RansomEye.exe report --database <db> --case <id> --output report.txt --format text` | Generate formatted ASCII report | Exit code `0`; `49,624 bytes` generated (68 events, 14 findings) | **PASS** |
| **CAP-06** | `RansomEye.exe report --database <db> --case <id> --output report.pdf --format pdf` | Render dynamic ReportLab Platypus PDF | Exit code `0`; `589,585 bytes` valid PDF (`%PDF-1.4`) | **PASS** |
| **CAP-07** | `RansomEye.exe case list & show` | Case lifecycle querying | Exit code `0`; retrieved `CASE-2026-ENC-01`, host `SEC-CORP-EP01` | **PASS** |
| **CAP-08** | `RansomEye.exe custody list` | Append-only custody ledger | Exit code `0`; displayed 7 chain-of-custody log records | **PASS** |
| **CAP-09** | `RansomEye.exe ioc --file indicators.txt` | Extract normalized IOCs | Exit code `0`; extracted 10 indicators (IPv4, Domain, BTC, LOLBin) | **PASS** |
| **CAP-10** | `RansomEye.exe investigation reconstruct` | Reconstruct kill chain timeline | Exit code `0`; sequenced attack stages to CRITICAL score 100 | **PASS** |
| **CAP-11** | `RansomEye.exe dashboard --port 8989` | Live HTTP web dashboard | HTTP `200 OK` on `/` and `/api/cases` | **PASS** |
| **CAP-12** | `/api/report/<id>/pdf` | Browser-accessible PDF download | HTTP `200 OK`, returned binary PDF data stream | **PASS** |

---

## 6. Clean-Environment Execution Validation

The binary was executed in an isolated sub-process with:
- Sanitized `PATH`: `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`
- Stripped Python environment: `PYTHONPATH`, `PYTHONHOME`, and `PYTHONEXECUTABLE` undefined.

| Test ID | Command | Expected Result | Actual Empirical Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **CLEAN-01** | `RansomEye.exe --help` | Exit 0, standalone unpack | Exit code `0`, clean CLI help displayed | **PASS** |
| **CLEAN-02** | `RansomEye.exe static --file update_agent.exe` | Static PE inspection | Exit code `0`, computed entropy without host Python | **PASS** |
| **CLEAN-03** | `RansomEye.exe script --file verify_token.ps1` | Script AST inspection | Exit code `0`, flagged MITRE T1105 rule | **PASS** |

---

## 7. Full Repository Regression Test Suite

Execution of `.\.venv\Scripts\pytest -q` across the entire codebase:
- **Total Test Files:** 36
- **Total Tests Collected & Executed:** 1,000
- **Passed:** 1,000 (100.0%)
- **Failed:** 0
- **Skipped:** 0
- **Execution Time:** 162.43s (02:42)

---

## 8. Release Suitability Decision

**Candidate Decision:** **READY FOR AUTHENTICODE SIGNING (PHASE 3)**

1. **Packaging Soundness:** The PyInstaller specification correctly bundles all runtime dependencies (including ReportLab Platypus, Pillow image filters, and dashboard console static assets) into a standalone Windows binary requiring zero external Python components.
2. **Security Posture:** Both Phase 2F security improvements (safe database migration pre-flight backups and CORS allowlisting) are fully verified and functional in the packaged binary.
3. **Artifact Isolation:** The build process was non-destructive and strictly isolated. No production data or baseline release binaries were altered.
4. **Prerequisite for Production Release:** Candidate binary `dist_phase2g_rc\RansomEye.exe` must now be signed using a trusted code-signing certificate via `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256` before creating MSI/EXE installers or distributing to end users.
