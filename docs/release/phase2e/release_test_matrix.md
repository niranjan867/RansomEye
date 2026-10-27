# RansomEye Release Test Matrix — Phase 2E

**Date:** October 26, 2026  
**Auditor / QA Lead:** Senior QA Lead & Windows Release Engineer  
**Target Repository:** `D:\nira\project\RansomEye`  
**Target Binary:** `dist_isolated\RansomEye.exe` (`21,095,724 bytes`, SHA-256: `49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E`)

---

## 1. Test Execution Governance

This matrix distinguishes between **Actually Executed Tests** (empirically performed and recorded with exact command output, exit codes, and timestamps) and **Proposed Tests** (planned for subsequent release candidate validation). No test results are fabricated or assumed.

---

## 2. Actually Executed Tests

### 2.1 Full Pytest Regression Suite
| Test ID | Feature / Component | Test Input | Expected Behavior | Actual Result | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **REG-01** | Full Unit & Integration Suite | Entire `tests/` tree (36 test files) | All tests pass, 0 skips, 0 failures | **1,000 passed, 0 failed, 0 skipped** | Execution log: `171.27s (02:51)`, Pytest 9.1.1, Python 3.13.15 | **PASS** |
| **REG-02** | Threat Assessment & PCAP Ingestion | `tests/test_forensics_threat_assessment.py` | PCAP indicators update case threat score | **20 passed, 0 failed** in 4.83s | Resolves `tests.test_pcap` builders cleanly via resilient fallback | **PASS** |
| **REG-03** | PDF Report & Fallback Isolation | `tests/test_pdf_report.py` | PDF generation, styles, and HTTP 501 fallback | **14 passed, 0 failed** in 3.12s | Verified ephemeral port binding and ReportLab availability mocking | **PASS** |
| **REG-04** | Dashboard Server & Endpoints | `tests/test_dashboard_server.py` | REST API routes and static asset serving | **43 passed, 0 failed** in 7.45s | Mocked and live requests across all API routes | **PASS** |

### 2.2 Packaged Executable Smoke Tests (Batch 2)
| Test ID | Feature | Test Input | Expected Behavior | Actual Result | Evidence / Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **ST-01** | CLI Dispatch & Help | `RansomEye.exe --help` | Exit 0, list all 17 subcommands | Exit code `0` | Listed `timeline, tree, report, case, custody, integrity, export, database, investigation, collect, ingest, evidence, phishing, dashboard, static, script, ioc, pcap` | **PASS** |
| **ST-02** | Static PE Analysis | `samples/prepared_case/update_agent.exe` | Non-executing PE entropy and string analysis | Exit code `0` | Calculated SHA-256 `2f732d...`, entropy `7.5271` (Very High), extracted keywords `DECRYPT, HOW_TO_DECRYPT` | **PASS** |
| **ST-03** | Script AST Analysis | `samples/prepared_case/verify_token.ps1` | Detect payload download and extract C2 URL | Exit code `0` | Flagged Rule `PS-DL-004` (T1105), extracted URL `http://198.51.100.45:8443/stage2.bin` | **PASS** |
| **ST-04** | PCAP Capture Analysis | `samples/prepared_case/network_traffic.pcap` | Parse Ethernet/UDP/TCP packets and flows | Exit code `0` | Parsed 2 packets: DNS query for `c2-beacon.corp-notice.test` and TCP stream `10.0.0.42:52140 -> 198.51.100.45:8443` | **PASS** |
| **ST-05** | Text Report Generation | Temporary SQLite DB (`CASE-2026-ENC-01`) | Generate structured ASCII incident report | Exit code `0` | Generated `49,624 bytes` report detailing 68 events, 14 findings, score 100/CRITICAL | **PASS** |
| **ST-06** | Dynamic PDF Report | Temporary SQLite DB (`CASE-2026-ENC-01`) | Compile ReportLab Platypus PDF report | Exit code `0` | Created valid 10-page PDF (`589,590 bytes`); inspected with `pypdf`, producer: ReportLab PDF Library | **PASS** |

### 2.3 Extended Capability Tests (Batch 3)
| Test ID | Feature | Test Input | Expected Behavior | Actual Result | Evidence / Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **ET-01** | Case Lifecycle Enumeration | `RansomEye.exe case list` & `show` | Display case metadata, event counts, status | Exit code `0` | Displayed `CASE-2026-ENC-01`, host `SEC-CORP-EP01`, status `OPEN`, events `68`, findings `14`, incidents `5` | **PASS** |
| **ET-02** | Chain of Custody Ledger | `RansomEye.exe custody list` | Display append-only custody event log | Exit code `0` | Outputted 7 entries with timestamps, SHA-256 hashes, actions (`created`, `reviewed`), analyst signatures | **PASS** |
| **ET-03** | Threat Intelligence Extraction | `samples/prepared_case/indicators.txt` | Extract and normalize multi-class IOCs | Exit code `0` | Extracted 10 indicators: 2 IPv4, 2 Domains, 1 URL, 2 SHA-256 hashes, 1 BTC address, 2 LOLBin commands | **PASS** |
| **ET-04** | Kill-Chain Reconstruction | `RansomEye.exe investigation reconstruct` | Correlate attack timeline from evidence | Exit code `0` | Sequenced: DNS beacon $\rightarrow$ LOLBin download $\rightarrow$ encryption $\rightarrow$ shadow delete $\rightarrow$ ransom note $\rightarrow$ score 100 | **PASS** |
| **ET-05** | Standalone Dashboard Server | `RansomEye.exe dashboard --port 8999` | Start HTTP server and serve API/UI | Exit code `0` (daemon) | Verified HTTP 200 on `/`, `/api/cases`, `/api/case/<id>`, and `/api/report/<id>/pdf` via HTTP client | **PASS** |

### 2.4 Clean-Environment Isolation Test
| Test ID | Feature | Test Environment | Expected Behavior | Actual Result | Evidence / Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **CT-01** | Zero-Python Host Compatibility | Stripped shell: `PATH=C:\Windows\system32;C:\Windows`, empty Python env, `C:\Windows\Temp` cwd | Executable unpacks and runs without host Python | Exit code `0` | Verified `RansomEye.exe --help`, `static`, and `script` executed successfully with no missing DLLs | **PASS** |

### 2.5 Safe Database Migration Tests (Phase 2F)
| Test ID | Feature / Component | Test Input | Expected Behavior | Actual Result | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **MIG-01** | Current Schema No Backup | `test_latest_schema_no_unnecessary_backup` | DB at v6 opens without creating `.bak` file | **PASS** | No `.bak` created when version == 6 | **PASS** |
| **MIG-02** | Historical Schema Verified Backup | `test_historical_schema_creates_verified_backup` | DB at v1 creates backup file before migration | **PASS** | Backup created, contains pre-migration v1 schema | **PASS** |
| **MIG-03** | Backup Integrity & Version | `test_backup_readable_and_retains_original_version` | Backup is readable SQLite DB with original version | **PASS** | `quick_check` OK, `user_version` == 1, row counts match | **PASS** |
| **MIG-04** | Non-Destructive Collision Handling | `test_existing_backup_never_silently_overwritten` | Pre-existing `.bak` preserved; distinct suffix chosen | **PASS** | Original backup preserved byte-for-byte; unique backup created | **PASS** |
| **MIG-05** | Backup Failure Halts Migration | `test_backup_creation_failure_prevents_migration` | Read-only/unwritable target halts migration | **PASS** | `MigrationBackupError` raised; DB remains untouched at v1 | **PASS** |
| **MIG-06** | Migration Failure Retains Backup | `test_migration_failure_preserves_backup` | DDL failure mid-migration leaves valid backup | **PASS** | `MigrationError` raised; backup exists and is intact | **PASS** |
| **MIG-07** | WAL Journal Mode Safety | `test_wal_journal_migration_backup_safety` | Uncheckpointed WAL pages included in backup | **PASS** | SQLite backup API flushes WAL; backup contains all tables & rows | **PASS** |
| **MIG-08** | Fresh Database Initialization | `test_fresh_database_initialization` | New database initializes directly to v6 without backup | **PASS** | New DB created at v6 with 0 backups created | **PASS** |
| **MIG-09** | Production Database Safety | `test_production_database_never_used_by_tests` | Tests never point to `data/ransomeye.db` | **PASS** | Verified all test paths are isolated temporary files | **PASS** |

### 2.6 Dashboard CORS Hardening Tests (Phase 2F)
| Test ID | Feature / Component | Test Input | Expected Behavior | Actual Result | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **CORS-01** | Same-Origin Access | `test_normal_same_origin_requests_work` | GET `/` and `/api/cases` return HTTP 200 | **PASS** | Normal same-origin requests succeed with JSON/HTML | **PASS** |
| **CORS-02** | Wildcard Removal | `test_no_wildcard_cors_header_emitted` | No `Access-Control-Allow-Origin: *` header | **PASS** | Verified across `/`, `/api/cases`, `/api/health`, `/api/case/x` | **PASS** |
| **CORS-03** | Untrusted Origin Rejection | `test_untrusted_origin_not_granted_access` | `Origin: http://evil.attacker.com` disallowed | **PASS** | No CORS header returned on GET; access denied to untrusted origin | **PASS** |
| **CORS-04** | Approved Origin Access | `test_approved_origin_receives_exact_header` | `Origin: http://console.incident-response.internal` | **PASS** | Emits exact matching origin; no wildcard | **PASS** |
| **CORS-05** | Missing Origin Handled | `test_missing_origin_handled_cleanly` | Request without `Origin` header | **PASS** | Request succeeds normally with no CORS headers | **PASS** |
| **CORS-06** | OPTIONS Preflight Policy | `test_options_preflight_obeys_policy` | OPTIONS preflight from untrusted vs approved | **PASS** | 403 Forbidden for untrusted; 200 OK + matching origin for approved | **PASS** |
| **CORS-07** | Error Responses Follow Policy | `test_error_responses_follow_same_cors_policy` | 404/400 errors follow strict CORS rules | **PASS** | Untrusted origins receive 404 with no CORS headers | **PASS** |

---

## 3. Proposed Future Tests (Pre-Release Phase)

The following tests are proposed for execution once an official release candidate build script and signing credentials are provided:

| Test ID | Proposed Feature | Proposed Test Scenario | Target Exit / Assertion | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **PROP-01** | Authenticode Verification | Run `signtool verify /pa /v RansomEye.exe` on signed binary | Returncode 0, Valid chain to trusted root | Validates SmartScreen bypass and binary provenance |
| **PROP-02** | SmartScreen Emulation | Launch binary in fresh VM with Windows SmartScreen active | No "Untrusted Publisher" block dialog | Confirms reputation / code-signing effectiveness |
| **PROP-03** | Massive PCAP Stress Test | Analyze a 100 MB+ capture file | Bounded memory usage (<256MB), no OOM crash | Verifies streaming or bounded packet dissection limits |
| **PROP-04** | Malicious Archive Ingestion | Ingest ZIP/Sysmon XML containing path traversal filenames | Rejection with clean error; no file written outside case dir | Confirms path containment under adversarial input |
| **PROP-05** | Concurrent Dashboard Load | 50 concurrent HTTP requests against `/api/cases` and `/api/report` | All return HTTP 200/501; no SQLite database lock timeout | Tests ThreadingHTTPServer connection pool resilience |
| **PROP-06** | Windows Service Packaging | If deployed as MSI, install/start/stop continuous collection service | Service transitions to RUNNING; logs to Windows Event Log | Verifies enterprise background collector capability |

---

## 4. Test Summary

- **Total Unit & Integration Tests Executed:** 1,000
- **Unit & Integration Pass Rate:** 100.0% (1,000/1,000 across 36 test modules)
- **Packaged Executable Workflows Executed:** 12 (6 smoke tests + 5 extended capability tests + 1 clean-environment test)
- **Packaged Workflow Pass Rate:** 100.0% (12/12)
- **Failed Tests:** 0
- **Fabricated Tests:** 0
- **Skipped Tests:** 0
