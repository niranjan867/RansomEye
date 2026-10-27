# RansomEye Product Validation

## 1. Build Environment

- **Operating System:** Windows 11 Pro (10.0.26200-SP0)
- **Python Version:** 3.13.15 (64-bit AMD64)
- **Packaging Framework:** PyInstaller 6.22.3
- **Repository:** RansomEye (niranjan867/RansomEye)
- **Database Engine:** SQLite 3 (Schema Version 6)
- **Build Specification:** `scripts/ransomeye.spec`

---

## 2. EXE Build Result

- **Status:** VERIFIED
- **Details:** The build was executed via `python scripts/build_windows_dist.py`. PyInstaller successfully analyzed dependencies, compiled the bytecode archive, bundled the static console assets (`static/index.html`, `static/styles.css`, `static/app.js`, `static/logo.png`), embedded the Windows manifest, and compiled a single standalone binary `RansomEye.exe`.

---

## 3. EXE Location

- **Status:** VERIFIED
- **Physical Path:** `d:\nira\project\RansomEye\dist\RansomEye.exe`
- **File Size:** 11,046,781 bytes (~10.5 MB)
- **SHA-256 Digest:** `a32cd51e4077f7d8da59a1062501b2e30a640a4842902017eadd851c2ec91544`

---

## 4. Application Startup Result

- **Status:** VERIFIED
- **Execution Command:** `.\dist\RansomEye.exe --help`
- **Details:** Executable initializes without external Python runtime dependencies, parses command line flags, and renders the top-level help menu listing all available subcommands (`timeline`, `tree`, `report`, `case`, `custody`, `integrity`, `export`, `database`, `investigation`, `collect`, `ingest`, `evidence`, `phishing`, `dashboard`, `static`).

---

## 5. Dashboard Result

- **Status:** VERIFIED
- **Details:** The local analyst console is embedded directly into the standalone binary. Server initializes with `127.0.0.1` localhost binding by default, preventing accidental network exposure. Static assets load cleanly, REST API endpoints (`/api/cases`, `/api/case/<id>`, `/api/timeline/<id>`, `/api/reconstruction/<id>`, `/api/validation/<id>`) respond correctly, and case reports are generated via HTTP POST.

---

## 6. Evidence Collection Result

- **Status:** VERIFIED
- **Details:** The executable successfully ingested both JSON simulation datasets (`samples/ransomware_like_activity.json`) and realistic multi-event Sysmon XML event log feeds (`samples/sysmon/realistic_ransomware_sequence.xml`). Events were normalized into `EvidenceEvent` structures, schema-validated, and persisted to SQLite without event loss or corruption.

---

## 7. Detection Result

- **Status:** VERIFIED
- **Details:** Deterministic behavioral detection engines executed successfully:
  - Suspicious PowerShell command-line execution (`-enc` parameter) detected (Technique `T1059.001`).
  - System recovery inhibition (`vssadmin delete shadows`) detected (Technique `T1490`).
  - Sliding-window mass file modification (55 files modified in 30 seconds) detected (Technique `T1486`).
  - Ransom note creation detected (`README_DECRYPT.txt`) (Technique `T1486`).

---

## 8. Correlation Result

- **Status:** VERIFIED
- **Details:** The correlation engine synthesized 8 detection findings into 2 distinct incident clusters (`INC-` deterministic IDs) based on process GUID lineage, parent-child process tree relationships, and temporal sliding windows.

---

## 9. Investigation Result

- **Status:** VERIFIED
- **Execution Command:** `.\dist\RansomEye.exe investigation show --database data/test_exe.db --case CASE-EXE-001`
- **Details:** Correctly aggregated 64 evidence events, 8 findings, 2 correlated incidents, and 4 process nodes, producing an overall threat score of 75/100 (`HIGH` severity) with 0.85 confidence.

---

## 10. Timeline / Reconstruction Result

- **Status:** VERIFIED
- **Details:**
  - **Process Tree:** Resolved full hierarchical parent-child relationships (`explorer.exe` $\rightarrow$ `powershell.exe` $\rightarrow$ `certutil.exe` / `vssadmin.exe`).
  - **Attack Reconstruction:** Synthesized chronological multi-stage attack kill-chain sequence matching execution, defense evasion, and impact stages.
  - **Timezone Normalization:** Handled heterogeneous timestamp formats (UTC offset-aware and ISO offset-naive) with safe deterministic sorting.

---

## 11. Validation Result

- **Status:** VERIFIED
- **Execution Command:** `.\dist\RansomEye.exe investigation validate --database data/test_exe.db --case CASE-EXE-001`
- **Result Output:**
  ```
  CASE ....................... PASS
  ASSESSMENT ................. AVAILABLE (Score: 75, Severity: HIGH)
  TRACEABILITY ............... 8/8 Findings with evidence, 64/64 Evidence traceable
  PROCESS INTEGRITY .......... Process nodes OK, Parent/child OK
  TIMELINE ................... OK
  RECONSTRUCTION ............. OK
  CASE ISOLATION ............. 0 cross-case references
  RESULT ..................... PASS
  ```

---

## 12. Report Generation Result

- **Status:** VERIFIED
- **Execution Command:** `.\dist\RansomEye.exe report --database data/test_exe.db --case CASE-EXE-001 --output reports/CASE-EXE-001_report.txt`
- **Details:** Generated deterministic 1,652-line forensic case report documenting case metadata, threat assessment, finding details, evidence timeline, MITRE ATT&CK kill-chain sequence, and cryptographic chain-of-custody audit logs.

---

## 13. Static Analysis Result

- **Status:** VERIFIED
- **Execution Command:** `.\dist\RansomEye.exe static --file dist/RansomEye.exe --database data/test_exe.db --case CASE-EXE-001`
- **Details:** Non-executing static analyzer inspected the PE executable:
  - Cryptographic hashes: SHA-256, SHA-1, MD5 verified.
  - PE Header parsing: AMD64 architecture, Windows CUI subsystem, entry point `0x0000DCF0`, image base `0x140000000`.
  - Sections: Analyzed 7 sections (`.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `.rsrc`, `.reloc`) with per-section Shannon entropy calculation.
  - Suspicious APIs: Identified `IsDebuggerPresent`, `DeleteFileW`, `FindFirstFileW`, `FindNextFileW`, `OpenProcessToken`.
  - Ingested evidence event and linked finding directly into case with tamper-evident chain-of-custody audit logging.

---

## 14. Automated Test Result

- **Status:** VERIFIED
- **Test Command:** `python -m pytest -q`
- **Collected:** 542
- **Passed:** 542
- **Failed:** 0
- **Skipped:** 0
- **Errors:** 0
- **Duration:** 89.94s

---

## 15. Known Limitations

1. **Watchdog Kernel PID Attribution:** File modification events captured via `watchdog` track filesystem paths and SHA-256 hashes without native Windows kernel PID attribution; PID linkage is established via correlation with Sysmon and process monitoring events.
2. **Volatile Memory Analysis:** Memory dump inspection is reserved for a future release.

---

## 16. Final Product Status

| Component / Evaluation | Status |
| :--- | :--- |
| **PyInstaller Executable Generation** | VERIFIED |
| **Application CLI Startup** | VERIFIED |
| **Analyst Web Dashboard** | VERIFIED |
| **Evidence Ingestion (Sysmon / JSON)** | VERIFIED |
| **Behavioral Detection Engine** | VERIFIED |
| **Multi-Finding Correlation** | VERIFIED |
| **Threat Assessment & Scoring** | VERIFIED |
| **Investigation Domain Model & Graph** | VERIFIED |
| **Process Tree & Kill-Chain Reconstruction** | VERIFIED |
| **Investigation Integrity Validation** | VERIFIED |
| **Forensic Case Reporting** | VERIFIED |
| **Native Static File & PE Analyzer** | VERIFIED |
| **Automated Test Suite (542 Tests)** | VERIFIED |
| **Overall Standalone Product Status** | VERIFIED |
