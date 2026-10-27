# RansomEye Current Status

## 1. Current Architecture

RansomEye is a defensive, evidence-centric Digital Forensics and Incident Response (DFIR) platform designed to detect ransomware activity, reconstruct multi-stage attack chains, validate forensic integrity, and provide investigator diagnostics.

The authoritative pipeline workflow is strictly structured as follows:

```
Evidence Sources (Live Process, Live File, Live Network, Canary Decoys, Sysmon XML, JSON)
       │
       ▼
CollectionPipeline & Normalization (EvidenceEvent dataclass validation)
       │
       ▼
EvidenceStore (Local SQLite database `data/ransomeye.db`, Schema Version 6)
       │
       ▼
Behavioral Detection (Process behaviors, file system churn, mass modifications, ransom notes)
       │
       ▼
Finding Generation (Deterministic SHA-256 finding identities & MITRE ATT&CK mapping)
       │
       ▼
Incident Correlation (Deterministic incident grouping across time-windows and process keys)
       │
       ▼
Threat Assessment (Normalized scoring, severity bands, explainable reasoning)
       │
       ▼
Investigation Domain Model (Graph nodes, edges, process trees, and advanced timelines)
       │
       ▼
Validation & Forensics (Forensic integrity verification, chain-of-custody tracking)
       │
       ▼
Reporting & Analyst Console (Deterministic case reports and local HTTP analyst dashboard)
```

The system operates strictly local-first with no cloud dependencies, no cloud LLMs, no destructive auto-quarantine, and no autonomous process termination.

---

## 2. Implemented Features

The following features are verified to be fully implemented and covered by automated tests in the codebase:

| Feature / Component | Status | Description |
| :--- | :--- | :--- |
| **EvidenceEvent Schema** | IMPLEMENTED | Strongly typed event dataclass with schema normalization and field range validation (`src/ransomeye/evidence.py`). |
| **EvidenceStore SQLite Storage** | IMPLEMENTED | Local SQLite storage with foreign keys, schema migrations (v1-v6), indexing, and audit logging (`src/ransomeye/storage.py`). |
| **Sysmon XML Ingestion** | IMPLEMENTED | Sysmon XML parser supporting Events 1, 2, 3, 5, 7, 11, 12, 13, 22, 23, 25 with namespace tolerance and fallback parsing (`src/ransomeye/sysmon_reader.py`). |
| **JSON Evidence Ingestion** | IMPLEMENTED | Robust parsing of single events, event arrays, and wrapped JSON objects (`src/ransomeye/commands.py`). |
| **Live Process Collection** | IMPLEMENTED | Polling-based live process creator/terminator with synthetic intra-session tokenization and fault-tolerant permission handling (`src/ransomeye/collectors/live_process.py`). |
| **Live File Collection** | IMPLEMENTED | Watchdog-based file event streaming (creation, modification, deletion, rename) with SHA-256 calculation (`src/ransomeye/collectors/live_file.py`). |
| **Live Network Collection** | IMPLEMENTED | Connection polling via psutil tracking established TCP/UDP network connections (`src/ransomeye/collectors/live_network.py`). |
| **Canary Decoy Collection** | IMPLEMENTED | Decoy file deployment and file system trap monitor generating tamper evidence events (`src/ransomeye/collectors/canary_collector.py`). |
| **Composite Collector** | IMPLEMENTED | Fault-isolated concurrent management of child collectors with unified event dispatch and truthful status metrics (`src/ransomeye/collectors/composite.py`). |
| **Collection Pipeline** | IMPLEMENTED | Batch and streaming queue ingestion with bounded buffers, case lifecycle synchronization, and store persistence (`src/ransomeye/collection.py`). |
| **PowerShell Behavioral Detection** | IMPLEMENTED | Detection of encoded commands, download strings, and script execution (`src/ransomeye/behavior.py`). |
| **CertUtil Abuse Detection** | IMPLEMENTED | Detection of certutil download cache and decoding parameters (`src/ransomeye/behavior.py`). |
| **Recovery Inhibition Detection** | IMPLEMENTED | Detection of shadow copy deletion (vssadmin, wmic, wbadmin) (`src/ransomeye/behavior.py`). |
| **Mass File Modification Detection** | IMPLEMENTED | Sliding-window detection of high-volume modifications per process identity (`src/ransomeye/file_behavior.py`). |
| **Mass File Creation/Deletion** | IMPLEMENTED | High-volume create/delete burst detection (`src/ransomeye/file_behavior.py`). |
| **File Churn Detection** | IMPLEMENTED | Simultaneous rapid create and delete pattern detection within tight windows (`src/ransomeye/file_behavior.py`). |
| **Ransom Note Detection** | IMPLEMENTED | Keyword pattern matching on created file paths (`src/ransomeye/file_behavior.py`). |
| **Extension Change Detection** | IMPLEMENTED | Detection of file rename events altering extensions (`src/ransomeye/file_behavior.py`). |
| **Shannon Entropy Calculation** | IMPLEMENTED | Shannon entropy byte calculation and buffer chunking for packed/encrypted data detection (`src/ransomeye/entropy.py`). |
| **Incident Correlation Engine** | IMPLEMENTED | Multi-finding incident correlation linking process relationships and time windows with deterministic hashing (`src/ransomeye/correlation.py`). |
| **Unified Threat Assessment** | IMPLEMENTED | Multi-engine score aggregation, deduplication, confidence estimation, and MITRE mapping (`src/ransomeye/threat_assessment.py`). |
| **Investigation Graph** | IMPLEMENTED | In-memory graph model building process, file, network, finding, and incident nodes/edges (`src/ransomeye/investigation_graph.py`). |
| **Process Tree Reconstruction** | IMPLEMENTED | Hierarchical parent-child process tree builder with GUID and PID resolution (`src/ransomeye/timeline.py`). |
| **Attack Reconstruction** | IMPLEMENTED | Kill-chain stage classification matching evidence to initial access, execution, defense evasion, impact (`src/ransomeye/reconstruction.py`). |
| **Investigation Validation** | IMPLEMENTED | Automated integrity checks evaluating case existence, assessment presence, findings traceability, and cross-case isolation (`src/ransomeye/investigation_validation.py`). |
| **Cryptographic Integrity** | IMPLEMENTED | SHA-256 manifest generation and verification (`src/ransomeye/integrity.py`). |
| **Chain of Custody** | IMPLEMENTED | Append-only SQLite custody audit trail protected by database triggers (`src/ransomeye/storage.py`). |
| **Case Package Exporter** | IMPLEMENTED | Atomic case package export with lock-file concurrency management and SHA-256 manifest (`src/ransomeye/export.py`). |
| **Database Backup & Restore** | IMPLEMENTED | Safe online SQLite vacuum backups and integrity-checked restoration (`src/ransomeye/storage.py`). |
| **Forensic Case Reporting** | IMPLEMENTED | Deterministic textual case report generation covering evidence, findings, timeline, and custody (`src/ransomeye/report.py`). |
| **Analyst Web Dashboard** | IMPLEMENTED | Local single-page web console (`http.server`) rendering overview stats, case graphs, timelines, and incident traces (`src/ransomeye/dashboard_server.py`). |

---

## 3. Partially Implemented Features

| Feature / Component | Status | Gap Description |
| :--- | :--- | :--- |
| **CLI Dashboard Command** | PARTIAL | `dashboard_server.py` exists as a runnable script, but is not exposed as a standard subcommand `ransomeye dashboard` in `commands.py`. |
| **Dashboard Network Binding** | PARTIAL | The HTTP server currently binds to `""` (all interfaces / 0.0.0.0) by default instead of `127.0.0.1`, which poses network exposure risks on multi-homed environments. |

---

## 4. Planned / Missing Features

| Feature / Component | Status | Requirement / Gap Description |
| :--- | :--- | :--- |
| **Native Static File Analyzer** | MISSING | A native standalone static analyzer for PE/binary/script examination (header parsing, section extraction, import API hashing, string and IOC extraction) without executing the sample. |
| **Windows Executable Packaging** | PLANNED | Packaging configuration (e.g. PyInstaller or Windows installer bundle) to generate a standalone `RansomEye.exe` distribution. |
| **Memory Forensics Engine** | PLANNED | Deep volatility/memory dump parsing (planned for future major version). |

---

## 5. Test Results

The test suite was executed in the workspace using pytest:

- **Tests Collected:** 531
- **Tests Passed:** 531
- **Tests Failed:** 0
- **Tests Skipped:** 0
- **Errors:** 0
- **Execution Time:** ~79.10 seconds

All existing unit, integration, behavioral detection, case lifecycle, chain of custody, and dashboard endpoint tests pass cleanly with 100% success.

---

## 6. Security Findings

1. **Dashboard Bind Address (Resolved/Pending Fix):**
   - *Finding:* `dashboard_server.py` binds to `("", port)` which listens on `0.0.0.0`.
   - *Risk:* Exposes unauthenticated local DFIR endpoints to the local area network.
   - *Remediation:* Default bind address to `127.0.0.1` (localhost) with an explicit configurable `--host` parameter.
2. **Safe Subprocess Execution:**
   - *Finding:* No unsafe `shell=True` subprocess calls exist in the core codebase.
3. **Path Traversal Protection:**
   - *Finding:* Path traversal safeguards are actively enforced via `_validate_safe_id` and strict `Path.resolve()` checks in `dashboard_server.py` and `export.py`.
4. **SQL Injection Safety:**
   - *Finding:* All database queries use parameterized SQLite statements (`?` parameters) with foreign key enforcement.
5. **No Autonomous Destructive Actions:**
   - *Finding:* No process termination or destructive file operations exist in the platform.

---

## 7. Packaging Status

- **Status:** PLANNED
- **Details:** The project currently runs via Python (`python -m ransomeye.commands` or `ransomeye` script via `pip install -e .`). No standalone `RansomEye.exe` binary is currently packaged in the repository.

---

## 8. Documentation Accuracy

- **README.md:** Currently lists project capabilities. Needs clear delineation of CURRENTLY IMPLEMENTED vs PARTIAL vs PLANNED features to strictly reflect source code truth.
- **Rules Documentation:** `.agents/rules/ransomeye.md` and `.cursor/rules/ransomeye.md` accurately document database safety and test execution procedures.

---

## 9. Technical Debt

1. **Unified CLI Access:** Missing `dashboard` and `static` subcommands in `ransomeye` CLI entry point.
2. **Static File Inspection:** Shannon entropy utility (`entropy.py`) is standalone and not yet unified with a file inspection tool.

---

## 10. Recommended Build Order

1. **P0 / P1 — Security Hardening:** Bind dashboard server to `127.0.0.1` by default and add host argument.
2. **P1 — CLI Unification:** Add `ransomeye dashboard` subcommand in `commands.py` to launch the analyst dashboard from the main entrypoint.
3. **P2 — Native Static File Analyzer:** Build `src/ransomeye/static_analyzer.py` providing safe, non-executing PE and static file metadata, section parsing, import analysis, entropy, string extraction, and IOC discovery.
4. **P2 — Static Analysis CLI & Pipeline Integration:** Register `ransomeye analyze-file` (or `ransomeye static`) CLI command to allow standalone static analysis or ingestion into case investigations.
5. **P2 — Test Suite Expansion:** Add comprehensive unit and integration tests for static file analysis, dashboard command, and security fixes.
6. **P3 — Packaging Verification & Scripting:** Provide PyInstaller build script/specification for standalone Windows EXE distribution.
7. **Documentation Updates:** Update `README.md` and generate final `RANSOMEYE_BUILD_REPORT.md`.
