# RansomEye — Evidence-Centric Ransomware Detection & Forensics

RansomEye is a local-first, defensive Digital Forensics and Incident Response (DFIR) platform designed for endpoint evidence ingestion, behavioral ransomware detection, automated incident correlation, multi-stage attack reconstruction, static executable inspection, forensic report generation, and tamper-evident chain-of-custody tracking.

---

## Architecture Overview

RansomEye operates under an authoritative evidence-to-finding pipeline model:

```
Evidence Sources (Sysmon XML, JSON, Live Process, Live File, Live Network, Canary Decoys)
       │
       ▼
CollectionPipeline & Normalization (EvidenceEvent Schema Validation)
       │
       ▼
EvidenceStore (Local SQLite database `data/ransomeye.db`, Schema v6)
       │
       ▼
Behavioral Detection & Static Analysis (Process indicators, Churn, Notes, PE Analysis)
       │
       ▼
Finding Generation (Deterministic SHA-256 finding identities & MITRE ATT&CK Mapping)
       │
       ▼
Incident Correlation (Time-window & Process-Key Correlation)
       │
       ▼
Threat Assessment (Unified Scoring, Severity Categorization, Explainable Reasons)
       │
       ▼
Investigation Domain Model (Graph Construction, Process Hierarchy, Advanced Timeline)
       │
       ▼
Validation & Cryptographic Custody (Automated Integrity Validation, SHA-256 Manifests)
       │
       ▼
Forensic Reporting & Analyst Web Console (Textual Investigation Reports & HTTP Dashboard)
```

---

## Feature Implementation Status

### CURRENTLY IMPLEMENTED

- **Evidence Ingestion:** Full ingestion and normalization of Sysmon XML event logs (Events 1-25) and structured JSON evidence streams.
- **Continuous Live Collection:** Real-time collectors for process creation/termination, file system modifications (`watchdog`), established network sockets (`psutil`), and decoy canary traps (`CanaryCollector`).
- **Composite Collector & Streaming Pipeline:** Fault-isolated multi-collector orchestrator with bounded queues and clean lifecycle control.
- **Behavioral Detection Engines:**
  - Suspicious PowerShell (`-enc`, `iex`, `downloadstring`, `frombase64string`)
  - CertUtil abuse (`-urlcache`, `-split`, `-decode`)
  - Recovery inhibition (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`)
  - Mass file modification (sliding-window burst detection)
  - Mass file creation & deletion churn
  - Ransom note keyword pattern detection
  - Suspicious file extension changes
- **Native Static File & PE Analyzer:** Pure-Python safe static inspector extracting SHA-256/SHA-1/MD5 hashes, file types, PE headers, section entropies, import table APIs, suspicious capability indicators, bounded strings, and IOCs.
- **Incident Correlation:** Deterministic grouping of related findings by process lineage and temporal sliding windows.
- **Unified Threat Assessment:** Normalized 0–100 scoring, severity bands (SAFE, LOW, MEDIUM, HIGH, CRITICAL), and MITRE ATT&CK technique mapping.
- **Investigation Graph & Attack Reconstruction:** In-memory directional graph connecting processes, files, network destinations, findings, and kill-chain stages.
- **Investigation Integrity Validation:** Automated validation ensuring 100% finding-to-evidence linkage, referential integrity, and cross-case isolation.
- **Chain of Custody & Audit Trail:** Tamper-evident, trigger-protected append-only SQLite custody audit logs.
- **Unified Analyst Web Dashboard:** Dark-themed single-page web console (`http.server`) bound securely to `127.0.0.1` providing complete UI workflows for all CLI operations: Cases, Monitor, Incidents, Findings, Evidence Search & Trace, Investigation Graph & Processes, Process Hierarchy Tree, Attack Reconstruction, Forensics Reports, Collection & Ingestion, Integrity Manifests, Chain of Custody Ledger, Case Export & Locks, Database Maintenance, Safe Static PE Analysis, and Phishing Email Inspection.
- **Standalone Windows Executable Distribution:** Packaged standalone Windows EXE (`dist/RansomEye.exe`) built via PyInstaller with embedded static web assets and zero external dependencies.
- **Comprehensive Test Suite:** 549 automated unit, integration, and end-to-end tests passing with 100% success.

### PARTIALLY IMPLEMENTED

- **Live Process Attribution on Generic Filesystem Events:** File system events captured via standard OS file notifications track file paths and hashes; process correlation relies on temporal and process-tree linkage.

### FUTURE WORK / PLANNED

- **Memory Forensics Engine:** Direct RAM dump and volatile memory symbol parsing.

---

## Getting Started

### Requirements
- Python 3.13 or newer
- Windows, Linux, or macOS

### Installation

Clone the repository and install dependencies in development mode:

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package in editable mode with development dependencies
pip install -e .
pip install pytest watchdog psutil pyinstaller
```

Or execute the automated setup script:
```powershell
.\start_ransomeye_setup.bat
```

### Building Standalone Windows Executable

To produce the standalone portable Windows executable:
```powershell
python scripts/build_windows_dist.py
```
Output executable: `dist/RansomEye.exe` (~10.5 MB).

---

## CLI Usage Guide

All commands can be run via `ransomeye <command>`, `python -m ransomeye.commands <command>`, or `.\dist\RansomEye.exe <command>`.

### 1. Case Lifecycle Management
```powershell
# Create a new forensic case
ransomeye case create --database data/ransomeye.db --case CASE-2026-001 --name "Ransomware Triage" --host "FIN-WS-04"

# List stored cases
ransomeye case list --database data/ransomeye.db

# Show case details
ransomeye case show --database data/ransomeye.db --case CASE-2026-001

# Update case status
ransomeye case update --database data/ransomeye.db --case CASE-2026-001 --status TRIAGED --note "Initial triage complete"
```

### 2. Evidence Ingestion & Live Collection
```powershell
# Ingest Sysmon XML event log
ransomeye ingest --database data/ransomeye.db --case CASE-2026-001 --file samples/sysmon/event_1_process_creation.xml --format sysmon-xml

# Ingest synthetic JSON evidence
ransomeye ingest --database data/ransomeye.db --case CASE-2026-001 --file samples/ransomware_like_activity.json --format json

# Start live streaming collector
ransomeye collect live --database data/ransomeye.db --case CASE-2026-001 --watch-dir data/live_watch --canary-dir data/live_canary
```

### 3. Investigation, Process Trees & Reconstruction
```powershell
# View investigation summary
ransomeye investigation show --database data/ransomeye.db --case CASE-2026-001

# Build and display investigation graph
ransomeye investigation graph --database data/ransomeye.db --case CASE-2026-001

# Display process execution hierarchy tree
ransomeye tree --database data/ransomeye.db --case CASE-2026-001

# Reconstruct multi-stage attack kill-chain
ransomeye investigation reconstruct --database data/ransomeye.db --case CASE-2026-001

# Deep-dive process drilldown by PID or Process GUID
ransomeye investigation process --database data/ransomeye.db --case CASE-2026-001 --process "{11111111-2222-3333-4444-555555555555}"

# Validate investigation integrity
ransomeye investigation validate --database data/ransomeye.db --case CASE-2026-001

# Generate deterministic textual forensic case report
ransomeye report --database data/ransomeye.db --case CASE-2026-001 --output reports/CASE-2026-001_report.txt
```

### 4. Integrity, Custody, Export & Database Maintenance
```powershell
# Compute SHA-256 hash manifest of forensic artifacts
ransomeye integrity hash --file reports/CASE-2026-001_report.txt

# Verify artifact against manifest
ransomeye integrity verify --manifest reports/manifest.json

# Record append-only chain of custody entry
ransomeye custody record --database data/ransomeye.db --case CASE-2026-001 --artifact reports/CASE-2026-001_report.txt --action verified --analyst "Analyst-1"

# Export case forensic bundle
ransomeye export --database data/ransomeye.db --case CASE-2026-001 --output exports/CASE-2026-001.zip

# Run SQLite database integrity check
ransomeye database check --database data/ransomeye.db

# Perform hot SQLite online backup
ransomeye database backup --database data/ransomeye.db --destination backups/ransomeye_backup.db
```

### 5. Static File & Phishing Analysis
```powershell
# Inspect suspicious executable or binary statically (pure-Python PE inspection)
ransomeye static --file samples/suspicious_payload.bin

# Inspect suspicious email message for phishing indicators
ransomeye phishing --file samples/phishing_sample.eml
```

### 6. Unified Analyst Web Console
```powershell
# Launch local HTTP analyst console on localhost:8080
ransomeye dashboard --database data/ransomeye.db --host 127.0.0.1 --port 8080
```
Open `http://localhost:8080` in your web browser to access the complete interactive investigation console.

---

## Testing & Quality Assurance

To execute the complete automated test suite:

```powershell
$env:PYTHONPATH="src"
python -m pytest -v
```

### Current Verification Results
- **Total Tests:** 549
- **Passed:** 549
- **Failed:** 0
- **Skipped:** 0
- **Errors:** 0
- **Code Coverage:** Full coverage across evidence normalization, storage, rules, correlation, graph, validation, static analysis, phishing analysis, process resolution, chain of custody, export locking, database maintenance, and dashboard REST API.

---

## Defensive Boundaries & Ethics

RansomEye is strictly a defensive forensics and investigation tool:
- **No autonomous process termination:** RansomEye never terminates running processes automatically.
- **No autonomous file quarantine / deletion:** Evidence is preserved without destructive tampering.
- **No payload execution:** The static analyzer parses PE headers, sections, strings, and byte structures without executing untrusted code.
- **Local-first privacy:** All telemetry, database records, and investigation artifacts reside on the local system.
