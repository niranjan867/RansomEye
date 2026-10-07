# PROJECT AUDIT REPORT

Audit type: Read-only repository analysis  
Repository: RansomEye (niranjan867/RansomEye)  
Audit date: 2026-09-09  
Implementation source of truth: Source code  
Modification performed: NONE  

---

## EXECUTIVE SUMMARY

**RansomEye** is a defensive Digital Forensics and Incident Response (DFIR) application and Command-Line Interface (CLI) tool designed for case lifecycle management, evidence ingestion, ransomware behavioral analysis, automated threat assessment, investigation graph construction, attack reconstruction, forensic report generation, and chain-of-custody tracking. It includes a built-in local web dashboard server (`http.server`) with a dark-themed single-page analyst console.

The project operates under a strict defensive model:
- It does not contain or execute malware payloads.
- It analyzes evidence collected from live Windows endpoints (Sysmon event logs, process activity, network connections, file system traps) and synthetic/recorded evidence files (JSON, Sysmon XML).
- It stores all case data, normalized evidence, detection findings, correlation incidents, and audit trails in a local SQLite database (`data/ransomeye.db`) using an append-only custody pattern with schema migration support (currently Schema Version 6).

---

# PHASE 1 — REPOSITORY INVENTORY

### High-Level Repository Map

```
RansomEye/
├── .agents/
│   └── rules/
│       └── ransomeye.md                # Agent workspace instructions & database safety rules
├── .cursor/
│   └── rules/
│       └── ransomeye.md                # Defensive DFIR project rules & simulation guidelines
├── .vscode/
│   └── settings.json                   # VS Code configuration (Python environment manager)
├── docs/
│   ├── 12x_source_to_source_audit.md   # Architectural audit comparing RansomEye and 12X
│   └── dashboard-ui-plan.md            # Specification plan for dashboard REST server & UI
├── samples/
│   ├── normal_activity.json            # Synthetic benign file/process activity dataset
│   ├── ransomware_like_activity.json   # Synthetic mass encryption & ransom note dataset
│   ├── simulation_activity.json        # Synthetic test activity for rule validation
│   └── sysmon/                         # 22 raw Sysmon XML event samples (Events 1-25)
├── src/
│   └── ransomeye/                      # Core RansomEye Python application package
│       ├── __init__.py                 # Package initializer
│       ├── advanced_timeline.py        # Kill-chain and multi-stage analytical timeline
│       ├── behavior.py                 # Process behavioral detection rules (PowerShell, certutil, vssadmin)
│       ├── collection.py               # Streaming/batch evidence collection pipeline & worker
│       ├── commands.py                 # Primary CLI parser, command handlers, and execution dispatcher
│       ├── correlation.py              # Multi-finding incident correlation engine & time windowing
│       ├── dashboard_server.py         # HTTP REST API server & static asset file server
│       ├── entropy.py                  # Shannon entropy calculator for file/buffer packing detection
│       ├── evidence.py                 # Common evidence schema, normalization & validation
│       ├── export.py                   # Case package exporter, lock-file management & verification
│       ├── file_behavior.py            # File system behavioral engine (churn, mass mod/del, note, extension)
│       ├── integrity.py                # SHA-256 file hashing & manifest verification
│       ├── investigation.py            # Aggregated case investigation domain model
│       ├── investigation_graph.py      # In-memory graph model (nodes, edges, adjacency indices)
│       ├── investigation_validation.py # Complete case integrity & relationship validator
│       ├── logging.py                  # Structured JSON audit logging with sensitive key redaction
│       ├── main.py                     # Legacy/simple CLI entry point for simulation testing
│       ├── permissions.py              # Windows/POSIX privilege inspection helper
│       ├── pipeline.py                 # Procedural live Sysmon collection helper
│       ├── reconstruction.py           # Attack stage reconstruction & sequence builder
│       ├── report.py                   # Formatted plain-text case and audit report generator
│       ├── rules.py                    # Baseline rule detection engine & thresholds
│       ├── simulation.py               # Read-only synthetic dataset loader & validator
│       ├── storage.py                  # SQLite database manager, schemas, models & v1->v6 migrations
│       ├── sysmon_reader.py            # Sysmon XML parser & live Windows wevtutil reader
│       ├── threat_assessment.py        # Threat scoring, severity assignment, and deduplication
│       ├── timeline.py                 # Basic chronological event timeline & process tree builder
│       ├── collectors/                 # Evidence collector subpackage
│       │   ├── __init__.py             # Collectors package initializer
│       │   ├── base.py                 # BaseCollector abstract base class & CollectorState enum
│       │   ├── canary_collector.py     # Decoy canary honeypot file monitor (via watchdog)
│       │   ├── composite.py            # Composite collector managing multiple child collectors
│       │   ├── file.py                 # Batch evidence file collector
│       │   ├── live_file.py            # Real-time directory filesystem watcher (via watchdog)
│       │   ├── live_network.py         # Real-time network connection poller (via psutil)
│       │   └── live_process.py         # Real-time running process poller (via psutil)
│       └── static/                     # Web dashboard frontend static assets
│           ├── app.js                  # Vanilla JavaScript dashboard state & UI controller
│           ├── index.html              # Single-page HTML5 dashboard interface
│           ├── logo.png                # RansomEye brand logo image
│           └── styles.css              # Custom CSS design system (dark theme)
├── tests/                              # Pytest test suite (43 test files, 509 tests)
│   ├── test_advanced_timeline.py
│   ├── test_attack_reconstruction.py
│   ├── test_backup.py
│   ├── test_behavior.py
│   ├── test_canary_collector.py
│   ├── test_case_lifecycle.py
│   ├── test_chain_of_custody.py
│   ├── test_collect_live_cli.py
│   ├── test_collection.py
│   ├── test_commands.py
│   ├── test_composite_collector.py
│   ├── test_correlation.py
│   ├── test_dashboard_server.py
│   ├── test_database.py
│   ├── test_detection_integration.py
│   ├── test_entropy.py
│   ├── test_evidence.py
│   ├── test_export.py
│   ├── test_file_behavior.py
│   ├── test_hardening.py
│   ├── test_integration.py
│   ├── test_integrity.py
│   ├── test_investigation.py
│   ├── test_investigation_graph.py
│   ├── test_investigation_validation.py
│   ├── test_live_file_collector.py
│   ├── test_live_network_collector.py
│   ├── test_live_process_collector.py
│   ├── test_live_streaming_pipeline.py
│   ├── test_logging.py
│   ├── test_migrations.py
│   ├── test_network_evidence.py
│   ├── test_permissions.py
│   ├── test_pipeline.py
│   ├── test_report.py
│   ├── test_restore.py
│   ├── test_schema_integration.py
│   ├── test_simulation.py
│   ├── test_smoke.py
│   ├── test_storage.py
│   ├── test_sysmon_reader.py
│   ├── test_threat_assessment.py
│   └── test_timeline.py
├── .env.example                        # Template for environment variables
├── .gitignore                          # Git ignore rules for virtualenvs, databases, logs, reports
├── AGENTS.md                           # Pointer rule for workspace agent rules
├── pyproject.toml                      # PEP 517/518 build definition & CLI console script entry point
├── README.md                           # High-level overview & quickstart commands
├── README_SETUP.md                     # Detailed Windows setup instructions
├── setup_ransomeye.ps1                 # Minimal PowerShell environment helper ($env:PYTHONPATH)
└── start_ransomeye_setup.bat           # Automated 8-step Windows setup batch script
```

### Purpose of Every Major Directory

1. `src/ransomeye/`: Contains the complete production and library source code for the RansomEye backend, domain logic, detection engine, collectors, storage layer, and HTTP server.
2. `src/ransomeye/collectors/`: Specialized evidence collection plugins. Provides both static batch ingestion and live background polling/monitoring.
3. `src/ransomeye/static/`: Front-end web application assets (HTML, CSS, JS, logo) served directly by `dashboard_server.py`.
4. `tests/`: Comprehensive regression and integration test suite executing via `pytest`.
5. `samples/`: Static evidentiary test data and 22 real-world Sysmon XML event files for validating ingestion and rules.
6. `docs/`: Technical planning documentation, including an architectural comparison with the 12X system and the dashboard UI specification.
7. `.agents/` and `.cursor/`: Development governance rules restricting unsafe actions (e.g. prohibiting malware execution or real file encryption).

---

# PHASE 2 — TECHNOLOGY AUDIT

### Technology Audit Table

| Technology / Library | Declared Version | Where Used | Evidence (Source File) | Status |
|---|---|---|---|---|
| **Python** | `>=3.13` | Entire project | `pyproject.toml:10`, `commands.py`, `storage.py` | **ACTUALLY USED** |
| **SQLite 3** | Built-in (3.x) | Case & evidence database | `src/ransomeye/storage.py:7` (`import sqlite3`) | **ACTUALLY USED** |
| **http.server** | Built-in | REST API & asset server | `src/ransomeye/dashboard_server.py:10` (`ThreadingHTTPServer`) | **ACTUALLY USED** |
| **argparse** | Built-in | CLI subcommand parsing | `src/ransomeye/commands.py:5`, `dashboard_server.py:580` | **ACTUALLY USED** |
| **xml.etree.ElementTree** | Built-in | Sysmon XML parsing | `src/ransomeye/sysmon_reader.py:5` | **ACTUALLY USED** |
| **dataclasses** | Built-in | Domain models | `src/ransomeye/evidence.py`, `correlation.py`, `investigation.py` | **ACTUALLY USED** |
| **hashlib** | Built-in | SHA-256 integrity hashing | `src/ransomeye/integrity.py:5`, `entropy.py`, `export.py` | **ACTUALLY USED** |
| **threading & queue** | Built-in | Background pipeline streaming | `src/ransomeye/collection.py:6-8` | **ACTUALLY USED** |
| **ctypes** | Built-in | Windows admin token check | `src/ransomeye/permissions.py:23` | **ACTUALLY USED** |
| **wevtutil.exe** | Windows OS native | Live Sysmon event reader | `src/ransomeye/sysmon_reader.py:335,362` (`subprocess.run`) | **ACTUALLY USED** (Windows only) |
| **HTML5 / Vanilla JS / CSS3** | Native browser | Analyst dashboard UI | `src/ransomeye/static/index.html`, `styles.css`, `app.js` | **ACTUALLY USED** |
| **Google Fonts (Inter, JetBrains)** | Web CDN | Dashboard styling | `src/ransomeye/static/index.html:12` | **ACTUALLY USED** |
| **pytest** | `9.1.1` (installed) | Test execution | `pyproject.toml:19`, `tests/*` | **TEST ONLY** |
| **psutil** | None specified | Live process & network polling | `src/ransomeye/collectors/live_process.py:43`, `live_network.py:32` | **OPTIONAL RUNTIME DEPENDENCY** (Guarded with fallback; not installed in global environment) |
| **watchdog** | None specified | Live filesystem & canary traps | `src/ransomeye/collectors/live_file.py:34`, `canary_collector.py:25` | **OPTIONAL RUNTIME DEPENDENCY** (Guarded with fallback; not installed in global environment) |
| **setuptools** | `>=68` | Packaging & build system | `pyproject.toml:2` | **BUILD ONLY** |
| **Supabase** | N/A | Discussed in audit docs | `docs/12x_source_to_source_audit.md` | **DOCUMENTATION ONLY** (Explicitly rejected by architecture) |
| **Capstone / Pefile** | N/A | Discussed in audit docs | `docs/12x_source_to_source_audit.md` | **DOCUMENTATION ONLY** (Not implemented in codebase) |
| **FastAPI / Uvicorn** | N/A | Discussed in audit docs | `docs/12x_source_to_source_audit.md` | **DOCUMENTATION ONLY** (Rejected in favor of `http.server`) |

---

# PHASE 3 — APPLICATION ARCHITECTURE

RansomEye is structured around a centralized evidence store and an explainable, deterministic detection pipeline.

### Architectural Flow

```
INPUT
  ├── Sysmon XML Files / Live Windows Event Log (wevtutil)
  ├── Structured Evidence JSON Files
  ├── Canary Decoy File Tampering (watchdog)
  ├── Live Directory File Activity (watchdog)
  └── Live Process / Network Connections (psutil)
        ↓
COLLECTORS & READERS
  ├── SysmonReader (sysmon_reader.py)
  ├── FileCollector (collectors/file.py)
  ├── LiveProcessCollector (collectors/live_process.py)
  ├── LiveNetworkCollector (collectors/live_network.py)
  ├── LiveFileCollector (collectors/live_file.py)
  └── CanaryCollector (collectors/canary_collector.py)
        ↓
NORMALIZATION & VALIDATION
  ├── EvidenceEvent.from_dict() (evidence.py)
  └── normalize_events() (evidence.py) [Validates 22 ALLOWED_EVENT_TYPES & schemas]
        ↓
COLLECTION PIPELINE
  ├── CollectionPipeline (collection.py) [Queue-based batching & background worker]
        ↓
STORAGE
  └── EvidenceStore (storage.py) [SQLite database with foreign keys & append-only triggers]
        ↓
DETECTION & ANALYSIS ENGINES
  ├── BehaviorEngine (behavior.py) [PowerShell, certutil, shadowcopy inhibition]
  ├── FileBehaviorEngine (file_behavior.py) [Mass modify, mass delete, churn, ransom notes]
  ├── CorrelationEngine (correlation.py) [Cluster findings into CorrelatedIncidents]
  ├── ThreatAssessment (threat_assessment.py) [Composite scoring, severity, floor rules]
  ├── AttackReconstruction (reconstruction.py) [Ordered kill-chain attack stages]
  └── AdvancedTimeline (advanced_timeline.py) [Multi-stage timeline sequence]
        ↓
INVESTIGATION GRAPH & VALIDATION
  ├── InvestigationGraph (investigation_graph.py) [In-memory directional multi-relational graph]
  └── InvestigationValidation (investigation_validation.py) [Integrity, traceability & schema checks]
        ↓
OUTPUT & PRESENTATION
  ├── CLI Commands (commands.py)
  ├── Plaintext Forensic Reports (report.py)
  ├── Signed Export Packages (export.py & integrity.py)
  └── Local REST Dashboard (dashboard_server.py + static/app.js)
```

### Component Communication
- **Data Ingestion to Storage**: Collectors yield raw dictionaries. `evidence.normalize_events()` parses ISO timestamps, validates types against `ALLOWED_EVENT_TYPES`, and outputs typed `EvidenceEvent` objects. `EvidenceStore.save_event()` executes parameterized SQL `INSERT INTO events`.
- **Storage to Analysis**: Analysis engines (`analyze_behavior`, `analyze_file_behavior`, `correlate_findings`, `assess_threat`) take event lists directly and compute structured findings without mutating the input events.
- **Analysis to Reporting/UI**: The findings, incidents, and assessments are persisted back into SQLite tables (`findings`, `finding_evidence`, `assessments`). `load_investigation()` reconstructs a consolidated `Investigation` dataclass, which feeds the `InvestigationGraph`, attack reconstruction, timeline generators, and the REST API.

---

# PHASE 4 — EXECUTION FLOW

### Runtime Execution Paths

#### 1. Evidence Ingestion Path (CLI)
```
commands.py:main()
  → commands.py:ingest_evidence()
    → commands.py:parse_evidence_file()
      → (If XML) sysmon_reader.py:iter_sysmon_events()
      → (If JSON) json.loads()
    → evidence.py:normalize_events()
      → evidence.py:EvidenceEvent.from_dict()
    → storage.py:EvidenceStore.save_event()
    → behavior.py:analyze_behavior()
    → file_behavior.py:analyze_file_behavior()
    → storage.py:EvidenceStore.save_finding()
    → storage.py:EvidenceStore.link_finding_evidence()
    → threat_assessment.py:assess_threat()
      → correlation.py:correlate_findings()
    → storage.py:EvidenceStore.save_assessment()
    → Output summary printed to stdout
```

#### 2. Live Streaming Collection Path (CLI / Daemon)
```
commands.py:run_collect_live_command()
  → collectors.composite.py:CompositeCollector.add_collector()
    → collectors.live_file.py:LiveFileCollector
    → collectors.live_process.py:LiveProcessCollector
    → collectors.live_network.py:LiveNetworkCollector
    → collectors.canary_collector.py:CanaryCollector
  → collection.py:CollectionPipeline.start(streaming=True)
    → Background thread: collection.py:CollectionPipeline._streaming_worker()
      → collector.start() [Watches filesystem events and polls OS tables]
      → Events pushed to thread-safe queue.Queue
      → Periodic flush: collection.py:CollectionPipeline.flush_and_analyze()
        → Normalizes events
        → Writes to EvidenceStore
        → Executes behavioral analyzers and persists updated assessments
```

#### 3. Analyst Dashboard Server Path
```
dashboard_server.py:main()
  → dashboard_server.py:run_server()
    → http.server.ThreadingHTTPServer.serve_forever()
      → Client requests GET /
        → DashboardHandler.serve_file('index.html')
      → Client loads static assets (styles.css, app.js, logo.png)
      → app.js:init() → fetch('/api/cases')
        → DashboardHandler.handle_api_get('/api/cases')
          → SQLite SELECT * FROM cases
      → User selects case → fetch('/api/case/<id>')
        → Returns case metadata, latest assessment score, event and incident counts
      → User views Timeline / Reconstruction / Process profile
        → DashboardHandler calls load_investigation()
        → build_investigation_graph()
        → reconstruct_attack()
        → build_advanced_timeline()
        → Serializes to JSON response
```

#### 4. Error Handling Flow
- Database operations wrap inside transactions with explicit rollback or structured exceptions (`sqlite3.Error`).
- Ingestion errors (file not found, corrupted JSON, invalid XML, payload > 50 MB, schema violations) raise `EvidenceValidationError` or `ValueError` and cleanly exit CLI with exit code `1` and descriptive messages on `stderr`.
- Missing optional dependencies (`watchdog`, `psutil`) do not crash the application: collectors transition their state to `CollectorState.ERROR` and record human-readable explanations in `error_message`.
- HTTP server catches `ValueError` (returning HTTP 400), `FileNotFoundError` (HTTP 404), and unexpected exceptions (HTTP 500), logging tracebacks via `logging.exception`.

---

# PHASE 5 — MODULE-BY-MODULE ANALYSIS

### Core Modules

#### 1. `src/ransomeye/storage.py`
- **Classification**: CORE
- **Responsibility**: Local SQLite persistence for cases, events, findings, assessments, lifecycle history, and chain of custody.
- **Classes**: `EvidenceStore`
- **Functions**: `check_database_integrity`, `backup_database`, `restore_database`, `_now`, `_event_dict`
- **Inputs**: Case IDs, event dictionaries/dataclasses, findings, assessment objects, database paths.
- **Outputs**: SQLite rows, dictionaries, backup database files.
- **Dependencies**: `sqlite3`, `pathlib`, `ransomeye.logging.try_write_audit_event`
- **Actively Used**: Yes. Central datastore across all operations.

#### 2. `src/ransomeye/evidence.py`
- **Classification**: CORE
- **Responsibility**: Canonical evidence schema definition, validation, and normalization.
- **Classes**: `EvidenceEvent`, `EvidenceValidationError`
- **Functions**: `normalize_event`, `normalize_events`, `validate_event_dict`, field validators (`_validate_event_type`, `_parse_timestamp`, etc.)
- **Inputs**: Raw event dictionaries.
- **Outputs**: Validated, immutable `EvidenceEvent` dataclass instances.
- **Dependencies**: `dataclasses`, `datetime`, `json`, `typing`
- **Actively Used**: Yes. Enforces the 22 allowed event types.

#### 3. `src/ransomeye/behavior.py`
- **Classification**: CORE
- **Responsibility**: Detection rules for suspicious process commands and ransomware staging.
- **Functions**: `detect_suspicious_powershell`, `detect_suspicious_certutil`, `detect_recovery_inhibition`, `analyze_behavior`
- **Rules & Techniques**:
  - `suspicious_powershell`: Flags `-enc`, `-encodedcommand`, `invoke-expression`, `iex `, `downloadstring`, `frombase64string` (MITRE T1059.001, Score: 10, Conf: 0.80).
  - `suspicious_certutil`: Flags `-urlcache`, `-split`, `-f`, `-decode`, `-decodehex`, `-verifyctl` (MITRE T1105, Score: 12, Conf: 0.80).
  - `recovery_inhibition`: Flags `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `recoveryenabled no` (MITRE T1490, Score: 15, Conf: 0.85).
- **Actively Used**: Yes. Invoked in every ingestion and live pipeline flush.

#### 4. `src/ransomeye/file_behavior.py`
- **Classification**: CORE
- **Responsibility**: Sliding-window algorithms for file modification bursts, mass deletion, churn, ransom notes, and extension tampering.
- **Functions**: `detect_mass_modification`, `detect_mass_creation`, `detect_mass_deletion`, `detect_file_churn`, `detect_ransom_note`, `detect_extension_changes`, `analyze_file_behavior`
- **Rules & Heuristics**:
  - `mass_file_modification`: >= 50 file modifications within 30s per process (MITRE T1486, Score: 20, Conf: 0.80).
  - `mass_file_creation`: >= 100 file creations within 30s per process (MITRE T1486, Score: 0 informational, Conf: 0.60).
  - `mass_file_deletion`: >= 50 file deletions within 30s per process (MITRE T1485, Score: 0 informational, Conf: 0.60).
  - `file_churn`: >= 10 creates AND >= 10 deletes within 10s per process (MITRE T1486, Score: 15, Conf: 0.50).
  - `ransom_note`: Matches keywords `DECRYPT`, `RECOVER`, `RANSOM`, `RESTORE_FILES`, `HOW_TO_DECRYPT`, `README_DECRYPT` in created filenames (MITRE T1486, Score: 10, Conf: 0.90).
  - `extension_change`: File rename changing the file extension (MITRE T1486, Score: 15, Conf: 0.60).
- **Actively Used**: Yes. Core ransomware file analysis engine.

#### 5. `src/ransomeye/threat_assessment.py`
- **Classification**: CORE
- **Responsibility**: Aggregates findings, deduplicates overlapping detections between engines, correlates findings into incidents, and calculates composite scores.
- **Functions**: `assess_threat`, `_severity_from_score`, `_combine_confidence`, `_ensure_finding_ids`
- **Thresholds**:
  - Score 0–24: `SAFE`
  - Score 25–49: `LOW`
  - Score 50–69: `MEDIUM`
  - Score 70–84: `HIGH`
  - Score 85–100: `CRITICAL`
  - Correlation bonus: +10 points if baseline suspicious file activity correlates with process behavior.
  - Behavior floor: 25 for single behavior finding, 50 for multi-behavior findings.
- **Actively Used**: Yes. Generates the final assessment metrics.

#### 6. `src/ransomeye/correlation.py`
- **Classification**: CORE
- **Responsibility**: Correlates disparate findings into coherent security incidents based on process tree lineage and sliding temporal windows (60s).
- **Classes**: `CorrelatedIncident`
- **Functions**: `correlate_findings`, `correlate_events`, `generate_incident_id`, `_compute_time_delta`
- **Outputs**: Deterministic incident objects with IDs formatted as `INC-<sha256-hash>`.
- **Actively Used**: Yes.

#### 7. `src/ransomeye/commands.py`
- **Classification**: CORE
- **Responsibility**: Command-line interface definition and orchestration. Implements 12 root command families and subcommands.
- **Functions**: `main`, `ingest_evidence`, `parse_evidence_file`, `show_investigation`, `show_investigation_graph`, `run_collect_file_command`, `run_collect_live_command`, etc.
- **Actively Used**: Yes. Main project entry point via `ransomeye` executable or `python -m ransomeye.commands`.

#### 8. `src/ransomeye/dashboard_server.py`
- **Classification**: CORE
- **Responsibility**: HTTP service delivering REST endpoints and static assets for the analyst web interface.
- **Classes**: `DashboardHandler`
- **Functions**: `run_server`, `_get_store`, `_validate_safe_id`, `json_response`, `error_response`
- **Actively Used**: Yes. Started via `python -m ransomeye.dashboard_server`.

#### 9. `src/ransomeye/sysmon_reader.py`
- **Classification**: CORE
- **Responsibility**: Sysmon XML parser supporting 16 Sysmon Event IDs (1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 22, 23, 25) and live reader via Windows `wevtutil.exe`.
- **Classes**: `SysmonReaderError`
- **Functions**: `parse_sysmon_event`, `iter_sysmon_events`, `read_sysmon_events`, `sysmon_is_available`, `read_process_creation_events`
- **Actively Used**: Yes.

#### 10. `src/ransomeye/investigation.py`, `investigation_graph.py`, `investigation_validation.py`
- **Classification**: CORE
- **Responsibility**: Multi-relational graph representation of cases (processes, files, network, findings, evidence), attack reconstruction, and structural consistency validation.
- **Classes**: `Investigation`, `GraphNode`, `GraphEdge`, `InvestigationGraph`, `ValidationIssue`, `InvestigationValidationResult`
- **Actively Used**: Yes. Used in CLI investigation subcommands and dashboard visualization.

#### 11. `src/ransomeye/collection.py` & `collectors/*`
- **Classification**: CORE
- **Responsibility**: Streaming and batch collection pipeline with thread-safe queue and pluggable collectors (`FileCollector`, `LiveFileCollector`, `LiveProcessCollector`, `LiveNetworkCollector`, `CanaryCollector`, `CompositeCollector`).
- **Actively Used**: Yes.

### Supporting Modules
- `src/ransomeye/entropy.py`: Calculates Shannon entropy (0.0 to 8.0) and chunked distributions to identify packed/encrypted binary segments.
- `src/ransomeye/export.py`: Packages case evidence, database dumps, and reports into a verifiable directory with `.lock` file concurrency controls.
- `src/ransomeye/integrity.py`: SHA-256 chunked file hasher and manifest verifier.
- `src/ransomeye/logging.py`: Structured JSON-lines audit logger with automated redaction of sensitive dictionary keys.
- `src/ransomeye/permissions.py`: Windows `ctypes` admin token inspection.
- `src/ransomeye/report.py`: Plain-text ASCII forensic case report generator.
- `src/ransomeye/timeline.py` & `advanced_timeline.py`: Chronological timeline and process-tree formatters.
- `src/ransomeye/simulation.py`: Read-only loader and schema verifier for synthetic datasets.

### Legacy / Superseded Modules
- `src/ransomeye/main.py`: **LEGACY**. Initial prototype CLI executing `rules.analyze_events()`. Superseded by `commands.py`.
- `src/ransomeye/rules.py`: **LEGACY / SUPPORTING**. Original baseline rules; partially retained for threshold constants and fallback scoring in `threat_assessment.py`.
- `src/ransomeye/pipeline.py`: **LEGACY**. Procedural `collect_and_store()` function superseded by `CollectionPipeline` in `collection.py`.

---

# PHASE 6 — DATA FLOW

```
EVIDENCE SOURCE
  ├── File Ingestion (JSON / XML)
  └── Live Collectors (Watchdog / Psutil / Windows wevtutil)
        ↓
  [Input Format: Raw JSON object or Sysmon XML string]
        ↓
PARSING & EXTRACTION
  sysmon_reader.py:iter_sysmon_events() OR json.loads()
        ↓
SCHEMA NORMALIZATION & VALIDATION
  evidence.py:normalize_events()
  - Validates event_type in ALLOWED_EVENT_TYPES (22 allowed types)
  - Coerces timestamps to ISO-8601 UTC
  - Converts PIDs to integers
  - Validates network and metadata structures
        ↓
  [Internal Representation: EvidenceEvent dataclass]
        ↓
STORAGE INSERTION
  storage.py:EvidenceStore.save_event()
  - Executes SQL INSERT INTO events
  - Maintains relational integrity with cases table
        ↓
DETECTION ENGINES
  ├── behavior.py: Process inspection (PowerShell, certutil, shadow copies)
  └── file_behavior.py: Sliding time-window analysis on file events
        ↓
  [Internal Representation: List of finding dictionaries]
        ↓
FINDINGS & EVIDENCE LINKING
  storage.py:EvidenceStore.save_finding()
  storage.py:EvidenceStore.link_finding_evidence()
  - Populates findings table
  - Populates finding_evidence join table (finding_id <-> event_id)
        ↓
INCIDENT CORRELATION & THREAT ASSESSMENT
  correlation.py:correlate_findings()
  threat_assessment.py:assess_threat()
  - Computes deterministic incident hashes (INC-<hash>)
  - Applies scoring weights, deduplication, and behavior floors
  - Saves to assessments table
        ↓
ANALYSIS AGGREGATION
  investigation.py:load_investigation()
  investigation_graph.py:build_investigation_graph()
  reconstruction.py:reconstruct_attack()
  advanced_timeline.py:build_advanced_timeline()
        ↓
USER INTERFACE / EXPORT
  ├── CLI stdout tables & ASCII trees (commands.py)
  ├── Plaintext report files (report.py)
  ├── Verifiable SHA-256 export packages (export.py)
  └── REST API JSON payloads to Web Dashboard (dashboard_server.py -> app.js)
```

### Database Schema Details (SQLite Schema Version 6)

```sql
cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    host TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    severity TEXT NOT NULL DEFAULT 'SAFE',
    created_at TEXT NOT NULL
);

events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    process_name TEXT,
    pid TEXT,
    parent_pid TEXT,
    process_guid TEXT,
    parent_process_guid TEXT,
    parent_image TEXT,
    parent_command_line TEXT,
    command_line TEXT,
    file_path TEXT,
    file_count INTEGER,
    network_json TEXT,
    confidence REAL,
    metadata_json TEXT
);

findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    finding_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence REAL,
    technique TEXT,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

finding_evidence (
    finding_id INTEGER NOT NULL REFERENCES findings(finding_id),
    event_id TEXT NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (finding_id, event_id)
);

assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    techniques_json TEXT NOT NULL,
    correlations_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

case_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    note TEXT,
    changed_at TEXT NOT NULL
);

case_custody (
    custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    artifact_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('created', 'verified', 'exported', 'reviewed')),
    analyst TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    verification_result INTEGER
);
```

**Triggers Enforcing Immutability:**
- `prevent_custody_update`: `BEFORE UPDATE ON case_custody BEGIN SELECT RAISE(ABORT, 'case custody records are append-only'); END;`
- `prevent_custody_delete`: `BEFORE DELETE ON case_custody BEGIN SELECT RAISE(ABORT, 'case custody records are append-only'); END;`

---

# PHASE 7 — API AUDIT

The application exposes two interfaces: a Command-Line Interface (CLI) and an HTTP REST API server.

### 1. HTTP REST Endpoints (`dashboard_server.py`)

| Method | Endpoint | Handler | Input Parameters | Output | Purpose | Auth | Status |
|---|---|---|---|---|---|---|---|
| **GET** | `/` | `DashboardHandler.serve_file` | None | `index.html` (text/html) | Serves single-page dashboard | None | **IMPLEMENTED** |
| **GET** | `/<asset>.css/js/png` | `DashboardHandler.serve_file` | Static asset name | Asset byte stream | Serves styles, scripts, logo | None | **IMPLEMENTED** |
| **GET** | `/api/cases` | `DashboardHandler.handle_api_get` | None | `{"cases": [...]}` | List all stored cases | None | **IMPLEMENTED** |
| **GET** | `/api/case/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"case": {...}, "assessment": {...}, "stats": {...}}` | Case overview & assessment | None | **IMPLEMENTED** |
| **GET** | `/api/incidents/<case_id>`| `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"incidents": [...]}` | Correlated security incidents | None | **IMPLEMENTED** |
| **GET** | `/api/findings/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"findings": [...]}` | Case findings list | None | **IMPLEMENTED** |
| **GET** | `/api/recent_activity/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"activity": [...]}` | 10 most recent case events | None | **IMPLEMENTED** |
| **GET** | `/api/search/<case_id>` | `DashboardHandler.handle_api_get` | `q` query param | `{"results": [...]}` | Search events by text/indicator | None | **IMPLEMENTED** |
| **GET** | `/api/inspect/<case_id>` | `DashboardHandler.handle_api_get` | `event_id` query param | `{"event": {...}, "trace": {...}}` | Inspect event & graph trace | None | **IMPLEMENTED** |
| **GET** | `/api/process/<case_id>/<query>` | `DashboardHandler.handle_api_get` | `case_id`, `pid` or `guid` | `{"process": {...}, "parent": ..., "children": ...}` | Deep process tree profile | None | **IMPLEMENTED** |
| **GET** | `/api/timeline/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"timeline": [...]}` | Chronological timeline entries | None | **IMPLEMENTED** |
| **GET** | `/api/reconstruction/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"stages": [...], "status": "OK"}` | Attack kill-chain stages | None | **IMPLEMENTED** |
| **GET** | `/api/validation/<case_id>` | `DashboardHandler.handle_api_get` | `case_id` in URL path | `{"passed": bool, "issues": [...]}` | Case integrity audit results | None | **IMPLEMENTED** |
| **GET** | `/api/collect/status` | `DashboardHandler.handle_api_get` | `case_id` query param | `{"status": {...}, "rendered": "..."}` | Pipeline collector metrics | None | **IMPLEMENTED** |
| **POST** | `/api/report/<case_id>` | `DashboardHandler.handle_api_post` | `case_id` in URL path | `{"message": "...", "path": "...", "content": "..."}` | Generates text case report file | None | **IMPLEMENTED** |
| **POST** | `/api/collect` | `DashboardHandler.handle_api_post` | `{"case_id", "file_path", "format_type"}` (JSON) | `{"message": "...", "summary": {...}}` | Triggers file ingestion | None | **IMPLEMENTED** |

### 2. CLI Commands (`commands.py`)

| Command | Subcommands | Purpose | Status |
|---|---|---|---|
| `ransomeye ingest` | N/A | Ingests JSON or Sysmon XML file into case | **IMPLEMENTED** |
| `ransomeye collect` | `file`, `status`, `live` | Runs continuous pipeline or batch collection | **IMPLEMENTED** |
| `ransomeye case` | `create`, `list`, `show`, `status`, `update`, `history` | Manages case lifecycle and state | **IMPLEMENTED** |
| `ransomeye custody` | `record`, `list` | Manages chain-of-custody log entries | **IMPLEMENTED** |
| `ransomeye integrity` | `hash`, `verify` | Creates and verifies SHA-256 manifests | **IMPLEMENTED** |
| `ransomeye export` | `lock-info`, `lock-status`, `unlock`, default export | Exports case packages with concurrency locks | **IMPLEMENTED** |
| `ransomeye database`| `check`, `backup`, `restore` | SQLite integrity check, online backup & restore | **IMPLEMENTED** |
| `ransomeye investigation` | `show`, `graph`, `reconstruct`, `timeline`, `incident`, `process`, `validate` | Graph modeling, reconstruction & audit | **IMPLEMENTED** |
| `ransomeye evidence`| `search`, `inspect`, `trace` | Queries events and graphs supporting findings | **IMPLEMENTED** |
| `ransomeye timeline`| Default (with `--advanced`) | Outputs chronological case events | **IMPLEMENTED** |
| `ransomeye tree` | N/A | Prints ASCII process tree | **IMPLEMENTED** |
| `ransomeye report` | N/A | Generates case summary report | **IMPLEMENTED** |

---

# PHASE 8 — FRONTEND / UI AUDIT

The frontend is a lightweight Single-Page Application (SPA) located at `src/ransomeye/static/`.

### Architecture & Tech Stack
- **Framework**: None (Pure Vanilla HTML5 / Vanilla ES6+ JavaScript / Vanilla CSS3).
- **Styling**: Modern dark cybersecurity aesthetic using CSS custom properties (`--re-bg-base: #050914`, `--re-accent: #06b6d4`, red `#ef4444`, amber `#f59e0b`, green `#10b981`).
- **Typography**: Inter (UI text) and JetBrains Mono (code/IDs/hashes) loaded via Google Fonts CDN.
- **State Management**: Centralized in-memory JavaScript object `state` in `app.js`.

### User Interface Views

1. **Overview View**:
   - Header with active case ID, status badge, severity badge, host name, and manual "Refresh" / "Generate Report" buttons.
   - Summary stat cards: Threat Score, Severity, Confidence, Incident Count, Finding Count, Evidence Event Count.
   - Panels displaying Recent Findings and Recent System Activity with drill-down links.
2. **Monitor View**:
   - Live pipeline status dashboard showing collector state, collection throughput, error logs, and an on-demand batch ingestion form.
3. **Threat Assessment View**:
   - Detailed breakdown of composite score, MITRE ATT&CK techniques, and triggered detection reasons with score increments.
4. **Incidents View**:
   - Table of correlated multi-event incidents displaying start/end times, durations, process keys, and associated findings.
5. **Findings View**:
   - Complete list of rule triggers showing MITRE ATT&CK technique IDs, confidence scores, and reasons. Clicking a finding opens the Detail Drawer.
6. **Evidence View**:
   - Searchable evidence table with real-time text query filtering, event type badges, timestamps, process names, and file paths.
7. **Timeline View**:
   - Chronological analytical event log displaying stage types, timestamps, processes, and event IDs.
8. **Reconstruction View**:
   - Step-by-step visual attack sequence showing kill-chain phases with flow arrows (`↓`).
9. **Reports View**:
   - Generates and displays the plain-text forensic report with an on-screen preview and one-click copy to clipboard.
10. **Detail Drawer (Right-side slideout)**:
    - Provides drill-down context for individual events (showing graph-linked findings, incidents, and processes) and individual processes (showing command line, parent process, child processes, touched files, and network connections).

---

# PHASE 9 — CORE LOGIC / BUSINESS LOGIC

### 1. Process Behavioral Rules (`behavior.py`)
- **PowerShell Execution** (`detect_suspicious_powershell`): Scans `command_line` of `powershell.exe` for `-enc`, `-encodedcommand`, `invoke-expression`, `iex `, `downloadstring`, `frombase64string`. Triggers finding with Score: 10, Confidence: 0.80, Technique: `T1059.001`.
- **CertUtil Abuse** (`detect_suspicious_certutil`): Scans `certutil.exe` for `-urlcache`, `-split`, `-f`, `-decode`, `-decodehex`, `-verifyctl`. Triggers finding with Score: 12, Confidence: 0.80, Technique: `T1105`.
- **Recovery Inhibition** (`detect_recovery_inhibition`): Scans for `vssadmin delete shadows`, `wmic shadowcopy delete`, `delete shadows`, `wbadmin delete catalog`, `recoveryenabled no`. Triggers finding with Score: 15, Confidence: 0.85, Technique: `T1490`.

### 2. File Behavioral Engine (`file_behavior.py`)
- **Mass Modification Window** (`detect_mass_modification`): Evaluates sliding time window of 30 seconds per process. If >= 50 files are modified within 30s, triggers finding with Score: 20, Confidence: 0.80, Technique: `T1486`.
- **Mass Creation & Deletion** (`detect_mass_creation`, `detect_mass_deletion`): Detects >= 100 creations or >= 50 deletions in 30s. Flags informational findings (Score: 0, Confidence: 0.60) to avoid false-positive inflation from installer unpacking while logging activity for correlation.
- **File Churn** (`detect_file_churn`): Detects simultaneous rapid creation and deletion (>= 10 creates AND >= 10 deletes within 10s). Triggers finding with Score: 15, Confidence: 0.50, Technique: `T1486`.
- **Ransom Note Detection** (`detect_ransom_note`): Evaluates created file paths against keywords (`DECRYPT`, `RECOVER`, `RANSOM`, `RESTORE_FILES`, `HOW_TO_DECRYPT`, `README_DECRYPT`). Triggers finding with Score: 10, Confidence: 0.90, Technique: `T1486`.
- **Extension Tampering** (`detect_extension_changes`): Evaluates rename events with `metadata.old_path`. If extension changes, triggers finding with Score: 15, Confidence: 0.60, Technique: `T1486`.

### 3. Unified Threat Assessment & Scoring (`threat_assessment.py`)
- **Deduplication**: If `file_behavior.py` detects mass modification or ransom notes, corresponding legacy contributions from `rules.py` are subtracted to prevent double-counting.
- **Correlation Bonus**: An additional +10 points is added if suspicious file activity is accompanied by suspicious process behaviors.
- **Behavior Floors**: Enforces minimum scores for confirmed malicious process activity (floor of 25 for one finding, 50 for multiple findings).
- **Severity Classification**:
  - `0 - 24`: `SAFE`
  - `25 - 49`: `LOW`
  - `50 - 69`: `MEDIUM`
  - `70 - 84`: `HIGH`
  - `85 - 100`: `CRITICAL`

### 4. Correlation & Attack Reconstruction (`correlation.py`, `reconstruction.py`)
- Groups findings into `CorrelatedIncident` entities when they share a process GUID, PID, parent-child relationship, or occur within a 60-second temporal window.
- Computes deterministic, reproducible IDs: `F-<sha256[:16]>` for findings and `INC-<sha256[:16]>` for incidents.
- Reconstructs kill chains into ordered stages: `PROCESS_EXECUTION` → `NETWORK_ACTIVITY` → `FILE_ACTIVITY` → `MASS_FILE_MODIFICATION` → `RANSOM_NOTE` → `SUSPICIOUS_COMMAND` → `FINDING` → `CORRELATION` → `ASSESSMENT`.

---

# PHASE 10 — SECURITY AUDIT

### Source Code Security Findings

| Severity | Category | Description | Evidence |
|---|---|---|---|
| **MEDIUM** | Network Exposure / Insecure Default | The dashboard HTTP server binds to all network interfaces (`""` / `0.0.0.0`) by default instead of `127.0.0.1`. | `src/ransomeye/dashboard_server.py:570` (`server_address = ("", port)`) |
| **MEDIUM** | Authentication / Authorization | The REST API and web dashboard have zero authentication or authorization controls. Any user or host reaching port 8080 can read case evidence, findings, and trigger reports. | `src/ransomeye/dashboard_server.py:61-90` |
| **LOW** | Permissive CORS | CORS headers allow all origins (`Access-Control-Allow-Origin: *`) across all GET and POST requests. | `src/ransomeye/dashboard_server.py:49,67` |
| **LOW** | Subprocess Execution | `sysmon_reader.py` executes system `wevtutil.exe` via `subprocess.run()`. While arguments are safely passed as a list, it relies on system PATH resolution for `wevtutil.exe`. | `src/ransomeye/sysmon_reader.py:335,362` |
| **INFO** | Path Traversal Protection | Path traversal is actively mitigated: `_validate_safe_id` checks IDs against `^[A-Za-z0-9_\-]+$`, static file serving verifies `static_dir in filepath.parents`, and report generation verifies `reports_dir in out_path.parents`. | `src/ransomeye/dashboard_server.py:29,112,504` |
| **INFO** | SQL Injection Protection | All SQL queries in `storage.py` and `dashboard_server.py` use parameterized queries with `?` placeholders. No dynamic string concatenation was found in SQL statements. | `src/ransomeye/storage.py`, `dashboard_server.py` |
| **INFO** | Hardcoded Secrets | Zero hardcoded passwords, tokens, API keys, or private keys were found. `logging.py` includes active redaction for sensitive keys. | `src/ransomeye/logging.py:11-20` |

---

# PHASE 11 — TESTING AUDIT

### Test Suite Execution & Verification

- **Framework**: `pytest 9.1.1`
- **Total Test Files**: 43 files in `tests/`
- **Total Discovered Tests**: 509 tests
- **Execution Command**: `python -m pytest -q`

```
Test Execution Results:
Total Discovered: 509
Passed:           483
Failed:           26
Skipped:          0
```

### Analysis of Test Failures

All 26 test failures occur exclusively within CLI subprocess integration tests:
- `tests/test_backup.py` (4 tests)
- `tests/test_database.py` (3 tests)
- `tests/test_hardening.py` (15 tests)
- `tests/test_restore.py` (4 tests)

**Root Cause**:
In `tests/test_restore.py` (and similar files), the test helper defines:
```python
def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ransomeye.commands"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
```
When `_run_cli` executes `sys.executable -m ransomeye.commands` with `cwd=tmp_path`, Python searches for the module `ransomeye` in `tmp_path`. Because `ransomeye` was not installed in editable mode (`pip install -e .`) into the active Python environment, and `_run_cli` does not pass `PYTHONPATH` in its `env` parameter, Python raises:
`ModuleNotFoundError: No module named 'ransomeye'`.

All 483 in-process unit tests (testing algorithms, schemas, graph logic, timeline, entropy, sysmon parsing, correlation, and storage) pass with zero failures.

---

# PHASE 12 — CONFIGURATION & ENVIRONMENT

### Environment Variables

| Variable | Default | Purpose | Status |
|---|---|---|---|
| `RANSOMEYE_DATABASE` | `data/ransomeye.db` | Primary SQLite database path | **OPTIONAL** |
| `RANSOMEYE_RULES_DIR` | `rules` | Custom detection rules directory | **REFERENCED IN .env.example ONLY** |
| `RANSOMEYE_REPORT_DIR` | `reports` | Target directory for generated reports | **OPTIONAL** |
| `RANSOMEYE_ANALYST` | Empty string | Default analyst identity for custody logging | **OPTIONAL** |
| `RANSOMEYE_LOG_PATH` | `logs/audit.jsonl` | Filepath for JSON audit logging | **OPTIONAL** |
| `RANSOMEYE_DB` | None | Alternative database path for dashboard server | **OPTIONAL** |

### Runtime & System Requirements
- **Python Version**: Python 3.13 or newer (`pyproject.toml:10`).
- **Operating System**: Windows recommended (required for live Sysmon log reading via `wevtutil.exe` and `ctypes` admin checks). Core analysis and database functions are cross-platform compatible.
- **Default Ports**: Port `8080` for dashboard HTTP server.
- **Default Paths**:
  - Database: `data/ransomeye.db`
  - Reports: `reports/`
  - Logs: `logs/audit.jsonl`

---

# PHASE 13 — EXTERNAL DEPENDENCIES

| Dependency | Purpose | Runtime / Dev / Test | Evidence | Required? |
|---|---|---|---|---|
| **Python Standard Library** | All core logic, storage, server, parsing | Runtime | `src/ransomeye/*.py` | **REQUIRED** |
| **pytest** | Test suite runner | Test | `pyproject.toml:19` | **TEST ONLY** |
| **setuptools** | Package build backend | Build | `pyproject.toml:1-3` | **BUILD ONLY** |
| **psutil** | Live process and network connection monitoring | Runtime | `collectors/live_process.py:43`, `collectors/live_network.py:32` | **OPTIONAL** (Graceful fallback if missing) |
| **watchdog** | Live filesystem watcher and canary honeypot monitor | Runtime | `collectors/live_file.py:34`, `collectors/canary_collector.py:25` | **OPTIONAL** (Graceful fallback if missing) |
| **Google Fonts CDN** | Web fonts (Inter, JetBrains Mono) | UI Runtime | `static/index.html:12` | **OPTIONAL** (Falls back to system sans-serif/monospace) |

There are **zero** external database services (no PostgreSQL, MySQL, Redis, or Supabase) and **zero** external cloud/SaaS APIs. The application is completely local-first.

---

# PHASE 14 — GIT / REPOSITORY HYGIENE

### Analysis of `.gitignore` and Tracked Files
- **Virtual Environments**: `.gitignore` correctly ignores `.venv/`, `venv/`, and `.release-venv/`. No virtual environments are tracked.
- **Cache Files**: `__pycache__/`, `*.pyc`, and `.pytest_cache/` are ignored.
- **Databases**: `*.db`, `*.sqlite`, `data/`, and memory dumps (`*.raw`, `*.dmp`) are properly ignored. No live databases are committed.
- **Reports and Logs**: `logs/`, `reports/`, and `exports/` are ignored.
- **Sensitive Credentials**: `.env` and `.env.*` are ignored while `.env.example` is retained.
- **Repository Cleanliness**: The repository is clean of binary artifacts, database dumps, and temporary test outputs.

---

# PHASE 15 — DOCUMENTATION ACCURACY

### Discrepancy List

1. **`README.md` Understates Project Capabilities**:
   - `README.md` describes RansomEye as a simple CLI tool for case lifecycle management, evidence export, and integrity verification. It does not mention the threat assessment engine, the 16 Sysmon event parsers, the correlation engine, the attack reconstruction module, or the built-in web dashboard.
2. **`pyproject.toml` Missing Runtime Dependencies**:
   - `pyproject.toml` does not declare `dependencies = [...]` under `[project]`. As a result, running `pip install -e .` does not install `psutil` or `watchdog`, leaving live process and canary collectors in an uninstalled state unless installed manually.
3. **`docs/12x_source_to_source_audit.md` References Unimplemented Features**:
   - The document discusses memory forensics, PE carving, and Capstone disassembly as potential additions. These features were never implemented in RansomEye; only the canary monitoring concept was ported.
4. **`.env.example` References Unused Variable**:
   - `RANSOMEYE_RULES_DIR=rules` is defined in `.env.example`, but the codebase does not load detection rules dynamically from a external rules directory. Rules are hardcoded in `behavior.py` and `file_behavior.py`.

---

# PHASE 16 — PROJECT MATURITY

| Area | Rating | Evaluation Details |
|---|---|---|
| **Architecture Quality** | **COMPLETE** | Clean separation of concerns between storage, validation, detection, correlation, graph modeling, and presentation. |
| **Code Organization** | **COMPLETE** | Well-structured package layout, modular collectors, consistent type hints, and immutable dataclasses. |
| **Core Detection Engine** | **FUNCTIONAL** | Robust behavioral heuristics for ransomware staging, shadow copy deletion, churn, and mass encryption. |
| **Evidence Storage** | **COMPLETE** | Production-grade SQLite implementation with foreign keys, append-only custody triggers, and v1-to-v6 migration logic. |
| **Web Dashboard** | **FUNCTIONAL** | Zero-dependency HTTP server delivering an intuitive, responsive, and dark-themed forensic UI with detailed drawer inspection. |
| **Testing** | **FUNCTIONAL** | 509 tests covering edge cases, graphs, timelines, and detectors. CLI subprocess tests require environment installation. |
| **Deployment Readiness** | **PARTIAL** | Fully operational for local analyst workstations. Lacks daemon service wrappers, multi-user authentication, and TLS encryption. |
| **Documentation** | **PARTIAL** | Setup documentation (`README_SETUP.md` and batch scripts) is thorough, but user-facing architecture documentation in `README.md` is minimal. |

---

# PHASE 17 — IMPORTANT FINDINGS

### Strengths
- **Deterministic & Explainable**: Detection scores, finding IDs (`F-<hash>`), incident IDs (`INC-<hash>`), and attack sequences are fully reproducible and explainable.
- **Zero Heavy Dependencies**: Built primarily on the Python standard library and SQLite, ensuring rapid startup, high performance, and minimal supply-chain risk.
- **Forensic Integrity**: Enforces strict chain-of-custody tracking with SQLite database triggers that disallow updating or deleting custody rows.
- **Deep Windows Sysmon Integration**: Natively parses 16 Sysmon XML event types and reads live event streams via Windows `wevtutil.exe`.
- **Graph & Validation Engine**: Rich in-memory multi-relational graph (`InvestigationGraph`) that models processes, files, network connections, findings, and evidence, validated by `investigation_validation.py`.

### Weaknesses
- **Unauthenticated HTTP Dashboard**: Dashboard server has no login mechanism or token verification, relying entirely on local host isolation.
- **Dashboard Interface Binding**: Binds to `0.0.0.0` by default instead of `127.0.0.1`.
- **CLI Subprocess Test Fragility**: Test helpers in `tests/test_restore.py` invoke `sys.executable -m ransomeye.commands` without propagating `PYTHONPATH`, failing when the package is not installed via `pip install -e .`.
- **Packaging Specification**: `pyproject.toml` lacks explicit optional dependency declarations for `psutil` and `watchdog`.

### Risks
- **Evasion of Heuristic Thresholds**: Sophisticated ransomware operating below the 50-file/30s threshold or sleeping between file encryptions would not trigger `detect_mass_modification`.
- **Lack of Kernel-Level Enforcement**: RansomEye is a user-space DFIR analysis tool; it does not block encryption in the kernel (e.g., via a mini-filter driver).

### Missing Features
- Multi-user authentication and role-based access control (RBAC) for the dashboard.
- TLS/HTTPS support for the dashboard HTTP server.
- Dynamic rule loading from external YAML/Sigma/YARA files (rules are currently static Python code).

### Technical Debt
- Coexistence of legacy detection modules (`rules.py`, `main.py`, `pipeline.py`) alongside modern engines (`behavior.py`, `file_behavior.py`, `collection.py`).

### Dead / Unused Code
- `src/ransomeye/main.py`: Prototype entry point; completely unused by the CLI console script or dashboard.
- `docs/12x_source_to_source_audit.md`: Historical audit artifact discussing external submodules (`MemRev-Engine`, `NEXUS-SCAN`) not present in this repository.

### Contradictions
- `.env.example` advertises `RANSOMEYE_RULES_DIR=rules`, but no external rule loading logic exists in the codebase.

---

# PHASE 18 — FINAL PROJECT SUMMARY

- **PROJECT**: RansomEye
- **PURPOSE**: Defensive DFIR platform for ransomware detection, Sysmon analysis, case lifecycle tracking, forensic reporting, and evidence management.
- **CURRENT STATE**: Fully functional defensive DFIR application with active CLI and local web dashboard.
- **PRIMARY TECHNOLOGIES**: Python 3.13, SQLite 3, `http.server`, HTML5, Vanilla JavaScript, Vanilla CSS, Windows `wevtutil`. Optional runtime: `psutil`, `watchdog`. Test: `pytest`.
- **ARCHITECTURE**: Ingestion/Collectors → Normalization (`EvidenceEvent`) → SQLite Store (`EvidenceStore`) → Behavioral & Correlation Engines → Multi-relational In-Memory Graph (`InvestigationGraph`) → CLI / REST API / Web Dashboard.
- **MAIN DATA FLOW**: Endpoint Events → Schema Validation → SQLite Storage → Detection Findings → Incident Correlation → Attack Reconstruction & Advanced Timeline → Analyst Console / Forensic Reports.
- **KEY FEATURES ACTUALLY IMPLEMENTED**:
  - 16 Sysmon event XML parsers and live `wevtutil` reading.
  - 6 filesystem behavioral detection rules (mass modification, creation, deletion, churn, ransom notes, extension renames).
  - 3 process behavioral detection rules (PowerShell, CertUtil, Shadow Copy / Catalog deletion).
  - Multi-event correlation engine generating deterministic `INC-<hash>` incidents.
  - Directional in-memory investigation graph and automated attack reconstruction sequence.
  - Append-only chain-of-custody table with database-level abort triggers.
  - Database online backup, integrity check, and restore verification.
  - Dark-themed SPA analyst dashboard with real-time process profiles and evidence drill-down drawer.
- **TEST STATUS**: 509 discovered tests; 483 passed, 26 failed due to `PYTHONPATH` resolution in subprocess test helpers.
- **SECURITY STATUS**: Zero hardcoded secrets; parameterized SQL queries; path traversal protections verified; lacks authentication on dashboard server; binds to `0.0.0.0` by default.
- **EXTERNAL DEPENDENCIES**: Completely local-first with zero cloud backends. Standard library core; optional `watchdog` and `psutil`.
- **MAJOR LIMITATIONS**: User-space detection only (no kernel blocking); sliding window thresholds can be evaded by slow-encryption malware; hardcoded rules.
- **MAJOR RISKS**: Dashboard network exposure on unsegmented networks; lack of TLS.
- **NEXT PRIORITIES**:
  1. Add `dependencies` and optional extras (`[project.optional-dependencies]`) to `pyproject.toml`.
  2. Bind dashboard server to `127.0.0.1` by default.
  3. Ensure test subprocess helpers inherit `PYTHONPATH` or `sys.path`.
  4. Deprecate and remove legacy `main.py` and `pipeline.py`.

---

# AUDIT CONFIDENCE

### HIGH
- Claims directly verified from implementation:
  - Repository structure, file inventory, line counts, and AST definitions.
  - SQLite schema (Version 6), tables, indexes, and custody trigger definitions in `storage.py`.
  - Evidence schema allowed types and field requirements in `evidence.py`.
  - Detection rules, MITRE ATT&CK technique IDs, scores, and sliding window thresholds in `behavior.py` and `file_behavior.py`.
  - Correlation logic, incident ID hashing, and attack stage mapping in `correlation.py` and `reconstruction.py`.
  - Dashboard server endpoints, request routing, and frontend static assets in `dashboard_server.py`, `app.js`, and `index.html`.
  - Sysmon Event ID parsing logic and wevtutil command strings in `sysmon_reader.py`.
  - Test suite count and test execution pass/fail figures verified via `pytest`.

### MEDIUM
- Claims inferred from multiple code paths:
  - Impact of missing `psutil` and `watchdog` on production systems (code contains fallback exception handling, but live OS behavior depends on host configuration).

### LOW
- None.

### UNKNOWN
- None.
