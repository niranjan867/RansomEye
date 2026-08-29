# 12X Source-to-Source Audit

## 1. Executive Summary
This document presents the findings of a read-only, source-to-source audit between the `RansomEye` and `12X-RANSOWARE-ANALYSIS` projects. The objective is to identify 12X capabilities that can be integrated into RansomEye without violating the core architectural constraint: RansomEye remains the single source of truth for evidence, correlation, and response.

## 2. RansomEye Current Architecture
RansomEye operates on a centralized evidence and finding correlation model.
- **Evidence Schema**: Defined in `src/ransomeye/evidence.py`. Supports an explicit `ALLOWED_EVENT_TYPES` set and standardizes fields across all event types via `EvidenceEvent`.
- **Storage**: Uses a local SQLite database (`storage.py`) with tables for `cases`, `events`, `findings`, `finding_evidence`, `assessments`, and `case_history`. The current schema version is 6.
- **Analysis Pipeline**: Events flow from Collection -> EvidenceStore -> Detection -> Finding -> Assessment.

## 3. 12X Actual Architecture
12X is an amalgamation of several loosely coupled modules that share a Supabase backend with a local SQLite fallback (`engine_12x/database.py`).
- **SentinelGuard/System Guard**: Monitors processes, file systems (canary traps), and network connections (`SystemGuardManager`). Emits events directly to a separate database.
- **MemRev-Engine/Memory Forensics**: Provides RAM dump analysis, PE/shellcode carving, Capstone-based disassembly, and IOC extraction (`MemoryForensicsAnalyzer`).
- **NEXUS-SCAN & ExtenderRem**: Submodules for analysis and remediation/response.
- **Database**: Uses `scan_results`, `system_events`, `threat_alerts`, and `memory_forensics` tables, completely disconnected from RansomEye's evidence store.

## 4. Source-to-Source Capability Comparison

### Memory Forensics (`engine_12x/core/memory_forensics.py`)
- **Class**: `MemoryForensicsAnalyzer`
- **Does**: Scans memory dumps for MZ headers, high-entropy RWX buffers, extracts IOCs (IPs, URLs, domains). Uses Capstone for disassembly.
- **RansomEye Equivalent**: None.
- **Adaptation**: Highly valuable. Must adapt to emit `EvidenceEvent` objects for the `EvidenceStore` rather than writing directly to its own DB.

### System Guard / Canary Monitor (`engine_12x/core/system_guard.py`)
- **Class**: `SystemGuardManager`
- **Does**: Uses `watchdog` to monitor canary files. Uses `psutil` to monitor process starts for ransomware CLI indicators (e.g., `vssadmin delete shadows`). Monitors network connections via `psutil`.
- **RansomEye Equivalent**: Some overlap with existing process/network collectors, but the active canary file monitoring is net-new.
- **Adaptation**: The canary monitoring logic can be ported to a new RansomEye `BaseCollector`. The hardcoded DB inserts and desktop notifications must be stripped out.

## 5. Duplicate Functionality
- **Process Monitoring**: `12X` uses `psutil` to poll for new processes. RansomEye already has more robust system monitoring (e.g., Sysmon). The `12X` process polling is redundant.
- **Network Monitoring**: `12X` polls `psutil.net_connections`. RansomEye handles network events natively.

## 6. Net-New Capabilities
- **Canary/Honeypot Monitoring**: Active filesystem monitoring for ransomware encryption traps.
- **Memory Forensics & Shellcode Carving**: `12X` introduces `capstone` to carve and disassemble PE files from RAM dumps.

## 7. Database Conflicts
- **RansomEye Schema**: Highly relational (`cases`, `events`, `findings`, `assessments`).
- **12X Databases**: `engine_12x/database.py` defines tables (`scan_results`, `system_events`, `threat_alerts`) that duplicate RansomEye's core function. 
- **Conflict**: 12X writes alerts directly to `threat_alerts`. This violates the RansomEye architecture.
- **Resolution**: Do not migrate the 12X schema. Adapt 12X detection logic to generate `EvidenceEvent` and `Finding` objects that fit into RansomEye's existing tables.

## 8. Dependency Conflicts
- **KEEP**: `psutil`, `watchdog` (useful for canary).
- **ADD (Optional)**: `pefile`, `capstone` (for memory forensics).
- **REJECT**: `supabase` (violates local-first architecture), `fastapi`, `uvicorn` (unless replacing RansomEye's dashboard).

## 9. Security Findings
- **Autonomous Response**: 12X modules appear to have logic for aggressive containment (e.g., desktop notifications, potentially process killing).
- **Finding**: Autonomous actions must be disabled. Response actions must be routed through RansomEye's approved containment workflows.

## 10. Test Coverage Comparison
- **RansomEye**: Has a dedicated `tests/` directory and `pytest` integration.
- **12X**: Minimal to no visible unit tests in the core engines (`MemRev-Engine` has a `tests/` dir, but coverage is unverified).
- **Requirement**: Any adapted 12X code must have full `pytest` coverage added in RansomEye.

## 11. Capability Decision Matrix

| Capability | 12X Source | RansomEye Equivalent | Decision | Priority | Reason | Integration Point |
|---|---|---|---|---|---|---|
| Canary Monitoring | `system_guard.py` | None | ADAPT | P1 | Active ransomware detection | `BaseCollector` |
| Memory Forensics | `memory_forensics.py` | None | ADAPT | P2 | Advanced analysis | `investigation.py` |
| Process Polling | `system_guard.py` | Sysmon/Collectors | REJECT | P3 | Inferior to existing | N/A |
| Threat DB (Supabase) | `database.py` | `storage.py` | REJECT | P0 | Architecture Violation | N/A |

## 12. Recommended Combined Architecture
RansomEye remains the central hub.
- 12X `SystemGuard` canary logic becomes a `CanaryCollector`.
- 12X `MemoryForensics` becomes a specialized analyzer invoked during `ThreatAssessment`.

## 13. P0/P1/P2/P3 Roadmap
- **P0**: Strip all Supabase and autonomous response code from 12X logic.
- **P1**: Port Canary monitoring to a RansomEye collector.
- **P2**: Port Memory Forensics (PE carving, Capstone disassembly).
- **P3**: Port advanced ML anomaly detection (if present and viable).

## 14. Exact Files/Functions to Adapt
- `engine_12x/core/system_guard.py`: `_on_fs_change` (for canary logic).
- `engine_12x/core/memory_forensics.py`: `analyze_memory_dump`, `disassemble_hex`.

## 15. Exact Files/Functions to Reject
- `engine_12x/database.py`: Entire file.
- `engine_12x/core/system_guard.py`: `_emit_event` (violates schema).

## 16. Risks
- Integrating `capstone` and `pefile` increases the dependency footprint.
- Canary monitoring using `watchdog` may have performance implications on large filesystems.

## 17. Open Questions
- Do we want to officially support `capstone` in RansomEye, or should memory forensics be an optional plugin?

## 18. Estimated implementation effort
- Porting Canary Collector: 2 days.
- Porting Memory Forensics: 3 days.

## 19. Definition of Done
- 12X logic successfully encapsulated in RansomEye collectors/analyzers.
- Zero secondary databases created.
- Full test coverage for new components.

AUDIT STATUS:
COMPLETE

FILES MODIFIED:
Only docs/12x_source_to_source_audit.md

CODE MODIFIED:
NONE

DATABASE MODIFIED:
NONE

DEPENDENCIES INSTALLED:
NONE

COMMIT:
NO

PUSH:
NO
