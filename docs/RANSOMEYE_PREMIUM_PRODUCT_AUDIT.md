# RansomEye Premium Product Audit

**Date:** 2026-10-07  
**Branch:** `integration/12x-capabilities` at `8d299bd`  
**Audit Type:** Read-only product, architecture, UX, and security audit  
**Auditor:** Claude Opus 4.6

---

## 1. Executive Summary

RansomEye is a functional, architecturally sound cybersecurity investigation product with a complete evidence-to-report pipeline. The investigation lifecycle is fully implemented: evidence collection → normalization → storage → behavioral detection → finding generation → correlation → threat assessment → investigation graph → attack reconstruction → reporting. The codebase is clean, stdlib-only at runtime, and locally self-contained.

**Current product maturity: Functional Internal Tool (level 2 of 4)**, with strong investigation architecture that reaches toward Professional Product (level 3). The gap is primarily in UI/UX polish — not architecture.

**Key strengths:** Complete investigation pipeline, evidence traceability, deterministic findings, attack reconstruction, process relationship tracking, case lifecycle management, chain of custody. Three specialized analyzers (static, script, phishing) with the script and phishing views demonstrating the target-quality safe DOM rendering pattern.

**Key gaps:** XSS vulnerabilities across most dashboard views, inconsistent rendering patterns between views, 18-item flat navigation, missing bidirectional investigation links (finding → evidence), no PCAP/memory forensics capability, static "Monitor" view.

**Recommendation:** Address XSS hardening (P0) and investigation UX links (P1) before adding PCAP (P2). PCAP integrates cleanly into the existing architecture with zero schema changes.

---

## 2. Current Product Architecture

### 2.1 Module Inventory (30 modules)

| Category | Modules | Purpose |
|----------|---------|---------|
| **Evidence Pipeline** | `evidence.py`, `storage.py`, `sysmon_reader.py` | Event normalization, SQLite v6 schema, Sysmon XML parsing |
| **Detection** | `behavior.py`, `file_behavior.py`, `rules.py` | PowerShell/certutil/shadow detection, file behavior patterns, mass modification rules |
| **Analysis** | `correlation.py`, `threat_assessment.py` | Cross-behavior correlation with 60s window, unified scoring/severity |
| **Investigation** | `investigation.py`, `investigation_graph.py`, `investigation_validation.py` | Domain model, in-memory graph (nodes/edges), validation checks |
| **Reconstruction** | `reconstruction.py`, `advanced_timeline.py`, `timeline.py` | Attack stages, chronological reconstruction, process trees |
| **Specialized Analyzers** | `static_analyzer.py`, `script_analyzer.py`, `phishing.py` | Binary analysis, script deobfuscation, phishing/scam detection |
| **DFIR Operations** | `collection.py`, `integrity.py`, `export.py`, `entropy.py` | Evidence collection pipeline, SHA-256 manifests, case export, entropy calculation |
| **Presentation** | `dashboard_server.py`, `commands.py`, `report.py` | HTTP API + static assets, CLI interface, text report generation |
| **Infrastructure** | `main.py`, `logging.py`, `permissions.py`, `simulation.py`, `__init__.py` | Entry point, audit logging, access control, simulation framework |
| **Collectors** | `collectors/base.py`, `composite.py`, `live_process.py`, `live_file.py`, `live_network.py`, `canary_collector.py` | Pluggable evidence collection framework |

### 2.2 Technology Stack

- **Runtime:** Python 3.13, stdlib only (no third-party runtime deps)
- **Storage:** SQLite with schema versioning (v6), foreign keys enabled
- **Server:** `http.server.BaseHTTPRequestHandler` / `ThreadingHTTPServer`
- **Frontend:** Single-page HTML/CSS/JS (no framework), dark theme
- **Fonts:** Inter (UI), JetBrains Mono (code/data)
- **Tests:** pytest, 769 tests passing
- **Build:** PyInstaller standalone distribution

### 2.3 Schema (SQLite v6)

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `cases` | Investigation cases | case_id, case_name, host, status, severity |
| `events` | Normalized evidence | event_id, case_id, timestamp, source, event_type, process_*, network_json, metadata_json |
| `findings` | Detection results | finding_id, case_id, finding_type, score, confidence, technique |
| `finding_evidence` | Finding ↔ Event links | finding_id, event_id (composite PK) |
| `assessments` | Threat assessments | score, severity, confidence, reasons_json, techniques_json, correlations_json |
| `case_history` | Status transitions | old_status, new_status, note, changed_at |
| `case_custody` | Chain of custody | artifact_path, sha256, action, analyst |
| `schema_version` | PRAGMA user_version | v6 |

---

## 3. Existing Investigation Capabilities

### 3.1 Evidence Lifecycle

```
JSON/XML file → parse_evidence_file() → normalize_events() → EvidenceEvent
    ↓
EvidenceStore.insert_events(case_id, events)
    ↓
analyze_behavior() + analyze_file_behavior() + analyze_events()
    ↓
Finding generation → correlate_findings() → CorrelatedIncident
    ↓
assess_threat() → Assessment (score/severity/confidence)
    ↓
Investigation.load() → InvestigationGraph
    ↓
reconstruct_attack() → AttackSequence → AttackStage[]
    ↓
build_advanced_timeline() / generate_case_report()
```

### 3.2 Evidence Traceability

The `finding_evidence` junction table links findings to supporting evidence events. The investigation graph creates typed relationships:

- `EVIDENCE:event_id` → `SUPPORTS` → `FINDING:finding_id`
- `FINDING:finding_id` → `ASSOCIATED_WITH` → `INCIDENT:incident_id`
- `PROCESS:guid` → `SPAWNED` → `PROCESS:child_guid`
- `PROCESS:guid` → `CREATED/MODIFIED/DELETED` → `FILE:path`
- `PROCESS:guid` → `CONNECTED_TO` → `NETWORK:dest`

The `/inspect` and `/evidence/{case}/{event}/trace` API endpoints resolve the full evidence trace chain.

### 3.3 Specialized Analyzers

| Analyzer | Input | Integration | Dashboard Rendering |
|----------|-------|-------------|---------------------|
| Static | File path | Case finding ingestion via `ingest_static_finding` | Partially safe (replaceChildren for indicators/sections) |
| Script | File path or paste | Case finding ingestion via `ingest_script_finding` | **Fully hardened** (textContent/scriptEl) |
| Phishing | Text/subject/sender | Case finding ingestion via `ingest_phishing_finding` | **Fully hardened** (textContent/scriptEl) |

---

## 4. Current User Journey

### 4.1 Journey Map

| Step | Action | Status | Notes |
|------|--------|--------|-------|
| **1. Launch** | `python -m ransomeye dashboard --database case.db` | Works | Clear CLI with `--help` |
| **2. Open Dashboard** | Browser at `http://localhost:8080` | Works | Professional dark UI loads |
| **3. Create Case** | Cases view → Create modal | Works | Clean form with validation |
| **4. Ingest Evidence** | Collection view → file path + format | Works | JSON and Sysmon XML supported |
| **5. View Overview** | Select case → Overview | Works | Threat score, severity, confidence, incident/finding/evidence counts |
| **6. Investigate** | Navigate to findings/evidence/timeline | Works | Data tables with clickable elements |
| **7. Inspect Evidence** | Click event → drawer opens | Works | Properties + Evidence Trace + Raw Data tabs |
| **8. Process Profile** | Click process → drawer updates | Works | Lineage, Files, Network, Findings tabs |
| **9. Timeline** | Timeline view | Works | Chronological event listing |
| **10. Reconstruction** | Reconstruction view | Works | Attack stages with evidence/finding links |
| **11. Report** | Reports view → Generate | Works | Full text report saved to disk |
| **12. Export** | Export view → case bundle | Works | Zipped case export with lock management |

### 4.2 Journey Breaks

| Break | Location | Severity | Description |
|-------|----------|----------|-------------|
| **Missing Monitor content** | Monitor view | Medium | Static text "truth content" — no live monitoring |
| **Finding → Evidence gap** | Findings view | High | Findings table shows finding_type, technique, score but NO link to supporting evidence events |
| **Reconstruction → Evidence gap** | Reconstruction view | Medium | Shows evidence_ids as text but clicking does not navigate |
| **No search from overview** | Overview → Evidence | Low | Must manually navigate to Evidence view to search |
| **Assessment view empty** | Assessment view | Medium | Returns nothing if assessment is null (no graceful empty state) |

---

## 5. UI/UX Audit

### 5.1 Navigation Structure (Current)

```
Core Operations (3)
├── Overview
├── Cases
└── Monitor          ← Static placeholder

Analysis & Investigation (9)
├── Threat Assessment
├── Incidents
├── Findings
├── Evidence
├── Investigation
├── Timeline
├── Process Tree
├── Reconstruction
└── Reports

DFIR Operations (5)
├── Collection & Ingest
├── Integrity Verification
├── Chain of Custody
├── Case Export
└── Database Maintenance

Specialized Analyzers (3)
├── Static Analysis
├── Script Analysis
└── Phishing Analysis
```

**Issues:**
- 18 nav items — too many for a sidebar, causes scrolling
- "Investigation" view duplicates information available across Assessment, Incidents, Findings, Timeline
- "Process Tree" could be a tab within Investigation
- "Monitor" is a static placeholder with no functionality
- Database Maintenance is a system admin function mixed with investigation

### 5.2 Visual Design Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Color system | Good | Consistent CSS variables, professional dark theme |
| Typography | Good | Inter + JetBrains Mono, appropriate sizing hierarchy |
| Layout | Good | Sidebar + main workspace + drawer — standard analytics pattern |
| Tables | Good | Consistent `.data-table` class, clickable rows |
| Forms | Good | Labeled inputs, validation feedback, loading states |
| Badges | Good | Severity-colored badges (critical/high/medium/low) |
| Cards | Good | Stat cards with label/value pattern |
| Drawer | Good | Tabbed inspection panel with properties/trace/raw |
| Modal | Acceptable | Used for create/update operations |
| Empty states | Mixed | Some views have good empty states, others show nothing |
| Loading states | Mixed | Some buttons show "Analyzing...", others don't indicate loading |
| Error states | Acceptable | Alert components with error styling |
| Responsive | Not tested | `overflow: hidden` on body suggests desktop-only |

### 5.3 Terminology Consistency

| Term | Used In | Issue |
|------|---------|-------|
| "Incidents" | Nav + Overview | Sometimes called "correlations" in API responses |
| "Evidence" | Nav + drawer | Tab says "Evidence Trace" but it's really the traceability chain |
| "Assessment" | Nav | Could be "Threat Assessment" everywhere |
| "Monitor" | Nav | Suggests live monitoring but is static text |
| Status values | Cases | UI shows IN_PROGRESS/ARCHIVED but server maps these to TRIAGED/CLOSED |
| "Collection & Ingest" | Nav | Combines two concepts in one view |

---

## 6. Investigation UX Audit

### 6.1 Can the user naturally trace: Finding → Evidence → Timeline → Process → Reconstruction → Report?

| Link | Exists? | How? | Quality |
|------|---------|------|---------|
| Finding → Evidence | **MISSING** | Findings view shows no evidence links | **Gap** |
| Evidence → Finding | Yes | Evidence drawer "Evidence Trace" tab | Good |
| Evidence → Process | Yes | "OPEN PROCESS PROFILE" button in drawer | Excellent |
| Process → Children | Yes | Process Profile "Lineage" tab | Good |
| Process → Files | Yes | Process Profile "Files" tab | Good |
| Process → Network | Yes | Process Profile "Network" tab | Good |
| Process → Findings | Yes | Process Profile "Findings" tab | Good |
| Timeline → Process | Yes | Click process name in timeline entry | Good |
| Incident → Findings | Yes | Incident drawer shows finding IDs | Acceptable (IDs only, not clickable to details) |
| Incident → Processes | Yes | Incident drawer shows process names + click to inspect | Good |
| Reconstruction → Evidence | **WEAK** | Shows evidence_ids[0] as text, not clickable | **Gap** |
| Overview → Incidents | Yes | Click incident row → drawer | Good |
| Overview → Activity | Yes | Click activity row → drawer | Good |

### 6.2 Missing Investigation Links

1. **Finding → Evidence**: The `finding_evidence` junction table exists in the DB, but the Findings view does not display or link to supporting evidence events. This is the highest-priority investigation UX gap.

2. **Reconstruction → Evidence/Finding drill-down**: Reconstruction stages show evidence_ids and finding_ids as text strings but provide no clickable navigation.

3. **Incident finding details**: Incident drawer shows `FINDING:123` as text but doesn't show finding_type, technique, or allow clicking through to a finding detail view.

---

## 7. Evidence Traceability Audit

### 7.1 Schema Support

The `finding_evidence` junction table and `assessments.correlations_json` provide the underlying data for full traceability. The API endpoints `/inspect`, `/evidence/{case}/{event}/trace`, `/investigation/{case}/graph`, and `/process/{case}/{id}` all correctly resolve graph relationships.

### 7.2 API Completeness

| Chain Link | API Endpoint | Returns |
|------------|-------------|---------|
| Event → Findings | `/inspect/{case}?event_id=X` | `trace.findings[]` |
| Event → Incidents | `/inspect/{case}?event_id=X` | `trace.incidents[]` |
| Event → Processes | `/inspect/{case}?event_id=X` | `trace.processes[]` |
| Event → Full Trace | `/evidence/{case}/{event}/trace` | parent_process, current_process, findings, incidents |
| Process → Full Profile | `/process/{case}/{id}` | parent, children, files, network, findings |
| Case → Graph | `/investigation/{case}/graph` | All nodes + edges |
| Case → Validation | `/investigation/{case}/validation` | Completeness checks |

### 7.3 Traceability Gaps

- **No API for**: "Given a finding_id, return all supporting evidence events" — this is available via the graph but not as a direct endpoint.
- **No API for**: "Given an incident_id, return the full incident detail with resolved finding and evidence data" — incident drawer only has the local `state.incidents` data.

---

## 8. Security / XSS Audit

### 8.1 innerHTML Usage Analysis

**Total innerHTML assignments in app.js: ~55**

| View | innerHTML with Dynamic Data | XSS Risk | Data Source |
|------|---------------------------|----------|-------------|
| **Overview** | `incTbody.innerHTML`, `actTbody.innerHTML` | **HIGH** | incident_id, severity, timestamp, event_type, process_name — all Sysmon-derived |
| **Cases** | `tbody.innerHTML` | **MEDIUM** | case_id, case_name, host — user-created but rendered unsafely |
| **Case History Modal** | `dom.modalBody.innerHTML` | **MEDIUM** | status, notes, timestamp — includes `h.notes` directly |
| **Assessment** | `p.innerHTML` | **HIGH** | reasons[], techniques[] — derived from detection rules but include event data |
| **Incidents** | `tbody.innerHTML` | **HIGH** | incident_id, severity, start_time, finding_ids — correlation-derived |
| **Findings** | `tbody.innerHTML` | **MEDIUM** | finding_type, technique, score — mostly controlled vocabulary but reason text could contain event data |
| **Evidence** | `tbody.innerHTML` | **HIGH** | timestamp, event_type, process_name, pid, event_id — directly from Sysmon events |
| **Investigation** | `graphSumEl.innerHTML`, `validSumEl.innerHTML` | **MEDIUM** | Counts and status strings — lower risk but still innerHTML |
| **Process Tree** | `container.innerHTML` (recursive) | **CRITICAL** | process name, PID, command_line, GUID — attacker can craft process names and command lines |
| **Timeline** | `container.innerHTML` | **HIGH** | description, process_name, process_guid — Sysmon-derived |
| **Reconstruction** | `container.innerHTML` | **HIGH** | stage_type, title, description — derived from evidence |
| **Collection feedback** | `fbIngest.innerHTML` | **LOW** | Server-controlled counts |
| **Integrity feedback** | `fbHash.innerHTML`, `fbVerify.innerHTML` | **MEDIUM** | File paths from server (user-provided) |
| **Custody** | `tbody.innerHTML` | **MEDIUM** | artifact names, analyst names — user-provided |
| **Export feedback** | `fbExport.innerHTML` | **LOW** | Server-controlled paths |
| **Database feedback** | `resCheck.innerHTML`, `resBackup.innerHTML` | **LOW** | Server status |
| **Evidence Drawer** | `dom.drawerContent.innerHTML` | **CRITICAL** | Full event data: event_id, timestamp, source, event_type, process_name, PID, GUID, command_line, image_path — ALL Sysmon-derived |
| **Process Drawer** | `dom.drawerContent.innerHTML` | **CRITICAL** | Process name, PID, GUID, command_line, parent/children names, file paths — ALL attacker-influenced |
| **Incident Drawer** | `dom.drawerContent.innerHTML` | **HIGH** | Finding IDs, process names/PIDs/GUIDs — attacker-influenced |
| **Script Analysis** | None | **SAFE** | Uses textContent/scriptEl exclusively |
| **Phishing Analysis** | None | **SAFE** | Uses textContent/scriptEl exclusively |
| **Static Analysis** | Partial | **LOW** | Uses replaceChildren for indicators; some fields use textContent |

### 8.2 Highest-Risk Sinks

1. **Process Tree** (line 717-728): `command_line` interpolated directly into innerHTML — an attacker who sets a process command line to `<img src=x onerror=alert(1)>` would achieve XSS.

2. **Evidence Drawer** (lines 1888-1922): `ev.command_line`, `ev.process_name`, `ev.image_path`, `ev.event_id` all interpolated — any Sysmon event with HTML in process_name or command_line would execute.

3. **Process Drawer** (lines 1960-1994): `p.name`, `p.command_line`, parent/children names, file paths — same risk.

4. **Overview Activity** (lines 310-316): `a.process_name`, `a.event_type` interpolated.

### 8.3 Safe Patterns Already Established

The script and phishing views demonstrate the correct pattern:
- `scriptEl(tag, opts, children)` — creates elements via `document.createElement`, sets text via `textContent`
- `scriptKv(key, value)` — safe key-value display
- `scriptSection(title, open, bodyNodes)` — collapsible sections
- `renderScriptResult()` / `renderPhishingResult()` — pure DOM construction, zero innerHTML

These helpers are already generic enough to reuse across all views.

### 8.4 showModal() Sink

`showModal(title, bodyHtml, footerHtml)` at line 88 uses `innerHTML` for both body and footer. The title uses `textContent` (safe). Several callers pass user-provided or attacker-derived strings into the body HTML (e.g., case history modal at line 497 interpolates `h.notes`).

---

## 9. 12X Integration Assessment

### 9.1 Disposition Matrix

| Capability | Source | Disposition | Reason |
|------------|--------|-------------|--------|
| **PCAP Network Analysis** | ExtenderRem `pcap_analyzer.py` | **ADAPT** | Zero overlap, 100% stdlib, fills critical gap, clean architecture fit |
| **IOC Extraction (enhanced)** | ExtenderRem `ioc_extractor.py` | **MERGE** | ~60% overlap; merge new patterns (ETH wallets, defanged URLs, Windows APIs) into existing extractors |
| Memory Forensics (stdlib core) | MemRev-Engine `reader.py`, `process_scan.py`, `carver.py` | **DEFER** | High value but high complexity; target Stage 8 |
| Memory Forensics (full) | MemRev-Engine + engine_12x `memory_forensics.py` | **DEFER** | Requires pefile/capstone (optional deps); defer until stdlib core proven |
| Registry Monitor | SentinelGuard `registry_monitor.py` | **DEFER** | ~70% overlap with Sysmon registry parsing; adds live monitoring but duplicate data |
| USB Monitor | SentinelGuard `usb_monitor.py` | **REJECT** | Requires psutil, dead code, niche forensic value for ransomware |
| Network Monitor | SentinelGuard `network_monitor.py` | **REJECT** | Requires psutil, overlaps with Sysmon network events |
| DLL Injection Monitor | SentinelGuard `dll_monitor.py` | **DEFER** | Requires psutil, valuable but overlaps with image_load event type |
| Response Actions | engine_12x `response_actions.py` | **REJECT** | DESTRUCTIVE — kills processes, blocks network |
| Tarpit Deception | engine_12x `tarpit_deception.py` | **REJECT** | DESTRUCTIVE — creates junction loops |
| VSS Rollback | engine_12x `vss_rollback.py` | **REJECT** | DESTRUCTIVE — automatic restoration |
| System Guard | engine_12x `system_guard.py` | **REJECT** | DESTRUCTIVE — auto-rollback |
| Threat Intelligence | ExtenderRem `threat_intel.py` | **REJECT** | CLOUD — requires external APIs |
| Crypto Tracker | engine_12x `crypto_tracker.py` | **REJECT** | NETWORK — calls blockchain.info API |
| ML Anomaly Detection | Multiple sources | **REJECT** | NON-STDLIB — requires numpy/sklearn |
| Static Triage | engine_12x `static_triage.py` | **REJECT** | NON-STDLIB + OVERLAP — requires pefile/yara, overlaps static_analyzer |
| Condition Eval | NEXUS-SCAN `condition_eval.py` | **REJECT** | UNSAFE — uses `eval()` |

---

## 10. PCAP Architecture Verification (Stage 0)

### 10.1 EvidenceEvent Model Compatibility

| Field | Current Semantics | PCAP Mapping | Schema Change? |
|-------|------------------|--------------|----------------|
| `event_type` | Sysmon event types | `network_connect` for HTTP observations, `dns_query` for DNS | **None** — types already exist |
| `source` | Free text (e.g., "Sysmon") | `"pcap"` | **None** — not restricted |
| `timestamp` | ISO-8601 datetime | PCAP packet timestamp | **None** |
| `network_json` | Structured network data (dict) | `{"http_method": "GET", "uri": "/beacon", "host": "evil.com", "user_agent": "..."}` | **None** |
| `metadata_json` | Structured metadata (dict) | `{"pcap_file": "capture.pcap", "packet_offset": 12345}` | **None** |
| `process_name` | Optional | `null` (PCAP has no process context) | **None** |
| `pid` | Optional | `null` | **None** |

### 10.2 Provenance Distinction

The `source` field already distinguishes provenance:
- Current: `source: "Sysmon"` for Sysmon-derived events
- PCAP: `source: "pcap"` (or `source: "pcap:capture.pcap"` for filename provenance)

This avoids the need for new event types. The existing `network_connect` and `dns_query` types are semantically correct — a PCAP observation of an HTTP request IS a network connection, regardless of collection method. The provenance distinction answers "where did this evidence come from?" which is what `source` is for.

### 10.3 Storage Compatibility

No schema migration needed:
- Events table already has `network_json TEXT` for structured network data
- Events table already has `metadata_json TEXT` for additional context
- `finding_evidence` junction already links findings to any event type

### 10.4 Detection Pipeline Compatibility

PCAP-derived evidence flows through the same detection pipeline:
- Behavioral rules can match on `network_connect` events regardless of source
- New PCAP-specific detection rules (C2 beacon patterns, DNS exfiltration, suspicious user agents) would be added to `rules.py` or a new `pcap_rules.py`
- Findings generated from PCAP evidence link to the evidence via `finding_evidence` exactly like Sysmon findings

### 10.5 Investigation Graph Compatibility

The investigation graph already creates NETWORK nodes:
- `PROCESS:guid` → `CONNECTED_TO` → `NETWORK:dest_ip`
- PCAP observations without process context create orphan NETWORK nodes, but these still contribute to the investigation graph topology

### 10.6 Dashboard Compatibility

- The Evidence view already displays `network_connect` and `dns_query` events
- The Process Profile "Network" tab already shows network connections
- A new "PCAP Analysis" view under Specialized Analyzers follows the established pattern

### 10.7 Verdict

**PCAP integrates cleanly into the existing architecture with zero schema changes.** The `source` field provides provenance distinction, existing event types carry the semantics, `network_json` stores the structured data, and the detection/investigation pipeline processes PCAP evidence identically to Sysmon evidence.

One design consideration: PCAP observations lack process context (PID/GUID), so they will not appear in process-centric views (Process Tree, Process Profile network tab). They will appear in Evidence, Timeline, and any network-focused views. This is correct — PCAP captures network activity, not process activity.

---

## 11. Premium Product Gaps

### 11.1 Gap Assessment

| Gap | Category | Impact | Effort |
|-----|----------|--------|--------|
| **XSS in most dashboard views** | Security | CRITICAL | Medium — established pattern exists, apply systematically |
| **Findings view has no evidence links** | Investigation UX | HIGH | Low — data is in `finding_evidence` table, need API endpoint + UI |
| **Monitor view is static** | Feature | MEDIUM | Decision needed — is live monitoring in scope? |
| **18-item flat navigation** | UX | MEDIUM | Low — consolidate/group items |
| **Reconstruction stages not clickable** | Investigation UX | MEDIUM | Low — add onclick handlers for evidence/finding IDs |
| **Process tree command_line XSS risk** | Security | HIGH | Low — convert to safe DOM rendering |
| **Drawer innerHTML injection** | Security | HIGH | Medium — largest single block of unsafe rendering |
| **No empty state for Assessment** | UX | LOW | Trivial |
| **Status value mapping confusion** | UX | LOW | Align UI options with actual case statuses |
| **No PCAP / network forensics** | Capability | HIGH | Medium — clean architecture fit verified |
| **No memory forensics** | Capability | MEDIUM | High — complex implementation |

### 11.2 Product Maturity Rating

| Dimension | Rating (1-5) | Notes |
|-----------|:---:|-------|
| Architecture | 5 | Clean pipeline, well-separated concerns, extensible |
| Investigation model | 4 | Complete lifecycle with minor UX gaps |
| Evidence traceability | 4 | Schema and API support; UI not fully connected |
| Detection quality | 3 | Rule-based, deterministic; no false claims made |
| UI design system | 4 | Professional dark theme, consistent CSS variables |
| UI implementation | 2 | innerHTML sinks, inconsistent rendering patterns |
| Security posture | 2 | XSS vulnerabilities across most views |
| Test coverage | 4 | 769 tests, XSS probe tests for hardened views |
| Documentation | 2 | No user documentation; code comments minimal (correct approach) |
| Packaging | 4 | PyInstaller spec, standalone distribution |

---

## 12. Prioritized Roadmap

### P0 — Critical (address before any new capability)

| ID | Task | Rationale |
|----|------|-----------|
| P0-1 | **Harden all dashboard views against XSS** | Attacker-controlled data (process names, command lines, file paths, event IDs) flows through innerHTML. This is a security vulnerability in a tool that processes adversary artifacts. |
| P0-2 | **Harden drawer rendering** | Evidence Drawer, Process Drawer, and Incident Drawer all use innerHTML with attacker-controlled data. These are the highest-risk components. |
| P0-3 | **Harden showModal() callers** | Case history modal interpolates `h.notes` via innerHTML. |

### P1 — High Value Investigation Improvements

| ID | Task | Rationale |
|----|------|-----------|
| P1-1 | **Add evidence links to Findings view** | Finding → Evidence is the most critical missing investigation link. The data exists in `finding_evidence`; needs a `/findings/{case}/detail` endpoint and UI with clickable evidence rows. |
| P1-2 | **Make Reconstruction stages clickable** | Evidence_ids and finding_ids in reconstruction view should navigate to evidence/finding inspection. |
| P1-3 | **Consolidate navigation** | Group related views; consider tabs within Investigation for Graph/Tree/Reconstruction. Reduce from 18 to ~12-14 visible items. |
| P1-4 | **Add empty/loading states to all views** | Assessment, Incidents, Findings views have inconsistent empty state handling. |

### P2 — Valuable Forensic Capabilities

| ID | Task | Rationale |
|----|------|-----------|
| P2-1 | **PCAP Network Analysis** (12X integration) | Highest-scoring capability (47/50), zero overlap, 100% stdlib, verified clean architecture fit. |
| P2-2 | **Enhanced IOC merge** | Merge ExtenderRem IOC patterns (ETH wallets, defanged URLs, Windows API names) into existing static_analyzer/script_analyzer. |

### P3 — Optional Enhancements

| ID | Task | Rationale |
|----|------|-----------|
| P3-1 | Memory Forensics (stdlib core) | High DFIR value but complex — defer until PCAP vertical slice proven |
| P3-2 | Dashboard responsive layout | Currently desktop-only; mobile/tablet layout for field analysts |
| P3-3 | Dashboard dark/light theme toggle | Currently dark-only |
| P3-4 | Keyboard navigation | Power-user investigation workflow |

---

## 13. Recommended Navigation

### Proposed Structure (consolidation, not redesign)

```
COMMAND CENTER
├── Overview
├── Cases

INVESTIGATE
├── Threat Assessment
├── Incidents
├── Findings
├── Evidence
├── Investigation    ← includes Graph, Process Tree, Reconstruction as tabs
├── Timeline
└── Reports

FORENSICS
├── Static Analysis
├── Script Analysis
├── Phishing Analysis
└── PCAP Analysis    ← future (P2-1)

OPERATIONS
├── Collection & Ingest
├── Integrity & Custody    ← merge two low-traffic views
├── Case Export
└── Database               ← collapse into settings or smaller control
```

**Changes from current:**
- Removed "Monitor" (static placeholder — reintroduce when live monitoring exists)
- Merged Process Tree and Reconstruction into Investigation view as tabs
- Merged Integrity + Custody (both concern evidence provenance/trust)
- Reduced from 18 items to 14 (13 without PCAP)
- Section names align with product identity (Command Center, Investigate, Forensics, Operations)

---

## 14. Recommended Investigation Flow

### Primary Investigation Path

```
Overview (threat state)
    → click incident → Incident Drawer (severity, timeframe, findings, processes)
        → click finding → Finding Detail (type, technique, evidence links) [P1-1]
            → click evidence → Evidence Drawer (properties, trace, raw)
                → click process → Process Profile (lineage, files, network, findings)
                    → click child → deeper process inspection
    → Timeline (chronological view)
        → click process → Process Profile
    → Investigation (graph + tree + reconstruction)
        → click stage → Evidence/Finding drill-down [P1-2]
    → Report (complete text report)
```

### Forensic Analysis Path

```
Forensics → [Static | Script | Phishing | PCAP] Analysis
    → submit artifact
    → view results (verdict, indicators, IOCs, techniques)
    → ingest into case (creates finding + evidence)
    → navigate to Findings/Evidence views
    → continue investigation
```

---

## 15. Premium UX Contract

### The 12 Principles

1. **Clear** — Every screen communicates its purpose within 3 seconds. No ambiguous icons or unnamed controls.

2. **Hierarchical** — Information follows progressive disclosure: summary → detail → raw data. Never dump everything at once.

3. **Consistent** — Same data type renders the same way everywhere. Severity badges, timestamps, process names, case IDs use one pattern.

4. **Evidence-driven** — Every finding, alert, or assessment is traceable to specific evidence events. No black-box conclusions.

5. **Action-oriented** — Every screen makes the user's next action obvious. "What should I investigate next?" has a visible answer.

6. **Explainable** — Findings show WHY, WHAT EVIDENCE, WHEN, WHICH PROCESS. Never "suspicious activity detected" without specifics.

7. **Traceable** — The user can follow the chain: Evidence → Finding → Incident → Process → Timeline → Reconstruction → Report.

8. **Safe** — All attacker-controlled content (process names, command lines, URLs, file paths, IOC values) renders via `textContent` / safe DOM construction. Never innerHTML with dynamic data.

9. **Responsive** — Loading states ("Analyzing..."), empty states ("No findings in case"), and error states ("Unable to load evidence") are handled for every view.

10. **Advanced but approachable** — Technical depth is available but not forced. Expand to see raw data; collapse to see the summary.

11. **Unique without gimmicks** — The unique value is the evidence traceability chain, not visual effects. The investigation flow IS the product experience.

12. **Professional** — Calm, trustworthy, no unnecessary alerts. The tool should reduce analyst stress, not add to it.

---

## 16. Risks

### 16.1 Security Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| XSS via Sysmon event data | HIGH | HIGH | P0 — Harden all views with safe DOM rendering |
| XSS via process command lines | HIGH | HIGH | P0 — Process tree and drawer rendering |
| Path traversal in file-path inputs | LOW | MEDIUM | Already mitigated by `SAFE_ID_REGEX` for case IDs; file path handling uses `resolve()` |
| CORS open to all origins | LOW | LOW | Acceptable for local-first tool; would need restriction for network deployment |
| SQLite concurrency | MEDIUM | LOW | `_get_store()` creates fresh connections; ThreadingHTTPServer handles basic concurrency |

### 16.2 Architecture Risks

| Risk | Mitigation |
|------|------------|
| Dashboard JS growing unmanageably | Already at 2009 lines; consider splitting into per-view modules if it exceeds ~3000 |
| New capability breaks existing tests | Regression suite at 769 tests provides good coverage; run full suite before every commit |
| PCAP parser memory exhaustion | Add input size validation (max 100MB), chunked processing, per-type result caps |

---

## 17. What NOT to Implement

1. **React, Vue, or any JS framework** — The stdlib `http.server` + vanilla JS approach is correct for a local-first tool. Framework overhead is unnecessary.

2. **FastAPI, Flask, or any Python web framework** — Same rationale. `BaseHTTPRequestHandler` works.

3. **Live system monitoring** — Until a clear product decision defines what "Monitor" means, do not build it. If built, it must be read-only observation, never destructive response.

4. **External threat intelligence** — No API calls to AbuseIPDB, OTX, VirusTotal, or any external service. RansomEye is offline-first.

5. **ML/AI detection** — No numpy, sklearn, or cloud ML. Detection must be deterministic and explainable.

6. **Autonomous response** — No process killing, network blocking, quarantine, VSS rollback, or any destructive action.

7. **Cloud storage** — No Supabase, PostgreSQL, Redis, AWS. SQLite is the storage layer.

8. **Docker/container** — PyInstaller standalone distribution is the deployment model.

9. **Production performance claims** — No false detection rate, accuracy, or enterprise readiness claims.

10. **Flashy dashboard widgets** — No animated graphs, real-time meters, or decorative visualizations that don't serve investigation.

---

## 18. Final Architecture Recommendation

### Assessment

The current RansomEye architecture is **sound and extensible**. The canonical pipeline (Evidence → Finding → Correlation → Investigation → Reconstruction → Report) is fully implemented, well-tested, and correctly factored. The schema supports the investigation model without needing changes for the next capability (PCAP). The specialized analyzer pattern (static, script, phishing) provides a proven template for new forensic capabilities.

### Recommended Next Stage

**P0 first: XSS hardening of all dashboard views** — before adding any new capability. This is not optional; it is a security requirement for a tool that processes adversary-crafted data.

After P0:

**P1-1: Finding → Evidence links** — the highest-value investigation UX improvement.

Then:

**P2-1: PCAP Network Analysis** — the next forensic capability, following the vertical slice pattern from script analyzer (Stages 1-6). Architecture verification confirms zero schema changes needed.

### Vertical Slice Template

Each new capability follows:
1. Core analyzer module (Python, stdlib-only)
2. CLI command integration
3. Dashboard API endpoint
4. Dashboard view (safe DOM rendering)
5. Evidence ingestion + finding generation
6. Test suite (unit + integration + XSS probes)
7. PyInstaller spec update

### PCAP Can Be Integrated Cleanly

Yes. Zero schema changes. Use `source: "pcap"`, existing event types (`network_connect`, `dns_query`), `network_json` for structured data. The detection/investigation/reporting pipeline processes PCAP evidence identically to Sysmon evidence.

---

*This audit is read-only. No files were modified except this report. No application behavior was changed. No implementation was started.*
