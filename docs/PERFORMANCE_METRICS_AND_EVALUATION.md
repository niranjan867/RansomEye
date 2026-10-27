# PERFORMANCE METRICS & EVALUATION

## Executive Overview

RansomEye is a local-first, evidence-centric Digital Forensics and Incident Response (DFIR) framework designed to detect, correlate, and reconstruct ransomware-like behaviors across Windows endpoint activity without relying on external cloud telemetry or modifying customer data.

This document outlines the performance metrics, evaluation methodology, and current verification status of the RansomEye platform. In accordance with strict scientific and engineering rigor:
- No artificial, estimated, or fabricated benchmark numbers are reported.
- Metrics requiring controlled physical testbed calibration are designated as **"TO BE MEASURED EXPERIMENTALLY."**
- Deterministic capabilities (traceability, investigation graph generation, attack reconstruction, cryptographic integrity, and test suite execution) are validated directly against the active implementation.

---

## Safe Evaluation Principles & Constraints

All evaluation procedures adhere to strict defensive safety constraints:
1. **Zero Malware Execution:** Never executes live malware, ransomware payloads, or destructive binaries.
2. **Zero Data Destruction:** Never encrypts, alters, or destroys user files or endpoint file systems. Controlled tests execute entirely against isolated synthetic fixtures and temporary directories.
3. **Zero Host Interference:** Never terminates real operating system processes or performs destructive containment actions on live production environments.
4. **Local-First & Offline:** Evaluates entirely on local fixtures with no external cloud services, API dependencies, or sensitive telemetry export.
5. **Deterministic Replicability:** Test cases use deterministic fixtures (`samples/normal_activity.json`, `samples/ransomware_like_activity.json`, Sysmon XML event corpora).

---

## Core Performance Metrics & Evaluation

### 1. Detection Accuracy
- **Definition:** Measures how correctly RansomEye identifies ransomware-related behavior across comprehensive mixed test datasets (proportion of true positives and true negatives over total evaluated scenarios).
- **Evaluation Method:** Controlled evaluation across categorized test corpora containing both advanced ransomware behavioral patterns and legitimate administrator/developer activity.
- **Numerical Result:** `TO BE MEASURED EXPERIMENTALLY.`

### 2. Detection Rate (True Positive Rate / Sensitivity)
- **Definition:** Measures the percentage of known ransomware-like test activities and technique stages (e.g., volume shadow copy deletion via `vssadmin`, bcdedit recovery disablement, mass file modifications, rapid extension mutations, ransom note drop) detected and flagged as elevated threat findings.
- **Evaluation Method:** Execution against positive synthetic ransomware behavior datasets (`samples/ransomware_like_activity.json` and Sysmon event collections).
- **Numerical Result:** `TO BE MEASURED EXPERIMENTALLY.`

### 3. False Positive Rate
- **Definition:** Measures how often legitimate administrative, developer, or system operations (e.g., standard PowerShell administration, routine batch renaming, document edits, backup operations) are incorrectly classified as suspicious or malicious ransomware attacks.
- **Evaluation Method:** Execution against standard benign activity datasets (`samples/normal_activity.json`) and clean endpoint baseline event streams.
- **Numerical Result:** `TO BE MEASURED EXPERIMENTALLY.`

### 4. Detection Time (Latency)
- **Definition:** Measures the time interval between endpoint ingestion of a suspicious evidence event and the generation of an actionable behavioral finding and threat assessment.
- **Evaluation Method:** Monotonic high-resolution timer (`time.perf_counter()`) measuring pipeline processing from event ingestion to database finding commit.
- **Numerical Result:** `TO BE MEASURED EXPERIMENTALLY.`

### 5. Evidence Traceability
- **Definition:** Verifies that every generated finding is strictly and deterministically linked back to its originating evidence event(s) in SQLite storage via the `finding_evidence` relational junction table.
- **Evaluation Method:** Verification of relational database schema constraints, foreign key validation, and automated execution of `ransomeye.investigation_validation.validate_investigation()`.
- **Numerical Result:** Verified (100% of generated findings link directly to valid source `event_id` records in `finding_evidence` junction table).
- **Status:** Verified.

### 6. Investigation Completeness
- **Definition:** Verifies that ingested and correlated evidence deterministically generates all core investigative artifacts:
  - **Investigation Graph:** Node and edge generation mapping process lineage, network connections, and file targets.
  - **Timeline:** Chronological sequencing of multi-source endpoint events.
  - **Process Tree:** Hierarchical parent-child process relationship reconstruction.
  - **Attack Reconstruction:** MITRE ATT&CK technique mapping and attack stage synthesis.
  - **Forensic Case Report:** Structured textual investigation reports detailing case metadata, findings, evidence provenance, and chain of custody.
- **Evaluation Method:** Automated investigation validator (`validate_investigation`) and unit/integration verification tests.
- **Numerical Result:** Verified (All investigation modules compile and render complete diagnostic artifacts).
- **Status:** Verified.

### 7. Integrity & Chain-of-Custody
- **Definition:** Verifies cryptographic SHA-256 integrity functions for evidence files, report manifests, database backups, and tamper-evident chronological case custody logs.
- **Evaluation Method:** Automated validation of `sha256_file()`, `verify_file()`, `verify_manifest()`, and `EvidenceStore.record_custody_event()`.
- **Numerical Result:** Verified (SHA-256 hash digests and manifest verifications pass exact cryptographic checks; custody logs maintain strict chronological ordering).
- **Status:** Verified.

### 8. Automated Testing
- **Definition:** Verification that all core modules, CLI commands, collectors, detectors, parsers, and evaluation routines pass automated regression and unit test suites.
- **Evaluation Method:** Pytest test suite executed in the current environment.
- **Numerical Result:** **516 passed** (516 of 516 tests passing, 0 failures).
- **Status:** Verified.

---

## Evaluation Summary Table

| Metric | Evaluation Method | Result | Status |
| :--- | :--- | :--- | :--- |
| **Detection Accuracy** | Controlled test cases across mixed benign & ransomware behavior | TO BE MEASURED EXPERIMENTALLY | Pending |
| **Detection Rate** | Positive ransomware-like scenarios (`vssadmin`, mass edit, ransom notes) | TO BE MEASURED EXPERIMENTALLY | Pending |
| **False Positive Rate** | Benign baseline scenarios (`normal_activity.json`) | TO BE MEASURED EXPERIMENTALLY | Pending |
| **Detection Time** | Event-to-finding timestamp and latency benchmarking | TO BE MEASURED EXPERIMENTALLY | Pending |
| **Evidence Traceability** | `finding_evidence` junction table & `validate_investigation` | 100% Traceable Evidence-to-Finding Linkage | Verified |
| **Investigation Completeness** | Investigation Graph + Timeline + Process Tree + Reconstruction + Report | Complete Multi-Artifact Synthesis Verified | Verified |
| **Integrity & Chain-of-Custody**| SHA-256 file/manifest verification & chronological custody logs | Cryptographic Validation & Custody Log Verified | Verified |
| **Automated Testing** | Full pytest test suite (`tests/`) | 516 Passed / 0 Failed | Verified |

---

## Dedicated Evaluation Test Suite

The automated evaluation framework is implemented in `tests/test_performance_evaluation.py`.

It can be executed at any time using:

```powershell
# Set PYTHONPATH and execute evaluation test suite
$env:PYTHONPATH="src"
python -m pytest tests/test_performance_evaluation.py -v
```

To run the complete RansomEye test suite:

```powershell
$env:PYTHONPATH="src"
python -m pytest tests/ -v
```
