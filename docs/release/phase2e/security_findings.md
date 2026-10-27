# RansomEye Security & Vulnerability Review — Phase 2E

**Date:** October 26, 2026  
**Auditor:** Application Security Reviewer & DFIR Security Architect  
**Scope:** Standalone Executable (`dist_isolated\RansomEye.exe`), Source Code (`src/ransomeye/`), Web Console (`static/`), and Storage Layer (`storage.py`)  
**Commit Audited:** `da617241d4e8a597b556869e5bf59575955935af`

---

## 1. Executive Summary

A comprehensive application security and binary provenance assessment was conducted on the RansomEye release candidate artifacts. The overall security architecture exhibits strong defensive design, including:
- Safe DOM construction in the web console with **zero** `innerHTML` usage.
- Strict path canonicalization preventing directory traversal in HTTP file serving and case exports.
- Exclusive file descriptor creation (`O_CREAT | O_EXCL`) preventing accidental file overwrites.
- Append-only SQL triggers defending chain-of-custody integrity.
- Exploit mitigations compiled into the PE binary (ASLR, High-Entropy 64-bit ASLR, DEP/NX, CFG).

However, specific security findings have been identified and categorized below to govern release readiness.

---

## 2. Findings Log

### FINDING-01: Standalone Binary is Unsigned (SmartScreen / Provenance Risk)
- **Severity:** HIGH (Release Blocker for General Distribution)
- **Status:** **VERIFIED**
- **Evidence:**
  `pefile` analysis of `dist_isolated\RansomEye.exe`:
  ```text
  IMAGE_DIRECTORY_ENTRY_SECURITY VirtualAddress: 0x0, Size: 0
  Signed: False
  ```
- **Impact:**
  When downloaded or executed on a clean Windows machine without prior local execution history, Microsoft Defender SmartScreen will block the executable with a red/blue warning dialog ("Windows protected your PC: Unknown publisher"). In corporate environments with strict AppLocker or Windows Defender Application Control (WDAC) policies, unsigned binaries cannot be launched.
- **Recommended Remediation:**
  Digitally sign the final distribution binary using an Authenticode Code Signing Certificate (EV or Azure Trusted Signing) with an RFC 3161 SHA-256 timestamp.

---

### FINDING-02: Automatic In-Place Database Schema Upgrades Upon Instantiation
- **Severity:** MEDIUM
- **Status:** **RESOLVED (Phase 2F)**
- **Evidence:**
  `src/ransomeye/storage.py` lines 185-360:
  Implemented `_create_and_verify_migration_backup` using SQLite's online backup API (`connection.backup`) before applying any schema modification. The safeguard:
  1. Detects schema version prior to any writes.
  2. Generates a non-colliding backup path (`<db>.bak`, `<db>.v<ver>.bak`, or unique timestamped fallback).
  3. Verifies backup readability and pre-migration version before proceeding.
  4. Aborts migration safely without destroying pre-migration state if backup or migration fails.
  5. Tested and verified in `tests/test_safe_migration.py` (9 passed, 0 failed).

---

### FINDING-03: Permissive CORS Configuration on Analyst HTTP Console
- **Severity:** LOW
- **Status:** **RESOLVED (Phase 2F)**
- **Evidence:**
  `src/ransomeye/dashboard_server.py` lines 100-142:
  Wildcard `Access-Control-Allow-Origin: *` was completely removed. Replaced with strict origin validation:
  1. No CORS headers are emitted for same-origin or missing Origin requests.
  2. Cross-origin access is permitted only for explicitly configured trusted origins (`ALLOWED_ORIGINS` / `--allowed-origin` / `RANSOMEYE_ALLOWED_ORIGINS`).
  3. Untrusted preflight OPTIONS requests are rejected with HTTP 403 Forbidden without CORS headers.
  4. Tested and verified in `tests/test_dashboard_cors.py` (7 passed, 0 failed).

---

### FINDING-04: Potential Command-Line Secret Disclosure in Unredacted Case Reports
- **Severity:** LOW
- **Status:** **VERIFIED**
- **Evidence:**
  `src/ransomeye/report.py` lines 300-330 and `src/ransomeye/pdf_report.py` lines 410-440 render raw event command lines directly into generated text and PDF reports:
  ```python
  report_lines.append(f"  Command: {cmd}")
  ```
- **Impact:**
  If an adversary or administrative script invoked commands containing plain-text passwords, API tokens, or encryption keys (e.g. `net use \\share /user:admin Secret123`), the unredacted string appears verbatim in exported reports and PDF documents. If the report is subsequently shared across ticketing systems or external incident response partners, sensitive credentials may be unintentionally leaked.
- **Recommended Remediation:**
  Introduce an optional `--redact` flag on `ransomeye report` that scans command lines for common credential assignment patterns (`/p:`, `-password`, `api_key=`, `Bearer`) and masks them with `[REDACTED]`.

---

### FINDING-05: Absence of Automated SmartScreen Reputation & WDAC Testing
- **Severity:** INFORMATIONAL
- **Status:** **NOT VERIFIED / PROPOSED**
- **Evidence:**
  Testing was conducted on a developer workstation where binary execution is unrestricted. No automated test exists in CI/CD to verify behavior under Windows Defender Application Control (WDAC) user-mode enforcement or clean-profile SmartScreen prompt.
- **Impact:**
  Real-world deployment behavior on managed corporate workstations cannot be completely guaranteed until verified on an enterprise-managed testbed.
- **Recommended Remediation:**
  Incorporate a clean Windows Sandbox or VM smoke test step in the release engineering pipeline prior to customer-facing distribution.

---

## 3. Exploit Mitigations & Binary Characteristics Review

Binary mitigation flags were verified on `dist_isolated\RansomEye.exe` via PE directory inspection:

| Mitigation Control | Compiler Flag / PE Header | Verification Status | Evaluation |
| :--- | :--- | :---: | :--- |
| **Data Execution Prevention (DEP / NX)** | `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | **ENABLED** | Prevents execution of shellcode from data heaps and stacks. |
| **Address Space Layout Randomization (ASLR)** | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | **ENABLED** | Randomizes memory layout of executable code on launch. |
| **High Entropy 64-bit ASLR** | `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` | **ENABLED** | Extends ASLR randomization space to full 64-bit virtual memory. |
| **Control Flow Guard (CFG)** | `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | **ENABLED** | Restricts indirect call targets to valid entry points. |
| **Structured Exception Handling (SEH)** | `IMAGE_DLLCHARACTERISTICS_NO_SEH` (Unset) | **PROTECTED** | Standard x64 table-based exception handling; not susceptible to x86 SEH overwrites. |

---

## 4. Provenance and Licensing Review

All 19 components in the dependency inventory were inspected:
- **MIT License:** `altgraph`, `pefile`, `charset-normalizer`, `pluggy`, `12X reference algorithms`.
- **BSD 3-Clause / BSD 2-Clause:** `reportlab`, `pypdf`, `pywin32-ctypes`, `psutil`.
- **HPND (Historical Permission Notice and Disclaimer):** `pillow`.
- **Apache 2.0:** `watchdog`.
- **PyInstaller Bootloader Exception:** PyInstaller 6.22.3 uses GPLv2 with an explicit exception clause:
  > *"As a special exception to the GPL, you may package your software using PyInstaller and distribute the resulting executable under terms of your choice, including commercial proprietary terms."*
- **Copyleft / Viral License Assessment:** **CLEAN**. There are zero unshielded GPL or AGPL libraries in the RansomEye runtime.
