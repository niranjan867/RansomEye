# RansomEye Release Go / No-Go Governance Checklist — Phase 3

**Date:** October 26, 2026  
**Product:** RansomEye DFIR Platform (`RansomEye.exe`)  
**Target Release:** Release Candidate 3 (`v1.0.0-rc.3`)  
**Candidate Location:** `dist_phase2g_rc\RansomEye.exe`  
**Candidate SHA-256:** `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`  

---

## 1. Governance Evaluation Summary

| Gate | Category | Status | Blocking Condition |
| :---: | :--- | :---: | :--- |
| **Gate 1** | Build Provenance & Packaging Integrity | **GO (WITH LIMITATIONS)** | Source snapshot retroactive; dependency pinning absent |
| **Gate 2** | Automated Regression & Empirical Validation | **GO (HISTORICAL EVIDENCE)** | Raw pytest log absent; PDF test excluded |
| **Gate 3** | Data & Baseline Asset Preservation | **GO (COMPLETED)** | None |
| **Gate 4** | Application Security & Licensing Review | **GO (COMPLETED)** | FINDING-02 & FINDING-03 resolved |
| **Gate 5** | Authenticode Code Signing & Identity | **NO-GO (BLOCKED)** | **Awaiting Enterprise Certificate Provisioning** |
| **Gate 6** | RFC 3161 Timestamping & Verification | **PENDING GATE 5** | Depends on Gate 5 execution |
| **Gate 7** | Clean-Machine & SmartScreen Emulation | **PENDING GATE 5** | Awaiting signed binary artifact |
| **Gate 8** | Release Documentation & Manifest Audit | **GO (TEMPLATE STAGED)** | Final signed manifest not yet generated |
| **Gate 9** | Formal Distribution Approval | **NO-GO (BLOCKED)** | Gate 5, 6, 7 must be verified first |

**Overall Release State:** **`NOT READY`** — blocked on certificate provisioning (Gate 5.3/5.4). See §4 Release State Definitions below.

---

## 2. Detailed Itemized Checklist

### Gate 1: Candidate Hash & Build Provenance
- [x] **1.1 Candidate Exists in Approved Path:** `dist_phase2g_rc\RansomEye.exe` verified present (`21,100,919 bytes`).
- [x] **1.2 Cryptographic Hash Match:** Freshly calculated SHA-256 matches manifest exactly: `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`.
- [x] **1.3 PE Header Inspection:** AMD64 architecture (`0x8664`), Console subsystem (`3`), Characteristics (`0x22`).
- [x] **1.4 Embedded Manifest:** UAC execution level `asInvoker` present in PE resource tree.
- [x] **1.5 Build Toolchain Audit:** PyInstaller 6.22.3, Python 3.13.15, Windows 11 SDK 10.0.26100.0 logged in `build_provenance.json`.
- [x] **1.6 Source Snapshot:** Retroactive capture created in Phase 3F. Archive SHA-256 `92285336A76C20D5576D1201C3522411129F35D9B07275C1CCDA8E1DA5667485` with 45/45 entries present. **Limitation:** this snapshot was captured after the build and does not cryptographically prove the exact source consumed during the Phase 2G build. Build-time per-file hashes were not recorded. Corroborating evidence only.
- [ ] **1.7 Dependency Pinning:** **[NOT SATISFIED]** No `requirements.txt`, `poetry.lock`, `uv.lock`, or other lockfile exists. Transitive dependency versions consumed during the Phase 2G build cannot be reconstructed. Requires documented risk acceptance or approved resolution before release.

---

### Gate 2: Regression & Packaged Capability Tests
- [x] **2.1 Full Pytest Regression Suite:** 1,011 passed, 0 failed, 0 skipped, 158.56s runtime (Phase 3C historical report evidence; `tests/test_pdf_report.py` excluded — `pypdf` unavailable; no raw pytest log was persisted to disk).
- [x] **2.2 Packaged Database Migration Safety:** All 6 scenarios passed (current-schema no backup, historical backup, collision handling, backup failure abort, migration failure preservation, fresh DB initialization).
- [x] **2.3 Packaged Dashboard CORS Hardening:** All 10 scenarios passed (wildcard removed, 403 preflight rejection, explicit allowlist, PDF download).
- [x] **2.4 Packaged DFIR Workflows:** All 12 forensic capabilities passed (CLI help, static PE, script AST, PCAP, text report, PDF report, case lifecycle, custody ledger, IOC extraction, kill-chain reconstruction, dashboard server, PDF endpoint).
- [x] **2.5 Clean-Environment Execution:** All 3 scenarios passed in stripped shell (0 host Python, sanitized PATH).
- [ ] **2.6 Retained Raw Pytest Log:** **[NOT SATISFIED]** No raw pytest log file was persisted to disk during Phase 3C. The manifest's `capture_log_sha256` remains `null`. A fresh `pytest -q` capture with output redirected to a persistent log file is required for manifest finalization.
- [ ] **2.7 PDF Report Test Coverage:** **[NOT SATISFIED]** `tests/test_pdf_report.py` was excluded from all known runs because `pypdf` is not installed. Requires operator decision: install `pypdf` and run the test, or document formal exclusion with risk acceptance.

---

### Gate 3: Database & Baseline Asset Preservation
- [x] **3.1 Production Database Invariant:** `data\ransomeye.db` preserved with exact SHA-256: `9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB`.
- [x] **3.2 Baseline Executable Invariant:** `dist\RansomEye.exe` preserved with exact SHA-256: `65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542`.
- [x] **3.3 Phase 2D Executable Invariant:** `dist_isolated\RansomEye.exe` preserved with exact SHA-256: `49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E`.
- [x] **3.4 Build Workspaces Preserved:** `build\`, `build_isolated\`, `build_phase2g_rc\` preserved intact.
- [x] **3.5 Git Working Tree Preservation:** Branch `integration/12x-capabilities`, HEAD `da617241d4e8a597b556869e5bf59575955935af` unmodified; `git diff --check` passes cleanly.

---

### Gate 4: Security & Licensing Review
- [x] **4.1 CORS Hardening (FINDING-02):** Wildcard removed; explicit origin allowlist active; untrusted preflight returns 403. **[RESOLVED]**
- [x] **4.2 Pre-Migration Backup (FINDING-03):** Verified online SQLite backup implemented; DDL abort on error. **[RESOLVED]**
- [x] **4.3 In-Memory Local Dashboard (FINDING-05):** Localhost-only binding default (`127.0.0.1`); reverse proxy requirement documented. **[DOCUMENTED]**
- [x] **4.4 Third-Party Licensing:** `THIRD_PARTY_NOTICES.md` bundled into standalone distribution package.
- [ ] **4.5 Unsigned Executable (FINDING-01):** Candidate remains unsigned. **[BLOCKED - PENDING GATE 5]**

---

### Gate 5: Authenticode Code Signing & Identity
- [x] **5.1 SignTool Availability:** Official Microsoft SignTool 10.0.26100.0 identified at `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe`.
- [x] **5.2 Safe Automated Script Staged:** `scripts/sign_release_candidate.ps1` prepared and verified (fail-closed, non-destructive, non-executing).
- [ ] **5.3 Code Signing Certificate Available:** **[NOT SATISFIED]** No code-signing certificate currently present in `CurrentUser\My` or `LocalMachine\My`.
- [ ] **5.4 Azure Trusted Signing Account:** **[NOT SATISFIED]** No Azure Trusted Signing profile or `metadata.json` configured on this workstation.
- [ ] **5.5 Authenticode Signing Execution:** **[NOT EXECUTED]** Awaiting certificate provisioning and explicit administrative approval.
- [ ] **5.6 Signature Status Verification:** Awaiting signed binary in `dist_phase3_signed\RansomEye.exe`.

---

### Gate 6: RFC 3161 Timestamping
- [x] **6.1 Timestamp Standard Defined:** Enforces `/td SHA256 /tr <TSA_URL>` using RFC 3161 compliant server.
- [ ] **6.2 Timestamp Applied to Binary:** **[PENDING GATE 5]**
- [ ] **6.3 Timestamp Verified via SignTool:** **[PENDING GATE 5]**

---

### Gate 7: Clean-Machine & SmartScreen Validation
- [x] **7.1 Clean Host Command Verification:** Unsigned candidate validated in stripped-environment execution.
- [ ] **7.2 Clean Windows VM Sandbox Deployment:** **[PENDING SIGNED BINARY]** Test signed executable on independent Windows 11 machine without developer tools.
- [ ] **7.3 Windows Defender SmartScreen Evaluation:** Document SmartScreen warning behavior on clean machine.

---

### Gate 8: Release Documentation & Manifest Integrity
- [x] **8.1 Signing Readiness Report:** Documented at `docs/release/phase3/signing_readiness_report.md`.
- [x] **8.2 Signing Workflow Specification:** Documented at `docs/release/phase3/signing_workflow.md`.
- [x] **8.3 Release Manifest Template:** Structured at `docs/release/phase3/release_manifest.template.json`.
- [x] **8.4 Go/No-Go Checklist:** Staged at `docs/release/phase3/release_go_no_go_checklist.md`.
- [ ] **8.5 Final Signed Manifest:** `dist_phase3_signed/signed_artifact_manifest.json` (Generated upon signing execution).

---

### Gate 9: Formal Distribution Approval
- [ ] **9.1 Lead Release Engineer Sign-Off:** Pending completion of Gates 5 through 7.
- [ ] **9.2 Product Security Lead Sign-Off:** Pending Authenticode verification.
- [ ] **9.3 DFIR Incident Response Product Owner Approval:** Pending final release review.

---

## 3. Required Action Sequence

To advance from **NOT READY** to **RELEASE APPROVED**, the following steps must be completed in order:

1. **Provision Certificate Material:**
   - **Option A (Recommended):** Enroll in Azure Trusted Signing; configure `metadata.json` and install `Azure.CodeSigning.Dlib.dll`.
   - **Option B:** Procure an enterprise Code Signing hardware token (USB token / HSM); install vendor drivers; verify certificate visibility in `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`.
2. **Resolve outstanding advisory items (recommended before signing):**
   - Capture a fresh `pytest -q` log and record its SHA-256 in the manifest (Gate 2.6).
   - Decide on `pypdf` / PDF test: install and run, or formally exclude with risk acceptance (Gate 2.7).
   - Decide on dependency pinning: generate a lockfile, or formally accept the risk (Gate 1.7).
3. **Obtain written signing authorization:** The Lead Release Engineer (or designated authority) reviews the evidence package and issues a written authorization naming: certificate thumbprint or Azure identity, timestamp URL, candidate hash, and the authorized operator.
4. **Execute `scripts/sign_release_candidate.ps1`** with the authorized parameters.
5. **Verify signed binary:** Confirm Authenticode status, timestamp countersigner, and protected-artifact invariants (Gates 5.5, 5.6, 6.2, 6.3).
6. **Perform clean-machine SmartScreen validation** on a clean Windows 11 VM (Gate 7.2, 7.3).
7. **Collect three formal sign-offs** (Gate 9.1, 9.2, 9.3).
8. **Finalize and distribute** the signed release with the completed `signed_artifact_manifest.json`.

---

## 4. Release State Definitions

The following states describe the release lifecycle. Each transition requires the evidence listed. Documents in this repository must use these terms consistently and must not use `READY FOR SIGNING` as an ambiguous substitute.

| State | Definition | Minimum evidence to enter |
| :--- | :--- | :--- |
| **NOT READY** | One or more technical prerequisites are unmet; the signing workflow cannot execute. | Default state. |
| **READY FOR HUMAN SIGNING APPROVAL** | All technical prerequisites for signing are met. Human authorization has not been granted. | Gates 1–4 satisfied (including retained raw test log if required by policy). Gate 5.1 + 5.2 satisfied (SignTool + script). Gate 5.3 or 5.4 satisfied (certificate exists). Gate 8 template staged. |
| **AUTHORIZED TO SIGN** | A designated human has reviewed the evidence and explicitly authorized the signing operation, naming the certificate identity, timestamp URL, candidate hash, and authorized operator. | All of the above + written authorization. |
| **SIGNED — VERIFICATION PENDING** | The signing script completed with exit code 0. Post-signing verification has not been independently confirmed. | Script step 5 exit code 0. `dist_phase3_signed\RansomEye.exe` exists. |
| **SIGNED — VERIFICATION PASSED** | Independent verification confirms valid Authenticode, valid RFC 3161 timestamp, and all protected-artifact invariants preserved. | Script steps 6 + 7 passed. `signed_artifact_manifest.json` generated. Gates 3, 5.6, 6.2, 6.3 satisfied. |
| **RELEASE APPROVED** | All 9 gates are GO. Three formal sign-offs recorded. Distribution is authorized. | Gates 1–9 all satisfied. Gate 7 (SmartScreen) validated. Gate 9 (three sign-offs) recorded. |
| **RELEASE REJECTED** | A gate has failed and cannot be remediated within the current release cycle. | Any gate marked FAIL with no remediation path. |

**Current release state as of Phase 3L (2026-10-27): `NOT READY`** — blocked on code-signing certificate provisioning (Gate 5.3/5.4).
