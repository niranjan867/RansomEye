# RansomEye Phase 3 — Authenticode Signing Readiness Report

**Date:** October 26, 2026  
**Auditor / Roles:** Senior Windows Release Engineer, Application Security Engineer, DFIR Product Release Manager  
**Repository:** `D:\nira\project\RansomEye`  
**Branch:** `integration/12x-capabilities`  
**Git HEAD:** `da617241d4e8a597b556869e5bf59575955935af`  
**Release Candidate Target:** `dist_phase2g_rc\RansomEye.exe`  
**Candidate SHA-256:** `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`  

---

## 1. Executive Summary

This report evaluates the technical readiness of the RansomEye Phase 2G Release Candidate binary for Authenticode code signing.

The application has achieved technical stabilization. A historical regression pass of 1,011/1,011 automated pytest cases was reported during Phase 3C (historical report evidence only; `tests/test_pdf_report.py` excluded — `pypdf` unavailable; no raw pytest log was persisted to disk). Additionally, 31/31 packaged empirical validation scenarios were reported as passed during Phase 3C. The build toolchain has been verified and isolated. The host environment provides official Windows SDK SignTool tooling (`signtool.exe` version `10.0.26100.0`).

**Release State:** **`NOT READY`** — blocked on certificate provisioning. See `release_go_no_go_checklist.md` §4 for state definitions.

The candidate executable cannot be signed at this stage because:
1. No commercial or enterprise Code Signing certificate exists in the local machine or current user Windows certificate stores (`Cert:\CurrentUser\My`, `Cert:\LocalMachine\My`).
2. No Azure Trusted Signing (formerly Azure Code Signing / ACS) identity profile or Dlib integration configuration is currently provisioned on this workstation.
3. In accordance with strict release safety instructions, no test signing, self-signed certificates, or mock signing have been executed.

Signing is blocked exclusively on external administrative certificate provisioning; the application code, build spec, and automated signing workflow are fully prepared.

---

## 2. Release Candidate Binary Technical Profile

| Metric | Empirical Value |
| :--- | :--- |
| **Path** | `dist_phase2g_rc\RansomEye.exe` |
| **File Size** | `21,100,919 bytes` (20.12 MB) |
| **SHA-256 Checksum** | `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871` |
| **Current Authenticode Status** | `NotSigned` |
| **PE Machine Architecture** | `0x8664` (`IMAGE_FILE_MACHINE_AMD64` — x64 64-bit) |
| **PE Subsystem** | `3` (`IMAGE_SUBSYSTEM_WINDOWS_CUI` — Console Application) |
| **PE Characteristics** | `0x22` (`IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE`) |
| **PE Header TimeDateStamp** | `1793026853` (2026-10-26 15:00:53 UTC) |
| **Embedded Manifest** | Included via PyInstaller bootloader (UAC execution level: `asInvoker`) |
| **Runtime Dependencies** | Standalone bundle: Python 3.13.15 runtime, SQLite 3, ReportLab, Pillow, dependencies packaged |

---

## 3. Host Tooling & SignTool Assessment

An inspection of the local workstation identified the official Windows 11 SDK `signtool.exe`:

- **Primary Path:** `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe`
- **Secondary Path:** `C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe`
- **SDK Build Version:** Windows 11 SDK `10.0.26100.0`
- **Command Support:** Supports `sign`, `timestamp`, `verify`, `/fd SHA256`, `/tr`, `/td SHA256`, `/dlib` (Azure Trusted Signing dynamic library integration).
- **Tooling Assessment:** **SATISFIED** (Official Microsoft SDK SignTool is available).

---

## 4. Microsoft Authenticode & SmartScreen Standards Review

Based on current official Microsoft documentation ([learn.microsoft.com](https://learn.microsoft.com/)):

### 4.1 Mandatory Requirements (Normative)
1. **Cryptographic Digest:** Signatures MUST use the SHA-256 file digest (`/fd SHA256`) and timestamp digest (`/td SHA256`). SHA-1 signatures are deprecated by Windows and rejected by modern Windows Defender and SmartScreen policies.
2. **RFC 3161 Timestamping:** Binaries MUST be timestamped using an RFC 3161 compliant Timestamp Authority (TSA) via SignTool's `/tr <TSA_URL>` parameter. The legacy Authenticode timestamping flag `/t` is obsolete. Timestamping guarantees that signatures remain valid even after the signing certificate expires.
3. **Key Protection:** Standard code-signing certificates issued after June 1, 2023, mandate FIPS 140-2 Level 2 or Common Criteria EAL 4+ hardware security modules (HSMs) or cloud key protection (such as Azure Key Vault or Azure Trusted Signing). Storing raw, unprotected PFX files on disk violates CA/Browser Forum Baseline Requirements.
4. **Enhanced Key Usage (EKU):** The leaf certificate must include Code Signing EKU (`1.3.6.1.5.5.7.3.3`) and chain to a Microsoft-trusted root CA.

### 4.2 Recommendations & SmartScreen Behavior (Informative)
1. **Reputation-Based Trust:** Microsoft Defender SmartScreen evaluates binary reputation in addition to cryptographic validity. Signing an executable with a newly issued certificate will initially display an *"Unknown Publisher / Windows protected your PC"* prompt until the certificate/identity accumulates sufficient download prevalence across the Windows telemetry ecosystem.
2. **Extended Validation (EV) / Cloud Identity:** Using an EV certificate or Microsoft Azure Trusted Signing (formerly Azure Code Signing) provides organizational identity validation that accelerates SmartScreen reputation accumulation compared to standard OV certificates.
3. **Integrity Check Compatibility:** For sensitive DFIR software, binaries signed with cloud-verified identities prevent AV/EDR heuristic false positives during live triage and incident response operations.

---

## 5. Available Signing Mechanisms & Decision Matrix

| Option | Architecture | Private Key Location | CI/CD Compatibility | RansomEye Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Option A: Azure Trusted Signing (Recommended)** | Cloud-native Microsoft service (`dlib.dll` integration) | Azure HSM (no local keys or USB tokens) | Excellent (Native Azure DevOps / GitHub Actions) | **Recommended for production.** Eliminates physical HSM token sharing across analysts. |
| **Option B: Hardware USB Token (YubiKey / SafeNet)** | Local physical smart card token via PKCS#11 / CSP | Hardware Token | Manual release station | **Supported fallback.** Requires physical presence at the build workstation. |
| **Option C: Azure Key Vault + SignTool** | Cloud HSM with AzureSignTool | Azure Key Vault Premium HSM | Excellent | **Enterprise standard.** Supported via `azuresigntool` CLI. |
| **Option D: Local PFX / Cert Store** | Local software certificate | Machine/User certificate store | Local only | **Restricted.** Acceptable only in isolated lab environments; unsafe for public software distribution. |

---

## 6. Gaps & Missing Prerequisites

To proceed with binary signing in Phase 3 execution, the following prerequisites must be provided by the organization:

1. **Certificate Selection & Enrollment:** Selection between Option A (Azure Trusted Signing) and Option B/C (Hardware/Cloud HSM).
2. **Identity Verification:** Completed organization identity verification with a trusted public Certificate Authority or Microsoft Azure.
3. **Workstation Integration:**
   - If using **Azure Trusted Signing**: Install `Azure.CodeSigning.Dlib.dll` and provide `metadata.json` configuring the Azure endpoint, account name, and certificate profile.
   - If using **Local Hardware Token**: Connect smart card / HSM token, install vendor CSP/KSP drivers, and verify certificate visibility in `Cert:\CurrentUser\My`.
4. **Timestamp Service Endpoint:** Confirm organizational approval of external TSA endpoint (e.g. `http://timestamp.digicert.com` or `http://timestamp.sectigo.com`).
5. **Signed Binary Destination:** Ensure `dist_phase3_signed\` directory is approved for receiving signed release packages.
6. **Fresh Regression-Test Capture (recommended):** Re-run `pytest -q` with output redirected to a persistent log file, compute the log's SHA-256, and record it in the release manifest (`capture_log_sha256`). The existing 1,011-test result is historical Phase 3C evidence only; no raw log was persisted.
7. **Dependency Pinning Decision (advisory):** No lockfile (`requirements.txt`, `poetry.lock`, `uv.lock`, etc.) exists. Transitive dependency versions consumed during the Phase 2G build cannot be reconstructed. The organization must either generate a lockfile and verify reproducibility, or formally accept this as a known limitation and record the risk acceptance.
8. **Source Provenance Limitation (advisory):** The source snapshot captured in Phase 3F is retroactive. It does not cryptographically prove that the exact source files were consumed during the Phase 2G build, as build-time per-file hashes were not recorded. This is documented in the release manifest template's `_provenance_limitation` field.

---

## 7. Next Actions Requiring Approval

1. **Decision on Signing Provider:** Authorize either Azure Trusted Signing or Hardware HSM certificate provider.
2. **Administrative Provisioning:** Complete enrollment and supply certificate thumbprint or Azure metadata.
3. **Execution Authorization:** Review the evidence package and issue written authorization naming: certificate identity, timestamp URL, candidate hash (`F22F93B2…CB871`), and authorized operator. See `release_go_no_go_checklist.md` §3 for the full approval sequence and §4 for release state definitions.
