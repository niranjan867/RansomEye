# RansomEye Phase 3 — Authenticode Signing Workflow Specification

**Document Version:** 1.0  
**Target Application:** RansomEye DFIR Platform (`RansomEye.exe`)  
**Script Implementation:** [scripts/sign_release_candidate.ps1](file:///d:/nira/project/RansomEye/scripts/sign_release_candidate.ps1)  
**Security Classification:** Release Engineering & Governance  

---

## 1. Architectural Overview

The RansomEye code signing workflow enforces a strict, auditable separation between **unsigned compilation artifacts** and **signed distribution binaries**.

```
+-------------------------------------------------------------+
| Phase 2G Build Stage (Completed & Verified)                 |
| - Unsigned Candidate: dist_phase2g_rc\RansomEye.exe         |
| - SHA-256: F22F93B2A5855FA906CF8816EB893D77769FCE0952...     |
+-------------------------------------------------------------+
                              |
                              | [Non-destructive Copy & Verification]
                              v
+-------------------------------------------------------------+
| Phase 3 Signing Stage (scripts\sign_release_candidate.ps1)  |
| 1. Cryptographic pre-signing invariant verification         |
| 2. Input candidate SHA-256 validation against manifest      |
| 3. Copy to isolated target: dist_phase3_signed\RansomEye.exe|
| 4. SignTool execution (/fd SHA256 /tr <TSA> /td SHA256)     |
| 5. Post-sign Authenticode verification & timestamp check    |
| 6. Final SHA-256 calculation & signed_artifact_manifest.json|
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Verified Output Artifacts                                   |
| - Signed Binary: dist_phase3_signed\RansomEye.exe           |
| - Provenance: dist_phase3_signed\signed_artifact_manifest   |
| - Audit Logs: dist_phase3_signed\logs\signtool_*.log        |
+-------------------------------------------------------------+
```

---

## 2. Mandatory Security Rules & Invariants

1. **Strict Input Confinement:** The signing script strictly refuses to sign any binary located outside the verified candidate directory (`dist_phase2g_rc\`). Arbitrary file paths are rejected immediately.
2. **Pre-Sign Checksum Enforcement:** The binary's SHA-256 is recalculated and verified against the known candidate hash (`F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`) before any signing tool is called.
3. **Zero In-Place Overwrites:** The original candidate binary in `dist_phase2g_rc\` is NEVER modified or signed in-place. The file is copied to `dist_phase3_signed\` and signed there.
4. **Digest & Timestamp Standards:**
   - File digest: Strictly `SHA-256` (`/fd SHA256`).
   - Timestamp digest: Strictly `SHA-256` (`/td SHA256`).
   - Timestamp protocol: RFC 3161 compliant (`/tr <URL>`).
5. **No Embedded Secrets:** Passwords, private keys, or API tokens MUST NEVER be committed to Git, hardcoded in scripts, or logged to console output. Environment variables are NOT a secure credential channel — they are inherited by child processes, visible to any process that can enumerate command-line arguments while SignTool is running, and routinely captured by shell transcripts and CI log collectors. The signing script already redacts `/p <value>` from every diagnostic line it emits, but the stronger controls are:
   - **Preferred:** use a hardware token (`-SigningMethod LocalCertStore -CertThumbprint <SHA1>`), Azure Trusted Signing (`-SigningMethod AzureTrustedSigning` with an explicit absolute `-AzureDlibPath` and a metadata file held outside the Git working tree), or Azure Key Vault via a dedicated `azuresigntool` invocation.
   - **Acceptable fallback for isolated lab builds only:** `-SigningMethod PfxFile` with the password supplied via SignTool's interactive prompt (no `RANSOMEYE_SIGN_PFX_PASSWORD` set); this still exposes the password briefly on the SignTool command line but never persists it in a shell environment or transcript.
   - **Not acceptable for any public-release signing:** committing a PFX file or its password to Git, hardcoding either in scripts, or exporting `RANSOMEYE_SIGN_PFX_PASSWORD` on a shared or CI workstation.
6. **Fail-Closed Design:** Any failure in toolchain resolution, certificate verification, timestamping, or post-signing hash validation results in immediate script abortion with non-zero exit code.

---

## 3. Operational Execution Guide

### Option A: Signing via Windows Certificate Store (Hardware Token / Smart Card)

When using an EV Code Signing USB token (e.g. YubiKey, SafeNet, Thales):
1. Insert the hardware token into the signing workstation.
2. Ensure vendor smart card drivers (e.g. SafeNet Authentication Client) are running.
3. Locate and verify SignTool from the installed Windows SDK:
   ```powershell
   $SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
   Get-AuthenticodeSignature $SignTool   # Must show Valid, signed by Microsoft
   ```
   The signing script requires `-SignToolPath` with the absolute path to `signtool.exe`. It will not search PATH or SDK directories automatically. The operator must obtain SignTool from a trusted Windows SDK installation and verify its provenance before use.
4. Identify the certificate thumbprint:
   ```powershell
   Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert | Select-Object Subject, Thumbprint
   ```
5. Execute the signing script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\sign_release_candidate.ps1 `
       -SigningMethod LocalCertStore `
       -CertThumbprint "<THUMBPRINT_HEX>" `
       -SignToolPath "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" `
       -TimestampUrl "http://timestamp.digicert.com"
   ```
6. Enter the hardware token PIN when prompted by the CSP dialog.

---

### Option B: Signing via Azure Trusted Signing (Cloud-Native Identity)

When using Microsoft Azure Trusted Signing:
1. Ensure `.NET 8.0 Runtime` is installed.
2. Ensure `Azure.CodeSigning.Dlib.dll` is installed in the Windows SDK directory or system PATH.
3. Prepare a secure `azure_metadata.json` file outside the Git working tree (e.g. in `C:\RansomEyeSigning\azure_metadata.json`):
   ```json
   {
     "Endpoint": "https://eus.codesigning.azure.net/",
     "CodeSigningAccountName": "RansomEyeOrg",
     "CertificateProfileName": "RansomEyePublicProfile",
     "CorrelationId": "ransomeye-release-phase3"
   }
   ```
4. Authenticate to Azure via Azure CLI (`az login`) or Managed Identity.
5. Execute the signing script (note: `-SignToolPath` is required):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\sign_release_candidate.ps1 `
       -SigningMethod AzureTrustedSigning `
       -AzureMetadataFile "C:\RansomEyeSigning\azure_metadata.json" `
       -SignToolPath "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" `
       -TimestampUrl "http://timestamp.acs.microsoft.com"
   ```

---

## 4. Verification and Audit Procedure

Upon script completion, verify:

1. **SignTool Exit Status:** Inspect `dist_phase3_signed\logs\signtool_sign.log` for `Number of files successfully Signed: 1`.
2. **PowerShell Signature Status:**
   ```powershell
   Get-AuthenticodeSignature .\dist_phase3_signed\RansomEye.exe | Format-List
   ```
   Must display `Status: Valid`.
3. **SignTool Verification:**
   ```powershell
   & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" verify /pa /v .\dist_phase3_signed\RansomEye.exe
   ```
   Must display:
   - `Successfully verified: .\dist_phase3_signed\RansomEye.exe`
   - `Hash of file (sha256): ...`
   - `Signing Certificate Chain: ...`
   - `The signature is timestamped: ...`
4. **Provenance Linkage:** Inspect `dist_phase3_signed\signed_artifact_manifest.json` and ensure:
   - `original_candidate.sha256` matches `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`.
   - `invariants.production_db_preserved` is `true`.
   - `invariants.unsigned_candidate_preserved` is `true`.

---

## 5. Clean-Machine Validation Procedure

Before public distribution, the signed executable must be tested on a clean Windows VM or sandbox:

1. Transfer `dist_phase3_signed\RansomEye.exe` to a clean Windows 11 machine with standard SmartScreen and UAC settings enabled.
2. Double-click or run from command prompt.
3. Confirm that the Digital Signatures tab in File Properties shows:
   - Valid signature.
   - Valid timestamp.
   - Trusted root certification authority chain.
4. Execute `RansomEye.exe --help`, `static`, and `dashboard` to verify normal functionality.
