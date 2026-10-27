# RansomEye Authenticode Code Signing Architecture & Plan — Phase 2E

**Date:** October 26, 2026  
**Auditor / Security Architect:** Senior Windows Software Release Engineer & Security Reviewer  
**Target Binary:** `RansomEye.exe` (Standalone Windows Executable)

---

## 1. Executive Summary

Digital code signing using Microsoft Authenticode is mandatory for RansomEye before public distribution. Signing establishes publisher identity, guarantees binary integrity against tampering, and prevents Microsoft Defender SmartScreen execution blocks on clean Windows endpoints.

This document details the certificate architecture, key protection requirements, signing command parameters, timestamping infrastructure, and post-signing validation procedures.

---

## 2. Certificate Authority & Certificate Options

### 2.1 Certificate Tiers

| Certificate Type | CA Options | Key Storage Requirement | SmartScreen Reputation | Suitability for RansomEye |
| :--- | :--- | :--- | :--- | :--- |
| **Cloud HSM / Azure Trusted Signing** *(Recommended)* | Microsoft Azure Trusted Signing (formerly Identity Verification) | FIPS 140-2 Level 3 Azure Key Vault / Cloud HSM | **Immediate trust** via Microsoft identity federation | **Highest** (Eliminates physical USB token; integrates with CI/CD runners) |
| **Extended Validation (EV) Code Signing** | DigiCert, Sectigo, GlobalSign | Physical USB token (e.g. YubiKey FIPS) or cloud HSM | **Immediate trust**; bypasses SmartScreen immediately | **High** (Standard enterprise CA approach) |
| **Standard / Organization Validation (OV)** | DigiCert, Sectigo | FIPS 140-2 Level 2 USB token (mandated since June 2023) | Builds reputation gradually; initial SmartScreen warnings likely | **Medium** (Subject to initial user friction) |
| **Self-Signed / Internal Enterprise CA** | Internal Active Directory CS | Software PFX or internal HSM | Trusted only on domain-joined machines with root CA installed | **Development / Internal Testing Only** |

### 2.2 Recommendation
Deploy **Azure Trusted Signing** or a **DigiCert EV Code Signing Certificate**. As of June 1, 2023, CA/Browser Forum baseline requirements mandate that all private keys for code signing certificates must be stored on hardware security modules (HSM) certified to at least FIPS 140-2 Level 2 or Common Criteria EAL 4+. Software-based `.pfx` files on developer disks are no longer issued by commercial CAs.

---

## 3. Secure Private Key Handling & Pipeline Integration

To protect the private signing key from compromise or unauthorized signing:
1. **Zero Key Material on Developer Workstations:** The private key must never exist as a bare file in the project repository or on local developer machines.
2. **Hardware or Cloud Access Controls:**
   - For Azure Trusted Signing: Use Azure CLI / Azure DevOps authentication with role-based access control (RBAC) restricted to the `Release Signing` role.
   - For Hardware Token: The token requires a physical PIN prompt for each signing transaction.
3. **Audit Logging:** Every signing operation must generate a logged audit event recording the build ID, Git commit hash, and signing identity.

---

## 4. Signing Specification & Command Syntax

### 4.1 Cryptographic Parameters
- **Digest Algorithm:** `SHA256` (SHA-1 is deprecated and rejected by modern Windows releases).
- **File Digest:** `SHA256` (`/fd SHA256`).
- **Timestamp Digest:** `SHA256` (`/td SHA256`).
- **Timestamp Authority (RFC 3161):** Authenticated RFC 3161 compliant server (e.g. `http://timestamp.digicert.com` or `http://timestamp.sectigo.com`).
  - *Critical Rule:* An accurate timestamp ensures that the digital signature remains valid even after the code signing certificate expires.

### 4.2 Standard Signing Invocation (`signtool.exe`)

```powershell
# Prerequisites: Windows SDK installed, signtool.exe available on PATH

$SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
$TargetBinary = "dist_isolated\RansomEye.exe"
$TimestampServer = "http://timestamp.digicert.com"
$Description = "RansomEye DFIR Console"
$WebUrl = "https://github.com/niranjan867/RansomEye"

# Execution using Hardware Token or Windows Certificate Store:
& $SignTool sign `
    /v `
    /s "My" `
    /n "RansomEye Technologies" `
    /fd SHA256 `
    /tr $TimestampServer `
    /td SHA256 `
    /d $Description `
    /du $WebUrl `
    $TargetBinary
```

### 4.3 Azure Trusted Signing Invocation (Azure dlib)

```powershell
# Using the Azure Trusted Signing dlib plugin:
& $SignTool sign `
    /v `
    /dlib "C:\Tools\AzureTrustedSigning\Azure.CodeSigning.Dlib.dll" `
    /dmdf "metadata.json" `
    /fd SHA256 `
    /tr "http://timestamp.acs.microsoft.com" `
    /td SHA256 `
    $TargetBinary
```

---

## 5. Signature Verification & Validation Procedure

Following signing, the binary must undergo automated verification before release:

### Step 1: SignTool Direct Verification
```powershell
& $SignTool verify /pa /v dist_isolated\RansomEye.exe
```
- `/pa`: Uses the Default Authentication Verification Policy (verifies trust chain to a trusted root CA).
- **Expected Returncode:** `0` (Success: File is signed and chain is valid).

### Step 2: PowerShell Authenticode Cmdlet
```powershell
$sig = Get-AuthenticodeSignature -FilePath "dist_isolated\RansomEye.exe"
$sig | Format-List Status, StatusMessage, Path, SignerCertificate, TimeStamperCertificate
if ($sig.Status -ne "Valid") {
    throw "Authenticode signature validation failed: $($sig.StatusMessage)"
}
```
- Verifies:
  - `Status`: `Valid`
  - `SignerCertificate`: Matches official organization subject name.
  - `TimeStamperCertificate`: Non-null and valid.

### Step 3: PE Header Security Directory Inspection
Using Python / `pefile`:
```python
import pefile
pe = pefile.PE("dist_isolated/RansomEye.exe")
sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
assert sec_dir.Size > 0, "Security directory is empty; binary is not signed"
assert sec_dir.VirtualAddress > 0, "Security directory virtual address invalid"
print(f"Verified embedded PKCS#7 certificate size: {sec_dir.Size} bytes")
```

---

## 6. Post-Signing Artifact Manifestation

Because digital signing appends a PKCS#7 certificate table and adjusts PE checksums, **the SHA-256 hash of the binary changes after signing**:
1. Record pre-signing hash in internal release build logs.
2. Sign the binary.
3. Compute the **post-signing SHA-256 hash**.
4. Embed the post-signing hash into `release_manifest.json` and publish it alongside the download links.
5. Never alter or rebuild the executable after signing (any edit invalidates the signature).

---

## 7. Clean-Machine Verification Test

Before authorizing general download:
1. Boot a fresh Windows 11 sandbox or virtual machine without developer certificates or custom trust stores installed.
2. Download the signed `RansomEye.exe`.
3. Verify that right-clicking the file $\rightarrow$ **Properties** displays the **Digital Signatures** tab with a valid timestamp and certificate status.
4. Launch `RansomEye.exe --help` from Windows Terminal.
5. Verify that Microsoft Defender SmartScreen allows execution without warning prompts.
