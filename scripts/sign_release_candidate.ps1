<#
.SYNOPSIS
    Signs an isolated RansomEye Release Candidate executable with Authenticode.

.DESCRIPTION
    Automates non-destructive, auditable Authenticode signing for RansomEye:
    - Verifies input executable is within an approved candidate directory (e.g. dist_phase2g_rc).
    - Cryptographically validates input SHA-256 against release manifest before signing.
    - Preserves the original unsigned candidate intact (never overwrites).
    - Copies candidate to an isolated output directory (default: dist_phase3_signed).
    - Requires explicit certificate configuration (Local Cert Store, PFX, or Azure Trusted Signing).
    - Enforces SHA-256 file digest and RFC 3161 compliant timestamping.
    - Captures SignTool stdout/stderr and validates exit code.
    - Verifies resulting signature chain and timestamp using signtool verify and Get-AuthenticodeSignature.
    - Computes signed binary SHA-256 and writes signed_artifact_manifest.json linking candidate provenance.
    - Fails closed on any error, missing prerequisite, or integrity mismatch.

.PARAMETER InputExe
    Path to the approved release candidate executable. Must reside in dist_phase2g_rc.
    Default: dist_phase2g_rc\RansomEye.exe

.PARAMETER ExpectedSha256
    Expected SHA-256 checksum of the unsigned candidate.
    Default: F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871

.PARAMETER OutputDir
    Target directory for the signed executable. Must not be the input candidate directory.
    Default: dist_phase3_signed

.PARAMETER SigningMethod
    The signing mechanism to use: 'LocalCertStore', 'AzureTrustedSigning', or 'PfxFile'.
    Default: LocalCertStore

.PARAMETER CertThumbprint
    SHA-1 thumbprint of code-signing certificate in CurrentUser\My or LocalMachine\My.

.PARAMETER CertSubject
    Subject name or substring of code-signing certificate in Windows Certificate Store.

.PARAMETER AzureMetadataFile
    Path to Azure Trusted Signing JSON metadata configuration file.

.PARAMETER PfxPath
    Path to PKCS#12 (.pfx) certificate file (must be accompanied by secure password prompt).

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority URL. Default: http://timestamp.digicert.com

.PARAMETER SignToolPath
    Mandatory absolute path to signtool.exe from a trusted Windows SDK installation.
    The operator must obtain SignTool from a verified Windows 10/11 SDK and supply its
    full path. The script will not search PATH or SDK directories automatically.

.EXAMPLE
    .\scripts\sign_release_candidate.ps1 -CertSubject "Acme Corp DFIR Security"
#>

[CmdletBinding()]
param(
    [string]$InputExe = "dist_phase2g_rc\RansomEye.exe",
    [string]$ExpectedSha256 = "F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871",
    [string]$OutputDir = "dist_phase3_signed",
    [ValidateSet("LocalCertStore", "AzureTrustedSigning", "PfxFile")]
    [string]$SigningMethod = "LocalCertStore",
    [string]$CertThumbprint = "",
    [string]$CertSubject = "",
    [string]$AzureMetadataFile = "",
    [string]$AzureDlibPath = "",
    [string]$PfxPath = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$SignToolPath = "",
    # Phase 3B D3 remediation: deliberate opt-in required to replace a prior signed
    # output. Even then, the prior artifact is renamed aside, never overwritten.
    [switch]$AllowReplaceSignedOutput
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $ProjectRoot

# Baseline Cryptographic Constants for Invariant Protection
$BASELINE_DB_SHA256 = "9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB"
$BASELINE_ORIG_DIST_SHA256 = "65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542"
$BASELINE_PHASE2D_SHA256 = "49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E"

$DbPath = Join-Path $ProjectRoot "data\ransomeye.db"
$OrigDistExe = Join-Path $ProjectRoot "dist\RansomEye.exe"
$Phase2dExe = Join-Path $ProjectRoot "dist_isolated\RansomEye.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       RANSOMEYE AUTHENTICODE SIGNING WORKFLOW              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot"
Write-Host "Input Exe    : $InputExe"
Write-Host "Output Dir   : $OutputDir"
Write-Host "Method       : $SigningMethod"
Write-Host "Timestamp    : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))"
Write-Host "------------------------------------------------------------"

# ---------------------------------------------------------------------------
# 1. Prerequisite & Cryptographic Invariant Checks
# ---------------------------------------------------------------------------
Write-Host "[1/7] Verifying pre-signing invariants and input integrity..." -ForegroundColor Yellow

# Verify protected assets
if (-not (Test-Path $DbPath)) { throw "Fatal: Production database $DbPath not found." }
$CurrentDbHash = (Get-FileHash -Path $DbPath -Algorithm SHA256).Hash
if ($CurrentDbHash -ne $BASELINE_DB_SHA256) {
    throw "Fatal: Production database modified! Expected $BASELINE_DB_SHA256, got $CurrentDbHash"
}

if (-not (Test-Path $OrigDistExe)) { throw "Fatal: Baseline executable $OrigDistExe not found." }
$CurrentOrigHash = (Get-FileHash -Path $OrigDistExe -Algorithm SHA256).Hash
if ($CurrentOrigHash -ne $BASELINE_ORIG_DIST_SHA256) {
    throw "Fatal: dist\RansomEye.exe modified! Expected $BASELINE_ORIG_DIST_SHA256, got $CurrentOrigHash"
}

if (Test-Path $Phase2dExe) {
    $CurrentPhase2dHash = (Get-FileHash -Path $Phase2dExe -Algorithm SHA256).Hash
    if ($CurrentPhase2dHash -ne $BASELINE_PHASE2D_SHA256) {
        throw "Fatal: dist_isolated\RansomEye.exe modified! Expected $BASELINE_PHASE2D_SHA256, got $CurrentPhase2dHash"
    }
}

# Resolve candidate executable path
$ResolvedInputExe = (Resolve-Path $InputExe -ErrorAction Stop).Path
$ApprovedCandidateDir = (Resolve-Path (Join-Path $ProjectRoot "dist_phase2g_rc") -ErrorAction Stop).Path

# Phase 3B D1 remediation: directory-boundary check requires a trailing
# separator so a sibling named "dist_phase2g_rc_backup" cannot satisfy the
# prefix match.
$ApprovedCandidatePrefix = $ApprovedCandidateDir
if (-not $ApprovedCandidatePrefix.EndsWith([IO.Path]::DirectorySeparatorChar)) {
    $ApprovedCandidatePrefix = $ApprovedCandidatePrefix + [IO.Path]::DirectorySeparatorChar
}
if (-not ($ResolvedInputExe.StartsWith($ApprovedCandidatePrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "Security Violation: Input binary ($ResolvedInputExe) must reside within approved directory ($ApprovedCandidateDir)."
}

# Verify candidate SHA-256
$InputHash = (Get-FileHash -Path $ResolvedInputExe -Algorithm SHA256).Hash
if ($InputHash -ne $ExpectedSha256) {
    throw "Security Violation: Candidate SHA-256 ($InputHash) does not match expected manifest hash ($ExpectedSha256)."
}

Write-Host "      Candidate input hash verified: $InputHash" -ForegroundColor Green

# Phase 3B D3 remediation (early guard): validate the output directory and
# refuse to overwrite an existing signed output BEFORE probing certificate
# stores or SignTool. If the operator chose a forbidden output location or
# a dirty destination, we fail cheaply and loudly rather than after walking
# Cert:\.
$AbsoluteOutputDir = (New-Item -ItemType Directory -Path $OutputDir -Force).FullName
$ForbiddenRoots = @(
    $ApprovedCandidateDir,
    (Join-Path $ProjectRoot "dist"),
    (Join-Path $ProjectRoot "dist_isolated"),
    (Join-Path $ProjectRoot "data")
) | ForEach-Object {
    try { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path } catch { $null }
} | Where-Object { $_ -ne $null }
foreach ($forbidden in $ForbiddenRoots) {
    $forbiddenPrefix = $forbidden
    if (-not $forbiddenPrefix.EndsWith([IO.Path]::DirectorySeparatorChar)) {
        $forbiddenPrefix = $forbiddenPrefix + [IO.Path]::DirectorySeparatorChar
    }
    if (($AbsoluteOutputDir -eq $forbidden) -or
        ($AbsoluteOutputDir.StartsWith($forbiddenPrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
        throw "Security Violation: OutputDir ($AbsoluteOutputDir) cannot be identical to or beneath a protected location ($forbidden)."
    }
}
$SignedTargetExe = Join-Path $AbsoluteOutputDir "RansomEye.exe"
if (Test-Path -LiteralPath $SignedTargetExe) {
    if (-not $AllowReplaceSignedOutput.IsPresent) {
        throw ("Security Violation: signed output already exists at $SignedTargetExe. " +
               "Choose a fresh -OutputDir, or pass -AllowReplaceSignedOutput to rename the prior output aside.")
    }
    $StampSuffix = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $PriorExe = $SignedTargetExe + ".replaced-" + $StampSuffix
    $PriorManifest = (Join-Path $AbsoluteOutputDir "signed_artifact_manifest.json")
    $PriorManifestMoved = $null
    Move-Item -LiteralPath $SignedTargetExe -Destination $PriorExe
    if (Test-Path -LiteralPath $PriorManifest) {
        $PriorManifestMoved = $PriorManifest + ".replaced-" + $StampSuffix
        Move-Item -LiteralPath $PriorManifest -Destination $PriorManifestMoved
    }
    Write-Host "      Prior signed artifact preserved: $PriorExe" -ForegroundColor Yellow
    if ($PriorManifestMoved) {
        Write-Host "      Prior signed manifest preserved: $PriorManifestMoved" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Validate SignTool Path (Phase 3H hardening)
# ---------------------------------------------------------------------------
Write-Host "[2/7] Validating SignTool path..." -ForegroundColor Yellow

# Phase 3H: require an explicit, absolute, verified path to signtool.exe.
# The operator must obtain SignTool from a trusted Windows SDK installation
# and verify its provenance before passing it here. The script no longer
# searches known SDK directories or $env:PATH, eliminating the risk of
# executing a planted signtool.exe resolved from an attacker-controlled
# PATH entry.
if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
    throw ("Prerequisite Missing: -SignToolPath is required. Supply the absolute path to " +
           "signtool.exe from a trusted Windows 10/11 SDK installation (e.g. " +
           "'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe').")
}
if (-not [IO.Path]::IsPathRooted($SignToolPath)) {
    throw "Security Violation: -SignToolPath must be an absolute path; got '$SignToolPath'."
}
if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
    throw "Prerequisite Missing: SignTool not found at '$SignToolPath'. Verify the Windows SDK is installed and the path is correct."
}
$SignToolResolved = (Resolve-Path -LiteralPath $SignToolPath).Path
if ([IO.Path]::GetFileName($SignToolResolved).ToLowerInvariant() -ne "signtool.exe") {
    throw "Security Violation: -SignToolPath must point to a file named signtool.exe; got '$([IO.Path]::GetFileName($SignToolResolved))'."
}
Write-Host "      Validated SignTool: $SignToolResolved" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Validate Signing Identity Configuration
# ---------------------------------------------------------------------------
Write-Host "[3/7] Validating signing credentials configuration..." -ForegroundColor Yellow

$SignArgs = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")

# Phase 3B D4+D5 remediation: validate code-signing identity BEFORE handing
# any argument to SignTool, so an ambiguous subject never silently selects
# the wrong certificate and an expired / wrong-EKU / unusable certificate
# is rejected with an explicit error instead of a cryptic SignTool failure.
$CodeSigningOid = "1.3.6.1.5.5.7.3.3"
$SelectedCertThumbprint = $null

switch ($SigningMethod) {
    "LocalCertStore" {
        if ($CertThumbprint -eq "" -and $CertSubject -eq "") {
            throw "Prerequisite Missing: SigningMethod 'LocalCertStore' requires -CertThumbprint (preferred) or -CertSubject. No signing identity specified."
        }

        $Candidates = @()
        if ($CertThumbprint -ne "") {
            $NormalizedThumb = ($CertThumbprint -replace '\s','').ToUpperInvariant()
            $Candidates = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                            Where-Object { $_.Thumbprint -and $_.Thumbprint.ToUpperInvariant() -eq $NormalizedThumb })
        } else {
            Write-Host "      WARNING: subject-based cert selection is less safe than thumbprint. Prefer -CertThumbprint for production." -ForegroundColor Yellow
            $Candidates = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
                            Where-Object { $_.Subject -like "*$CertSubject*" })
        }

        if ($Candidates.Count -eq 0) {
            throw "Prerequisite Missing: no code-signing certificate found in CurrentUser\My or LocalMachine\My matching the supplied selector."
        }
        if ($Candidates.Count -gt 1) {
            $thumbs = ($Candidates | ForEach-Object { $_.Thumbprint }) -join ', '
            throw "Security Violation: multiple certificates match the supplied selector. Disambiguate with -CertThumbprint. Candidate thumbprints: $thumbs"
        }
        $Cert = $Candidates[0]

        if (-not $Cert.HasPrivateKey) {
            throw "Prerequisite Missing: selected certificate ($($Cert.Thumbprint)) has no accessible private key."
        }
        if ($Cert.NotAfter -lt (Get-Date)) {
            throw "Prerequisite Missing: selected certificate ($($Cert.Thumbprint)) expired on $($Cert.NotAfter.ToString('u'))."
        }
        if ($Cert.NotBefore -gt (Get-Date)) {
            throw "Prerequisite Missing: selected certificate ($($Cert.Thumbprint)) is not yet valid (NotBefore $($Cert.NotBefore.ToString('u')))."
        }
        $hasCodeSigning = $false
        foreach ($ext in $Cert.Extensions) {
            if ($ext.Oid.Value -eq "2.5.29.37") {
                $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ext
                foreach ($usage in $eku.EnhancedKeyUsages) {
                    if ($usage.Value -eq $CodeSigningOid) { $hasCodeSigning = $true }
                }
            }
        }
        if (-not $hasCodeSigning) {
            throw "Security Violation: selected certificate ($($Cert.Thumbprint)) lacks the Code Signing EKU ($CodeSigningOid)."
        }
        # Test-Certificate's view of chain trust is advisory only (it depends
        # on the local trust store, not on the public distribution chain).
        # Record whether it passes but do not treat failure as fatal here;
        # the authoritative check is `signtool verify /pa` after signing.
        try {
            $trustAdvisory = Test-Certificate -Cert $Cert -Policy CodeSigning -ErrorAction Stop
            Write-Host "      Advisory: Test-Certificate -Policy CodeSigning returned $trustAdvisory for $($Cert.Thumbprint)." -ForegroundColor Yellow
        } catch {
            Write-Host "      Advisory: Test-Certificate -Policy CodeSigning raised: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        $SelectedCertThumbprint = $Cert.Thumbprint
        # Always sign by exact thumbprint; even when the caller supplied -CertSubject,
        # we use the single disambiguated cert we just validated.
        $SignArgs += @("/sha1", $Cert.Thumbprint)
    }
    "AzureTrustedSigning" {
        # Phase 3B D8 remediation: refuse to let SignTool bare-load
        # "Azure.CodeSigning.Dlib.dll" from the current working directory,
        # which would permit DLL planting. Require an absolute path either
        # via -AzureDlibPath or via $env:AZURE_CODESIGNING_DLIB_PATH.
        if ($AzureMetadataFile -eq "" -or (-not (Test-Path -LiteralPath $AzureMetadataFile))) {
            throw "Prerequisite Missing: SigningMethod 'AzureTrustedSigning' requires -AzureMetadataFile pointing to valid JSON metadata."
        }
        $DlibCandidate = $AzureDlibPath
        if ($DlibCandidate -eq "") { $DlibCandidate = $env:AZURE_CODESIGNING_DLIB_PATH }
        if ([string]::IsNullOrWhiteSpace($DlibCandidate)) {
            throw "Prerequisite Missing: SigningMethod 'AzureTrustedSigning' requires -AzureDlibPath or the AZURE_CODESIGNING_DLIB_PATH environment variable, set to the absolute path of Azure.CodeSigning.Dlib.dll."
        }
        if (-not (Test-Path -LiteralPath $DlibCandidate)) {
            throw "Prerequisite Missing: Azure Trusted Signing Dlib not found at '$DlibCandidate'."
        }
        $ResolvedDlib = (Resolve-Path -LiteralPath $DlibCandidate).Path
        if (-not [IO.Path]::IsPathRooted($ResolvedDlib)) {
            throw "Security Violation: Azure Trusted Signing Dlib path must be absolute; got '$ResolvedDlib'."
        }
        $ResolvedMetadata = (Resolve-Path -LiteralPath $AzureMetadataFile).Path
        Write-Host "      Azure Trusted Signing Dlib    : $ResolvedDlib" -ForegroundColor Green
        Write-Host "      Azure Trusted Signing metadata: $ResolvedMetadata" -ForegroundColor Green
        $SignArgs += @("/dlib", $ResolvedDlib, "/dmdf", $ResolvedMetadata)
    }
    "PfxFile" {
        if ($PfxPath -eq "" -or (-not (Test-Path -LiteralPath $PfxPath))) {
            throw "Prerequisite Missing: SigningMethod 'PfxFile' requires a valid -PfxPath."
        }
        $ResolvedPfx = (Resolve-Path -LiteralPath $PfxPath).Path
        $SignArgs += @("/f", $ResolvedPfx)
        # Phase 3B D6 remediation: PFX passwords are passed through the
        # argument vector only, and the display line further down redacts /p.
        # Prefer hardware token or Azure Trusted Signing; a password-protected
        # PFX is a weaker credential channel than either.
        if ($env:RANSOMEYE_SIGN_PFX_PASSWORD) {
            $SignArgs += @("/p", $env:RANSOMEYE_SIGN_PFX_PASSWORD)
            Write-Host "      PFX password supplied via RANSOMEYE_SIGN_PFX_PASSWORD (value redacted in all diagnostics)." -ForegroundColor Yellow
        } else {
            Write-Host "      No PFX password supplied; SignTool will prompt interactively if required." -ForegroundColor Yellow
        }
    }
}

Write-Host "      Signing configuration valid for method: $SigningMethod" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Prepare Isolated Output Binary (Non-Destructive Preservation)
# ---------------------------------------------------------------------------
# The output directory, forbidden-root rejection, and overwrite guard already
# ran as part of the early guard block in step 1. Here we only copy the
# candidate to the already-validated $SignedTargetExe path and re-check that
# the copy is bit-identical to the input.
Write-Host "[4/7] Preparing isolated output target..." -ForegroundColor Yellow

# Copy without -Force; the destination path was verified absent (or moved
# aside under -AllowReplaceSignedOutput) by the early guard.
Copy-Item -LiteralPath $ResolvedInputExe -Destination $SignedTargetExe

$PreSignHash = (Get-FileHash -LiteralPath $SignedTargetExe -Algorithm SHA256).Hash
if ($PreSignHash -ne $InputHash) {
    throw "Fatal: Target copy hash mismatch! Expected $InputHash, got $PreSignHash"
}
Write-Host "      Candidate safely copied to: $SignedTargetExe" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Execute SignTool
# ---------------------------------------------------------------------------
Write-Host "[5/7] Executing Authenticode signing with RFC 3161 timestamp..." -ForegroundColor Yellow

$SignArgs += $SignedTargetExe
$LogDir = Join-Path $AbsoluteOutputDir "logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$SignLog = Join-Path $LogDir "signtool_sign.log"
$SignErrLog = Join-Path $LogDir "signtool_error.log"

# Phase 3B D6 remediation: build a sanitized display view that redacts
# SignTool's PFX password argument. The real $SignArgs array passed to
# Start-Process is never written to the console; only the sanitized copy
# is displayed. SignTool itself does not echo the /p value into its own
# stdout/stderr, so the captured log files remain safe.
function Format-RedactedSignArgs {
    param([string[]] $Argv)
    $out = @()
    for ($i = 0; $i -lt $Argv.Count; $i++) {
        $out += $Argv[$i]
        if ($Argv[$i] -eq "/p" -and ($i + 1) -lt $Argv.Count) {
            $out += "<redacted>"
            $i++
        }
    }
    return ($out -join ' ')
}
Write-Host "      Running: $SignToolResolved $(Format-RedactedSignArgs $SignArgs)"
$Process = Start-Process -FilePath $SignToolResolved -ArgumentList $SignArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $SignLog -RedirectStandardError $SignErrLog
# Phase 3B D12 remediation: force a definitive wait so the ExitCode is
# fully populated before we read it (closes a documented Start-Process race).
$Process.WaitForExit()

if ($Process.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $SignErrLog) {
        Get-Content -LiteralPath $SignErrLog -Tail 20
    }
    throw "Fatal: signtool sign failed with exit code $($Process.ExitCode). Review $SignLog"
}
Write-Host "      SignTool sign completed with exit code 0." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Verify Authenticode Signature & Timestamp
# ---------------------------------------------------------------------------
Write-Host "[6/7] Verifying Authenticode signature integrity and timestamp..." -ForegroundColor Yellow

$VerifyLog = Join-Path $LogDir "signtool_verify.log"
$VerifyErrLog = Join-Path $LogDir "verify_error.log"
$VerifyArgs = @("verify", "/pa", "/v", $SignedTargetExe)
$VerifyProc = Start-Process -FilePath $SignToolResolved -ArgumentList $VerifyArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $VerifyLog -RedirectStandardError $VerifyErrLog
# Phase 3B D12 remediation: force a definitive wait before reading ExitCode.
$VerifyProc.WaitForExit()

if ($VerifyProc.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $VerifyErrLog) {
        Get-Content -LiteralPath $VerifyErrLog -Tail 20
    }
    throw "Fatal: signtool verify failed with exit code $($VerifyProc.ExitCode). Review $VerifyLog"
}

# PowerShell Authenticode inspection
$AuthSig = Get-AuthenticodeSignature -FilePath $SignedTargetExe
if ($AuthSig.Status -ne "Valid") {
    throw "Fatal: Authenticode verification failed! Status: $($AuthSig.Status), Message: $($AuthSig.StatusMessage)"
}

# Phase 3B D11 remediation: explicitly verify the RFC 3161 timestamp
# countersigner. SignTool's `verify /pa /v` already fails closed if the
# timestamp is missing or untrusted, but we additionally require that
# Get-AuthenticodeSignature surfaces a TimeStamperCertificate distinct
# from the signing cert, so the signing manifest can record both.
# NOTE: a historical timestamp remains valid for the signature even
# after the timestamp certificate's NotAfter has passed; we therefore
# only use NotAfter here to warn about operator expectations, never to
# treat the timestamp as invalid.
if (-not $AuthSig.TimeStamperCertificate) {
    throw "Fatal: Authenticode is Valid but TimeStamperCertificate is missing. RFC 3161 timestamp required."
}
if ($AuthSig.SignerCertificate.Thumbprint -eq $AuthSig.TimeStamperCertificate.Thumbprint) {
    throw "Fatal: timestamp countersigner is identical to the signing certificate; a distinct RFC 3161 TSA is required."
}
if ($AuthSig.TimeStamperCertificate.NotAfter -lt (Get-Date)) {
    Write-Host "      Advisory: timestamp certificate NotAfter is in the past ($($AuthSig.TimeStamperCertificate.NotAfter.ToString('u'))); the embedded timestamp token remains cryptographically valid, but renewal planning is warranted." -ForegroundColor Yellow
}
Write-Host "      Authenticode Signature Status: $($AuthSig.Status)" -ForegroundColor Green
Write-Host "      Signer Subject               : $($AuthSig.SignerCertificate.Subject)"
Write-Host "      Signer Issuer                : $($AuthSig.SignerCertificate.Issuer)"
Write-Host "      Signature Algorithm          : $($AuthSig.SignerCertificate.SignatureAlgorithm.FriendlyName)"
Write-Host "      Timestamp Countersigner      : $($AuthSig.TimeStamperCertificate.Subject)"
Write-Host "      Timestamp Issuer             : $($AuthSig.TimeStamperCertificate.Issuer)"

# ---------------------------------------------------------------------------
# 7. Post-Signing Integrity & Provenance Manifest Generation
# ---------------------------------------------------------------------------
Write-Host "[7/7] Computing final signed hash and generating release manifest..." -ForegroundColor Yellow

$PostSignedHash = (Get-FileHash -LiteralPath $SignedTargetExe -Algorithm SHA256).Hash
$SignedItem = Get-Item -LiteralPath $SignedTargetExe

# Confirm unsigned candidate was not modified
$PostCheckCandidateHash = (Get-FileHash -LiteralPath $ResolvedInputExe -Algorithm SHA256).Hash
if ($PostCheckCandidateHash -ne $InputHash) {
    throw "CRITICAL VIOLATION: Original candidate binary was modified during signing! Expected $InputHash, got $PostCheckCandidateHash"
}

# Re-check database
$FinalDbHash = (Get-FileHash -LiteralPath $DbPath -Algorithm SHA256).Hash
if ($FinalDbHash -ne $BASELINE_DB_SHA256) {
    throw "CRITICAL VIOLATION: Production database was modified during signing process!"
}

# Phase 3B D2 remediation: symmetric post-sign re-check of the baseline
# executables. The signing workflow has no reason to touch them, so any
# drift here is a critical invariant violation.
$FinalOrigHash = (Get-FileHash -LiteralPath $OrigDistExe -Algorithm SHA256).Hash
if ($FinalOrigHash -ne $BASELINE_ORIG_DIST_SHA256) {
    throw "CRITICAL VIOLATION: dist\RansomEye.exe modified during signing! Expected $BASELINE_ORIG_DIST_SHA256, got $FinalOrigHash"
}
$FinalPhase2dHash = $null
if (Test-Path -LiteralPath $Phase2dExe) {
    $FinalPhase2dHash = (Get-FileHash -LiteralPath $Phase2dExe -Algorithm SHA256).Hash
    if ($FinalPhase2dHash -ne $BASELINE_PHASE2D_SHA256) {
        throw "CRITICAL VIOLATION: dist_isolated\RansomEye.exe modified during signing! Expected $BASELINE_PHASE2D_SHA256, got $FinalPhase2dHash"
    }
}

# Phase 3B D13 remediation: hash the SignTool logs so the manifest is
# tamper-evident with respect to the verification record itself.
function Get-SafeFileHash {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
$SignLogHash = Get-SafeFileHash $SignLog
$SignErrLogHash = Get-SafeFileHash $SignErrLog
$VerifyLogHash = Get-SafeFileHash $VerifyLog
$VerifyErrLogHash = Get-SafeFileHash $VerifyErrLog

# Phase 3B D13: capture SignTool version from file metadata, host OS, PS version.
$SignToolVersion = $null
try {
    $SignToolVersion = (Get-Item -LiteralPath $SignToolResolved).VersionInfo.ProductVersion
} catch { $SignToolVersion = $null }
$HostOs = $null
try {
    $HostOs = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1).Caption
} catch { $HostOs = [System.Environment]::OSVersion.VersionString }

# Phase 3B D14 remediation: record whether the git working tree was clean
# at signing time. Both the raw boolean and the porcelain diff summary go
# in the manifest so the release manifest template's working_tree_clean
# field is reproducible from this record.
$WorkingTreePorcelain = (& git status --porcelain 2>$null)
$WorkingTreeClean = [string]::IsNullOrWhiteSpace(($WorkingTreePorcelain -join "`n"))

$SignedManifest = @{
    artifact_name = "RansomEye.exe"
    distribution_stage = "Phase 3 Signed Release Candidate"
    manifest_schema = "ransomeye.signed_artifact_manifest.v2"
    original_candidate = @{
        path = $ResolvedInputExe
        sha256 = $InputHash
        size_bytes = (Get-Item -LiteralPath $ResolvedInputExe).Length
    }
    signed_binary = @{
        path = $SignedTargetExe
        sha256 = $PostSignedHash
        size_bytes = $SignedItem.Length
        authenticode_status = $AuthSig.Status.ToString()
        signer_subject = $AuthSig.SignerCertificate.Subject
        signer_issuer = $AuthSig.SignerCertificate.Issuer
        signer_thumbprint = $AuthSig.SignerCertificate.Thumbprint
        signer_notbefore_utc = $AuthSig.SignerCertificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        signer_notafter_utc = $AuthSig.SignerCertificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        timestamp_server = $TimestampUrl
        timestamp_countersigner_subject = $AuthSig.TimeStamperCertificate.Subject
        timestamp_countersigner_issuer = $AuthSig.TimeStamperCertificate.Issuer
        timestamp_countersigner_thumbprint = $AuthSig.TimeStamperCertificate.Thumbprint
        timestamp_countersigner_notafter_utc = $AuthSig.TimeStamperCertificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        signed_at_utc = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    }
    toolchain = @{
        signtool_path = $SignToolResolved
        signtool_version = $SignToolVersion
        signtool_exit_code = 0
        verify_exit_code = 0
        host_os = $HostOs
        powershell_version = $PSVersionTable.PSVersion.ToString()
        git_commit = (& git rev-parse HEAD)
        git_branch = (& git rev-parse --abbrev-ref HEAD)
        git_working_tree_clean = $WorkingTreeClean
    }
    invariants = @{
        production_db_preserved = ($FinalDbHash -eq $BASELINE_DB_SHA256)
        unsigned_candidate_preserved = ($PostCheckCandidateHash -eq $InputHash)
        dist_baseline_preserved = ($FinalOrigHash -eq $BASELINE_ORIG_DIST_SHA256)
        dist_isolated_preserved = (
            ($null -eq $FinalPhase2dHash) -or ($FinalPhase2dHash -eq $BASELINE_PHASE2D_SHA256)
        )
    }
    verification_logs = @{
        signtool_sign_log = $SignLog
        signtool_sign_log_sha256 = $SignLogHash
        signtool_sign_error_log = $SignErrLog
        signtool_sign_error_log_sha256 = $SignErrLogHash
        signtool_verify_log = $VerifyLog
        signtool_verify_log_sha256 = $VerifyLogHash
        signtool_verify_error_log = $VerifyErrLog
        signtool_verify_error_log_sha256 = $VerifyErrLogHash
    }
}

$ManifestFile = Join-Path $AbsoluteOutputDir "signed_artifact_manifest.json"
$SignedManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ManifestFile -Encoding utf8

Write-Host "============================================================" -ForegroundColor Green
Write-Host "      AUTHENTICODE SIGNING WORKFLOW COMPLETED               " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Original Candidate : $ResolvedInputExe (SHA-256: $InputHash)"
Write-Host "Signed Output      : $SignedTargetExe (SHA-256: $PostSignedHash)"
Write-Host "Manifest File      : $ManifestFile"
Write-Host "Signature Status   : $($AuthSig.Status)"
