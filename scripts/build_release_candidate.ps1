<#
.SYNOPSIS
    Builds a standalone RansomEye Release Candidate (RC) executable into an isolated directory.

.DESCRIPTION
    Automates an isolated, auditable PyInstaller build of RansomEye without touching:
    - Pre-existing release binary (dist\RansomEye.exe)
    - Phase 2D isolated binary (dist_isolated\RansomEye.exe)
    - Production database (data\ransomeye.db)
    - Git index or working tree

    This script enforces strict pre-build and post-build cryptographic invariant checks.
    If any preservation check fails, the script halts execution immediately.

.PARAMETER DistPath
    The target output directory for the compiled release candidate. Default: dist_rc

.PARAMETER WorkPath
    The temporary compilation workspace directory. Default: build_rc

.EXAMPLE
    .\scripts\build_release_candidate.ps1
#>

[CmdletBinding()]
param(
    [string]$DistPath = "dist_rc",
    [string]$WorkPath = "build_rc"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $ProjectRoot

# Baseline Cryptographic Constants
$BASELINE_DB_SHA256 = "9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB"
$BASELINE_ORIG_DIST_SHA256 = "65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542"
$BASELINE_ISOLATED_DIST_SHA256 = "49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E"

$DbPath = Join-Path $ProjectRoot "data\ransomeye.db"
$OrigDistExe = Join-Path $ProjectRoot "dist\RansomEye.exe"
$IsolatedDistExe = Join-Path $ProjectRoot "dist_isolated\RansomEye.exe"
$SpecFile = Join-Path $ProjectRoot "scripts\ransomeye.spec"
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       RANSOMEYE RELEASE CANDIDATE BUILD AUTOMATION         " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot"
Write-Host "Dist Path    : $DistPath"
Write-Host "Work Path    : $WorkPath"
Write-Host "Timestamp    : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))"
Write-Host "------------------------------------------------------------"

# ---------------------------------------------------------------------------
# 1. Pre-Build Safety & Invariant Verification
# ---------------------------------------------------------------------------
Write-Host "[1/5] Verifying pre-build cryptographic invariants..." -ForegroundColor Yellow

if (-not (Test-Path $DbPath)) {
    throw "Fatal: Production database $DbPath not found."
}
$CurrentDbHash = (Get-FileHash -Path $DbPath -Algorithm SHA256).Hash
if ($CurrentDbHash -ne $BASELINE_DB_SHA256) {
    throw "Fatal: Production database hash mismatch! Expected $BASELINE_DB_SHA256, got $CurrentDbHash"
}

if (-not (Test-Path $OrigDistExe)) {
    throw "Fatal: Original release executable $OrigDistExe not found."
}
$CurrentOrigDistHash = (Get-FileHash -Path $OrigDistExe -Algorithm SHA256).Hash
if ($CurrentOrigDistHash -ne $BASELINE_ORIG_DIST_SHA256) {
    throw "Fatal: Original dist executable hash mismatch! Expected $BASELINE_ORIG_DIST_SHA256, got $CurrentOrigDistHash"
}

if (Test-Path $IsolatedDistExe) {
    $CurrentIsolatedHash = (Get-FileHash -Path $IsolatedDistExe -Algorithm SHA256).Hash
    if ($CurrentIsolatedHash -ne $BASELINE_ISOLATED_DIST_SHA256) {
        throw "Fatal: dist_isolated executable hash mismatch! Expected $BASELINE_ISOLATED_DIST_SHA256, got $CurrentIsolatedHash"
    }
}

# Verify protected directories are not targeted
$AbsoluteDist = (New-Item -ItemType Directory -Path $DistPath -Force).FullName
$AbsoluteWork = (New-Item -ItemType Directory -Path $WorkPath -Force).FullName
$LogDir = Join-Path $AbsoluteWork "logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$ProtectedPaths = @((Join-Path $ProjectRoot "dist"), (Join-Path $ProjectRoot "dist_isolated"), (Join-Path $ProjectRoot "build"), (Join-Path $ProjectRoot "build_isolated"))
if ($ProtectedPaths -contains $AbsoluteDist) {
    throw "Fatal: Target DistPath cannot be an existing release directory ($AbsoluteDist)."
}

Write-Host "      All pre-build invariants verified." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Capture Build Provenance and Environment
# ---------------------------------------------------------------------------
Write-Host "[2/5] Capturing toolchain and Git provenance..." -ForegroundColor Yellow

$GitBranch = & git rev-parse --abbrev-ref HEAD
$GitCommit = & git rev-parse HEAD
$GitStatus = & git status --short

$ToolchainInfo = @{
    git_branch = $GitBranch
    git_commit = $GitCommit
    git_status = $GitStatus
    python_version = (& $PythonExe --version)
    pyinstaller_version = (& $PythonExe -m PyInstaller --version)
    timestamp_utc = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
}

$ToolchainJson = Join-Path $LogDir "build_provenance.json"
$ToolchainInfo | ConvertTo-Json -Depth 4 | Set-Content -Path $ToolchainJson -Encoding utf8
Write-Host "      Provenance logged to $ToolchainJson" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Execute PyInstaller Build
# ---------------------------------------------------------------------------
Write-Host "[3/5] Executing isolated PyInstaller build..." -ForegroundColor Yellow

$BuildLog = Join-Path $LogDir "pyinstaller_build.log"

$BuildArgs = @(
    "-m", "PyInstaller",
    "--distpath", $AbsoluteDist,
    "--workpath", $AbsoluteWork,
    "--clean",
    "--noconfirm",
    $SpecFile
)

Write-Host "      Running: $PythonExe $($BuildArgs -join ' ')"
$Process = Start-Process -FilePath $PythonExe -ArgumentList $BuildArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $BuildLog -RedirectStandardError (Join-Path $LogDir "pyinstaller_error.log")

if ($Process.ExitCode -ne 0) {
    Get-Content (Join-Path $LogDir "pyinstaller_error.log") -Tail 20
    throw "Fatal: PyInstaller build failed with exit code $($Process.ExitCode). Review $BuildLog"
}
Write-Host "      PyInstaller build succeeded (Exit Code 0)." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Verify Output Artifact & Calculate Hash
# ---------------------------------------------------------------------------
Write-Host "[4/5] Inspecting compiled Release Candidate artifact..." -ForegroundColor Yellow

$OutputExe = Join-Path $AbsoluteDist "RansomEye.exe"
if (-not (Test-Path $OutputExe)) {
    throw "Fatal: Output executable not found at $OutputExe"
}

$OutputItem = Get-Item $OutputExe
$OutputHash = (Get-FileHash -Path $OutputExe -Algorithm SHA256).Hash

Write-Host "      Output Binary : $($OutputItem.FullName)"
Write-Host "      Binary Size   : $($OutputItem.Length) bytes ($([Math]::Round($OutputItem.Length / 1MB, 2)) MB)"
Write-Host "      SHA-256 Hash  : $OutputHash" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 5. Post-Build Invariant & Integrity Re-Verification
# ---------------------------------------------------------------------------
Write-Host "[5/5] Re-verifying post-build cryptographic invariants..." -ForegroundColor Yellow

$PostDbHash = (Get-FileHash -Path $DbPath -Algorithm SHA256).Hash
if ($PostDbHash -ne $BASELINE_DB_SHA256) {
    throw "CRITICAL FAILURE: Production database was modified during build! Baseline: $BASELINE_DB_SHA256, Current: $PostDbHash"
}

$PostOrigDistHash = (Get-FileHash -Path $OrigDistExe -Algorithm SHA256).Hash
if ($PostOrigDistHash -ne $BASELINE_ORIG_DIST_SHA256) {
    throw "CRITICAL FAILURE: dist\RansomEye.exe was modified during build! Baseline: $BASELINE_ORIG_DIST_SHA256, Current: $PostOrigDistHash"
}

if (Test-Path $IsolatedDistExe) {
    $PostIsolatedHash = (Get-FileHash -Path $IsolatedDistExe -Algorithm SHA256).Hash
    if ($PostIsolatedHash -ne $BASELINE_ISOLATED_DIST_SHA256) {
        throw "CRITICAL FAILURE: dist_isolated\RansomEye.exe was modified during build! Baseline: $BASELINE_ISOLATED_DIST_SHA256, Current: $PostIsolatedHash"
    }
}

Write-Host "      All post-build invariants verified intact." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Summary Output
# ---------------------------------------------------------------------------
$BuildSummary = @{
    build_status = "SUCCESS"
    output_executable = $OutputExe
    file_size_bytes = $OutputItem.Length
    sha256 = $OutputHash
    db_sha256 = $PostDbHash
    dist_sha256 = $PostOrigDistHash
    dist_isolated_sha256 = $PostIsolatedHash
    completed_at_utc = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
}

$SummaryFile = Join-Path $LogDir "build_summary.json"
$BuildSummary | ConvertTo-Json -Depth 4 | Set-Content -Path $SummaryFile -Encoding utf8

Write-Host "============================================================" -ForegroundColor Green
Write-Host "      RELEASE CANDIDATE BUILD COMPLETED SUCCESSFULLY        " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Artifact   : $OutputExe"
Write-Host "SHA-256    : $OutputHash"
Write-Host "Summary    : $SummaryFile"
