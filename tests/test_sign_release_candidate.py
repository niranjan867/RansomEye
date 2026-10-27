"""Phase 3B — focused tests for scripts/sign_release_candidate.ps1.

These tests NEVER sign anything, never provide a real certificate, and
never invoke SignTool's ``sign`` subcommand. Each test exercises either:

* a static source assertion on the script (the fix is present), or
* a controlled invocation that is designed to fail-closed BEFORE SignTool
  is reached (e.g. a path outside the approved candidate directory, a
  missing Azure Dlib, an already-existing signed output, etc).

The protected baseline hashes checked at the very top of the script are
real and must match on this workstation; the invocation tests therefore
rely on the fact that the dist / dist_isolated / database baselines are
untouched.  If any of those drift, the tests will skip rather than crash.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "sign_release_candidate.ps1"
CANDIDATE = REPO_ROOT / "dist_phase2g_rc" / "RansomEye.exe"
MANIFEST_TEMPLATE = REPO_ROOT / "docs" / "release" / "phase3" / "release_manifest.template.json"
WORKFLOW_DOC = REPO_ROOT / "docs" / "release" / "phase3" / "signing_workflow.md"
EXPECTED_CANDIDATE_SHA256 = (
    "F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871"
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _invoke(args: list[str], cwd: Path = REPO_ROOT, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Invoke the PowerShell signing script with -NoProfile.

    Returns the completed process. The caller is expected to assert on
    exit code and stdout/stderr content. Tests should not depend on
    specific exit codes other than zero / non-zero because PowerShell
    maps ``throw`` to varying exit codes depending on version.
    """
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT),
        *args,
    ]
    return subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
    )


# --------------------------------------------------------------------------- #
# Static source assertions
# --------------------------------------------------------------------------- #

def test_script_exists_and_parseable():
    assert SCRIPT.is_file()
    src = SCRIPT.read_text(encoding="utf-8")
    # Every remediation marker must be present.
    for marker in (
        "Phase 3B D1 remediation",
        "Phase 3B D2 remediation",
        "Phase 3B D3 remediation",
        "Phase 3B D4+D5 remediation",
        "Phase 3B D6 remediation",
        "Phase 3B D8 remediation",
        "Phase 3B D11 remediation",
        "Phase 3B D12 remediation",
        "Phase 3B D13 remediation",
        "Phase 3B D14 remediation",
    ):
        assert marker in src, f"missing remediation marker: {marker}"


def test_script_redacts_pfx_password_in_display(tmp_path):
    """D6: the display line must not interpolate /p's value."""
    src = SCRIPT.read_text(encoding="utf-8")
    # The literal \"Running: $SignToolResolved $($SignArgs -join ' ')\" from the
    # pre-remediation script must NOT appear.
    assert "$($SignArgs -join ' ')" not in src, (
        "D6 regression: raw argument array still interpolated into the display line."
    )
    assert "Format-RedactedSignArgs" in src
    assert "<redacted>" in src


def test_script_requires_opt_in_to_replace_signed_output():
    """D3: AllowReplaceSignedOutput switch exists and gates the replace path."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "AllowReplaceSignedOutput" in src
    assert "signed output already exists" in src
    # The script must not use Copy-Item -Force on the final signed destination.
    # (Copy-Item is now called without -Force; the prior -Force branch is gone.)
    assert "Copy-Item -Path $ResolvedInputExe -Destination $SignedTargetExe -Force" not in src


def test_script_tightens_directory_boundary_check():
    """D1: directory-prefix check requires a trailing separator."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "ApprovedCandidatePrefix" in src
    assert "DirectorySeparatorChar" in src


def _switch_block(src: str) -> str:
    """Return the body of the ``switch ($SigningMethod)`` block in the script."""
    marker = 'switch ($SigningMethod)'
    i = src.index(marker)
    # Walk forward to the matching closing brace of the switch body.
    j = src.index('{', i)
    depth = 1
    k = j + 1
    while k < len(src) and depth > 0:
        if src[k] == '{':
            depth += 1
        elif src[k] == '}':
            depth -= 1
        k += 1
    return src[i:k]


def test_script_rejects_ambiguous_cert_subject():
    """D4: subject-based match pre-enumerates candidates and throws on >1 hit."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "multiple certificates match" in src
    switch_body = _switch_block(src)
    # Isolate the LocalCertStore branch of the switch.
    local_block = switch_body.split('"LocalCertStore"', 1)[1].split('"AzureTrustedSigning"', 1)[0]
    # The chosen cert is always passed by /sha1 thumbprint, never /n.
    assert '"/sha1"' in local_block
    assert '"/n"' not in local_block, (
        "D4 regression: /n (subject) still passed to SignTool; must use the "
        "disambiguated thumbprint."
    )


def test_script_requires_absolute_azure_dlib():
    """D8: Azure Dlib must be an explicit absolute path, not bare-named."""
    src = SCRIPT.read_text(encoding="utf-8")
    switch_body = _switch_block(src)
    azure_block = switch_body.split('"AzureTrustedSigning"', 1)[1].split('"PfxFile"', 1)[0]
    # Pre-remediation code passed the bare name as a /dlib argument via
    #   $SignArgs += @("/dlib", "Azure.CodeSigning.Dlib.dll", ...)
    # Allow the string to appear inside the explanatory comment, but reject
    # any live argument-array construction that pins /dlib to a bare name.
    assert '"/dlib", "Azure.CodeSigning.Dlib.dll"' not in azure_block, (
        "D8 regression: Azure Dlib still loaded by bare name via /dlib."
    )
    assert "AzureDlibPath" in azure_block
    assert "AZURE_CODESIGNING_DLIB_PATH" in azure_block
    assert "IsPathRooted" in azure_block


def test_script_verifies_timestamp_countersigner():
    """D11: timestamp countersigner is explicitly asserted present."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "TimeStamperCertificate" in src
    assert "RFC 3161 timestamp required" in src
    # And the signer and countersigner must be distinct.
    assert "identical to the signing certificate" in src


def test_script_rechecks_baseline_binaries_post_sign():
    """D2: post-sign recheck of dist\\ and dist_isolated\\ baselines."""
    src = SCRIPT.read_text(encoding="utf-8")
    # Both baseline hashes must appear in BOTH the pre-sign check AND the
    # post-sign block.
    assert src.count("BASELINE_ORIG_DIST_SHA256") >= 2
    assert src.count("BASELINE_PHASE2D_SHA256") >= 2
    assert "dist\\RansomEye.exe modified during signing" in src


def test_script_enriches_manifest_with_toolchain_and_logs():
    """D13: manifest records log hashes, SignTool version, host OS, timestamp signer."""
    src = SCRIPT.read_text(encoding="utf-8")
    for marker in (
        "verification_logs",
        "signtool_sign_log_sha256",
        "signtool_verify_log_sha256",
        "timestamp_countersigner_subject",
        "timestamp_countersigner_thumbprint",
        "signtool_version",
        "host_os",
        "powershell_version",
    ):
        assert marker in src, f"D13 regression: missing manifest field '{marker}'"


def test_script_records_working_tree_state_in_manifest():
    """D14: git_working_tree_clean is captured in the signing manifest."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "git_working_tree_clean" in src


def test_script_uses_waitforexit():
    """D12: Start-Process is followed by WaitForExit() for both child procs."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert src.count("WaitForExit()") >= 2


# --------------------------------------------------------------------------- #
# Documentation assertions
# --------------------------------------------------------------------------- #

def test_workflow_doc_strengthens_password_guidance():
    """D7: the workflow doc no longer claims env vars are a secure channel."""
    text = WORKFLOW_DOC.read_text(encoding="utf-8")
    assert "Environment variables are NOT a secure credential channel" in text
    # And it must not still say "must be passed via secure runtime environment variables"
    # with the old wording.
    assert "secure runtime environment variables" not in text


def test_manifest_template_test_counts_nulled():
    """D15: pre-filled test totals replaced with null + explanatory comment."""
    data = json.loads(MANIFEST_TEMPLATE.read_text(encoding="utf-8"))
    ete = data["empirical_test_evidence"]
    assert "_comment" in ete
    assert "MUST be captured from actual test output" in ete["_comment"]
    reg = ete["full_regression_suite"]
    assert reg["total_tests"] is None
    assert reg["passed"] is None
    assert reg["pass_rate_percentage"] is None
    assert reg["runtime_seconds"] is None
    # Scenario names must remain, so operators know WHICH checks to run.
    assert "fresh_database_initialization" in ete["packaged_database_migration_scenarios"]["scenarios"]


def test_manifest_template_separates_unsigned_vs_signed_hashes():
    """D15 + general: unsigned and signed hash fields remain distinct."""
    data = json.loads(MANIFEST_TEMPLATE.read_text(encoding="utf-8"))
    unsigned_sha = data["candidate_artifacts"]["unsigned_candidate"]["sha256"]
    signed_sha = data["candidate_artifacts"]["signed_candidate"]["sha256"]
    assert unsigned_sha != signed_sha
    assert unsigned_sha == EXPECTED_CANDIDATE_SHA256
    # The signed hash slot is an explicit placeholder.
    assert signed_sha.startswith("<INSERT_")


# --------------------------------------------------------------------------- #
# Invocation tests — all designed to fail-closed before SignTool runs.
# --------------------------------------------------------------------------- #

def _skip_if_candidate_missing_or_drifted():
    if not CANDIDATE.is_file():
        pytest.skip("Phase 2G candidate missing on this workstation.")
    actual = _sha256(CANDIDATE)
    if actual != EXPECTED_CANDIDATE_SHA256:
        pytest.skip(f"Candidate SHA-256 drifted ({actual}); baseline tests cannot run.")


def test_invocation_rejects_input_outside_approved_directory(tmp_path):
    """D1 live: a candidate placed outside dist_phase2g_rc\\ is rejected."""
    _skip_if_candidate_missing_or_drifted()
    foreign = tmp_path / "RansomEye.exe"
    shutil.copyfile(CANDIDATE, foreign)
    cp = _invoke(["-InputExe", str(foreign), "-OutputDir", str(tmp_path / "out")])
    assert cp.returncode != 0
    assert "Security Violation" in (cp.stdout + cp.stderr)
    assert "approved directory" in (cp.stdout + cp.stderr)


def test_invocation_rejects_wrong_expected_hash(tmp_path):
    """Candidate matches real hash; passing a wrong -ExpectedSha256 fails closed."""
    _skip_if_candidate_missing_or_drifted()
    bogus = "0" * 64
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-ExpectedSha256", bogus,
        "-OutputDir", str(tmp_path / "out"),
    ])
    assert cp.returncode != 0
    assert "does not match expected" in (cp.stdout + cp.stderr)


def test_invocation_refuses_to_overwrite_existing_signed_output(tmp_path):
    """D3 live: existing signed output must block the run by default."""
    _skip_if_candidate_missing_or_drifted()
    outdir = tmp_path / "already_signed"
    outdir.mkdir()
    (outdir / "RansomEye.exe").write_bytes(b"preexisting")
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(outdir),
        # No cert selector; even if the overwrite guard didn't fire, step 3
        # would reject on missing identity. The overwrite guard must fire first
        # so we don't need identity material to prove this.
    ])
    assert cp.returncode != 0
    combined = cp.stdout + cp.stderr
    assert "signed output already exists" in combined or \
           "signed output already exists at" in combined, combined


def _make_fake_signtool(tmp_path: Path) -> str:
    """Create a placeholder signtool.exe so the script passes step 2."""
    fake = tmp_path / "signtool.exe"
    fake.write_bytes(b"fake-signtool-placeholder")
    return str(fake)


def test_invocation_rejects_azure_without_dlib_path(tmp_path):
    """D8 live: Azure method without -AzureDlibPath / env var is rejected."""
    _skip_if_candidate_missing_or_drifted()
    metadata = tmp_path / "azure_metadata.json"
    metadata.write_text(json.dumps({"Endpoint": "x", "CodeSigningAccountName": "y",
                                    "CertificateProfileName": "z"}))
    outdir = tmp_path / "azure_out"
    fake_signtool = _make_fake_signtool(tmp_path)
    env = {k: v for k, v in os.environ.items() if k != "AZURE_CODESIGNING_DLIB_PATH"}
    cmd = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT),
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(outdir),
        "-SigningMethod", "AzureTrustedSigning",
        "-AzureMetadataFile", str(metadata),
        "-SignToolPath", fake_signtool,
    ]
    cp = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True,
                        env=env, timeout=60)
    assert cp.returncode != 0
    assert "AzureDlibPath" in (cp.stdout + cp.stderr) or \
           "AZURE_CODESIGNING_DLIB_PATH" in (cp.stdout + cp.stderr)


def test_invocation_rejects_missing_identity(tmp_path):
    """D4/D5 live: LocalCertStore with no selector is rejected."""
    _skip_if_candidate_missing_or_drifted()
    fake_signtool = _make_fake_signtool(tmp_path)
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SigningMethod", "LocalCertStore",
        "-SignToolPath", fake_signtool,
    ])
    assert cp.returncode != 0
    assert "requires -CertThumbprint" in (cp.stdout + cp.stderr)


def test_invocation_rejects_unknown_thumbprint(tmp_path):
    """D4/D5 live: a thumbprint that matches no cert fails closed."""
    _skip_if_candidate_missing_or_drifted()
    bogus_thumb = "A" * 40
    fake_signtool = _make_fake_signtool(tmp_path)
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SigningMethod", "LocalCertStore",
        "-CertThumbprint", bogus_thumb,
        "-SignToolPath", fake_signtool,
    ])
    assert cp.returncode != 0
    assert "no code-signing certificate found" in (cp.stdout + cp.stderr)


# --------------------------------------------------------------------------- #
# Phase 3H: SignTool path enforcement tests
# --------------------------------------------------------------------------- #


def test_script_requires_signtool_path_parameter():
    """Phase 3H: source must not contain PATH fallback or SDK auto-discovery."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "Get-Command signtool.exe" not in src, (
        "Phase 3H regression: PATH fallback still present in script."
    )
    assert "KnownSdkPaths" not in src, (
        "Phase 3H regression: SDK auto-discovery array still present in script."
    )
    assert "IsPathRooted" in src
    assert "signtool.exe" in src.lower()


def test_invocation_rejects_missing_signtool_path(tmp_path):
    """Phase 3H live: omitting -SignToolPath is rejected."""
    _skip_if_candidate_missing_or_drifted()
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SigningMethod", "LocalCertStore",
        "-CertThumbprint", "A" * 40,
        # No -SignToolPath supplied
    ])
    assert cp.returncode != 0
    combined = cp.stdout + cp.stderr
    assert "-SignToolPath is required" in combined


def test_invocation_rejects_relative_signtool_path(tmp_path):
    """Phase 3H live: a relative SignTool path is rejected."""
    _skip_if_candidate_missing_or_drifted()
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SignToolPath", r"relative\path\signtool.exe",
    ])
    assert cp.returncode != 0
    combined = cp.stdout + cp.stderr
    assert "absolute path" in combined


def test_invocation_rejects_nonexistent_signtool_path(tmp_path):
    """Phase 3H live: a nonexistent absolute path is rejected."""
    _skip_if_candidate_missing_or_drifted()
    fake_path = str(tmp_path / "nonexistent" / "signtool.exe")
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SignToolPath", fake_path,
    ])
    assert cp.returncode != 0
    combined = cp.stdout + cp.stderr
    assert "not found at" in combined


def test_invocation_rejects_wrong_filename_signtool_path(tmp_path):
    """Phase 3H live: an absolute path to a non-signtool.exe file is rejected."""
    _skip_if_candidate_missing_or_drifted()
    wrong_name = tmp_path / "notsigntool.exe"
    wrong_name.write_bytes(b"fake")
    cp = _invoke([
        "-InputExe", str(CANDIDATE),
        "-OutputDir", str(tmp_path / "out"),
        "-SignToolPath", str(wrong_name),
    ])
    assert cp.returncode != 0
    combined = cp.stdout + cp.stderr
    assert "signtool.exe" in combined


# --------------------------------------------------------------------------- #
# Protected-artifact invariants (sanity check at test time)
# --------------------------------------------------------------------------- #

def test_protected_artifacts_still_match_recorded_baselines():
    """After all tests run, the protected baselines must still match."""
    baselines = {
        REPO_ROOT / "data" / "ransomeye.db":
            "9B0896FCB8EB108063DA3266B8A9C6CFEB1689940501F62E6136EA0A447A52DB",
        REPO_ROOT / "dist" / "RansomEye.exe":
            "65F413F27315C3D0FF9E06AC0FA0710E7F03EF6B13718401040F8526665AE542",
        REPO_ROOT / "dist_isolated" / "RansomEye.exe":
            "49D2D87526F72E97FB284B1A683E0E10C50485890449F2C388E5369A8AA6653E",
        CANDIDATE: EXPECTED_CANDIDATE_SHA256,
    }
    for path, expected in baselines.items():
        if not path.is_file():
            pytest.skip(f"{path} missing on this workstation")
        actual = _sha256(path)
        assert actual == expected, f"{path} drifted: {actual} != {expected}"
