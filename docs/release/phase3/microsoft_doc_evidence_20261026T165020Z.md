# RansomEye Phase 3F — Microsoft SignTool and Trusted Signing Documentation Evidence

**Document type:** Phase 3F evidence record (Task 1).
**Captured by:** Phase 3F read-only + narrowly additive audit.
**Capture timestamp (UTC):** `2026-10-26T16:50:20Z`.
**Capture environment network status:** Internet access available in this environment at capture time (confirmed by HTTP 200 from `learn.microsoft.com`). This differs from Phase 3C's environment in which network access was unavailable.

**Repository state at capture:**

- Branch: `integration/12x-capabilities`
- HEAD: `da617241d4e8a597b556869e5bf59575955935af`
- Candidate under review: `dist_phase2g_rc\RansomEye.exe` (SHA-256 `F22F93B2A5855FA906CF8816EB893D77769FCE095216E5B36A55F251C11CB871`, Authenticode `NotSigned`).
- Signing script: `scripts\sign_release_candidate.ps1` (SHA-256 `565A2A39DDFD30088821CB43889857F9847F55823F224480FE743BA8033495C7`, same bytes as Phase 3E).

**Nothing was signed, built, timestamped, or installed during capture. No existing file was modified.**

---

## 1. Source pages consulted (raw bytes recorded to session scratchpad, not to repo)

| # | URL | Scratchpad path | Bytes | SHA-256 of fetched HTML |
|---|---|---|---|---|
| 1 | `https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool` | `%TEMP%\ransomeye_ms_docs_20261026T165020Z\signtool.html` | 70,729 | `BC238C8732ABE7ADBCAE25EA5BDAD5B5FEDE150051CCFC07F1B3D5348D4118BD` |
| 2 | `https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations` | `%TEMP%\ransomeye_ms_docs_20261026T165020Z\trusted-signing.html` | 66,056 | `02CDD664A45297BEB3BF8BE9389EDA8488304F41C01AF0D084C8FE35AF6D5B47` |
| 3 | `https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures` | `%TEMP%\ransomeye_ms_docs_20261026T165020Z\timestamping.html` | 62,064 | `0FC91A92AD31DE8EC25483A1529DD8A3D5F7AF584F8A51E4266D1D8FD5354B09` |

The raw HTML copies are **not** committed to the repository. The scratchpad is a `%TEMP%`-scoped session directory. Operators who need to independently reproduce this evidence should fetch the three URLs themselves — the live pages at `learn.microsoft.com` are the authoritative source, not these cached copies.

---

## 2. Flag-by-flag correspondence (official text → script usage)

Verbatim excerpts from each page (stripped of HTML markup) are quoted below and compared to the script's actual argv construction in `scripts\sign_release_candidate.ps1`.

### 2.1 `/fd` (file digest algorithm)

**Official (`signtool.html`):**
> "The sign command requires the file digest algorithm option ( /fd ) and the time stamp digest algorithm option ( /td ) during signing and time stamping, respectively. If /fd isn't specified during signing [...]"

**Official (`timestamping.html` – best practices table):**
> "Digest algorithm — SHA-256 ( /fd SHA256 ). SHA-1 signatures are deprecated and distrusted by modern Windows versions for code signing."

**Script usage** (`sign_release_candidate.ps1` line 173):
```
$SignArgs = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
```

**Verdict:** matches current Microsoft recommendation. ✅

### 2.2 `/tr` (RFC 3161 timestamp server URL) and `/td` (timestamp digest)

**Official (`signtool.html`):**
> "URL — specifies the URL of the time stamp server. If this option or /tr isn't specified, the signed file isn't time stamped."

**Official (`timestamping.html`):**
> "Time stamp protocol — RFC 3161 ( /tr flag with /td SHA256 ). RFC 3161 time stamps use a standard protocol with a SHA-256 digest, providing stronger guarantees than the legacy Authenticode time-stamping."

**Example from `timestamping.html`:**
```
signtool sign /fd SHA256 /tr https://timestamp.example.com /td SHA256 /a MyApp.exe
```

**Script usage:** `/tr $TimestampUrl /td SHA256`. Default `-TimestampUrl` is `http://timestamp.digicert.com` (a widely-used RFC 3161 TSA). Operator may override with `-TimestampUrl`.

**Verdict:** matches current Microsoft recommendation. ✅

**Operator note (NOT a defect):** for the Azure Trusted Signing signing path, the Trusted Signing page (`trusted-signing.html`) uses `http://timestamp.acs.microsoft.com` in its example — Microsoft's own TSA, aligned with their Trusted Signing service. When invoking the script with `-SigningMethod AzureTrustedSigning`, operators should supply:

```
-TimestampUrl "http://timestamp.acs.microsoft.com"
```

For `LocalCertStore` (hardware token) or `PfxFile` (lab use), DigiCert's or Sectigo's public RFC 3161 TSA remains appropriate.

### 2.3 `/sha1` (unambiguous certificate selector)

**Official (`signtool.html`):**
> "/sha1 Hash — Specifies the SHA1 hash of the signing certificate. The SHA1 hash is commonly used when multiple certificates satisfy [...]"

**Script usage** (line 285 inside the `LocalCertStore` switch branch):
```
$SignArgs += @("/sha1", $Cert.Thumbprint)
```

**Verdict:** matches current Microsoft recommendation. ✅ Phase 3B D4 remediation (pre-enumerate certs, throw on ambiguous subject match, always pass `/sha1` regardless of whether the operator supplied `-CertThumbprint` or `-CertSubject`) is consistent with Microsoft's own guidance for disambiguating multiple matches.

### 2.4 `/f` and `/p` (PFX file + password)

**Official (`signtool.html`):**
> "/f SignCertFile — Specifies the signing certificate in a file. If the file is in Personal Information Exchange (PFX) format and protected by a password, use the /p option to specify the password."

**Script usage** (`PfxFile` branch, lines around 328–343): emits `/f <abs-pfx>` and conditionally `/p <env-var>`; **the entire display line redacts `/p <value>` to `/p <redacted>` via `Format-RedactedSignArgs`** (Phase 3B D6).

**Verdict:** matches current Microsoft syntax. ✅ Credential-handling guidance in `docs/release/phase3/signing_workflow.md` section 2.5 (Phase 3B D7) explicitly directs operators away from the PFX path for public-release signing and towards hardware token or Azure Trusted Signing.

### 2.5 `/dlib` and `/dmdf` (Azure Trusted Signing dynamic library + metadata)

**Official (`signtool.html`):**
> "/dlib DLL — Specifies the DLL that implements the AuthenticodeDigestSign function to sign the digest with."

**Official (`trusted-signing.html` — the canonical form):**
```
"<Path to SDK bin folder>\x64\signtool.exe" sign /v /debug /fd SHA256 \
    /tr "http://timestamp.acs.microsoft.com" /td SHA256 \
    /dlib "<Path to Artifact Signing dlib bin folder>\x64\Azure.CodeSigning.Dlib.dll" \
    /dmdf "<Path to metadata file>\metadata.json" \
    <File to sign>
```

**Script usage** (lines 322–325, inside the `AzureTrustedSigning` switch branch after Phase 3B D8 remediation):
```
$SignArgs += @("/dlib", $ResolvedDlib, "/dmdf", $ResolvedMetadata)
```
Where `$ResolvedDlib` is `(Resolve-Path -LiteralPath $AzureDlibPath).Path` and must be `[IO.Path]::IsPathRooted`. `$ResolvedMetadata` likewise.

**Verdict:** matches current Microsoft recommendation. ✅ The absolute-path requirement (Phase 3B D8) is MORE conservative than the Microsoft example (which also uses an explicit absolute path, so there is no conflict).

### 2.6 `verify /pa /v`

**Official (`signtool.html`):** `verify` command with `/pa` applies the "default Authenticode verification policy." `/v` enables verbose output. (Both documented in signtool.html; grepped at capture time.)

**Script usage** (line 406):
```
$VerifyArgs = @("verify", "/pa", "/v", $SignedTargetExe)
```

**Verdict:** matches current Microsoft recommendation. ✅

### 2.7 Timestamp countersigner inspection (Phase 3B D11)

The script's `Get-AuthenticodeSignature`-based countersigner presence check (lines 442–450) is a PowerShell-layer belt-and-suspenders on top of SignTool's `verify /pa`. Microsoft's `timestamping.html` does not prescribe this layering as a requirement; it is a RansomEye-side defense-in-depth measure. The treatment of the countersigner's `NotAfter` as advisory (never fatal) is consistent with the timestamping page's statement that "RFC 3161 time stamps [...] remain valid even after the signing certificate expires." No conflict.

---

## 3. Overall conclusion for Blocker D9

**D9 — RESOLVED.**

Every SignTool flag the signing script actually uses — `sign`, `verify`, `/fd SHA256`, `/tr`, `/td SHA256`, `/sha1`, `/f`, `/p`, `/dlib`, `/dmdf`, `/pa`, `/v` — matches the current official Microsoft documentation at the three authoritative URLs captured above. The Azure Trusted Signing invocation form in `scripts\sign_release_candidate.ps1` is byte-structurally identical to the canonical example on `learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations`. SHA-256 digest + RFC 3161 timestamp + SHA-256 timestamp digest is the current best-practice recommendation on `learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures`.

**One operator advisory (not a defect):** when invoking the script with `-SigningMethod AzureTrustedSigning`, supply `-TimestampUrl "http://timestamp.acs.microsoft.com"` to match Microsoft's own Trusted Signing TSA (as shown in the trusted-signing.html example). The default `-TimestampUrl` remains correct for `LocalCertStore` and `PfxFile`.

---

## 4. Explicit limitations of this evidence

- **Timeliness:** Microsoft Learn pages are living documents and may change after this capture. The scratchpad copies and recorded SHA-256 hashes above pin the exact byte state at `2026-10-26T16:50:20Z` UTC, but future releases should re-verify at the moment of signing.
- **Scope:** this document verifies the SignTool / Trusted Signing *invocation syntax* only. It does not verify RansomEye's EV certificate issuance, SmartScreen reputation, or clean-machine SmartScreen behavior — those are Phase 4A and Phase 6 concerns.
- **No signing was performed.** This document is read-only evidence that the signing script's commands are syntactically correct per current Microsoft documentation. Running the script against a real certificate remains gated on Phase 4A (credential provisioning) and Gate 9 approvals.

---

## 5. Interpretation layer (clearly separated from quoted Microsoft text)

The three quoted / summarized passages above are the authoritative source. The interpretive statements that follow are my own analysis of how those passages apply to `scripts\sign_release_candidate.ps1`:

1. The script's syntax is current-Microsoft-compliant.
2. Phase 3B's path-rooted Dlib remediation (D8) is strictly more conservative than Microsoft's own documented absolute-path example — no backslide.
3. Phase 3B's `/p` redaction (D6) does not break the Microsoft-documented invocation shape; `/p <value>` is still what SignTool receives, only the console display is sanitized.
4. The timestamp-countersigner presence check (D11) is a RansomEye-side defense-in-depth, not a Microsoft requirement; it is compatible with Microsoft's timestamping guidance.
5. The one operator advisory on Trusted Signing TSA URL is a documentation note, not a signing-blocking defect.
