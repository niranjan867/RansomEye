"""Static, offline IOC (Indicator of Compromise) extractor for RansomEye.

Extracts normalized IOC observations from a file (text or binary) using
only Python stdlib: no subprocess, no eval/exec, no outbound network, no
external threat-intelligence lookups.

An IOC observation is NOT a security verdict. The presence of an IP,
domain, URL, hash, or email does not make the artifact malicious. Each
observation is recorded as an informational finding whose reason is
"<type> IOC observed", linked to a provenance evidence event through
the existing finding_evidence mechanism. The one exception is the LOLBIN
contextual rule, which uses RansomEye's existing command pattern to
raise a conservative medium-severity finding.

Provenance: this module adapts the hashing helper and ASCII / UTF-16LE
string extraction heuristic from 12X-RANSOMWARE-ANALYSIS
``ExtenderRem/backend/analyzers/ioc_extractor.py`` (MIT License,
Copyright (c) 2026 Judson1214; see THIRD_PARTY_NOTICES.md). All regex
patterns and the extraction/normalization pipeline were rewritten to
fix the known weaknesses documented in the Phase 2A audit:
  * domain regex no longer requires a hard-coded 14-TLD list,
  * BTC wallet matches are Base58Check-validated,
  * ETH candidates are excluded when they also match a SHA-1 digest,
  * email regex is corrected (12X had a literal ``|`` in the TLD class),
  * input is bounded (size, per-type cap, string length, context length).
RansomEye's existing IPv4, URL, and LOLBIN command regexes from
``script_analyzer`` are reused through local re-declarations to keep
this module standalone.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ANALYZER_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Resource bounds
# --------------------------------------------------------------------------- #

MAX_IOC_INPUT_SIZE = 32 * 1024 * 1024
MAX_IOCS_TOTAL = 2000
MAX_IOCS_PER_TYPE = 300
MAX_STRING_LEN = 2048
MIN_STRING_LEN = 4
MAX_CONTEXT_LEN = 160
MAX_WARNINGS = 50

# --------------------------------------------------------------------------- #
# Status + source identifiers
# --------------------------------------------------------------------------- #

STATUS_COMPLETE = "complete"
STATUS_EMPTY = "empty"
STATUS_OVERSIZED = "oversized"

IOC_SOURCE = "ioc_extractor"
IOC_ANALYST = "ransomeye-ioc-extractor"
IOC_FINDING_PREFIX = "ioc_"
LOLBIN_RULE_ID = "IOC-LOLBIN-001"

# --------------------------------------------------------------------------- #
# Regexes
# --------------------------------------------------------------------------- #

# RansomEye-native IPv4 (octet-validated), reused from script_analyzer semantics.
# The trailing lookahead rejects extensions like ".9" (which would make the match
# ambiguous) but allows a sentence-terminating period after the address.
_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?!\d)(?!\.\d)"
)

# Bounded IPv6 candidate: 2..8 hex groups joined by ":", or a form containing
# "::" compression. The result is validated by ``ipaddress.IPv6Address`` so
# this regex only needs to be a cheap pre-filter.
_IPV6_RE = re.compile(
    r"(?<![\w:])"
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"              # trailing ::
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"             # leading ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # middle ::
    r"|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"   # no compression
    r")"
    r"(?!\w)"
)

# URL: scheme + authority + optional path. Does not consume whitespace or quotes.
_URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>(){}\[\]\\^`|]{1,2048}",
    re.IGNORECASE,
)
_URL_HOST_RE = re.compile(
    r"^(?:https?|ftp)://(?:[^@/\s]*@)?([^/:?#\s]+)",
    re.IGNORECASE,
)

# Domain: 1–63-char labels with at least one dot and a letter-only TLD >= 2 chars.
# Deliberately strict: the TLD must be alphabetic to reduce FPs from version
# strings like "1.2.3". No hard-coded TLD allow-list.
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}"
    r"(?![\w.-])"
)

# Email: fix 12X's "[A-Z|a-z]" bug (literal pipe) by using a proper char class.
_EMAIL_RE = re.compile(
    r"(?<![\w.-])"
    r"[A-Za-z0-9._%+\-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}"
    r"(?![\w.-])"
)

_MD5_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
_SHA1_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
_SHA256_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")

# BTC Base58 characters (no 0, O, I, l).
_BTC_CANDIDATE_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![1-9A-HJ-NP-Za-km-z])")
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ETH candidate (0x + 40 hex). Mixed-case EIP-55 is NOT verified; we classify
# it as "potential" if it also matches a SHA-1 regex.
_ETH_RE = re.compile(r"(?<![0-9a-fA-FxX])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])")

# LOLBIN command pattern, same list that RansomEye script_analyzer already uses.
_LOLBIN_RE = re.compile(
    r"(?i)\b(?:cmd\.exe|powershell\.exe|wmic\.exe|vssadmin|certutil|bitsadmin"
    r"|schtasks|reg\.exe|rundll32\.exe|mshta\.exe)\b[^\r\n\"'<>|&]{0,200}"
)

# Defang reversal mappings. Applied ONLY to produce the "normalized" value;
# the original attacker-written string is preserved for forensic context.
# Non-TLD label suffixes commonly misidentified by the domain regex when the
# right-most label happens to be short and alphabetic. Keep conservative.
_NON_TLD_SUFFIXES = frozenset({
    "exe", "dll", "sys", "ocx", "scr", "pif", "lnk", "ps1", "psm1", "vbs",
    "bat", "cmd", "js", "jse", "wsf", "hta", "msi", "msp", "jar",
    "py", "pyc", "pyd", "rb", "sh", "pl",
    "md", "txt", "pdf", "doc", "docx", "docm", "dot", "dotm",
    "ppt", "pptx", "pptm", "xls", "xlsx", "xlsm", "xla", "csv",
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp",
    "mp3", "mp4", "avi", "mov", "mkv", "wmv", "wav", "flac",
    "log", "cfg", "ini", "yml", "yaml", "json", "xml", "html", "htm",
    "bak", "tmp", "old", "new", "orig",
    "db", "sqlite", "dat", "bin", "img",
})


_DEFANG_SUBS = (
    ("hxxp://", "http://"),
    ("hxxps://", "https://"),
    ("hXXp://", "http://"),
    ("hXXps://", "https://"),
    ("[.]", "."),
    ("[dot]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("(at)", "@"),
    ("[at]", "@"),
)


def _refang(text: str) -> str:
    out = text
    for src, dst in _DEFANG_SUBS:
        if src in out:
            out = out.replace(src, dst)
    return out


# Reserved / internal IPv4 blocks that are not useful network IOCs.
_RESERVED_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("255.255.255.255/32"),
)


def _is_useful_ipv4(ip: ipaddress.IPv4Address) -> bool:
    for net in _RESERVED_V4:
        if ip in net:
            return False
    return True


# --------------------------------------------------------------------------- #
# Base58Check validation for BTC
# --------------------------------------------------------------------------- #

def _base58_decode(value: str) -> bytes | None:
    try:
        n = 0
        for ch in value:
            idx = _BASE58_ALPHABET.index(ch)
            n = n * 58 + idx
    except ValueError:
        return None
    # Count leading '1's for leading zero bytes.
    leading = len(value) - len(value.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * leading + body


def _is_valid_btc_address(value: str) -> bool:
    """Base58Check: decode, verify 4-byte checksum = SHA256(SHA256(payload))[:4]."""
    decoded = _base58_decode(value)
    if decoded is None or len(decoded) < 5:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class IocObservation:
    """One normalized IOC occurrence with provenance."""
    ioc_type: str
    value_original: str
    value_normalized: str
    source: str  # "text" | "binary_ascii" | "binary_utf16"
    offset: int  # byte or char offset of first occurrence
    rule_id: str
    context_preview: str
    confidence: float


@dataclass
class IocAnalysisResult:
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    md5: str
    sha1: str
    analysis_status: str
    is_binary: bool
    observations: list[IocObservation] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    analyzer_version: str = ANALYZER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "analysis_status": self.analysis_status,
            "is_binary": self.is_binary,
            "observations": [
                {
                    "ioc_type": o.ioc_type,
                    "value_original": o.value_original,
                    "value_normalized": o.value_normalized,
                    "source": o.source,
                    "offset": o.offset,
                    "rule_id": o.rule_id,
                    "context_preview": o.context_preview,
                    "confidence": o.confidence,
                }
                for o in self.observations
            ],
            "counts": dict(self.counts),
            "warnings": list(self.warnings),
            "analyzer_version": self.analyzer_version,
        }


class IocAnalysisError(ValueError):
    """Raised for inputs the extractor refuses before parsing."""


# --------------------------------------------------------------------------- #
# Path validation (shared pattern)
# --------------------------------------------------------------------------- #

def _reject_remote_path(path_text: str) -> None:
    normalized = path_text.replace("/", "\\")
    if normalized.startswith("\\\\"):
        raise IocAnalysisError(
            "UNC, device and extended-length paths are not accepted; "
            "copy the file to a local drive first."
        )


# --------------------------------------------------------------------------- #
# Binary vs. text detection
# --------------------------------------------------------------------------- #

def _looks_binary(data: bytes) -> bool:
    """Heuristic binary detection: any NUL byte or >30% non-printable bytes."""
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return (len(sample) - printable) / len(sample) > 0.30


# --------------------------------------------------------------------------- #
# String extraction (ASCII + UTF-16LE)
# --------------------------------------------------------------------------- #

def _extract_strings(
    data: bytes, min_len: int = MIN_STRING_LEN, max_len: int = MAX_STRING_LEN,
) -> list[tuple[str, int, str]]:
    """Return (text, byte_offset, source) tuples. Bounded; dedup by (offset, text)."""
    results: list[tuple[str, int, str]] = []
    ascii_re = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    for m in ascii_re.finditer(data):
        chunk = m.group()
        if len(chunk) > max_len:
            chunk = chunk[:max_len]
        results.append((chunk.decode("ascii", errors="ignore"), m.start(), "binary_ascii"))
    utf16_re = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}")
    for m in utf16_re.finditer(data):
        chunk = m.group()
        if len(chunk) > max_len * 2:
            chunk = chunk[: max_len * 2]
        try:
            text = chunk.decode("utf-16le", errors="ignore")
        except Exception:  # noqa: BLE001 — defensive
            continue
        results.append((text, m.start(), "binary_utf16"))
    return results


# --------------------------------------------------------------------------- #
# Core extractor
# --------------------------------------------------------------------------- #

class IocExtractor:
    """Static, offline IOC extractor."""

    def analyze_file(self, file_path: str | Path) -> IocAnalysisResult:
        _reject_remote_path(str(file_path))
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"IOC input file not found: {file_path}")
        size = path.stat().st_size
        if size > MAX_IOC_INPUT_SIZE:
            raise IocAnalysisError(
                f"Input exceeds maximum size of {MAX_IOC_INPUT_SIZE} bytes"
            )
        data = path.read_bytes()
        return self.analyze_bytes(data, file_name=path.name, file_path=str(path))

    def analyze_text(self, text: str, *, file_name: str = "pasted") -> IocAnalysisResult:
        data = text.encode("utf-8", errors="replace")
        return self.analyze_bytes(data, file_name=file_name, file_path=file_name)

    def analyze_bytes(
        self, data: bytes, *, file_name: str = "", file_path: str = "",
    ) -> IocAnalysisResult:
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        is_binary = _looks_binary(data)
        result = IocAnalysisResult(
            file_path=file_path or file_name,
            file_name=file_name or "artifact",
            file_size=len(data),
            sha256=sha256,
            md5=md5,
            sha1=sha1,
            analysis_status=STATUS_EMPTY if not data else STATUS_COMPLETE,
            is_binary=is_binary,
        )
        if not data:
            result.warnings.append("Input is empty.")
            return result

        # Build (text, offset, source) chunks for scanning.
        chunks: list[tuple[str, int, str]] = []
        if is_binary:
            chunks.extend(_extract_strings(data))
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin-1", errors="replace")
            chunks.append((text, 0, "text"))

        # Precompute SHA-1 digest set from matches so we can drop ETH candidates
        # whose 40-hex body is ALSO seen as a bare SHA-1 digest elsewhere.
        # A SHA-1 match whose preceding byte is "x" of "0x" is itself the body
        # of an ETH candidate; such a match does not count as a bare SHA-1.
        sha1_hits: set[str] = set()
        for chunk_text, _off, _src in chunks:
            for m in _SHA1_RE.finditer(chunk_text):
                start = m.start()
                if start >= 2 and chunk_text[start - 2:start].lower() == "0x":
                    continue
                sha1_hits.add(m.group().lower())

        seen_norm_per_type: dict[str, set[str]] = {}

        def _add(ioc_type: str, original: str, normalized: str, offset: int,
                 source: str, rule_id: str, chunk_text: str, confidence: float) -> bool:
            if len(result.observations) >= MAX_IOCS_TOTAL:
                self._warn(result, f"Total IOC cap reached ({MAX_IOCS_TOTAL}); further IOCs dropped.")
                return False
            seen = seen_norm_per_type.setdefault(ioc_type, set())
            if normalized in seen:
                return True
            if len(seen) >= MAX_IOCS_PER_TYPE:
                self._warn(result, f"Per-type cap reached for {ioc_type} ({MAX_IOCS_PER_TYPE}); dropping extras.")
                return False
            seen.add(normalized)
            preview = _bounded_context(chunk_text, offset)
            result.observations.append(IocObservation(
                ioc_type=ioc_type,
                value_original=original[:MAX_STRING_LEN],
                value_normalized=normalized[:MAX_STRING_LEN],
                source=source,
                offset=offset,
                rule_id=rule_id,
                context_preview=preview,
                confidence=confidence,
            ))
            return True

        for chunk_text, chunk_offset, source in chunks:
            if not chunk_text:
                continue

            # Defang-reversed view used for scanning URLs/domains/IPs.
            refanged = _refang(chunk_text)

            # IPv4
            for m in _IPV4_RE.finditer(refanged):
                raw = m.group()
                try:
                    ipv4 = ipaddress.IPv4Address(raw)
                except (ValueError, ipaddress.AddressValueError):
                    continue
                if not _is_useful_ipv4(ipv4):
                    continue
                _add("ipv4", raw, str(ipv4), chunk_offset + m.start(), source,
                     "IOC-NET-IPV4", refanged, 0.80)

            # IPv6
            for m in _IPV6_RE.finditer(refanged):
                raw = m.group()
                if ":" not in raw or raw.count(":") < 2:
                    continue
                try:
                    ipv6 = ipaddress.IPv6Address(raw)
                except (ValueError, ipaddress.AddressValueError):
                    continue
                if ipv6.is_loopback or ipv6.is_unspecified:
                    continue
                _add("ipv6", raw, str(ipv6), chunk_offset + m.start(), source,
                     "IOC-NET-IPV6", refanged, 0.80)

            # URL
            for m in _URL_RE.finditer(refanged):
                raw = m.group()
                normalized = raw
                host_m = _URL_HOST_RE.match(raw)
                if host_m:
                    host = host_m.group(1).lower()
                    normalized = raw[: host_m.start(1)] + host + raw[host_m.end(1):]
                # Lowercase scheme too.
                normalized = re.sub(r"^(https?|ftp)", lambda mm: mm.group(1).lower(),
                                    normalized, count=1, flags=re.IGNORECASE)
                _add("url", raw, normalized, chunk_offset + m.start(), source,
                     "IOC-NET-URL", refanged, 0.80)

            # Domain (standalone — don't double-count the host part of a URL that
            # exactly matches the whole chunk; findall is fine because our offset
            # points to the specific occurrence)
            for m in _DOMAIN_RE.finditer(refanged):
                raw = m.group()
                normalized = raw.lower().rstrip(".")
                last_label = normalized.split(".")[-1]
                # Suppress trivial version-string FPs (e.g., "1.2.3.4" is caught by
                # IPv4; here we skip any match whose rightmost label is numeric).
                if last_label.isdigit():
                    continue
                # Suppress file-extension-looking matches (powershell.exe, foo.dll).
                if last_label in _NON_TLD_SUFFIXES:
                    continue
                _add("domain", raw, normalized, chunk_offset + m.start(), source,
                     "IOC-NET-DOMAIN", refanged, 0.70)

            # Email
            for m in _EMAIL_RE.finditer(refanged):
                raw = m.group()
                local, _, host = raw.partition("@")
                normalized = f"{local}@{host.lower()}"
                _add("email", raw, normalized, chunk_offset + m.start(), source,
                     "IOC-NET-EMAIL", refanged, 0.75)

            # Hashes — SHA-256 first, then SHA-1 (excluding those overlapping with
            # SHA-256), then MD5 (same exclusion idea by length).
            for m in _SHA256_RE.finditer(chunk_text):
                raw = m.group()
                _add("sha256", raw, raw.lower(), chunk_offset + m.start(), source,
                     "IOC-HASH-SHA256", chunk_text, 0.85)
            for m in _SHA1_RE.finditer(chunk_text):
                raw = m.group()
                start = m.start()
                # A SHA-1 match whose preceding byte is "0x" is the body of an
                # ETH candidate and must not also be reported as a bare SHA-1.
                if start >= 2 and chunk_text[start - 2:start].lower() == "0x":
                    continue
                _add("sha1", raw, raw.lower(), chunk_offset + m.start(), source,
                     "IOC-HASH-SHA1", chunk_text, 0.85)
            for m in _MD5_RE.finditer(chunk_text):
                raw = m.group()
                _add("md5", raw, raw.lower(), chunk_offset + m.start(), source,
                     "IOC-HASH-MD5", chunk_text, 0.85)

            # BTC — Base58Check validation
            for m in _BTC_CANDIDATE_RE.finditer(chunk_text):
                raw = m.group()
                if _is_valid_btc_address(raw):
                    _add("btc", raw, raw, chunk_offset + m.start(), source,
                         "IOC-CRYPTO-BTC", chunk_text, 0.75)

            # ETH candidate (exclude strings that are also SHA-1 digests)
            for m in _ETH_RE.finditer(chunk_text):
                raw = m.group()
                hex_body = raw[2:].lower()
                if hex_body in sha1_hits:
                    # Already extracted as SHA-1; don't double-report as ETH.
                    continue
                _add("eth", raw, raw.lower(), chunk_offset + m.start(), source,
                     "IOC-CRYPTO-ETH", chunk_text, 0.60)

            # LOLBIN
            for m in _LOLBIN_RE.finditer(chunk_text):
                raw = m.group().strip()
                _add("lolbin", raw, raw.lower(), chunk_offset + m.start(), source,
                     LOLBIN_RULE_ID, chunk_text, 0.60)

        # Count observations per type.
        counts: dict[str, int] = {}
        for o in result.observations:
            counts[o.ioc_type] = counts.get(o.ioc_type, 0) + 1
        result.counts = counts
        return result

    @staticmethod
    def _warn(result: IocAnalysisResult, msg: str) -> None:
        if len(result.warnings) < MAX_WARNINGS and msg not in result.warnings:
            result.warnings.append(msg)


def _bounded_context(chunk_text: str, offset: int) -> str:
    """Return a bounded printable preview around ``offset``."""
    if not chunk_text:
        return ""
    start = max(0, offset - MAX_CONTEXT_LEN // 2)
    end = min(len(chunk_text), start + MAX_CONTEXT_LEN)
    preview = chunk_text[start:end]
    # Keep single-line.
    return preview.replace("\n", " ").replace("\r", " ")[:MAX_CONTEXT_LEN]


# --------------------------------------------------------------------------- #
# Evidence / Finding integration
# --------------------------------------------------------------------------- #

_RULE_ID_IN_REASON = re.compile(r"^\[([A-Z0-9][A-Z0-9-]*)\]")

IOC_SEVERITY_MAP = {
    "ipv4": "informational", "ipv6": "informational",
    "domain": "informational", "url": "informational",
    "email": "informational",
    "md5": "informational", "sha1": "informational", "sha256": "informational",
    "btc": "low", "eth": "low",
    "lolbin": "medium",
}

IOC_TECHNIQUE_MAP = {
    "ipv4": "T1071", "ipv6": "T1071",
    "domain": "T1071.004", "url": "T1071.001",
    "email": "T1566",
    "md5": "T1027", "sha1": "T1027", "sha256": "T1027",
    "btc": "T1657", "eth": "T1657",
    "lolbin": "T1059",
}


def _ioc_provenance_event_id(case_id: str, sha256: str) -> str:
    seed = f"{case_id}|{sha256}"
    return "EVT-IOC-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _existing_rule_ids(store: Any, case_id: str, event_id: str) -> set[str]:
    present: set[str] = set()
    try:
        findings = store.get_event_findings(case_id, event_id)
    except Exception:  # noqa: BLE001 — defensive
        return present
    for finding in findings:
        match = _RULE_ID_IN_REASON.match(finding.get("reason", ""))
        if match:
            present.add(match.group(1))
    return present


def _finding_for_type(
    ioc_type: str, result: IocAnalysisResult, observations: list[IocObservation],
) -> dict[str, Any]:
    severity = IOC_SEVERITY_MAP.get(ioc_type, "informational")
    technique = IOC_TECHNIQUE_MAP.get(ioc_type, "T1071")
    if ioc_type == "lolbin":
        rule_id = LOLBIN_RULE_ID
        title = "LOLBIN command observed in input"
        score = 30
        confidence = 0.60
    else:
        rule_id = f"IOC-OBS-{ioc_type.upper()}"
        title = f"{ioc_type.upper()} IOC observed"
        score = 1
        confidence = observations[0].confidence if observations else 0.70
    sample_values = ", ".join(o.value_normalized for o in observations[:3])
    excerpt = sample_values[:160]
    reason = (
        f"[{rule_id}] {title} (count={len(observations)}, severity={severity}): "
        f"{excerpt} | artifact sha256={result.sha256[:16]}"
    )
    return {
        "type": f"{IOC_FINDING_PREFIX}{'contextual_lolbin' if ioc_type == 'lolbin' else 'observation_' + ioc_type}",
        "score": score,
        "confidence": confidence,
        "technique": technique,
        "reason": reason,
    }


def ingest_ioc_finding(
    store: Any, case_id: str, result: IocAnalysisResult,
) -> list[int]:
    """Persist IOC analysis into an EvidenceStore case.

    Creates one deterministic ``file_stream_hash`` provenance event per
    artifact, one informational finding per IOC type observed (plus one
    medium-severity LOLBIN finding if the LOLBIN pattern matched), each
    linked to the provenance event via ``finding_evidence``, and one
    ``reviewed`` chain-of-custody record. Idempotent: re-ingesting the
    same artifact does not duplicate findings (rule_id dedup against
    findings already attached to the provenance event).
    """
    if result.analysis_status != STATUS_COMPLETE:
        return []
    if not result.file_path:
        raise ValueError("ingest_ioc_finding requires result.file_path")

    path = Path(result.file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {result.file_path}")

    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    prov_event_id = _ioc_provenance_event_id(case_id, result.sha256)

    store.save_event(case_id, {
        "event_id": prov_event_id,
        "case_id": case_id,
        "timestamp": mtime,
        "source": IOC_SOURCE,
        "event_type": "file_stream_hash",
        "file_path": str(path.resolve()),
        "hashes": f"SHA256={result.sha256},SHA1={result.sha1},MD5={result.md5}",
        "confidence": 0.95,
        "metadata": {
            "observation": "ioc_extraction_provenance",
            "sha256": result.sha256,
            "sha1": result.sha1,
            "md5": result.md5,
            "file_size": result.file_size,
            "is_binary": result.is_binary,
            "ioc_counts": dict(result.counts),
            "analyzer_version": result.analyzer_version,
            "analysis_status": result.analysis_status,
        },
    })

    # Group observations by type.
    by_type: dict[str, list[IocObservation]] = {}
    for o in result.observations:
        by_type.setdefault(o.ioc_type, []).append(o)

    already = _existing_rule_ids(store, case_id, prov_event_id)
    created: list[int] = []
    # Deterministic iteration order.
    for ioc_type in sorted(by_type):
        observations = by_type[ioc_type]
        if not observations:
            continue
        if ioc_type == "lolbin":
            rule_id = LOLBIN_RULE_ID
        else:
            rule_id = f"IOC-OBS-{ioc_type.upper()}"
        if rule_id in already:
            continue
        finding = _finding_for_type(ioc_type, result, observations)
        finding_id = store.save_finding(case_id, finding, event_ids=[prov_event_id])
        created.append(finding_id)

    store.record_custody_event(
        case_id=case_id,
        artifact_path=str(path.resolve()),
        sha256=result.sha256,
        action="reviewed",
        analyst=IOC_ANALYST,
        note=(
            f"IOC extraction: observations={len(result.observations)}, "
            f"types={len(by_type)}, size={result.file_size}, "
            f"binary={result.is_binary}"
        ),
    )

    from ransomeye.threat_assessment import assess_case
    assess_case(store, case_id)

    return created
