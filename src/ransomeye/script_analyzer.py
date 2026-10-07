"""Static, offline script analyzer for RansomEye.

Analyzes PowerShell, VBScript, exported VBA source, JScript, HTA, WSF, batch
files and bare command lines without executing them. Encoded and obfuscated
layers are decoded with strict, bounded, deterministic transforms, and every
layer is matched against RansomEye's native rule catalog.

Portions adapted from 12X-RANSOMWARE-ANALYSIS ExtenderRem (MIT License,
Copyright (c) 2026 Judson1214; see THIRD_PARTY_NOTICES.md):
    backend/analyzers/doc_js_analyzer.py: quoted "+" concatenation folding,
        the 40+ character Base64 candidate pattern, auto-execution entry point
        and scripting object names.
    backend/analyzers/ioc_extractor.py: octet-validated IPv4 pattern, reserved
        address filter and LOLBin command list.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

from ransomeye.rules import RANSOM_NOTE_KEYWORDS

ANALYZER_VERSION = "1.0.0"

MAX_SCRIPT_SIZE = 5 * 1024 * 1024
MAX_DECODE_DEPTH = 3
MAX_DECODED_BYTES = 1024 * 1024
MAX_DECODE_CANDIDATES = 64
MIN_STANDALONE_BASE64 = 40
MIN_PRINTABLE_RATIO = 0.80
PREVIEW_CHARS = 2000
EXCERPT_CHARS = 120
MAX_INDICATORS = 200
MAX_IOCS_PER_TYPE = 100
MAX_WARNINGS = 50

STATUS_COMPLETE = "complete"
STATUS_UNSUPPORTED_CONTAINER = "unsupported_container"
STATUS_BINARY_REJECTED = "binary_rejected"

SEVERITY_NONE = "NONE"
SEVERITY_NOT_ANALYZED = "NOT_ANALYZED"

LANGUAGES = frozenset(
    {"powershell", "vbscript", "vba", "jscript", "hta", "wsf", "batch", "command_line"}
)

EXTENSION_LANGUAGES = {
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".vbs": "vbscript",
    ".bas": "vba",
    ".cls": "vba",
    ".frm": "vba",
    ".js": "jscript",
    ".hta": "hta",
    ".wsf": "wsf",
    ".bat": "batch",
    ".cmd": "batch",
}

OFFICE_CONTAINER_EXTENSIONS = frozenset(
    {
        ".doc", ".docm", ".docx", ".dot", ".dotm",
        ".xls", ".xlsm", ".xlsb", ".xlsx", ".xla", ".xlam", ".xlt", ".xltm",
        ".ppt", ".pptm", ".pptx", ".pot", ".potm", ".ppsm",
        ".rtf",
    }
)

_CONTAINER_MAGICS = (
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
    (b"PK\x03\x04", "ZIP / Office Open XML container"),
    (b"{\\rtf", "RTF document"),
    (b"%PDF", "PDF document"),
)
_BINARY_MAGICS = (
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "ELF executable"),
)


class ScriptAnalysisError(ValueError):
    """Raised when an input cannot be accepted for script analysis."""


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True)
class ScriptRule:
    """One deterministic detection rule. Fires when every regex of any clause matches."""

    rule_id: str
    title: str
    category: str
    severity: str
    weight: int
    technique: str
    confidence: float
    view: str = "folded"
    clauses: tuple[tuple[re.Pattern[str], ...], ...] = ()


@dataclass(frozen=True)
class ScriptIndicator:
    """A rule match within one analyzed layer."""

    rule_id: str
    title: str
    category: str
    severity: str
    weight: int
    technique: str
    confidence: float
    layer_index: int
    depth: int
    line: int
    excerpt: str


@dataclass(frozen=True)
class DecodedLayer:
    """A payload recovered from an encoded region of a parent layer (index 0 is the original)."""

    index: int
    depth: int
    parent_index: int
    method: str
    offset: int
    sha256: str
    size: int
    encoding: str
    is_text: bool
    preview: str


@dataclass
class ScriptAnalysisResult:
    """Deterministic result of static script analysis. Contains no timestamps."""

    file_name: str
    file_path: str
    file_size: int
    sha256: str
    sha1: str
    md5: str
    language: str
    encoding: str
    line_count: int
    analysis_status: str
    score: int = 0
    severity: str = SEVERITY_NONE
    confidence: float = 0.0
    techniques: list[str] = field(default_factory=list)
    indicators: list[ScriptIndicator] = field(default_factory=list)
    decoded_layers: list[DecodedLayer] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    analyzer_version: str = ANALYZER_VERSION

    @property
    def rule_ids(self) -> list[str]:
        return sorted({indicator.rule_id for indicator in self.indicators})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_summary_text(self) -> str:
        lines = [
            "==================================================================",
            "               RANSOMEYE SCRIPT ANALYSIS REPORT                   ",
            "==================================================================",
            f"Target           : {self.file_name}",
            f"File Path        : {self.file_path or 'N/A'}",
            f"Size             : {self.file_size:,} bytes",
            f"Language         : {self.language}",
            f"Encoding         : {self.encoding}",
            f"Lines            : {self.line_count}",
            f"Analysis Status  : {self.analysis_status}",
            "",
            "--- HASHES ---",
            f"SHA-256 : {self.sha256}",
            f"SHA-1   : {self.sha1}",
            f"MD5     : {self.md5}",
            "",
            "--- VERDICT ---",
        ]
        if self.analysis_status != STATUS_COMPLETE:
            lines.append("Not analyzed: this content type is not supported by script analysis.")
        else:
            lines.extend(
                [
                    f"Severity         : {self.severity}",
                    f"Score            : {self.score}/100",
                    f"Confidence       : {self.confidence:.2f}",
                    f"Techniques       : {', '.join(self.techniques) or 'None'}",
                ]
            )
            if not self.indicators:
                lines.append(
                    "No known malicious patterns were found. Static analysis cannot prove a script is safe."
                )

        if self.indicators:
            lines.extend(["", f"--- INDICATORS ({len(self.indicators)}) ---"])
            for ind in self.indicators:
                lines.append(
                    f"  [{ind.severity.upper()}] {ind.rule_id} {ind.title} ({ind.technique})"
                    f" layer {ind.layer_index} depth {ind.depth} line {ind.line}"
                )
                lines.append(f"      {ind.excerpt}")

        if self.decoded_layers:
            lines.extend(["", f"--- DECODED LAYERS ({len(self.decoded_layers)}) ---"])
            for layer in self.decoded_layers:
                kind = layer.encoding if layer.is_text else "binary"
                lines.append(
                    f"  #{layer.index} depth {layer.depth} from #{layer.parent_index} @{layer.offset}"
                    f" {layer.method} {layer.size:,} bytes {kind} sha256={layer.sha256}"
                )

        populated = {name: values for name, values in self.iocs.items() if values}
        if populated:
            lines.extend(["", "--- EXTRACTED IOCS ---"])
            for name, values in populated.items():
                lines.append(f"  {name.replace('_', ' ').title()}: " + ", ".join(values[:10]))
                if len(values) > 10:
                    lines.append(f"    ... and {len(values) - 10} more")

        if self.warnings:
            lines.extend(["", "--- WARNINGS ---"])
            lines.extend(f"  [!] {warning}" for warning in self.warnings)

        lines.extend(["", "=================================================================="])
        return "\n".join(lines)


_L = r"[^\r\n]{0,400}"
_NOTE_KEYWORDS = "|".join(re.escape(keyword.lower()) for keyword in RANSOM_NOTE_KEYWORDS)

_ENCODED_COMMAND_RULE_ID = "PS-ENC-001"
_CHARCODE_RULE_ID = "OBF-018"
_MIXED_SCRIPT_RULE_ID = "OBF-019"

RULES: tuple[ScriptRule, ...] = (
    ScriptRule(_ENCODED_COMMAND_RULE_ID, "Encoded PowerShell command", "obfuscation",
               "high", 20, "T1027", 0.85),
    ScriptRule("PS-DEC-002", "Runtime Base64 + compression decode routine", "obfuscation",
               "medium", 15, "T1140", 0.80,
               clauses=((_rx(r"frombase64string"), _rx(r"gzipstream|deflatestream|io\.compression")),)),
    ScriptRule("PS-IEX-003", "Invoke-Expression execution", "execution",
               "medium", 15, "T1059.001", 0.75,
               clauses=((_rx(r"(?<![\w$-])(?:invoke-expression|iex)(?![\w-])"),),)),
    ScriptRule("PS-DL-004", "PowerShell payload download", "download",
               "high", 20, "T1105", 0.75,
               clauses=((_rx(
                   r"\.download(?:string|file|data)(?:async|taskasync)?\s*\("
                   r"|(?<![\w-])(?:invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer)(?![\w-])"
                   r"|net\.http\.httpclient"),),)),
    ScriptRule("PS-HID-005", "Hidden PowerShell window", "defense_evasion",
               "medium", 10, "T1564.003", 0.70,
               clauses=((_rx(
                   r"(?<![\w-])[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?"
                   r"\s+[\"']?h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?(?![\w-])"
                   r"|windowstyle\]::hidden"),),)),
    ScriptRule("PS-POL-006", "Execution policy bypass", "defense_evasion",
               "low", 5, "T1059.001", 0.50,
               clauses=((_rx(
                   r"(?<![\w-])[-/](?:ep|ex(?:e(?:c(?:u(?:t(?:i(?:o(?:n(?:p(?:o(?:l(?:i(?:c(?:y)?)?)?)?)?)?)?)?)?)?)?)?)?)"
                   r"\s+[\"']?(?:bypass|unrestricted)(?![\w-])"
                   r"|set-executionpolicy\s+(?:-executionpolicy\s+)?[\"']?(?:bypass|unrestricted)(?![\w-])"),),)),
    ScriptRule("PS-AMSI-007", "AMSI tampering", "defense_evasion",
               "critical", 30, "T1562.001", 0.90,
               clauses=((_rx(r"amsiutils|amsiinitfailed|amsiscanbuffer"),),)),
    ScriptRule("PS-DEF-008", "Microsoft Defender tampering", "defense_evasion",
               "high", 25, "T1562.001", 0.85,
               clauses=((_rx(rf"set-mppreference\b{_L}-disable\w*|add-mppreference\b{_L}-exclusion\w*"),),)),
    ScriptRule("PS-REF-009", "Reflective assembly loading", "execution",
               "high", 20, "T1620", 0.75,
               clauses=((_rx(
                   r"\[(?:system\.)?reflection\.assembly\]::(?:load|loadfile|loadfrom|unsafeloadfrom)\s*\("
                   r"|\[appdomain\]::currentdomain\.load\s*\("),),)),
    ScriptRule("REC-010", "System recovery inhibition", "recovery_inhibition",
               "critical", 35, "T1490", 0.90,
               clauses=((_rx(
                   r"vssadmin(?:\.exe)?\s+delete\s+shadows|vssadmin(?:\.exe)?\s+resize\s+shadowstorage"
                   r"|wmic(?:\.exe)?\s+shadowcopy\s+delete|\bdelete\s+shadows\b"
                   r"|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)"
                   r"|recoveryenabled\s+no\b|bootstatuspolicy\s+ignoreallfailures"
                   rf"|win32_shadowcopy{_L}(?:\.delete\s*\(|remove-(?:wmiobject|ciminstance))"),),)),
    ScriptRule("RAN-011", "File enumeration combined with symmetric encryption", "impact",
               "critical", 30, "T1486", 0.80,
               clauses=((
                   _rx(rf"get-childitem\b{_L}-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?\b"
                       rf"|(?<![\w-])(?:gci|ls|dir)\s{_L}-r(?:ecurse)?\b"
                       r"|\.getfiles\s*\(|\.enumeratefiles\s*\(|\.subfolders\b"),
                   _rx(r"aescryptoserviceprovider|aesmanaged|rijndaelmanaged"
                       r"|security\.cryptography\.aes\]::create|\.createencryptor\s*\("),
               ),)),
    ScriptRule("RAN-012", "Ransom note written to disk", "impact",
               "medium", 15, "T1486", 0.75,
               clauses=((
                   _rx(rf"out-file|set-content|add-content|writealltext|createtextfile|opentextfile"
                       rf"|(?<![\w-])echo\b{_L}>"),
                   _rx(rf"[\w.-]{{0,64}}(?:{_NOTE_KEYWORDS})[\w.-]{{0,64}}\.(?:txt|html?|hta|rtf|url)\b"),
               ),)),
    ScriptRule("VB-AUTO-013", "Office macro auto-execution entry point", "auto_execution",
               "medium", 10, "T1204.002", 0.70,
               clauses=((_rx(
                   r"^[ \t]*(?:(?:private|public)[ \t]+)?sub[ \t]+"
                   r"(?:autoopen|auto_open|autoexec|auto_exec|autoclose|auto_close|document_open"
                   r"|document_close|document_beforeclose|workbook_open|workbook_beforeclose"
                   r"|workbook_activate)[ \t]*\("),),)),
    ScriptRule("VB-EXEC-014", "VBScript/VBA shell execution", "execution",
               "medium", 15, "T1059.005", 0.75,
               clauses=((
                   _rx(r"(?:createobject|getobject)\s*\(\s*[\"'](?:wscript\.shell|shell\.application)[\"']"),
                   _rx(r"\.(?:run|exec|shellexecute)\b"),
               ),)),
    ScriptRule("VB-DL-015", "Download and write payload to disk", "download",
               "high", 25, "T1105", 0.85,
               clauses=(
                   (
                       _rx(r"msxml2\.(?:server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest"),
                       _rx(r"adodb\.stream"),
                       _rx(r"\.savetofile\b"),
                   ),
                   (_rx(r"\burldownloadtofile[aw]?\b"),),
               )),
    ScriptRule("VB-WMI-016", "WMI process creation", "execution",
               "high", 20, "T1047", 0.80,
               clauses=(
                   (_rx(r"winmgmts:"), _rx(r"win32_process"), _rx(r"\.create\b")),
                   (_rx(rf"invoke-(?:wmi|cim)method\b{_L}win32_process{_L}\bcreate\b"),),
               )),
    ScriptRule("OBF-017", "Dynamic execution of constructed code", "obfuscation",
               "medium", 15, "T1027.010", 0.70, view="raw",
               clauses=((_rx(
                   r"^[ \t]*execute(?:global)?\b[ \t]*\(?[ \t]*"
                   r"(?:chrw?[ \t]*\(|strreverse[ \t]*\(|replace[ \t]*\(|[a-z_]\w*[ \t]*(?:[&()]|$))"
                   r"|(?<![\w.])eval[ \t]*\([ \t]*(?![\"'][^\"'\r\n]{0,400}[\"'][ \t]*\))"
                   r"|\bnew[ \t]+function[ \t]*\("
                   r"|\[scriptblock\]::create[ \t]*\("),),)),
    ScriptRule(_CHARCODE_RULE_ID, "Character-code, reversal or backtick obfuscation", "obfuscation",
               "medium", 10, "T1027.010", 0.65, view="raw"),
    ScriptRule(_MIXED_SCRIPT_RULE_ID, "Mixed-script (homoglyph) identifier", "obfuscation",
               "medium", 10, "T1027.010", 0.65, view="raw"),
    ScriptRule("LOL-020", "Mshta executing remote or inline script", "lolbin",
               "high", 20, "T1218.005", 0.85,
               clauses=((_rx(r"mshta(?:\.exe)?[\"']?\s+[\"']?(?:https?://|vbscript:|javascript:|about:)"),),)),
    ScriptRule("LOL-021", "Regsvr32 scriptlet execution", "lolbin",
               "high", 20, "T1218.010", 0.85,
               clauses=((_rx(rf"regsvr32(?:\.exe)?\b{_L}/i:\s*[\"']?(?:https?|ftp)://"
                             rf"|regsvr32(?:\.exe)?\b{_L}scrobj\.dll"),),)),
    ScriptRule("LOL-022", "Rundll32 executing script or remote content", "lolbin",
               "high", 20, "T1218.011", 0.80,
               clauses=((_rx(rf"rundll32(?:\.exe)?\b{_L}(?:javascript:|vbscript:|https?://)"),),)),
    ScriptRule("LOL-023", "Certutil download or decode", "lolbin",
               "medium", 15, "T1105", 0.80,
               clauses=((_rx(rf"certutil(?:\.exe)?\b{_L}[-/](?:urlcache|decode|decodehex)\b"),),)),
    ScriptRule("LOL-024", "BITS job transfer", "lolbin",
               "medium", 15, "T1197", 0.75,
               clauses=((_rx(rf"bitsadmin(?:\.exe)?\b{_L}/(?:transfer|addfile|setnotifycmdline)\b"),),)),
    ScriptRule("PER-025", "Scheduled task creation", "persistence",
               "medium", 15, "T1053.005", 0.70,
               clauses=((_rx(rf"schtasks(?:\.exe)?\b{_L}/create\b|(?<![\w-])register-scheduledtask(?![\w-])"),),)),
    ScriptRule("PER-026", "Registry Run key persistence", "persistence",
               "medium", 15, "T1547.001", 0.75,
               clauses=((_rx(rf"(?:reg(?:\.exe)?[ \t]+add|set-itemproperty|new-itemproperty|\.regwrite)\b"
                             rf"{_L}\\currentversion\\run(?:once)?\b"),),)),
    ScriptRule("BAT-027", "Recursive destruction of user data", "impact",
               "medium", 15, "T1485", 0.75,
               clauses=((_rx(
                   rf"(?<![\w-])(?:del|erase)\b(?={_L}[ \t]/s\b)(?={_L}[ \t]/q\b){_L}"
                   r"(?:%userprofile%|%homepath%|%appdata%|%onedrive%|\\users\\)"
                   r"|(?<![\w-])cipher(?:\.exe)?[ \t]+/w:"
                   rf"|remove-item\b{_L}-recurse{_L}(?:\$env:userprofile|\\users\\)"),),)),
    ScriptRule("JS-EXEC-028", "JScript ActiveX shell execution", "execution",
               "medium", 15, "T1059.007", 0.75,
               clauses=((
                   _rx(r"new[ \t]+activexobject[ \t]*\([ \t]*[\"'](?:wscript\.shell|shell\.application)[\"']"),
                   _rx(r"\.(?:run|exec|shellexecute)\b"),
               ),)),
)

_RULES_BY_ID = {rule.rule_id: rule for rule in RULES}

_ENCODED_COMMAND_RE = re.compile(
    r"(?<![\w-])[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?"
    r"[ \t]+[\"']?([A-Za-z0-9+/]{8,}={0,2})",
    re.IGNORECASE,
)
_FROM_BASE64_RE = re.compile(
    r"frombase64string[ \t]*\([ \t]*[\"']([A-Za-z0-9+/=\s]{8,})[\"'][ \t]*\)",
    re.IGNORECASE,
)
_STANDALONE_BASE64_RE = re.compile(
    rf"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{{{MIN_STANDALONE_BASE64},}}={{0,2}}(?![A-Za-z0-9+/=])"
)
_HEX_ONLY_RE = re.compile(r"[0-9A-Fa-f]+")
_COMPRESSION_RE = re.compile(r"gzipstream|deflatestream|io\.compression", re.IGNORECASE)

_DASHES = str.maketrans({"\u2013": "-", "\u2014": "-", "\u2015": "-"})
_BACKTICK_RE = re.compile(r"`(?=\w)")
_PS_CHAR_RE = re.compile(r"\[char\][ \t]*(0x[0-9a-f]{1,6}|\d{1,7})", re.IGNORECASE)
_VB_CHR_RE = re.compile(r"\bchrw?[ \t]*\([ \t]*(&h[0-9a-f]{1,6}|\d{1,7})[ \t]*\)", re.IGNORECASE)
_JS_FROMCHARCODE_RE = re.compile(r"string\.fromcharcode[ \t]*\(([0-9 \t,]{1,8192})\)", re.IGNORECASE)
_CONCAT_RES = (
    re.compile(r"'[ \t]*\+[ \t]*'"),
    re.compile(r'"[ \t]*\+[ \t]*"'),
    re.compile(r'"[ \t]*&[ \t]*"'),
)

_CHARCODE_RE = re.compile(
    r"chrw?\s*\(\s*(?:\d+|&h[0-9a-f]+)\s*\)|\[char\]\s*(?:0x[0-9a-f]+|\d+)|fromcharcode\s*\(",
    re.IGNORECASE,
)
_REVERSE_RE = re.compile(r"strreverse\s*\(|\[array\]::reverse\s*\(", re.IGNORECASE)
_TICK_RE = re.compile(r"(?<=[a-z])`(?![rnt](?:[^a-z]|$))(?=[a-z])", re.IGNORECASE | re.MULTILINE)
_WORD_RE = re.compile(r"[^\W\d_]{2,}")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>(){}\[\]\\^`|]{1,2048}", re.IGNORECASE)
_URL_HOST_RE = re.compile(r"^(?:https?|ftp)://(?:[^@/\s]*@)?([^/:?#\s]+)", re.IGNORECASE)
_COMMAND_RE = re.compile(
    r"(?:cmd\.exe|powershell\.exe|wmic\.exe|vssadmin|certutil|bitsadmin|schtasks|reg\.exe"
    r"|rundll32\.exe|mshta\.exe)[^\r\n\"'<>|&]{0,200}",
    re.IGNORECASE,
)


def severity_for_score(score: int, has_indicators: bool) -> str:
    """Map a score to a severity band. Never returns SAFE: static analysis cannot prove safety."""
    if not has_indicators:
        return SEVERITY_NONE
    if score <= 49:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    if score <= 84:
        return "HIGH"
    return "CRITICAL"


def _reject_remote_path(path_text: str) -> None:
    normalized = path_text.replace("/", "\\")
    if normalized.startswith("\\\\"):
        raise ScriptAnalysisError(
            "UNC, device and extended-length paths are not accepted; copy the file to a local drive first."
        )


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\r\n")
    return printable / len(text)


def _looks_utf16le(raw: bytes) -> bool:
    sample = raw[:512]
    if len(sample) < 4:
        return False
    odd = sample[1::2]
    even = sample[0::2]
    return odd.count(0) / len(odd) >= 0.6 and (len(even) - even.count(0)) / len(even) >= 0.6


def _decode_document(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace"), "utf-16-be"
    if _looks_utf16le(data):
        return data.decode("utf-16-le", "replace"), "utf-16-le"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def _bytes_to_text(raw: bytes) -> tuple[str | None, str]:
    if not raw:
        return None, "empty"
    if _looks_utf16le(raw):
        text, encoding = raw.decode("utf-16-le", "replace"), "utf-16-le"
    else:
        try:
            text, encoding = raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            text, encoding = raw.decode("latin-1"), "latin-1"
    if _printable_ratio(text) < MIN_PRINTABLE_RATIO:
        return None, encoding
    return text, encoding


def _code_to_char(token: str) -> str | None:
    lowered = token.lower()
    value = int(lowered[2:], 16) if lowered.startswith(("0x", "&h")) else int(lowered)
    if value < 32 or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
        return None
    char = chr(value)
    if char in "'\"\\`" or not char.isprintable():
        return None
    return char


def _replace_ps_char(match: re.Match[str]) -> str:
    char = _code_to_char(match.group(1))
    return f"'{char}'" if char is not None else match.group(0)


def _replace_vb_chr(match: re.Match[str]) -> str:
    char = _code_to_char(match.group(1))
    return f'"{char}"' if char is not None else match.group(0)


def _replace_js_fromcharcode(match: re.Match[str]) -> str:
    codes = [part.strip() for part in match.group(1).split(",")]
    chars = []
    for code in codes:
        if not code.isdigit():
            return match.group(0)
        char = _code_to_char(code)
        if char is None:
            return match.group(0)
        chars.append(char)
    return '"' + "".join(chars) + '"'


def _fold(text: str) -> str:
    """Matching view: dash/backtick normalization, literal char-code reconstruction, literal concatenation folding.

    Line structure is preserved so line numbers stay valid.
    """
    folded = text.translate(_DASHES)
    folded = _BACKTICK_RE.sub("", folded)
    folded = _PS_CHAR_RE.sub(_replace_ps_char, folded)
    folded = _VB_CHR_RE.sub(_replace_vb_chr, folded)
    folded = _JS_FROMCHARCODE_RE.sub(_replace_js_fromcharcode, folded)
    for concat in _CONCAT_RES:
        folded = concat.sub("", folded)
    return folded


def _clean(text: str, limit: int) -> str:
    cleaned = "".join(ch if ch.isprintable() or ch == "\t" else " " for ch in text[:limit])
    return cleaned.strip()


def _line_and_excerpt(text: str, offset: int) -> tuple[int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    column = offset - start
    window_start = start + max(0, column - 40)
    return line, _clean(text[window_start:end], EXCERPT_CHARS)


def _detect_language(text: str, file_name: str, single_line_is_command: bool) -> str:
    extension = PureWindowsPath(file_name).suffix.lower()
    if extension in EXTENSION_LANGUAGES:
        return EXTENSION_LANGUAGES[extension]

    head = text[:65536].lower()
    if "<hta:application" in head:
        return "hta"
    if re.search(r"<(?:job|package)\b", head) and "<script" in head:
        return "wsf"
    if "attribute vb_name" in head:
        return "vba"
    stripped = text.strip()
    if single_line_is_command and stripped and "\n" not in stripped:
        return "command_line"
    if re.search(r"^\s*@?echo\s+off\b", head, re.MULTILINE):
        return "batch"

    scores = {
        "powershell": len(re.findall(r"\$[a-z_]\w*|\b(?:get|set|new|invoke|write|start|remove)-[a-z]+\b", head)),
        "vbscript": len(re.findall(r"\b(?:dim|end sub|end function|createobject|wscript\.echo)\b", head)),
        "jscript": len(re.findall(r"\b(?:var|function|new activexobject)\b", head)),
    }
    best = max(scores.values())
    if best == 0:
        return "unknown"
    winners = sorted(name for name, value in scores.items() if value == best)
    return winners[0] if len(winners) == 1 else "unknown"


@dataclass
class _Unit:
    index: int
    depth: int
    text: str
    folded: str


class _DecodeState:
    def __init__(self, original_sha256: str) -> None:
        self.candidates = 0
        self.decoded_bytes = 0
        self.seen = {original_sha256}
        self.warnings: list[str] = []
        self.truncated = False
        self._once: set[str] = set()

    def warn(self, message: str, once_key: str | None = None) -> None:
        if once_key is not None:
            if once_key in self._once:
                return
            self._once.add(once_key)
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append("Further warnings suppressed.")


def _bounded_inflate(raw: bytes, wbits: int, limit: int) -> bytes | None:
    """Decompress at most ``limit`` bytes; return None on error or if output would exceed the limit."""
    decompressor = zlib.decompressobj(wbits)
    try:
        output = decompressor.decompress(raw, limit + 1)
    except zlib.error:
        return None
    if len(output) > limit or decompressor.unconsumed_tail:
        raise OverflowError
    return output


def _inflate(raw: bytes, context: str, limit: int) -> tuple[bytes | None, str]:
    lowered = context.lower()
    if raw.startswith(b"\x1f\x8b") or "gzipstream" in lowered:
        attempts = ((16 + zlib.MAX_WBITS, "gzip"), (-zlib.MAX_WBITS, "deflate"), (zlib.MAX_WBITS, "zlib"))
    else:
        attempts = ((-zlib.MAX_WBITS, "deflate"), (16 + zlib.MAX_WBITS, "gzip"), (zlib.MAX_WBITS, "zlib"))
    for wbits, name in attempts:
        output = _bounded_inflate(raw, wbits, limit)
        if output is not None:
            return output, name
    return None, ""


class ScriptAnalyzer:
    """Safe, non-executing static analyzer for Windows script content."""

    def __init__(self, max_script_size: int = MAX_SCRIPT_SIZE) -> None:
        self.max_script_size = max_script_size

    def analyze_file(self, file_path: str | Path, language: str | None = None) -> ScriptAnalysisResult:
        _reject_remote_path(str(file_path))
        path = Path(file_path).resolve()
        _reject_remote_path(str(path))
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ScriptAnalysisError(f"Not a regular file: {path}")
        size = path.stat().st_size
        if size > self.max_script_size:
            raise ScriptAnalysisError(
                f"File size ({size} bytes) exceeds maximum limit of {self.max_script_size} bytes"
            )
        data = path.read_bytes()
        return self.analyze_bytes(data, file_name=path.name, file_path=str(path), language=language)

    def analyze_bytes(
        self,
        data: bytes,
        file_name: str = "buffer.txt",
        file_path: str = "",
        language: str | None = None,
    ) -> ScriptAnalysisResult:
        self._check_size(len(data))
        language = self._validate_language(language)
        extension = PureWindowsPath(file_name).suffix.lower()

        rejection = self._classify_unsupported(data, extension)
        if rejection is not None:
            status, reason = rejection
            return self._unsupported_result(data, file_name, file_path, language, status, reason)

        text, encoding = _decode_document(data)
        if text and _printable_ratio(text) < MIN_PRINTABLE_RATIO:
            return self._unsupported_result(
                data, file_name, file_path, language, STATUS_BINARY_REJECTED,
                "Content is binary data, not script text.",
            )
        detected = language or _detect_language(text, file_name, single_line_is_command=not extension)
        return self._analyze(data, text, encoding, file_name, file_path, detected)

    def analyze_text(
        self,
        text: str,
        file_name: str = "inline.txt",
        language: str | None = None,
    ) -> ScriptAnalysisResult:
        data = text.encode("utf-8")
        self._check_size(len(data))
        language = self._validate_language(language)
        detected = language or _detect_language(text, file_name, single_line_is_command=True)
        return self._analyze(data, text, "utf-8", file_name, "", detected)

    def _check_size(self, size: int) -> None:
        if size > self.max_script_size:
            raise ScriptAnalysisError(
                f"Content size ({size} bytes) exceeds maximum limit of {self.max_script_size} bytes"
            )

    @staticmethod
    def _validate_language(language: str | None) -> str | None:
        if language is None or language == "auto":
            return None
        normalized = language.strip().lower()
        if normalized not in LANGUAGES:
            raise ScriptAnalysisError(
                f"Unsupported language '{language}'. Expected one of: auto, {', '.join(sorted(LANGUAGES))}"
            )
        return normalized

    @staticmethod
    def _classify_unsupported(data: bytes, extension: str) -> tuple[str, str] | None:
        for magic, description in _BINARY_MAGICS:
            if data.startswith(magic):
                return STATUS_BINARY_REJECTED, f"{description} detected; use static analysis for binaries."
        for magic, description in _CONTAINER_MAGICS:
            if data.startswith(magic):
                return (
                    STATUS_UNSUPPORTED_CONTAINER,
                    f"{description} detected; embedded macro/script extraction is not supported in this version.",
                )
        if extension in OFFICE_CONTAINER_EXTENSIONS:
            return (
                STATUS_UNSUPPORTED_CONTAINER,
                f"Office document type '{extension}'; embedded macro extraction is not supported in this version.",
            )
        return None

    @staticmethod
    def _hashes(data: bytes) -> tuple[str, str, str]:
        return (
            hashlib.sha256(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.md5(data).hexdigest(),
        )

    def _unsupported_result(
        self,
        data: bytes,
        file_name: str,
        file_path: str,
        language: str | None,
        status: str,
        reason: str,
    ) -> ScriptAnalysisResult:
        sha256, sha1, md5 = self._hashes(data)
        return ScriptAnalysisResult(
            file_name=file_name,
            file_path=file_path,
            file_size=len(data),
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            language=language or "unknown",
            encoding="binary",
            line_count=0,
            analysis_status=status,
            severity=SEVERITY_NOT_ANALYZED,
            warnings=[reason],
        )

    def _analyze(
        self,
        data: bytes,
        text: str,
        encoding: str,
        file_name: str,
        file_path: str,
        language: str,
    ) -> ScriptAnalysisResult:
        sha256, sha1, md5 = self._hashes(data)
        state = _DecodeState(sha256)
        if not text.strip():
            state.warn("Content is empty.")

        units, layers, encoded_hits = self._decode_layers(text, state)
        indicators = self._evaluate_rules(units, encoded_hits, state)
        iocs = self._extract_iocs(units)

        fired = {ind.rule_id for ind in indicators}
        root_fired = {ind.rule_id for ind in indicators if ind.layer_index == 0}
        hidden = any(
            ind.layer_index != 0 and ind.rule_id not in root_fired and ind.severity in ("high", "critical")
            for ind in indicators
        )
        score = sum(_RULES_BY_ID[rule_id].weight for rule_id in fired) + (10 if hidden else 0)
        score = min(score, 100)

        if indicators:
            categories = {_RULES_BY_ID[rule_id].category for rule_id in fired}
            confidence = min(0.95, 0.50 + 0.10 * len(categories))
            if max(_RULES_BY_ID[rule_id].weight for rule_id in fired) <= 10:
                confidence = min(confidence, 0.60)
        else:
            confidence = 0.50

        return ScriptAnalysisResult(
            file_name=file_name,
            file_path=file_path,
            file_size=len(data),
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            language=language,
            encoding=encoding,
            line_count=text.count("\n") + 1 if text else 0,
            analysis_status=STATUS_COMPLETE,
            score=score,
            severity=severity_for_score(score, bool(indicators)),
            confidence=round(confidence, 2),
            techniques=sorted({_RULES_BY_ID[rule_id].technique for rule_id in fired}),
            indicators=indicators,
            decoded_layers=layers,
            iocs=iocs,
            warnings=state.warnings,
            truncated=state.truncated,
        )

    def _decode_layers(
        self, text: str, state: _DecodeState
    ) -> tuple[list[_Unit], list[DecodedLayer], list[tuple[int, int]]]:
        root = _Unit(index=0, depth=0, text=text, folded=_fold(text))
        units = [root]
        layers: list[DecodedLayer] = []
        encoded_hits: list[tuple[int, int]] = []
        queue = [root]

        while queue:
            unit = queue.pop(0)
            candidates = self._candidates(unit.folded)
            if not candidates:
                continue
            if unit.depth >= MAX_DECODE_DEPTH:
                state.truncated = True
                state.warn(
                    f"Maximum decode depth ({MAX_DECODE_DEPTH}) reached; deeper encoded content was not decoded.",
                    once_key="depth",
                )
                continue

            for offset, kind, encoded in candidates:
                if state.candidates >= MAX_DECODE_CANDIDATES:
                    state.truncated = True
                    state.warn(
                        f"Decoding candidate limit ({MAX_DECODE_CANDIDATES}) reached; remaining candidates were not decoded.",
                        once_key="candidates",
                    )
                    return units, layers, encoded_hits
                state.candidates += 1

                layer = self._decode_candidate(unit, offset, kind, encoded, len(layers) + 1, state)
                if layer is None:
                    continue
                decoded_text, decoded_layer = layer
                if kind == "encoded_command":
                    encoded_hits.append((unit.index, offset))
                layers.append(decoded_layer)
                if decoded_text is not None:
                    child = _Unit(decoded_layer.index, decoded_layer.depth, decoded_text, _fold(decoded_text))
                    units.append(child)
                    queue.append(child)

        return units, layers, encoded_hits

    @staticmethod
    def _candidates(folded: str) -> list[tuple[int, str, str]]:
        found: list[tuple[int, int, str, str]] = []
        taken: list[tuple[int, int]] = []

        for match in _ENCODED_COMMAND_RE.finditer(folded):
            found.append((match.start(), 0, "encoded_command", match.group(1)))
            taken.append(match.span(1))
        for match in _FROM_BASE64_RE.finditer(folded):
            found.append((match.start(), 1, "from_base64", match.group(1)))
            taken.append(match.span(1))
        for match in _STANDALONE_BASE64_RE.finditer(folded):
            start, end = match.span()
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            token = match.group(0)
            if len(token) % 4 != 0 or _HEX_ONLY_RE.fullmatch(token):
                continue
            found.append((start, 2, "standalone", token))

        found.sort(key=lambda item: (item[0], item[1]))
        return [(offset, kind, encoded) for offset, _, kind, encoded in found]

    def _decode_candidate(
        self,
        unit: _Unit,
        offset: int,
        kind: str,
        encoded: str,
        index: int,
        state: _DecodeState,
    ) -> tuple[str | None, DecodedLayer] | None:
        compact = "".join(encoded.split())
        location = f"layer {unit.index} offset {offset}"
        remaining = MAX_DECODED_BYTES - state.decoded_bytes

        if len(compact) * 3 // 4 > remaining:
            state.truncated = True
            state.warn(f"Decoded content budget ({MAX_DECODED_BYTES} bytes) exhausted at {location}.")
            return None
        try:
            raw = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            if kind != "standalone":
                state.warn(f"Malformed Base64 at {location} was not decoded.")
            return None

        method = "base64"
        if kind == "encoded_command":
            if len(raw) % 2 != 0:
                state.warn(f"EncodedCommand at {location} is not valid UTF-16LE.")
                return None
            text = raw.decode("utf-16-le", "replace")
            if _printable_ratio(text) < MIN_PRINTABLE_RATIO:
                state.warn(f"EncodedCommand at {location} did not decode to readable text.")
                return None
            payload, encoding, method = raw, "utf-16-le", "encoded-command-utf16le"
        else:
            payload = raw
            if kind == "from_base64" and _COMPRESSION_RE.search(unit.folded):
                try:
                    inflated, algorithm = _inflate(raw, unit.folded, remaining)
                except OverflowError:
                    state.truncated = True
                    state.warn(
                        f"Compressed payload at {location} exceeds the decoded content budget and was not expanded."
                    )
                    return None
                if inflated is not None:
                    payload, method = inflated, f"base64+{algorithm}"
                else:
                    state.warn(f"Compressed payload at {location} could not be decompressed.")
            text, encoding = _bytes_to_text(payload)
            if text is None and kind == "standalone":
                return None

        digest = hashlib.sha256(payload).hexdigest()
        if digest in state.seen:
            return None
        if len(payload) > remaining:
            state.truncated = True
            state.warn(f"Decoded content budget ({MAX_DECODED_BYTES} bytes) exhausted at {location}.")
            return None
        state.seen.add(digest)
        state.decoded_bytes += len(payload)

        layer = DecodedLayer(
            index=index,
            depth=unit.depth + 1,
            parent_index=unit.index,
            method=method,
            offset=offset,
            sha256=digest,
            size=len(payload),
            encoding=encoding if text is not None else "binary",
            is_text=text is not None,
            preview=_clean(text, PREVIEW_CHARS) if text is not None else "",
        )
        return text, layer

    def _evaluate_rules(
        self,
        units: list[_Unit],
        encoded_hits: list[tuple[int, int]],
        state: _DecodeState,
    ) -> list[ScriptIndicator]:
        indicators: list[ScriptIndicator] = []
        encoded_first: dict[int, int] = {}
        for unit_index, offset in encoded_hits:
            encoded_first[unit_index] = min(offset, encoded_first.get(unit_index, offset))

        for unit in units:
            for rule in RULES:
                if rule.rule_id == _ENCODED_COMMAND_RULE_ID:
                    offset = encoded_first.get(unit.index)
                elif rule.rule_id == _CHARCODE_RULE_ID:
                    offset = _charcode_obfuscation_offset(unit.text)
                elif rule.rule_id == _MIXED_SCRIPT_RULE_ID:
                    offset = _mixed_script_offset(unit.text)
                else:
                    offset = _match_rule(rule, unit.text if rule.view == "raw" else unit.folded)
                if offset is None:
                    continue
                view = unit.text if rule.view == "raw" else unit.folded
                line, excerpt = _line_and_excerpt(view, offset)
                indicators.append(
                    ScriptIndicator(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        weight=rule.weight,
                        technique=rule.technique,
                        confidence=rule.confidence,
                        layer_index=unit.index,
                        depth=unit.depth,
                        line=line,
                        excerpt=excerpt,
                    )
                )

        indicators.sort(key=lambda ind: (ind.layer_index, ind.line, ind.rule_id))
        if len(indicators) > MAX_INDICATORS:
            state.truncated = True
            state.warn(f"Indicator limit ({MAX_INDICATORS}) reached; additional matches omitted.")
            indicators = indicators[:MAX_INDICATORS]
        return indicators

    @staticmethod
    def _extract_iocs(units: list[_Unit]) -> dict[str, list[str]]:
        urls: set[str] = set()
        ips: set[str] = set()
        hosts: set[str] = set()
        commands: set[str] = set()
        for unit in units:
            text = unit.folded
            for url in _URL_RE.findall(text):
                urls.add(url)
                host = _URL_HOST_RE.match(url)
                if host:
                    hosts.add(host.group(1).lower().rstrip("."))
            for ip in _IPV4_RE.findall(text):
                if not (
                    ip.startswith(("127.", "0.", "169.254."))
                    or ip == "255.255.255.255"
                ):
                    ips.add(ip)
            for command in _COMMAND_RE.findall(text):
                commands.add(_clean(command, 200))

        def bounded(values: set[str]) -> list[str]:
            return sorted(values)[:MAX_IOCS_PER_TYPE]

        return {
            "urls": bounded(urls),
            "ipv4_addresses": bounded(ips),
            "hosts": bounded(hosts),
            "commands": bounded({command for command in commands if command}),
        }


def _match_rule(rule: ScriptRule, text: str) -> int | None:
    for clause in rule.clauses:
        positions = []
        for pattern in clause:
            match = pattern.search(text)
            if match is None:
                break
            positions.append(match.start())
        else:
            return positions[0]
    return None


def _charcode_obfuscation_offset(text: str) -> int | None:
    reverse = _REVERSE_RE.search(text)
    if reverse is not None:
        return reverse.start()

    threshold = max(8, -(-8 * len(text) // 1024))
    first: int | None = None
    count = 0
    for match in _CHARCODE_RE.finditer(text):
        if first is None:
            first = match.start()
        count += 1
        if count >= threshold:
            return first

    ticks = 0
    first_tick: int | None = None
    for match in _TICK_RE.finditer(text):
        if first_tick is None:
            first_tick = match.start()
        ticks += 1
        if ticks >= 2:
            return first_tick
    return None


def _script_of(char: str) -> str:
    return unicodedata.name(char, "").split(" ", 1)[0]


def _mixed_script_offset(text: str) -> int | None:
    if text.isascii():
        return None
    for match in _WORD_RE.finditer(text):
        word = match.group(0)
        if word.isascii() or not any(ch.isascii() for ch in word):
            continue
        if any(_script_of(ch) in ("CYRILLIC", "GREEK") for ch in word if not ch.isascii()):
            return match.start()
    return None


# --------------------------------------------------------------------------- #
# Evidence / Finding integration
# --------------------------------------------------------------------------- #

SCRIPT_EVENT_SOURCE = "script_analyzer"
SCRIPT_EVENT_TYPE = "file_stream_hash"
SCRIPT_ANALYST = "ransomeye-script-analyzer"
SCRIPT_FINDING_PREFIX = "script_"

_RULE_ID_IN_REASON = re.compile(r"^\[([A-Z0-9][A-Z0-9-]*)\]")


def _script_event_id(case_id: str, artifact_sha256: str, resolved_path: str) -> str:
    seed = f"{case_id}|{artifact_sha256}|{resolved_path}"
    return "EVT-SCRIPT-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _representative_indicators(result: ScriptAnalysisResult) -> list[ScriptIndicator]:
    """One indicator per rule_id: the earliest by (layer, line) since indicators are pre-sorted."""
    chosen: dict[str, ScriptIndicator] = {}
    for indicator in result.indicators:
        chosen.setdefault(indicator.rule_id, indicator)
    return [chosen[rule_id] for rule_id in sorted(chosen)]


def _finding_for_indicator(
    result: ScriptAnalysisResult, indicator: ScriptIndicator
) -> dict[str, Any]:
    excerpt = indicator.excerpt or indicator.title
    reason = (
        f"[{indicator.rule_id}] {indicator.title} "
        f"(layer {indicator.layer_index}, line {indicator.line}): {excerpt} "
        f"| artifact sha256={result.sha256[:16]}"
    )
    return {
        "type": f"{SCRIPT_FINDING_PREFIX}{indicator.category}",
        "score": indicator.weight,
        "confidence": indicator.confidence,
        "technique": indicator.technique,
        "reason": reason,
    }


def _existing_rule_ids(store: Any, case_id: str, event_id: str) -> set[str]:
    present: set[str] = set()
    for finding in store.get_event_findings(case_id, event_id):
        match = _RULE_ID_IN_REASON.match(finding.get("reason", ""))
        if match:
            present.add(match.group(1))
    return present


def ingest_script_finding(
    store: Any,
    case_id: str,
    result: ScriptAnalysisResult,
    *,
    event_id: str | None = None,
) -> list[int]:
    """Persist script-analysis findings into an EvidenceStore case.

    File-artifact mode (``event_id`` is None): creates one deterministic,
    case-scoped ``file_stream_hash`` evidence event for the artifact (timestamped
    with the file's last-modified time, with the artifact SHA-256 preserved in
    metadata), one finding per distinct triggered rule linked to that event, and
    one ``reviewed`` chain-of-custody record. Requires ``result.file_path`` to
    reference an existing file.

    Stored-event mode (``event_id`` given): creates findings only, linked to the
    existing event in the case. No new evidence event and no custody record are
    created. Used to annotate a stored process-creation event's command line.

    Idempotent: a rule already recorded against the target event is not
    duplicated on re-ingest. Returns the finding IDs created by this call.
    """
    from datetime import datetime, timezone

    if event_id is not None:
        if store.get_event(case_id, event_id) is None:
            raise ValueError(f"Event not found in case {case_id}: {event_id}")
        target_event_id = event_id
    else:
        if not result.file_path:
            raise ValueError(
                "File-artifact ingest requires result.file_path. Pass event_id= to "
                "annotate a stored command-line event; do not persist pasted text."
            )
        path = Path(result.file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Artifact file not found: {result.file_path}")

        resolved = str(path.resolve())
        target_event_id = _script_event_id(case_id, result.sha256, resolved)
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()

        store.save_event(
            case_id,
            {
                "event_id": target_event_id,
                "case_id": case_id,
                "timestamp": mtime,
                "source": SCRIPT_EVENT_SOURCE,
                "event_type": SCRIPT_EVENT_TYPE,
                "file_path": resolved,
                "hashes": f"SHA256={result.sha256},SHA1={result.sha1},MD5={result.md5}",
                "confidence": 0.90,
                "metadata": {
                    "observation": "static_script_analysis",
                    "sha256": result.sha256,
                    "file_size": result.file_size,
                    "language": result.language,
                    "analyzer_version": result.analyzer_version,
                    "analysis_status": result.analysis_status,
                    "score": result.score,
                    "severity": result.severity,
                },
            },
        )
        store.record_custody_event(
            case_id=case_id,
            artifact_path=resolved,
            sha256=result.sha256,
            action="reviewed",
            analyst=SCRIPT_ANALYST,
            note=(
                f"Script analysis: language={result.language}, status={result.analysis_status}, "
                f"severity={result.severity}, score={result.score}"
            ),
        )

    already = _existing_rule_ids(store, case_id, target_event_id)
    created: list[int] = []
    for indicator in _representative_indicators(result):
        if indicator.rule_id in already:
            continue
        finding_id = store.save_finding(
            case_id,
            _finding_for_indicator(result, indicator),
            event_ids=[target_event_id],
        )
        created.append(finding_id)
    return created
