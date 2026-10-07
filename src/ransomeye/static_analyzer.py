"""RansomEye Native Static File and PE Analyzer.

Provides safe, deterministic, non-executing static analysis of binary executables,
scripts, and suspicious files for ransomware and malware forensic investigation.

Capabilities:
- Cryptographic hashing (SHA-256, SHA-1, MD5)
- File type and format identification via magic bytes
- Safe pure-Python PE header and section parsing (DOS, COFF, Optional, Sections)
- Per-section Shannon entropy analysis and packing indicators
- Import directory parsing and suspicious API indicator classification
- Bounded string extraction (ASCII and UTF-16)
- Bounded IOC extraction (IPv4, URLs, emails, ransom keywords)
- Safe error handling for malformed or corrupted binaries
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ransomeye.entropy import EntropyAnalyzer

MAX_ANALYSIS_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_EXTRACTED_STRINGS = 500
MIN_STRING_LENGTH = 4

# Known suspicious Windows APIs associated with ransomware and malicious capabilities
SUSPICIOUS_API_PATTERNS: dict[str, str] = {
    # Encryption / Cryptography
    "CryptEncrypt": "encryption",
    "CryptDecrypt": "encryption",
    "CryptGenKey": "encryption",
    "CryptAcquireContext": "encryption",
    "BCryptEncrypt": "encryption",
    "BCryptDecrypt": "encryption",
    "BCryptGenerateSymmetricKey": "encryption",
    "CryptDeriveKey": "encryption",
    # Process Injection / Memory Manipulation
    "VirtualAllocEx": "process_injection",
    "WriteProcessMemory": "process_injection",
    "CreateRemoteThread": "process_injection",
    "NtUnmapViewOfSection": "process_injection",
    "QueueUserAPC": "process_injection",
    "SetThreadContext": "process_injection",
    # Defense Evasion / Privilege Escalation
    "AdjustTokenPrivileges": "privilege_escalation",
    "LookupPrivilegeValue": "privilege_escalation",
    "OpenProcessToken": "privilege_escalation",
    "IsDebuggerPresent": "defense_evasion",
    "CheckRemoteDebuggerPresent": "defense_evasion",
    # File System Destruction & Traversal
    "FindFirstFileW": "file_enumeration",
    "FindNextFileW": "file_enumeration",
    "FindFirstFileA": "file_enumeration",
    "FindNextFileA": "file_enumeration",
    "DeleteFileW": "file_destruction",
    "DeleteFileA": "file_destruction",
    "MoveFileExW": "file_manipulation",
    "SetFileAttributesW": "file_manipulation",
    # Service / Shadow Copy Manipulation
    "OpenSCManager": "service_control",
    "CreateService": "service_control",
    "ControlService": "service_control",
    # Network / C2
    "InternetOpen": "network_communication",
    "InternetConnect": "network_communication",
    "HttpOpenRequest": "network_communication",
    "WSAStartup": "network_communication",
    "connect": "network_communication",
    "send": "network_communication",
    "recv": "network_communication",
}

RANSOM_KEYWORD_PATTERNS = [
    "DECRYPT", "RANSOM", "RECOVER", "RESTORE_FILES", "HOW_TO_DECRYPT",
    "BITCOIN", "TOR_BROWSER", "ONION", "PRIVATE_KEY", "ENCRYPTED_FILES",
]


@dataclass
class PESection:
    """Parsed Portable Executable section information."""
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float
    is_high_entropy: bool


@dataclass
class StaticAnalysisResult:
    """Structured result of static file examination."""
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    sha1: str
    md5: str
    file_type: str
    is_pe: bool
    architecture: str | None = None
    subsystem: str | None = None
    entry_point: str | None = None
    image_base: str | None = None
    compile_timestamp: str | None = None
    total_entropy: float = 0.0
    entropy_rating: str = ""
    sections: list[PESection] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    imported_functions: list[str] = field(default_factory=list)
    suspicious_apis: dict[str, list[str]] = field(default_factory=dict)
    extracted_strings_sample: list[str] = field(default_factory=list)
    total_strings_count: int = 0
    extracted_iocs: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis result to JSON-serializable dictionary."""
        data = asdict(self)
        return data

    def to_summary_text(self) -> str:
        """Render a clean, human-readable forensic static analysis report."""
        lines = [
            "==================================================================",
            "               RANSOMEYE STATIC FILE ANALYSIS REPORT              ",
            "==================================================================",
            f"Target File      : {self.file_name}",
            f"File Path        : {self.file_path}",
            f"File Size        : {self.file_size:,} bytes",
            f"File Format      : {self.file_type}",
            f"Is PE Binary     : {'Yes' if self.is_pe else 'No'}",
            f"Total Entropy    : {self.total_entropy:.4f} ({self.entropy_rating})",
            "",
            "--- HASHES ---",
            f"SHA-256 : {self.sha256}",
            f"SHA-1   : {self.sha1}",
            f"MD5     : {self.md5}",
        ]

        if self.is_pe:
            lines.extend([
                "",
                "--- PE HEADERS ---",
                f"Architecture     : {self.architecture or 'Unknown'}",
                f"Subsystem        : {self.subsystem or 'Unknown'}",
                f"Entry Point      : {self.entry_point or 'N/A'}",
                f"Image Base       : {self.image_base or 'N/A'}",
                f"Compile Time     : {self.compile_timestamp or 'N/A'}",
            ])

            if self.sections:
                lines.extend(["", f"--- SECTIONS ({len(self.sections)}) ---"])
                for sec in self.sections:
                    packed_flag = " [HIGH ENTROPY/PACKED]" if sec.is_high_entropy else ""
                    lines.append(
                        f"  Section: {sec.name:<8} | Raw Size: {sec.raw_size:>8,} bytes | "
                        f"Entropy: {sec.entropy:.4f}{packed_flag}"
                    )

            if self.imported_dlls:
                lines.extend(["", f"--- IMPORTED LIBRARIES ({len(self.imported_dlls)}) ---"])
                lines.append("  " + ", ".join(self.imported_dlls[:20]))
                if len(self.imported_dlls) > 20:
                    lines.append(f"  ... and {len(self.imported_dlls) - 20} more libraries")

            if self.suspicious_apis:
                lines.extend(["", "--- SUSPICIOUS API INDICATORS ---"])
                for cat, apis in sorted(self.suspicious_apis.items()):
                    lines.append(f"  [{cat.upper()}]: " + ", ".join(apis))

        if self.extracted_iocs:
            lines.extend(["", "--- EXTRACTED IOCS & PATTERNS ---"])
            for k, vals in self.extracted_iocs.items():
                if vals:
                    lines.append(f"  {k.replace('_', ' ').title()}: " + ", ".join(vals[:10]))
                    if len(vals) > 10:
                        lines.append(f"    ... and {len(vals) - 10} more")

        if self.warnings:
            lines.extend(["", "--- WARNINGS & ANOMALIES ---"])
            for w in self.warnings:
                lines.append(f"  [!] {w}")

        lines.extend([
            "",
            "==================================================================",
        ])
        return "\n".join(lines)


class StaticAnalyzer:
    """Safe, non-executing static file and PE analyzer."""

    def __init__(self, max_file_size: int = MAX_ANALYSIS_FILE_SIZE) -> None:
        self.max_file_size = max_file_size
        self.entropy_analyzer = EntropyAnalyzer()

    def analyze_file(self, file_path: str | Path) -> StaticAnalysisResult:
        """Analyze a file statically without executing it."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        file_size = path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(
                f"File size ({file_size} bytes) exceeds maximum limit of {self.max_file_size} bytes"
            )

        data = path.read_bytes()
        return self.analyze_bytes(data, file_name=path.name, file_path=str(path))

    def analyze_bytes(
        self,
        data: bytes,
        file_name: str = "buffer.bin",
        file_path: str = "",
    ) -> StaticAnalysisResult:
        """Analyze raw bytes safely."""
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()

        file_type = self._detect_file_type(data)
        total_entropy = self.entropy_analyzer.calculate(data)
        entropy_rating = self.entropy_analyzer.get_entropy_rating(total_entropy)

        result = StaticAnalysisResult(
            file_path=file_path or file_name,
            file_name=file_name,
            file_size=len(data),
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            file_type=file_type,
            is_pe=False,
            total_entropy=total_entropy,
            entropy_rating=entropy_rating,
        )

        # Extract bounded strings and IOCs from content
        strings = self._extract_strings(data)
        result.total_strings_count = len(strings)
        result.extracted_strings_sample = strings[:50]
        result.extracted_iocs = self._extract_iocs(strings)

        # Attempt PE Header Parsing if MZ signature matches
        if data.startswith(b"MZ") and len(data) >= 64:
            self._parse_pe(data, result)

        return result

    def _detect_file_type(self, data: bytes) -> str:
        """Detect file format using standard magic byte signatures."""
        if len(data) < 4:
            return "Unknown (Empty or Very Small)"

        if data.startswith(b"MZ"):
            return "Windows PE Executable / DLL"
        if data.startswith(b"\x7fELF"):
            return "Linux ELF Executable"
        if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")):
            return "Mach-O Executable"
        if data.startswith(b"PK\x03\x04"):
            return "ZIP Archive / Office Open XML"
        if data.startswith(b"%PDF"):
            return "PDF Document"
        if data.startswith(b"{\n") or data.startswith(b"{\r") or data.startswith(b"{\""):
            return "JSON Document"
        if data.startswith(b"<?xml") or data.startswith(b"<"):
            return "XML / HTML Document"
        if data.startswith(b"#!"):
            return "Script File"

        # Check if plain ASCII text
        try:
            data[:512].decode("utf-8")
            return "Plain Text / Script"
        except UnicodeDecodeError:
            return "Binary Data"

    def _parse_pe(self, data: bytes, result: StaticAnalysisResult) -> None:
        """Safely parse PE headers, sections, and import tables without third-party dependencies."""
        try:
            # 1. DOS Header: Read e_lfanew at offset 0x3C
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 4 > len(data):
                result.warnings.append("Malformed DOS header: e_lfanew points beyond file size.")
                return

            pe_sig = data[e_lfanew:e_lfanew + 4]
            if pe_sig != b"PE\x00\x00":
                # Valid MZ but not a standard PE (e.g. 16-bit DOS)
                return

            result.is_pe = True

            # 2. COFF File Header (20 bytes at e_lfanew + 4)
            coff_offset = e_lfanew + 4
            if coff_offset + 20 > len(data):
                result.warnings.append("Malformed COFF File Header: truncated data.")
                return

            machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
                "<HHIIIHH", data, coff_offset
            )

            arch_map = {
                0x014C: "Intel 386 (32-bit)",
                0x8664: "AMD64 / x86-64 (64-bit)",
                0x0200: "Intel Itanium",
                0xAA64: "ARM64",
                0x01C0: "ARM",
            }
            result.architecture = arch_map.get(machine, f"Unknown (0x{machine:04X})")
            if timedatestamp > 0:
                from datetime import datetime, timezone
                try:
                    dt = datetime.fromtimestamp(timedatestamp, tz=timezone.utc)
                    result.compile_timestamp = dt.isoformat()
                except Exception:
                    result.compile_timestamp = f"Raw Epoch: {timedatestamp}"

            # 3. Optional Header (if present)
            opt_offset = coff_offset + 20
            rva_to_offset_sections: list[tuple[int, int, int, int]] = []  # (vaddr, vsize, raddr, rsize)

            if opt_hdr_size > 0 and opt_offset + opt_hdr_size <= len(data):
                magic = struct.unpack_from("<H", data, opt_offset)[0]
                is_64bit = (magic == 0x020B)

                if is_64bit:
                    entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                    image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
                    subsystem_val = struct.unpack_from("<H", data, opt_offset + 68)[0]
                else:
                    entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                    image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
                    subsystem_val = struct.unpack_from("<H", data, opt_offset + 68)[0]

                subsystem_map = {
                    1: "Native",
                    2: "Windows GUI",
                    3: "Windows CUI (Console)",
                    7: "POSIX CUI",
                    9: "Windows CE GUI",
                    10: "EFI Application",
                }
                result.subsystem = subsystem_map.get(subsystem_val, f"Subsystem {subsystem_val}")
                result.entry_point = f"0x{entry_point:08X}"
                result.image_base = f"0x{image_base:08X}"

            # 4. Section Headers
            sec_table_offset = opt_offset + opt_hdr_size
            sections: list[PESection] = []

            for i in range(num_sections):
                sec_offset = sec_table_offset + (i * 40)
                if sec_offset + 40 > len(data):
                    result.warnings.append("Truncated section header table.")
                    break

                raw_name = data[sec_offset:sec_offset + 8].split(b"\x00")[0]
                sec_name = raw_name.decode("utf-8", errors="replace").strip()

                vsize, vaddr, raw_size, raw_ptr, _, _, _, _, characteristics = struct.unpack_from(
                    "<IIIIIIHHI", data, sec_offset + 8
                )

                # Compute section entropy
                sec_bytes = b""
                if raw_ptr < len(data):
                    sec_end = min(len(data), raw_ptr + raw_size)
                    sec_bytes = data[raw_ptr:sec_end]

                sec_entropy = self.entropy_analyzer.calculate(sec_bytes) if sec_bytes else 0.0
                is_high_entropy = sec_entropy >= 7.0

                sections.append(
                    PESection(
                        name=sec_name,
                        virtual_size=vsize,
                        virtual_address=vaddr,
                        raw_size=raw_size,
                        raw_offset=raw_ptr,
                        characteristics=characteristics,
                        entropy=sec_entropy,
                        is_high_entropy=is_high_entropy,
                    )
                )
                rva_to_offset_sections.append((vaddr, vsize, raw_ptr, raw_size))

            result.sections = sections

            # 5. Extract Imports from Import Directory Data Directory if present
            self._parse_pe_imports(data, opt_offset, opt_hdr_size, rva_to_offset_sections, result)

        except Exception as exc:
            result.warnings.append(f"PE parsing encountered an error: {exc}")

    def _rva_to_file_offset(
        self, rva: int, sections: list[tuple[int, int, int, int]]
    ) -> int | None:
        """Convert a Virtual Address (RVA) to a physical file offset."""
        for vaddr, vsize, raw_ptr, raw_size in sections:
            size = max(vsize, raw_size)
            if vaddr <= rva < vaddr + size:
                return raw_ptr + (rva - vaddr)
        return None

    def _parse_pe_imports(
        self,
        data: bytes,
        opt_offset: int,
        opt_hdr_size: int,
        sections: list[tuple[int, int, int, int]],
        result: StaticAnalysisResult,
    ) -> None:
        """Parse the Import Table to identify imported DLLs and API calls."""
        if opt_hdr_size < 120:
            return

        magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_64bit = (magic == 0x020B)

        # Import Table directory entry is at opt_offset + 104 (32-bit) or opt_offset + 120 (64-bit)
        import_dir_offset = opt_offset + (120 if is_64bit else 104)
        if import_dir_offset + 8 > len(data):
            return

        import_rva, import_size = struct.unpack_from("<II", data, import_dir_offset)
        if import_rva == 0 or import_size == 0:
            return

        import_file_offset = self._rva_to_file_offset(import_rva, sections)
        if import_file_offset is None or import_file_offset + 20 > len(data):
            return

        # Iterate Import Descriptors (20 bytes each)
        idx = 0
        while True:
            desc_offset = import_file_offset + (idx * 20)
            if desc_offset + 20 > len(data):
                break

            orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, desc_offset
            )

            # Null descriptor marks the end of import table
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break

            # Resolve DLL Name
            dll_name_offset = self._rva_to_file_offset(name_rva, sections)
            if dll_name_offset is not None and dll_name_offset < len(data):
                dll_name_raw = data[dll_name_offset:dll_name_offset + 256].split(b"\x00")[0]
                dll_name = dll_name_raw.decode("utf-8", errors="replace").strip()
                if dll_name and dll_name not in result.imported_dlls:
                    result.imported_dlls.append(dll_name)

            # Resolve imported functions via thunk table
            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_offset = self._rva_to_file_offset(thunk_rva, sections)
            if thunk_offset is not None:
                self._read_thunk_functions(data, thunk_offset, is_64bit, sections, result)

            idx += 1
            if idx > 256:  # Safety bounding
                break

    def _read_thunk_functions(
        self,
        data: bytes,
        thunk_offset: int,
        is_64bit: bool,
        sections: list[tuple[int, int, int, int]],
        result: StaticAnalysisResult,
    ) -> None:
        """Iterate function thunks and extract API names."""
        entry_size = 8 if is_64bit else 4
        ordinal_mask = 0x8000000000000000 if is_64bit else 0x80000000

        for i in range(500):  # Bounded to 500 imports per DLL
            entry_offset = thunk_offset + (i * entry_size)
            if entry_offset + entry_size > len(data):
                break

            entry = struct.unpack_from("<Q" if is_64bit else "<I", data, entry_offset)[0]
            if entry == 0:
                break

            if entry & ordinal_mask:
                # Import by ordinal (skip named extraction)
                continue

            # Import by name: entry is RVA to IMAGE_IMPORT_BY_NAME (Hint 2 bytes, Name string)
            name_data_offset = self._rva_to_file_offset(entry, sections)
            if name_data_offset is not None and name_data_offset + 2 < len(data):
                fn_name_raw = data[name_data_offset + 2:name_data_offset + 128].split(b"\x00")[0]
                fn_name = fn_name_raw.decode("utf-8", errors="replace").strip()
                if fn_name:
                    result.imported_functions.append(fn_name)
                    # Check against suspicious API catalog
                    for pattern, category in SUSPICIOUS_API_PATTERNS.items():
                        if pattern.lower() == fn_name.lower():
                            result.suspicious_apis.setdefault(category, []).append(fn_name)

    def _extract_strings(self, data: bytes) -> list[str]:
        """Extract ASCII and UTF-16 strings with length and count bounds."""
        found_strings: list[str] = []

        # ASCII strings
        ascii_matches = re.findall(rb"[\x20-\x7E]{" + str(MIN_STRING_LENGTH).encode() + rb",}", data)
        for m in ascii_matches:
            try:
                s = m.decode("ascii").strip()
                if s:
                    found_strings.append(s)
            except Exception:
                pass
            if len(found_strings) >= MAX_EXTRACTED_STRINGS:
                return found_strings

        # UTF-16 LE strings
        utf16_matches = re.findall(
            rb"(?:[\x20-\x7E]\x00){" + str(MIN_STRING_LENGTH).encode() + rb",}", data
        )
        for m in utf16_matches:
            try:
                s = m.decode("utf-16-le").strip()
                if s and s not in found_strings:
                    found_strings.append(s)
            except Exception:
                pass
            if len(found_strings) >= MAX_EXTRACTED_STRINGS:
                return found_strings

        return found_strings

    def _extract_iocs(self, strings: list[str]) -> dict[str, list[str]]:
        """Extract network indicators and ransomware keywords from extracted strings."""
        iocs: dict[str, list[str]] = {
            "ipv4_addresses": [],
            "urls": [],
            "ransom_keywords": [],
        }

        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        url_pattern = re.compile(r"https?://[A-Za-z0-9\.\-_~:/?#[\]@!$&'()*+,;=%]+")

        for s in strings:
            # IPs
            for ip in ip_pattern.findall(s):
                octets = ip.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    if not ip.startswith("0.") and not ip.startswith("127."):
                        if ip not in iocs["ipv4_addresses"]:
                            iocs["ipv4_addresses"].append(ip)

            # URLs
            for url in url_pattern.findall(s):
                if url not in iocs["urls"]:
                    iocs["urls"].append(url)

            # Ransomware keywords
            s_upper = s.upper()
            for kw in RANSOM_KEYWORD_PATTERNS:
                if kw in s_upper and kw not in iocs["ransom_keywords"]:
                    iocs["ransom_keywords"].append(kw)

        return iocs


def ingest_static_finding(
    store: Any,
    case_id: str,
    result: StaticAnalysisResult,
) -> int:
    """Ingest a static analysis result as a finding into an EvidenceStore case with full evidence linkage."""
    from datetime import datetime, timezone
    import uuid

    event_id = f"EVT-STATIC-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    event_data = {
        "event_id": event_id,
        "case_id": case_id,
        "timestamp": now_iso,
        "source": "static_analyzer",
        "event_type": "file_stream_hash",
        "file_path": result.file_path or result.file_name,
        "hashes": f"SHA256={result.sha256}, SHA1={result.sha1}, MD5={result.md5}",
        "confidence": 0.90,
        "metadata": {
            "file_name": result.file_name,
            "file_size": result.file_size,
            "file_type": result.file_type,
            "is_pe": result.is_pe,
            "total_entropy": result.total_entropy,
            "entropy_rating": result.entropy_rating,
        },
    }

    # Save evidence event
    store.save_event(case_id, event_data)

    score = 0
    reasons = [f"Static analysis performed on {result.file_name} ({result.file_type})"]

    if result.total_entropy >= 7.0:
        score += 15
        reasons.append(f"High Shannon entropy ({result.total_entropy:.2f}): likely packed or encrypted content")

    if result.suspicious_apis:
        api_count = sum(len(apis) for apis in result.suspicious_apis.values())
        score += min(25, api_count * 5)
        reasons.append(f"Detected {api_count} suspicious API imports across {len(result.suspicious_apis)} categories")

    if result.extracted_iocs.get("ransom_keywords"):
        score += 15
        reasons.append(f"Embedded ransom keywords detected: {', '.join(result.extracted_iocs['ransom_keywords'])}")

    score = min(score, 100)

    finding_data = {
        "type": "static_file_analysis",
        "score": score,
        "confidence": 0.85 if score > 0 else 0.50,
        "technique": "T1027",
        "reason": "; ".join(reasons),
        "metadata": {
            "file_name": result.file_name,
            "sha256": result.sha256,
            "entropy": result.total_entropy,
            "suspicious_apis": result.suspicious_apis,
            "iocs": result.extracted_iocs,
        },
    }

    finding_id = store.save_finding(case_id, finding_data, event_ids=[event_id])

    # Record chain of custody event
    store.record_custody_event(
        case_id=case_id,
        artifact_path=result.file_path or result.file_name,
        sha256=result.sha256,
        action="reviewed",
        analyst="ransomeye-static-analyzer",
        note=f"Static analysis performed (Entropy={result.total_entropy:.2f}, Type={result.file_type})",
    )

    return finding_id
