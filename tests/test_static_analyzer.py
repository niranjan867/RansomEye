"""Unit and integration tests for RansomEye Static File and PE Analyzer."""

import json
import struct
import tempfile
from pathlib import Path

import pytest

from ransomeye.static_analyzer import (
    StaticAnalyzer,
    StaticAnalysisResult,
    PESection,
    ingest_static_finding,
    MAX_ANALYSIS_FILE_SIZE,
)
from ransomeye.storage import EvidenceStore
from ransomeye.commands import run_static_analysis_command


def create_synthetic_pe_bytes(
    is_64bit: bool = True,
    sections_info: list[tuple[str, bytes]] | None = None,
    dll_imports: list[tuple[str, list[str]]] | None = None,
) -> bytes:
    """Construct a well-formed synthetic PE binary in-memory for safe testing."""
    # Default sections
    if sections_info is None:
        sections_info = [
            (".text", b"\x90\x90\x55\x89\xe5\x5d\xc3" * 20),
            (".rdata", b"Ransomware decrypt instructions and test strings\x00" * 10),
            (".data", b"\x00\x01\x02\x03" * 30),
        ]

    # DOS Header (64 bytes)
    # 0x00: 'MZ' (2 bytes)
    # 0x3C: e_lfanew (4 bytes -> offset to PE signature, say 0x80)
    dos_header = bytearray(b"\x00" * 128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # PE Signature (4 bytes) at 0x80
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    machine = 0x8664 if is_64bit else 0x014C
    num_sections = len(sections_info)
    timedatestamp = 1700000000
    opt_hdr_size = 240 if is_64bit else 224
    characteristics = 0x0102  # Executable image, 32-bit/64-bit word

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timedatestamp,
        0,
        0,
        opt_hdr_size,
        characteristics,
    )

    # Optional Header
    opt_magic = 0x020B if is_64bit else 0x010B
    entry_point_rva = 0x1000
    image_base = 0x140000000 if is_64bit else 0x00400000
    subsystem = 3  # Console

    opt_header = bytearray(opt_hdr_size)
    struct.pack_into("<H", opt_header, 0, opt_magic)
    struct.pack_into("<I", opt_header, 16, entry_point_rva)
    if is_64bit:
        struct.pack_into("<Q", opt_header, 24, image_base)
        struct.pack_into("<H", opt_header, 68, subsystem)
    else:
        struct.pack_into("<I", opt_header, 28, image_base)
        struct.pack_into("<H", opt_header, 68, subsystem)

    # Build Sections
    # Headers follow Optional Header
    raw_offset = 0x400  # Start section raw data at 1024 bytes
    vaddr = 0x1000

    sec_headers = bytearray()
    sec_data_blocks = bytearray()

    for sec_name, data_bytes in sections_info:
        raw_size = len(data_bytes)
        # Pad name to 8 bytes
        padded_name = sec_name.encode("utf-8")[:8].ljust(8, b"\x00")
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            padded_name,
            raw_size,  # VirtualSize
            vaddr,  # VirtualAddress
            raw_size,  # SizeOfRawData
            raw_offset,  # PointerToRawData
            0,
            0,
            0,
            0,
            0x60000020,  # Characteristics: Code/Data, Execute/Read/Write
        )
        sec_headers.extend(sec_hdr)
        sec_data_blocks.extend(data_bytes)

        # Increment offsets
        vaddr += (raw_size + 0xFFF) & ~0xFFF
        raw_offset += raw_size

    # Assemble binary
    pe_file = bytearray(dos_header)
    # Pad up to 0x80
    pe_file.extend(b"\x00" * (0x80 - len(pe_file)))
    pe_file.extend(pe_sig)
    pe_file.extend(coff_header)
    pe_file.extend(opt_header)
    pe_file.extend(sec_headers)

    # Pad up to raw_offset start (0x400)
    if len(pe_file) < 0x400:
        pe_file.extend(b"\x00" * (0x400 - len(pe_file)))

    pe_file.extend(sec_data_blocks)
    return bytes(pe_file)


def test_detect_file_types(tmp_path: Path):
    analyzer = StaticAnalyzer()

    # Text / Script
    txt = tmp_path / "script.ps1"
    txt.write_text("Write-Host 'Test PowerShell Script'", encoding="utf-8")
    res = analyzer.analyze_file(txt)
    assert res.file_type == "Plain Text / Script"
    assert not res.is_pe

    # JSON
    js = tmp_path / "data.json"
    js.write_text('{"events": []}', encoding="utf-8")
    res = analyzer.analyze_file(js)
    assert res.file_type == "JSON Document"

    # XML
    xml = tmp_path / "events.xml"
    xml.write_text("<Events><Event></Event></Events>", encoding="utf-8")
    res = analyzer.analyze_file(xml)
    assert res.file_type == "XML / HTML Document"

    # PDF
    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.4\n%header bytes")
    res = analyzer.analyze_file(pdf)
    assert res.file_type == "PDF Document"


def test_synthetic_pe_parsing(tmp_path: Path):
    pe_bytes = create_synthetic_pe_bytes(
        is_64bit=True,
        sections_info=[
            (".text", b"\x90\x55\x89\xe5\x5d\xc3" * 50),
            (".rsrc", b"\xff\xfeH\x00e\x00l\x00l\x00o\x00"),  # UTF-16 string
        ],
    )
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(pe_bytes)

    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(pe_file)

    assert res.is_pe is True
    assert "AMD64" in str(res.architecture)
    assert res.subsystem == "Windows CUI (Console)"
    assert res.entry_point == "0x00001000"
    assert len(res.sections) == 2
    assert res.sections[0].name == ".text"
    assert res.sections[1].name == ".rsrc"
    assert res.total_entropy > 0.0
    assert len(res.sha256) == 64


def test_high_entropy_detection(tmp_path: Path):
    # Highly random / encrypted section
    import os
    random_bytes = os.urandom(2048)
    pe_bytes = create_synthetic_pe_bytes(
        sections_info=[
            (".text", b"\x90" * 200),
            (".packed", random_bytes),
        ]
    )
    pe_file = tmp_path / "packed_sample.exe"
    pe_file.write_bytes(pe_bytes)

    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(pe_file)

    assert res.is_pe is True
    assert len(res.sections) == 2
    packed_sec = [s for s in res.sections if s.name == ".packed"][0]
    assert packed_sec.entropy >= 7.0
    assert packed_sec.is_high_entropy is True


def test_string_and_ioc_extraction(tmp_path: Path):
    content = (
        b"MZ\x00\x00"
        b"Contact us at https://darknet-ransom-portal.onion/pay\n"
        b"Send 0.5 BTC to restore all ENCRYPTED_FILES.\n"
        b"C2 Server: 198.51.100.45\n"
        b"DECRYPT_INSTRUCTIONS for recovery.\n"
    )
    test_file = tmp_path / "ransom_artifact.bin"
    test_file.write_bytes(content)

    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(test_file)

    assert "https://darknet-ransom-portal.onion/pay" in res.extracted_iocs["urls"]
    assert "198.51.100.45" in res.extracted_iocs["ipv4_addresses"]
    assert "DECRYPT" in res.extracted_iocs["ransom_keywords"] or "ENCRYPTED_FILES" in res.extracted_iocs["ransom_keywords"]
    assert res.total_strings_count > 0


def test_file_size_limit_rejection(tmp_path: Path):
    analyzer = StaticAnalyzer(max_file_size=1024)
    oversized = tmp_path / "large.bin"
    oversized.write_bytes(b"\x00" * 2048)

    with pytest.raises(ValueError, match="exceeds maximum limit"):
        analyzer.analyze_file(oversized)


def test_malformed_pe_handling(tmp_path: Path):
    # File starts with MZ but has corrupt e_lfanew
    corrupt = tmp_path / "corrupt.exe"
    corrupt.write_bytes(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x999999))

    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(corrupt)

    assert res.is_pe is False
    assert len(res.warnings) > 0


def test_ingest_static_finding_into_case(tmp_path: Path):
    db_path = tmp_path / "test.db"
    store = EvidenceStore(db_path)
    try:
        case = store.create_case(case_id="CASE-STATIC-001", case_name="Static Test Case")

        test_file = tmp_path / "payload.exe"
        test_file.write_bytes(
            b"MZ" + b"\x00" * 100 + b"https://evil-ransom.org 203.0.113.50 DECRYPT RANSOM RECOVER"
        )

        analyzer = StaticAnalyzer()
        res = analyzer.analyze_file(test_file)

        finding_id = ingest_static_finding(store, "CASE-STATIC-001", res)
        assert finding_id > 0

        findings = store.get_case_findings("CASE-STATIC-001")
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "static_file_analysis"
        assert findings[0]["technique"] == "T1027"
    finally:
        store.close()


def test_run_static_analysis_command_cli(tmp_path: Path, capsys):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x00\x00Test Binary String Content with http://example.com/c2")

    # Test text output
    ret = run_static_analysis_command(file_path=target, as_json=False)
    assert ret == 0
    captured = capsys.readouterr().out
    assert "RANSOMEYE STATIC FILE ANALYSIS REPORT" in captured
    assert "SHA-256" in captured

    # Test JSON output and file export
    export_file = tmp_path / "export_report.json"
    ret = run_static_analysis_command(
        file_path=target,
        as_json=True,
        export_path=export_file,
    )
    assert ret == 0
    assert export_file.is_file()
    data = json.loads(export_file.read_text(encoding="utf-8"))
    assert data["file_name"] == "sample.bin"
    assert "sha256" in data
