"""Static, offline PCAP network analyzer for RansomEye.

Parses classic libpcap captures using pure Python stdlib (``struct``) with
no subprocess, no eval/exec, and no outbound network calls. Produces
``EvidenceEvent`` observations (``network_connect``, ``dns_query``) and
deterministic, explainable findings that link back to the specific events
that triggered them.

PCAP evidence is attacker-controlled input. The parser enforces strict
resource bounds (file size, packet count, flow count, DNS record count,
QNAME length, included packet length) and reports malformed packets as
warnings rather than raising.

PCAP captures provide no reliable endpoint process identity. This analyzer
NEVER fabricates PID, process GUID, process name, image path or command
line from a capture.

Provenance: magic-number signatures and the suspicious-user-agent heuristic
list are adapted from 12X-RANSOMWARE-ANALYSIS
``ExtenderRem/backend/analyzers/pcap_analyzer.py`` (MIT License,
Copyright (c) 2026 Judson1214; see THIRD_PARTY_NOTICES.md). The packet
parsing (link layer, IPv4/IPv6, TCP/UDP, DNS QNAME decoding) and
EvidenceEvent integration are RansomEye-native.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ANALYZER_VERSION = "1.0.0"

# Resource bounds (defensive against malicious captures).
MAX_PCAP_SIZE = 100 * 1024 * 1024
MAX_PACKETS = 500_000
MAX_FLOWS = 20_000
MAX_DNS_RECORDS = 10_000
MAX_HTTP_RECORDS = 5_000
MAX_INDICATORS = 200
MAX_QNAME_LEN = 253
MAX_PACKET_INCL_LEN = 262_144
MAX_WARNINGS = 50

# Magic numbers (classic libpcap big/little endian, pcapng).
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Status values.
STATUS_COMPLETE = "complete"
STATUS_UNSUPPORTED_FORMAT = "unsupported_format"
STATUS_EMPTY = "empty"
STATUS_MALFORMED = "malformed"

# EvidenceEvent constants.
PCAP_ANALYST = "ransomeye-pcap-analyzer"
PCAP_SOURCE = "pcap"
PCAP_PROVENANCE_SOURCE = "pcap_analyzer"
PCAP_FINDING_PREFIX = "pcap_"

# Link-layer types from PCAP global header.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

# Suspicious User-Agent substrings (adapted from 12X).
SUSPICIOUS_USER_AGENTS = (
    "python-urllib",
    "python-requests",
    "go-http-client",
    "curl/",
    "wget",
    "powershell",
    "mozilla/4.0 (compatible; msie 7.0;",
)

# High-abuse TLDs (deterministic indicator; conservative severity).
HIGH_ABUSE_TLDS = frozenset({"xyz", "top", "tk", "cc", "pw", "cf", "gq", "ml", "su"})

# Common service ports that should NOT trigger the "rare port" indicator.
COMMON_SERVICE_PORTS = frozenset(
    {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445,
     465, 500, 514, 587, 636, 993, 995, 1194, 1433, 1521, 3306, 3389, 5432,
     5900, 8080, 8443}
)

# Rule-ID extraction from finding reason (reused idempotency pattern).
_RULE_ID_IN_REASON = re.compile(r"^\[([A-Z0-9][A-Z0-9-]*)\]")

# HTTP method prefix detection (for TCP payload decode).
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
_HOST_HEADER_RE = re.compile(rb"\r\nHost:\s*([^\r\n]{1,253})", re.IGNORECASE)
_UA_HEADER_RE = re.compile(rb"\r\nUser-Agent:\s*([^\r\n]{1,256})", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$")

# DNS types we surface.
_DNS_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                   16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


class PcapAnalysisError(ValueError):
    """Raised for inputs the analyzer refuses before parsing."""


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class PcapFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: datetime
    packet_index: int
    packets: int = 0
    bytes: int = 0


@dataclass
class PcapDnsQuery:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    transaction_id: int
    qname: str
    qtype: str
    packet_index: int


@dataclass
class PcapHttpRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    method: str
    host: str
    user_agent: str
    packet_index: int


@dataclass
class PcapIndicator:
    rule_id: str
    title: str
    severity: str  # low | medium
    confidence: float
    technique: str
    category: str
    excerpt: str
    event_index: int  # index into analysis.events whose event_id triggered this


@dataclass
class PcapAnalysisResult:
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    link_type: int
    link_type_name: str
    analysis_status: str
    total_packets: int
    parsed_packets: int
    malformed_packets: int
    tcp_count: int
    udp_count: int
    dns_count: int
    http_count: int
    flows: list[PcapFlow] = field(default_factory=list)
    dns_queries: list[PcapDnsQuery] = field(default_factory=list)
    http_records: list[PcapHttpRecord] = field(default_factory=list)
    indicators: list[PcapIndicator] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    analyzer_version: str = ANALYZER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "link_type": self.link_type,
            "link_type_name": self.link_type_name,
            "analysis_status": self.analysis_status,
            "total_packets": self.total_packets,
            "parsed_packets": self.parsed_packets,
            "malformed_packets": self.malformed_packets,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "dns_count": self.dns_count,
            "http_count": self.http_count,
            "flows": [
                {
                    "src_ip": f.src_ip, "dst_ip": f.dst_ip,
                    "src_port": f.src_port, "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "first_seen": f.first_seen.isoformat(),
                    "packet_index": f.packet_index,
                    "packets": f.packets, "bytes": f.bytes,
                }
                for f in self.flows
            ],
            "dns_queries": [
                {
                    "timestamp": d.timestamp.isoformat(),
                    "src_ip": d.src_ip, "dst_ip": d.dst_ip,
                    "transaction_id": d.transaction_id,
                    "qname": d.qname, "qtype": d.qtype,
                    "packet_index": d.packet_index,
                }
                for d in self.dns_queries
            ],
            "http_records": [
                {
                    "timestamp": h.timestamp.isoformat(),
                    "src_ip": h.src_ip, "dst_ip": h.dst_ip,
                    "method": h.method, "host": h.host,
                    "user_agent": h.user_agent,
                    "packet_index": h.packet_index,
                }
                for h in self.http_records
            ],
            "indicators": [
                {
                    "rule_id": i.rule_id, "title": i.title,
                    "severity": i.severity, "confidence": i.confidence,
                    "technique": i.technique, "category": i.category,
                    "excerpt": i.excerpt,
                }
                for i in self.indicators
            ],
            "warnings": list(self.warnings),
            "analyzer_version": self.analyzer_version,
        }


# --------------------------------------------------------------------------- #
# Path validation
# --------------------------------------------------------------------------- #

def _reject_remote_path(path_text: str) -> None:
    normalized = path_text.replace("/", "\\")
    if normalized.startswith("\\\\"):
        raise PcapAnalysisError(
            "UNC, device and extended-length paths are not accepted; "
            "copy the capture to a local drive first."
        )


# --------------------------------------------------------------------------- #
# Protocol decoders
# --------------------------------------------------------------------------- #

def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS QNAME at ``offset``. Returns (qname, bytes_consumed).

    Only inline labels are decoded; pointer compression in the question
    section is treated as end-of-name. Length-bound by MAX_QNAME_LEN.
    """
    labels: list[str] = []
    pos = offset
    total = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:  # compression pointer in question section is unusual; stop.
            pos += 2
            break
        pos += 1
        if pos + length > len(data):
            raise ValueError("qname label overflow")
        label = data[pos:pos + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            labels.append(label.decode("ascii", errors="replace"))
        pos += length
        total += length + 1
        if total > MAX_QNAME_LEN:
            raise ValueError("qname too long")
    return (".".join(labels), pos - offset)


def _parse_dns_question(payload: bytes) -> tuple[int, str, int] | None:
    """Parse a DNS header + first question. Returns (txid, qname, qtype) or None."""
    if len(payload) < 12:
        return None
    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", payload[:12])
    if qdcount < 1:
        return None
    is_response = flags & 0x8000
    try:
        qname, consumed = _decode_qname(payload, 12)
    except ValueError:
        return None
    end = 12 + consumed
    if end + 4 > len(payload):
        return None
    qtype, _qclass = struct.unpack("!HH", payload[end:end + 4])
    if is_response:
        # We only emit dns_query events for query packets (flags.QR==0).
        return None
    if not qname:
        return None
    return (txid, qname, qtype)


def _ipv4_str(raw: bytes) -> str:
    return "{0}.{1}.{2}.{3}".format(*raw)


def _ipv6_str(raw: bytes) -> str:
    groups = struct.unpack("!8H", raw)
    return ":".join(f"{g:x}" for g in groups)


def _parse_ipv4(frame: bytes, offset: int) -> tuple[str, str, int, bytes] | None:
    """Return (src_ip, dst_ip, protocol, payload) for an IPv4 datagram at ``offset``."""
    if offset + 20 > len(frame):
        return None
    vhl = frame[offset]
    version = vhl >> 4
    if version != 4:
        return None
    ihl = (vhl & 0x0F) * 4
    if ihl < 20 or offset + ihl > len(frame):
        return None
    proto = frame[offset + 9]
    src = _ipv4_str(frame[offset + 12:offset + 16])
    dst = _ipv4_str(frame[offset + 16:offset + 20])
    total_len_bytes = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
    if total_len_bytes < ihl or offset + total_len_bytes > len(frame):
        total_len_bytes = len(frame) - offset
    payload = frame[offset + ihl:offset + total_len_bytes]
    return (src, dst, proto, payload)


def _parse_ipv6(frame: bytes, offset: int) -> tuple[str, str, int, bytes] | None:
    if offset + 40 > len(frame):
        return None
    v = frame[offset] >> 4
    if v != 6:
        return None
    next_header = frame[offset + 6]
    src = _ipv6_str(frame[offset + 8:offset + 24])
    dst = _ipv6_str(frame[offset + 24:offset + 40])
    payload = frame[offset + 40:]
    return (src, dst, next_header, payload)


def _unwrap_link(link_type: int, raw: bytes) -> tuple[str, bytes] | None:
    """Return (l3_proto, l3_bytes) stripped of link-layer headers.

    ``l3_proto`` is one of "ipv4", "ipv6" or None; ``l3_bytes`` is the IP datagram.
    """
    if link_type == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None
        ethertype = struct.unpack("!H", raw[12:14])[0]
        offset = 14
        # Skip single 802.1Q VLAN tag.
        if ethertype == 0x8100 and len(raw) >= 18:
            ethertype = struct.unpack("!H", raw[16:18])[0]
            offset = 18
        if ethertype == 0x0800:
            return ("ipv4", raw[offset:])
        if ethertype == 0x86DD:
            return ("ipv6", raw[offset:])
        return None
    if link_type == LINKTYPE_RAW_IP or link_type == LINKTYPE_IPV4:
        if len(raw) < 1:
            return None
        v = raw[0] >> 4
        if v == 4:
            return ("ipv4", raw)
        if v == 6:
            return ("ipv6", raw)
        return None
    if link_type == LINKTYPE_IPV6:
        return ("ipv6", raw)
    if link_type == LINKTYPE_LINUX_SLL:
        if len(raw) < 16:
            return None
        proto = struct.unpack("!H", raw[14:16])[0]
        if proto == 0x0800:
            return ("ipv4", raw[16:])
        if proto == 0x86DD:
            return ("ipv6", raw[16:])
        return None
    return None


def _link_type_name(link_type: int) -> str:
    return {
        LINKTYPE_ETHERNET: "Ethernet",
        LINKTYPE_RAW_IP: "Raw IP",
        LINKTYPE_LINUX_SLL: "Linux cooked",
        LINKTYPE_IPV4: "Raw IPv4",
        LINKTYPE_IPV6: "Raw IPv6",
    }.get(link_type, f"linktype_{link_type}")


# --------------------------------------------------------------------------- #
# Core parser
# --------------------------------------------------------------------------- #

class PcapAnalyzer:
    """Static PCAP network analyzer. Pure stdlib."""

    def __init__(self) -> None:
        pass

    def analyze_file(self, file_path: str | Path) -> PcapAnalysisResult:
        _reject_remote_path(str(file_path))
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        size = path.stat().st_size
        if size > MAX_PCAP_SIZE:
            raise PcapAnalysisError(
                f"Capture exceeds maximum size of {MAX_PCAP_SIZE} bytes"
            )
        with path.open("rb") as fh:
            data = fh.read()
        return self.analyze_bytes(data, file_name=path.name, file_path=str(path))

    def analyze_bytes(
        self,
        data: bytes,
        *,
        file_name: str = "",
        file_path: str = "",
    ) -> PcapAnalysisResult:
        sha256 = hashlib.sha256(data).hexdigest()
        result = PcapAnalysisResult(
            file_path=file_path or file_name,
            file_name=file_name or "capture.pcap",
            file_size=len(data),
            sha256=sha256,
            link_type=0,
            link_type_name="unknown",
            analysis_status=STATUS_EMPTY,
            total_packets=0,
            parsed_packets=0,
            malformed_packets=0,
            tcp_count=0,
            udp_count=0,
            dns_count=0,
            http_count=0,
        )

        if len(data) == 0:
            result.warnings.append("Capture is empty.")
            return result

        if len(data) < 4:
            result.analysis_status = STATUS_UNSUPPORTED_FORMAT
            result.warnings.append("Capture is too small to carry a PCAP magic number.")
            return result

        magic = data[:4]
        if magic == PCAPNG_MAGIC:
            result.analysis_status = STATUS_UNSUPPORTED_FORMAT
            result.link_type_name = "pcapng"
            result.warnings.append(
                "pcapng format detected. This analyzer currently supports classic "
                "libpcap only. Re-export the capture as libpcap (.pcap)."
            )
            return result

        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            result.analysis_status = STATUS_UNSUPPORTED_FORMAT
            result.warnings.append("Not a recognizable PCAP capture.")
            return result

        if len(data) < 24:
            result.analysis_status = STATUS_MALFORMED
            result.warnings.append("Global header truncated.")
            return result

        try:
            _ver_maj, _ver_min, _zone, _sigfigs, _snaplen, link_type = struct.unpack(
                endian + "HHiIII", data[4:24]
            )
        except struct.error:
            result.analysis_status = STATUS_MALFORMED
            result.warnings.append("Global header unreadable.")
            return result

        result.link_type = link_type
        result.link_type_name = _link_type_name(link_type)
        self._parse_packets(data, endian, link_type, result)
        self._evaluate_rules(result)
        if result.analysis_status == STATUS_EMPTY and result.total_packets > 0:
            result.analysis_status = STATUS_COMPLETE
        elif result.total_packets == 0 and result.analysis_status == STATUS_EMPTY:
            result.warnings.append("No packets found after global header.")
        else:
            result.analysis_status = STATUS_COMPLETE
        return result

    def _parse_packets(
        self,
        data: bytes,
        endian: str,
        link_type: int,
        result: PcapAnalysisResult,
    ) -> None:
        pos = 24
        pkt_index = 0
        flows: dict[tuple, PcapFlow] = {}
        while pos < len(data):
            if pkt_index >= MAX_PACKETS:
                self._warn(result, f"Packet cap reached ({MAX_PACKETS}); remainder skipped.")
                break
            if pos + 16 > len(data):
                self._warn(result, "Trailing per-packet header truncated; stopping.")
                break
            try:
                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                    endian + "IIII", data[pos:pos + 16]
                )
            except struct.error:
                self._warn(result, "Per-packet header unreadable; stopping.")
                break
            pos += 16
            pkt_index += 1
            result.total_packets += 1
            if incl_len == 0:
                continue
            if incl_len > MAX_PACKET_INCL_LEN:
                self._warn(result, f"Packet {pkt_index} exceeds included-length cap; skipped.")
                pos += incl_len
                result.malformed_packets += 1
                continue
            if pos + incl_len > len(data):
                self._warn(result, f"Packet {pkt_index} truncated; stopping.")
                result.malformed_packets += 1
                break
            raw = data[pos:pos + incl_len]
            pos += incl_len
            try:
                ts = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                ts = datetime.fromtimestamp(0, tz=timezone.utc)
            unwrapped = _unwrap_link(link_type, raw)
            if unwrapped is None:
                result.malformed_packets += 1
                continue
            l3_proto, l3_bytes = unwrapped
            if l3_proto == "ipv4":
                parsed = _parse_ipv4(l3_bytes, 0)
            elif l3_proto == "ipv6":
                parsed = _parse_ipv6(l3_bytes, 0)
            else:
                result.malformed_packets += 1
                continue
            if parsed is None:
                result.malformed_packets += 1
                continue
            src_ip, dst_ip, ip_proto, l4_payload = parsed
            result.parsed_packets += 1

            if ip_proto == 6:  # TCP
                self._handle_tcp(result, flows, pkt_index, ts, src_ip, dst_ip, l4_payload)
            elif ip_proto == 17:  # UDP
                self._handle_udp(result, flows, pkt_index, ts, src_ip, dst_ip, l4_payload)
            # Other protocols: counted as parsed but not expanded.

    def _handle_tcp(
        self,
        result: PcapAnalysisResult,
        flows: dict[tuple, PcapFlow],
        pkt_index: int,
        ts: datetime,
        src_ip: str,
        dst_ip: str,
        payload: bytes,
    ) -> None:
        if len(payload) < 20:
            result.malformed_packets += 1
            return
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or data_offset > len(payload):
            result.malformed_packets += 1
            return
        flags = payload[13]
        app = payload[data_offset:]
        result.tcp_count += 1
        self._accumulate_flow(result, flows, pkt_index, ts, src_ip, dst_ip,
                              src_port, dst_port, "tcp", flags, is_tcp_syn=(flags & 0x02 and not flags & 0x10))

        if len(app) >= 4 and any(app.startswith(m) for m in _HTTP_METHODS):
            if len(result.http_records) >= MAX_HTTP_RECORDS:
                return
            result.http_count += 1
            try:
                method_end = app.index(b" ")
                method = app[:method_end].decode("ascii", errors="replace")
            except ValueError:
                method = "?"
            host = ""
            ua = ""
            host_m = _HOST_HEADER_RE.search(app[:8192])
            if host_m:
                host = host_m.group(1).decode("ascii", errors="replace").strip()
            ua_m = _UA_HEADER_RE.search(app[:8192])
            if ua_m:
                ua = ua_m.group(1).decode("ascii", errors="replace").strip()
            result.http_records.append(PcapHttpRecord(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                method=method, host=host, user_agent=ua,
                packet_index=pkt_index,
            ))

    def _handle_udp(
        self,
        result: PcapAnalysisResult,
        flows: dict[tuple, PcapFlow],
        pkt_index: int,
        ts: datetime,
        src_ip: str,
        dst_ip: str,
        payload: bytes,
    ) -> None:
        if len(payload) < 8:
            result.malformed_packets += 1
            return
        src_port, dst_port, udp_len = struct.unpack("!HHH", payload[:6])
        app = payload[8:]
        result.udp_count += 1
        self._accumulate_flow(result, flows, pkt_index, ts, src_ip, dst_ip,
                              src_port, dst_port, "udp", 0, is_tcp_syn=False)
        if dst_port == 53 or src_port == 53:
            parsed = _parse_dns_question(app)
            if parsed is None:
                return
            if len(result.dns_queries) >= MAX_DNS_RECORDS:
                return
            txid, qname, qtype = parsed
            result.dns_count += 1
            result.dns_queries.append(PcapDnsQuery(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                transaction_id=txid, qname=qname,
                qtype=_DNS_TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                packet_index=pkt_index,
            ))

    def _accumulate_flow(
        self,
        result: PcapAnalysisResult,
        flows: dict[tuple, PcapFlow],
        pkt_index: int,
        ts: datetime,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        protocol: str, _flags: int, is_tcp_syn: bool,
    ) -> None:
        # 5-tuple keyed; TCP flow is "opened" on first SYN only; UDP flow uses first-packet.
        key = (protocol, src_ip, src_port, dst_ip, dst_port)
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= MAX_FLOWS:
                return
            if protocol == "tcp" and not is_tcp_syn:
                # Do not open a flow mid-stream; still count bytes on existing flows only.
                return
            flow = PcapFlow(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol, first_seen=ts,
                packet_index=pkt_index, packets=1, bytes=0,
            )
            flows[key] = flow
            result.flows.append(flow)
        else:
            flow.packets += 1

    def _warn(self, result: PcapAnalysisResult, msg: str) -> None:
        if len(result.warnings) < MAX_WARNINGS:
            result.warnings.append(msg)

    # ------------------------------------------------------------------ #
    # Rule evaluation
    # ------------------------------------------------------------------ #

    def _evaluate_rules(self, result: PcapAnalysisResult) -> None:
        if len(result.indicators) >= MAX_INDICATORS:
            return

        # --- DNS-based indicators ---
        dns_counts: dict[str, int] = {}
        for q in result.dns_queries:
            dns_counts[q.qname] = dns_counts.get(q.qname, 0) + 1

        seen_tld_qnames: set[str] = set()
        seen_dga_qnames: set[str] = set()
        for q in result.dns_queries:
            labels = [p for p in q.qname.split(".") if p]
            if not labels:
                continue
            tld = labels[-1].lower()
            if tld in HIGH_ABUSE_TLDS and q.qname not in seen_tld_qnames:
                seen_tld_qnames.add(q.qname)
                self._add_indicator(result, PcapIndicator(
                    rule_id="PCAP-DNS-TLD-001",
                    title="DNS query to high-abuse TLD",
                    severity="low",
                    confidence=0.45,
                    technique="T1071.004",
                    category="network_dns",
                    excerpt=q.qname,
                    event_index=-1,  # linked via qname at ingest time
                ))
            # DGA heuristic: single label with length >= 16 and low vowel ratio.
            if len(labels) >= 2:
                sld = labels[-2]
                if (len(sld) >= 16 and sld.isascii()
                        and self._non_vowel_ratio(sld) >= 0.6
                        and q.qname not in seen_dga_qnames):
                    seen_dga_qnames.add(q.qname)
                    self._add_indicator(result, PcapIndicator(
                        rule_id="PCAP-DNS-DGA-002",
                        title="DNS query matches random-looking label pattern",
                        severity="medium",
                        confidence=0.50,
                        technique="T1568.002",
                        category="network_dns",
                        excerpt=q.qname,
                        event_index=-1,
                    ))

        for qname, count in dns_counts.items():
            if count >= 20:
                self._add_indicator(result, PcapIndicator(
                    rule_id="PCAP-DNS-REPEATED-007",
                    title=f"Repeated DNS queries ({count}) for one name",
                    severity="low",
                    confidence=0.45,
                    technique="T1071.004",
                    category="network_dns",
                    excerpt=f"{qname} (count={count})",
                    event_index=-1,
                ))

        # --- HTTP-based indicators ---
        for h in result.http_records:
            if h.host and _IP_LITERAL_RE.match(h.host):
                self._add_indicator(result, PcapIndicator(
                    rule_id="PCAP-NET-RAW-IP-004",
                    title="HTTP Host header is a raw IP literal",
                    severity="medium",
                    confidence=0.60,
                    technique="T1071.001",
                    category="network_http",
                    excerpt=f"{h.method} Host: {h.host}",
                    event_index=-1,
                ))
            if h.user_agent:
                lowered = h.user_agent.lower()
                for probe in SUSPICIOUS_USER_AGENTS:
                    if probe in lowered:
                        self._add_indicator(result, PcapIndicator(
                            rule_id="PCAP-NET-SUSPICIOUS-UA-005",
                            title="HTTP User-Agent matches tooling pattern",
                            severity="low",
                            confidence=0.50,
                            technique="T1071.001",
                            category="network_http",
                            excerpt=h.user_agent[:120],
                            event_index=-1,
                        ))
                        break

        # --- Volume-based indicators ---
        dst_counts: dict[str, int] = {}
        for f in result.flows:
            dst_counts[f.dst_ip] = dst_counts.get(f.dst_ip, 0) + 1
        for dst, count in dst_counts.items():
            if count >= 50:
                self._add_indicator(result, PcapIndicator(
                    rule_id="PCAP-NET-HIGH-VOLUME-006",
                    title=f"High-volume connections to one destination ({count})",
                    severity="medium",
                    confidence=0.45,
                    technique="T1071",
                    category="network_flow",
                    excerpt=f"{dst} ({count} flows)",
                    event_index=-1,
                ))

        # --- Rare port indicator (very conservative) ---
        seen_rare: set[tuple] = set()
        for f in result.flows:
            if f.dst_port in COMMON_SERVICE_PORTS:
                continue
            if f.dst_port < 1024:
                continue
            key = (f.dst_ip, f.dst_port)
            if key in seen_rare:
                continue
            seen_rare.add(key)
            self._add_indicator(result, PcapIndicator(
                rule_id="PCAP-NET-RARE-PORT-003",
                title="Connection to uncommon service port",
                severity="low",
                confidence=0.35,
                technique="T1571",
                category="network_flow",
                excerpt=f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port} ({f.protocol})",
                event_index=-1,
            ))

    def _add_indicator(self, result: PcapAnalysisResult, indicator: PcapIndicator) -> None:
        if len(result.indicators) >= MAX_INDICATORS:
            return
        result.indicators.append(indicator)

    @staticmethod
    def _non_vowel_ratio(label: str) -> float:
        if not label:
            return 0.0
        vowels = sum(1 for c in label.lower() if c in "aeiou")
        return 1.0 - (vowels / len(label))


# --------------------------------------------------------------------------- #
# Evidence / Finding integration
# --------------------------------------------------------------------------- #

def _pcap_provenance_event_id(case_id: str, sha256: str) -> str:
    seed = f"{case_id}|{sha256}"
    return "EVT-PCAP-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _pcap_flow_event_id(case_id: str, sha256: str, flow: PcapFlow) -> str:
    seed = (
        f"{case_id}|{sha256}|flow|{flow.protocol}|"
        f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}|{flow.packet_index}"
    )
    return "EVT-PCAP-NET-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _pcap_dns_event_id(case_id: str, sha256: str, q: PcapDnsQuery) -> str:
    seed = f"{case_id}|{sha256}|dns|{q.qname}|{q.qtype}|{q.packet_index}"
    return "EVT-PCAP-DNS-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _existing_rule_ids(store: Any, case_id: str, event_ids: Iterable[str]) -> set[str]:
    present: set[str] = set()
    for eid in event_ids:
        try:
            findings = store.get_event_findings(case_id, eid)
        except Exception:
            continue
        for finding in findings:
            match = _RULE_ID_IN_REASON.match(finding.get("reason", ""))
            if match:
                present.add(match.group(1))
    return present


def _finding_for_indicator(
    result: PcapAnalysisResult, indicator: PcapIndicator, matched_event_ids: list[str]
) -> dict[str, Any]:
    reason = (
        f"[{indicator.rule_id}] {indicator.title}: {indicator.excerpt} "
        f"| capture sha256={result.sha256[:16]}"
    )
    score_map = {"low": 15, "medium": 35}
    return {
        "type": f"{PCAP_FINDING_PREFIX}{indicator.category}",
        "score": score_map.get(indicator.severity, 10),
        "confidence": indicator.confidence,
        "technique": indicator.technique,
        "reason": reason,
    }


def ingest_pcap_finding(
    store: Any,
    case_id: str,
    result: PcapAnalysisResult,
) -> list[int]:
    """Persist PCAP analysis into an EvidenceStore case.

    Creates:
      * one deterministic ``file_stream_hash`` provenance event per capture
      * one ``network_connect`` event per flow (deterministic id)
      * one ``dns_query`` event per DNS query (deterministic id)
      * one finding per distinct triggered rule, linked to the matching
        event IDs via ``finding_evidence``
      * one ``reviewed`` chain-of-custody record for the capture artifact

    Idempotent: existing deterministic events are not re-inserted (store
    uses ``INSERT OR REPLACE``); findings are deduplicated by rule_id
    against events already carrying that rule_id.
    """
    if result.analysis_status != STATUS_COMPLETE:
        # Non-complete analyses do not persist evidence.
        return []
    if not result.file_path:
        raise ValueError("ingest_pcap_finding requires result.file_path")

    path = Path(result.file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {result.file_path}")

    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    prov_event_id = _pcap_provenance_event_id(case_id, result.sha256)

    store.save_event(case_id, {
        "event_id": prov_event_id,
        "case_id": case_id,
        "timestamp": mtime,
        "source": PCAP_PROVENANCE_SOURCE,
        "event_type": "file_stream_hash",
        "file_path": str(path.resolve()),
        "hashes": f"SHA256={result.sha256}",
        "confidence": 0.95,
        "metadata": {
            "observation": "pcap_capture_provenance",
            "sha256": result.sha256,
            "file_size": result.file_size,
            "link_type": result.link_type,
            "link_type_name": result.link_type_name,
            "total_packets": result.total_packets,
            "parsed_packets": result.parsed_packets,
            "malformed_packets": result.malformed_packets,
            "analyzer_version": result.analyzer_version,
            "analysis_status": result.analysis_status,
        },
    })

    flow_event_ids: dict[int, str] = {}  # index into result.flows -> event_id
    for idx, flow in enumerate(result.flows):
        eid = _pcap_flow_event_id(case_id, result.sha256, flow)
        flow_event_ids[idx] = eid
        store.save_event(case_id, {
            "event_id": eid,
            "case_id": case_id,
            "timestamp": flow.first_seen.isoformat(),
            "source": PCAP_SOURCE,
            "event_type": "network_connect",
            "file_path": str(path.resolve()),
            "confidence": 0.90,
            "network": {
                "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                "src_port": flow.src_port, "dst_port": flow.dst_port,
                "protocol": flow.protocol,
            },
            "metadata": {
                "capture_file": result.file_name,
                "capture_sha256": result.sha256,
                "packet_index": flow.packet_index,
                "packets": flow.packets,
            },
        })

    dns_event_ids: dict[int, str] = {}
    for idx, q in enumerate(result.dns_queries):
        eid = _pcap_dns_event_id(case_id, result.sha256, q)
        dns_event_ids[idx] = eid
        store.save_event(case_id, {
            "event_id": eid,
            "case_id": case_id,
            "timestamp": q.timestamp.isoformat(),
            "source": PCAP_SOURCE,
            "event_type": "dns_query",
            "file_path": str(path.resolve()),
            "confidence": 0.90,
            "network": {
                "src_ip": q.src_ip, "dst_ip": q.dst_ip,
                "query_name": q.qname, "query_type": q.qtype,
            },
            "metadata": {
                "capture_file": result.file_name,
                "capture_sha256": result.sha256,
                "packet_index": q.packet_index,
                "transaction_id": q.transaction_id,
            },
        })

    all_evidence_event_ids = [prov_event_id] + list(flow_event_ids.values()) + list(dns_event_ids.values())
    already = _existing_rule_ids(store, case_id, all_evidence_event_ids)

    # Deduplicate indicators by rule_id for ingestion (one finding per rule).
    chosen_by_rule: dict[str, PcapIndicator] = {}
    for ind in result.indicators:
        chosen_by_rule.setdefault(ind.rule_id, ind)

    created: list[int] = []
    for rule_id in sorted(chosen_by_rule):
        if rule_id in already:
            continue
        indicator = chosen_by_rule[rule_id]
        matched = _match_event_ids_for_indicator(indicator, result, flow_event_ids, dns_event_ids)
        if not matched:
            matched = [prov_event_id]
        finding = _finding_for_indicator(result, indicator, matched)
        finding_id = store.save_finding(case_id, finding, event_ids=matched)
        created.append(finding_id)

    store.record_custody_event(
        case_id=case_id,
        artifact_path=str(path.resolve()),
        sha256=result.sha256,
        action="reviewed",
        analyst=PCAP_ANALYST,
        note=(
            f"PCAP analysis: packets={result.total_packets}, "
            f"parsed={result.parsed_packets}, flows={len(result.flows)}, "
            f"dns={result.dns_count}, http={result.http_count}, "
            f"indicators={len(result.indicators)}"
        ),
    )
    return created


def _match_event_ids_for_indicator(
    indicator: PcapIndicator,
    result: PcapAnalysisResult,
    flow_event_ids: dict[int, str],
    dns_event_ids: dict[int, str],
) -> list[str]:
    """Return the event IDs whose data triggered this indicator."""
    matched: list[str] = []
    excerpt = indicator.excerpt
    if indicator.category == "network_dns":
        head = excerpt.split(" ", 1)[0]
        for idx, q in enumerate(result.dns_queries):
            if q.qname == head or (q.qname and head.startswith(q.qname + " ")):
                eid = dns_event_ids.get(idx)
                if eid and eid not in matched:
                    matched.append(eid)
                    if len(matched) >= 10:
                        break
    elif indicator.category == "network_http":
        for idx, flow in enumerate(result.flows):
            if flow.protocol != "tcp":
                continue
            if flow.dst_port in (80, 8080):
                eid = flow_event_ids.get(idx)
                if eid and eid not in matched:
                    matched.append(eid)
                    if len(matched) >= 10:
                        break
    elif indicator.category == "network_flow":
        head = excerpt.split(" ", 1)[0]
        for idx, flow in enumerate(result.flows):
            flow_str_a = f"{flow.src_ip}:{flow.src_port}"
            flow_str_b = f"{flow.dst_ip}"
            if flow_str_a in excerpt or flow_str_b == head or flow.dst_ip == head.split(":", 1)[0]:
                eid = flow_event_ids.get(idx)
                if eid and eid not in matched:
                    matched.append(eid)
                    if len(matched) >= 10:
                        break
    return matched
