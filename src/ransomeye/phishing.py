"""Phishing and financial scam message identification engine for RansomEye.

Provides multi-vector message analysis, social engineering and financial fraud
heuristic detection, domain/URL intelligence, attachment payload risk scoring,
and integration with RansomEye DFIR case findings.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from ransomeye.storage import EvidenceStore


# --- MITRE ATT&CK Mapping ---
MITRE_INITIAL_ACCESS_LINK = "T1566.002"
MITRE_INITIAL_ACCESS_ATTACHMENT = "T1566.001"
MITRE_INITIAL_ACCESS_SERVICE = "T1566.003"
MITRE_USER_EXECUTION_LINK = "T1204.001"
MITRE_USER_EXECUTION_FILE = "T1204.002"
MITRE_CREDENTIAL_ACCESS = "T1598"


# --- Rule Weights and Thresholds ---
SCORE_THRESHOLD_BENIGN = 19
SCORE_THRESHOLD_LOW = 39
SCORE_THRESHOLD_SUSPICIOUS = 69
SCORE_THRESHOLD_HIGH = 89


# --- Known Brands for Lookalike / Subdomain Impersonation Detection ---
TARGETED_BRANDS = frozenset(
    {
        "paypal",
        "chase",
        "bankofamerica",
        "wellsfargo",
        "citibank",
        "capitalone",
        "apple",
        "microsoft",
        "google",
        "amazon",
        "netflix",
        "binance",
        "coinbase",
        "metamask",
        "dhl",
        "fedex",
        "ups",
        "usps",
        "geek squad",
        "geeksquad",
        "norton",
        "mcafee",
    }
)

SUSPICIOUS_TLDS = frozenset(
    {
        "xyz",
        "top",
        "zip",
        "mov",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "icu",
        "cfd",
        "buzz",
        "cam",
        "click",
        "country",
        "stream",
        "download",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "rb.gy",
        "buff.ly",
        "shorturl.at",
        "goo.gl",
    }
)

HIGH_RISK_ATTACHMENT_EXTENSIONS = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".wsf",
        ".hta",
        ".iso",
        ".img",
        ".vhd",
        ".lnk",
        ".docm",
        ".xlsm",
        ".pptm",
        ".dll",
    }
)

FREE_EMAIL_PROVIDERS = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
    }
)


@dataclass
class IndicatorMatch:
    """A detected threat indicator with weight, classification, and evidence."""

    rule_id: str
    category: str
    severity: str
    weight: int
    description: str
    matched_evidence: str
    mitre_attack: str = MITRE_INITIAL_ACCESS_LINK

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "weight": self.weight,
            "description": self.description,
            "matched_evidence": self.matched_evidence,
            "mitre_attack": self.mitre_attack,
        }


@dataclass
class MessagePayload:
    """Standardized representation of an inspected message (Email, SMS, or Chat)."""

    text: str = ""
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    @classmethod
    def from_text(cls, text: str, sender: str = "") -> MessagePayload:
        """Create payload from raw text or SMS body."""
        urls = extract_urls_from_text(text)
        return cls(text=text, sender=sender, urls=urls)

    @classmethod
    def from_email_bytes(cls, raw_bytes: bytes) -> MessagePayload:
        """Parse raw email bytes (RFC 822 / EML)."""
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        return cls._from_email_message(msg)

    @classmethod
    def from_email_file(cls, path: Path | str) -> MessagePayload:
        """Read and parse an .eml email file."""
        p = Path(path)
        raw_bytes = p.read_bytes()
        return cls.from_email_bytes(raw_bytes)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MessagePayload:
        """Create payload from structured dictionary."""
        text = str(data.get("text", "") or data.get("body", "") or data.get("message", ""))
        subject = str(data.get("subject", ""))
        sender = str(data.get("sender", "") or data.get("from", ""))
        recipient = str(data.get("recipient", "") or data.get("to", ""))
        headers = dict(data.get("headers", {}))
        urls = list(data.get("urls", []))
        if not urls:
            urls = extract_urls_from_text(f"{subject}\n{text}")
        attachments = list(data.get("attachments", []))
        return cls(
            text=text,
            subject=subject,
            sender=sender,
            recipient=recipient,
            headers=headers,
            urls=urls,
            attachments=attachments,
        )

    @classmethod
    def _from_email_message(cls, msg: EmailMessage) -> MessagePayload:
        subject = str(msg.get("subject", "") or "")
        sender = str(msg.get("from", "") or "")
        recipient = str(msg.get("to", "") or "")

        headers: dict[str, str] = {}
        for key in ("received-spf", "authentication-results", "reply-to", "return-path", "message-id"):
            val = msg.get(key)
            if val:
                headers[key] = str(val)

        body_parts: list[str] = []
        attachments: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
                elif content_type in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="replace"))

        full_text = "\n".join(body_parts)
        urls = extract_urls_from_text(f"{subject}\n{full_text}")

        return cls(
            text=full_text,
            subject=subject,
            sender=sender,
            recipient=recipient,
            headers=headers,
            urls=urls,
            attachments=attachments,
        )


@dataclass
class PhishingAnalysisResult:
    """Comprehensive verdict and forensic indicators from message analysis."""

    score: int
    risk_level: str
    confidence: str
    indicators: list[IndicatorMatch]
    extracted_urls: list[dict[str, Any]]
    attachment_findings: list[dict[str, Any]]
    mitre_techniques: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "extracted_urls": self.extracted_urls,
            "attachment_findings": self.attachment_findings,
            "recommendations": self.recommendations,
        }

    def to_summary_text(self) -> str:
        lines = [
            "=" * 64,
            f" RANSOMEYE PHISHING & SCAM FORENSIC VERDICT: {self.risk_level.upper()}",
            "=" * 64,
            f"Risk Score   : {self.score} / 100",
            f"Confidence   : {self.confidence}",
            f"ATT&CK Flags : {', '.join(self.mitre_techniques) if self.mitre_techniques else 'None'}",
            "",
            f"Detected Indicators ({len(self.indicators)}):",
        ]
        if not self.indicators:
            lines.append("  [+] No suspicious indicators matched.")
        else:
            for ind in self.indicators:
                lines.append(f"  - [{ind.severity.upper()}] {ind.rule_id} ({ind.category}): {ind.description}")
                lines.append(f"      Matched text: \"{ind.matched_evidence}\"")

        if self.extracted_urls:
            lines.append("")
            lines.append(f"Analyzed URLs ({len(self.extracted_urls)}):")
            for u in self.extracted_urls:
                flags = []
                if u.get("is_ip_hostname"):
                    flags.append("RAW_IP")
                if u.get("is_brand_subdomain"):
                    flags.append("BRAND_IN_SUBDOMAIN")
                if u.get("is_punycode"):
                    flags.append("PUNYCODE")
                if u.get("is_shortener"):
                    flags.append("SHORTENER")
                if u.get("has_suspicious_tld"):
                    flags.append("SUSPICIOUS_TLD")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                lines.append(f"  * {u.get('url')}{flag_str}")

        if self.attachment_findings:
            lines.append("")
            lines.append(f"Attachment Assessment ({len(self.attachment_findings)}):")
            for att in self.attachment_findings:
                lines.append(f"  * {att.get('filename')} -> Risk: {att.get('risk')} ({att.get('reason')})")

        lines.append("")
        lines.append("DFIR Remediation Recommendations:")
        for rec in self.recommendations:
            lines.append(f"  > {rec}")

        lines.append("=" * 64)
        return "\n".join(lines)


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all HTTP/HTTPS links and web references from text."""
    url_pattern = re.compile(
        r"(?:https?://[^\s<>\"\'\)]+|www\.[^\s<>\"\'\)]+)",
        re.IGNORECASE,
    )
    matches = url_pattern.findall(text)
    # Clean trailing punctuation commonly attached to URLs in text
    cleaned = []
    for m in matches:
        m = m.rstrip(".,;:!?)'\"")
        if m and m not in cleaned:
            cleaned.append(m)
    return cleaned


class PhishingDetector:
    """Core detection engine for phishing, smishing, and financial scam identification."""

    # Category 1: Coercion & Urgency Patterns
    URGENCY_RULES: list[tuple[str, str, int, str, re.Pattern]] = [
        (
            "URG-001",
            "Urgent Account Suspension Threat",
            25,
            "Urgent threat claiming account or service will be suspended/locked.",
            re.compile(
                r"\b(account (?:has been |is )?(?:suspended|locked|deactivated|closed|restricted)|suspended within 24 (?:hours|hrs)|immediate action required|final warning|urgent action required|terminate your account)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "URG-002",
            "Legal or Law Enforcement Intimidation",
            30,
            "Threats of arrest, court summons, or law enforcement action to induce panic.",
            re.compile(
                r"\b(law enforcement|arrest warrant|court summons|legal action|penal code|police department|fbi investigation)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "URG-003",
            "Security Alert Panic Inducement",
            20,
            "Claims of unauthorized access or suspicious foreign login requiring immediate verification.",
            re.compile(
                r"\b(unauthorized (?:access|transaction|login|activity)|security alert|someone accessed your account|login attempt from)\b",
                re.IGNORECASE,
            ),
        ),
    ]

    # Category 2: Financial Fraud Patterns
    FRAUD_RULES: list[tuple[str, str, int, str, re.Pattern]] = [
        (
            "FRD-KYC-001",
            "Banking KYC / Account Verification Fraud",
            35,
            "Demands to verify netbanking or update KYC/PAN details to prevent deactivation.",
            re.compile(
                r"\b(update your kyc|kyc (?:expired|verification|update)|netbanking (?:blocked|disabled)|pan card (?:blocked|link|update)|verify your bank (?:account|details)|debit card (?:blocked|suspended))\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-OTP-002",
            "OTP / 2FA Credential Harvesting",
            30,
            "Requests for One-Time Password or authentication code verification.",
            re.compile(
                r"\b(one-time password|share the otp|enter (?:your )?otp|verify (?:your )?otp|2fa code|security code to claim)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-TECH-003",
            "Fake Tech Support / Renewal Invoice Trap",
            30,
            "Disguised invoice or subscription renewal with callback helpline.",
            re.compile(
                r"\b(geek squad|norton (?:antivirus|renewal)|mcafee (?:subscription|renewal)|paypal (?:charge|invoice|receipt)|auto-renewal of \$?\d+|order has been processed for \$?\d+|call (?:our )?support at|toll[- ]free)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-CRYPTO-004",
            "Cryptocurrency & High-Yield Investment Fraud",
            25,
            "Unrealistic investment returns, liquidity pool scams, or crypto transfer requests.",
            re.compile(
                r"\b(guaranteed (?:profit|return|yield)|daily (?:return|profit) of \d+%|double your (?:bitcoin|btc|crypto)|send (?:btc|eth|usdt) to|deposit to wallet|crypto investment pool)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-LOTTERY-005",
            "Advance-Fee / Lottery / Inheritance Claim (419)",
            25,
            "Unsolicited claim of massive lottery winnings or unclaimed estate bequest.",
            re.compile(
                r"\b(unclaimed (?:funds|inheritance|consignment)|lottery winner|you have won \$?\d+|claim your prize|beneficiary of \$?\d+|international lottery award)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-PAYMENT-006",
            "Untraceable Payment Demands",
            25,
            "Demands for gift card pins, bitcoin ATMs, or direct wire transfers.",
            re.compile(
                r"\b(apple gift card|steam gift card|buy gift cards|bitcoin atm|wire transfer immediately|send via western union)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "FRD-TASK-007",
            "Task / Job Commission Scam",
            20,
            "Unsolicited offer for high-paying simple tasks with wallet recharges.",
            re.compile(
                r"\b(part[- ]time job|earn \$?\d+ (?:daily|per day)|like youtube videos|recharge your (?:wallet|account) to withdraw|telegram task job)\b",
                re.IGNORECASE,
            ),
        ),
    ]

    def analyze(self, payload: MessagePayload) -> PhishingAnalysisResult:
        """Execute comprehensive forensic analysis on a message payload."""
        indicators: list[IndicatorMatch] = []
        full_text = f"{payload.subject}\n{payload.text}"

        # 1. Linguistic & Urgency Heuristics
        for rule_id, category, weight, desc, pattern in self.URGENCY_RULES:
            match = pattern.search(full_text)
            if match:
                indicators.append(
                    IndicatorMatch(
                        rule_id=rule_id,
                        category="urgency_coercion",
                        severity="high" if weight >= 25 else "medium",
                        weight=weight,
                        description=desc,
                        matched_evidence=match.group(0),
                        mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                    )
                )

        # 2. Financial Fraud Heuristics
        for rule_id, category, weight, desc, pattern in self.FRAUD_RULES:
            match = pattern.search(full_text)
            if match:
                indicators.append(
                    IndicatorMatch(
                        rule_id=rule_id,
                        category="financial_fraud",
                        severity="critical" if weight >= 35 else "high",
                        weight=weight,
                        description=desc,
                        matched_evidence=match.group(0),
                        mitre_attack=MITRE_CREDENTIAL_ACCESS if "OTP" in rule_id or "KYC" in rule_id else MITRE_INITIAL_ACCESS_LINK,
                    )
                )

        # 3. URL and Domain Intelligence
        url_findings: list[dict[str, Any]] = []
        for url in payload.urls:
            u_info = self._analyze_url(url)
            url_findings.append(u_info)
            if u_info["indicators"]:
                for ind in u_info["indicators"]:
                    indicators.append(ind)

        # 4. Attachment Risk Scoring
        att_findings: list[dict[str, Any]] = []
        for att in payload.attachments:
            att_info = self._analyze_attachment(att)
            att_findings.append(att_info)
            if att_info["indicator"]:
                indicators.append(att_info["indicator"])

        # 5. Header / Mail Authentication Analysis
        header_inds = self._analyze_headers(payload)
        indicators.extend(header_inds)

        # 6. Score Computation & Classification
        raw_score = sum(ind.weight for ind in indicators)
        final_score = min(100, raw_score)

        if final_score <= SCORE_THRESHOLD_BENIGN:
            risk_level = "benign"
            confidence = "high" if not indicators else "medium"
        elif final_score <= SCORE_THRESHOLD_LOW:
            risk_level = "low"
            confidence = "medium"
        elif final_score <= SCORE_THRESHOLD_SUSPICIOUS:
            risk_level = "suspicious"
            confidence = "medium"
        elif final_score <= SCORE_THRESHOLD_HIGH:
            risk_level = "high"
            confidence = "high"
        else:
            risk_level = "critical"
            confidence = "high"

        # MITRE ATT&CK Mapping
        mitre_set = {ind.mitre_attack for ind in indicators}
        if any(att.get("risk") in ("critical", "high") for att in att_findings):
            mitre_set.add(MITRE_INITIAL_ACCESS_ATTACHMENT)
            mitre_set.add(MITRE_USER_EXECUTION_FILE)
        if any(u.get("risk_score", 0) >= 30 for u in url_findings):
            mitre_set.add(MITRE_INITIAL_ACCESS_LINK)
            mitre_set.add(MITRE_USER_EXECUTION_LINK)

        recommendations = self._generate_recommendations(risk_level, indicators)

        return PhishingAnalysisResult(
            score=final_score,
            risk_level=risk_level,
            confidence=confidence,
            indicators=indicators,
            extracted_urls=url_findings,
            attachment_findings=att_findings,
            mitre_techniques=sorted(mitre_set),
            recommendations=recommendations,
        )

    def _analyze_url(self, raw_url: str) -> dict[str, Any]:
        """Inspect URL for IP hostnames, brand in subdomain, punycode, and shorteners."""
        if not re.match(r"^https?://", raw_url, re.IGNORECASE):
            parse_target = f"http://{raw_url}"
        else:
            parse_target = raw_url

        try:
            parsed = urllib.parse.urlparse(parse_target)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            hostname = raw_url.lower()

        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        is_punycode = hostname.startswith("xn--") or "xn--" in hostname
        is_shortener = hostname in URL_SHORTENERS
        
        # Check suspicious TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        has_suspicious_tld = tld in SUSPICIOUS_TLDS

        # Brand subdomain injection check: e.g. paypal.com.account-update.xyz
        is_brand_subdomain = False
        impersonated_brand = ""
        host_parts = hostname.split(".")
        if len(host_parts) >= 3:
            registered_domain = ".".join(host_parts[-2:])
            subdomains = ".".join(host_parts[:-2])
            for brand in TARGETED_BRANDS:
                clean_brand = brand.replace(" ", "")
                if clean_brand in subdomains and clean_brand not in registered_domain:
                    is_brand_subdomain = True
                    impersonated_brand = brand
                    break

        url_indicators: list[IndicatorMatch] = []
        risk_score = 0

        if is_ip:
            risk_score += 35
            url_indicators.append(
                IndicatorMatch(
                    rule_id="URL-IP-001",
                    category="url_anomaly",
                    severity="high",
                    weight=35,
                    description="Direct IP address used as hostname instead of a domain.",
                    matched_evidence=hostname,
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        if is_brand_subdomain:
            risk_score += 40
            url_indicators.append(
                IndicatorMatch(
                    rule_id="URL-SPOOF-002",
                    category="url_anomaly",
                    severity="critical",
                    weight=40,
                    description=f"Brand impersonation in subdomain: masquerading as '{impersonated_brand}'.",
                    matched_evidence=hostname,
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        if is_punycode:
            risk_score += 30
            url_indicators.append(
                IndicatorMatch(
                    rule_id="URL-PUNY-003",
                    category="url_anomaly",
                    severity="high",
                    weight=30,
                    description="Punycode / Homoglyph lookalike domain detected.",
                    matched_evidence=hostname,
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        if is_shortener:
            risk_score += 20
            url_indicators.append(
                IndicatorMatch(
                    rule_id="URL-SHORT-004",
                    category="url_anomaly",
                    severity="medium",
                    weight=20,
                    description=f"Known URL shortener ({hostname}) used to conceal final destination.",
                    matched_evidence=raw_url,
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        if has_suspicious_tld:
            risk_score += 20
            url_indicators.append(
                IndicatorMatch(
                    rule_id="URL-TLD-005",
                    category="url_anomaly",
                    severity="medium",
                    weight=20,
                    description=f"High-abuse top-level domain (.{tld}) detected.",
                    matched_evidence=hostname,
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        return {
            "url": raw_url,
            "hostname": hostname,
            "is_ip_hostname": is_ip,
            "is_brand_subdomain": is_brand_subdomain,
            "is_punycode": is_punycode,
            "is_shortener": is_shortener,
            "has_suspicious_tld": has_suspicious_tld,
            "risk_score": risk_score,
            "indicators": url_indicators,
        }

    def _analyze_attachment(self, att: str | dict[str, Any]) -> dict[str, Any]:
        """Assess attachment file extension and name for execution risk."""
        filename = att if isinstance(att, str) else str(att.get("filename", "unknown"))
        lower_name = filename.lower()
        ext = Path(lower_name).suffix

        # Double extension detection (e.g. invoice.pdf.exe)
        parts = lower_name.split(".")
        is_double_ext = len(parts) >= 3 and parts[-1] in ("exe", "vbs", "js", "bat", "cmd", "scr")

        indicator: IndicatorMatch | None = None
        if is_double_ext:
            indicator = IndicatorMatch(
                rule_id="ATT-EVASION-001",
                category="attachment_risk",
                severity="critical",
                weight=50,
                description=f"Double extension evasion detected on attachment: '{filename}'.",
                matched_evidence=filename,
                mitre_attack=MITRE_INITIAL_ACCESS_ATTACHMENT,
            )
            return {"filename": filename, "risk": "critical", "reason": "Double extension evasion", "indicator": indicator}

        if ext in HIGH_RISK_ATTACHMENT_EXTENSIONS:
            indicator = IndicatorMatch(
                rule_id="ATT-EXECUTABLE-002",
                category="attachment_risk",
                severity="critical" if ext in (".exe", ".scr", ".iso", ".vbs") else "high",
                weight=45,
                description=f"Dangerous executable/script or container format attachment: '{ext}'.",
                matched_evidence=filename,
                mitre_attack=MITRE_INITIAL_ACCESS_ATTACHMENT,
            )
            return {"filename": filename, "risk": "critical", "reason": f"High risk extension {ext}", "indicator": indicator}

        return {"filename": filename, "risk": "benign", "reason": "Standard benign extension", "indicator": None}

    def _analyze_headers(self, payload: MessagePayload) -> list[IndicatorMatch]:
        """Inspect SPF, DKIM, DMARC, and sender/reply-to headers."""
        inds: list[IndicatorMatch] = []
        headers = payload.headers

        # SPF failure
        spf_hdr = headers.get("received-spf", "") + headers.get("authentication-results", "")
        if "spf=fail" in spf_hdr.lower() or "spf=softfail" in spf_hdr.lower():
            inds.append(
                IndicatorMatch(
                    rule_id="HDR-SPF-001",
                    category="header_auth",
                    severity="high",
                    weight=30,
                    description="Sender Policy Framework (SPF) authentication failed.",
                    matched_evidence="spf=fail",
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        # DMARC failure
        if "dmarc=fail" in spf_hdr.lower():
            inds.append(
                IndicatorMatch(
                    rule_id="HDR-DMARC-002",
                    category="header_auth",
                    severity="high",
                    weight=35,
                    description="DMARC alignment validation failed for sender domain.",
                    matched_evidence="dmarc=fail",
                    mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                )
            )

        # Free email provider impersonation: e.g. "CEO / IT Support" with @gmail.com
        sender = payload.sender.lower()
        if any(f"@{prov}" in sender for prov in FREE_EMAIL_PROVIDERS):
            if re.search(r"\b(support|security|billing|accounting|service|admin|ceo|director)\b", sender):
                inds.append(
                    IndicatorMatch(
                        rule_id="HDR-SPOOF-003",
                        category="header_auth",
                        severity="medium",
                        weight=25,
                        description="Administrative/Corporate role sender using free webmail service.",
                        matched_evidence=payload.sender,
                        mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                    )
                )

        # Reply-To mismatch
        reply_to = headers.get("reply-to", "").lower()
        if reply_to and sender:
            # Extract domain from email addresses
            sender_domain = sender.split("@")[-1].strip(">").strip() if "@" in sender else ""
            reply_domain = reply_to.split("@")[-1].strip(">").strip() if "@" in reply_to else ""
            if sender_domain and reply_domain and sender_domain != reply_domain:
                inds.append(
                    IndicatorMatch(
                        rule_id="HDR-REPLYTO-004",
                        category="header_auth",
                        severity="medium",
                        weight=20,
                        description=f"Reply-To domain ({reply_domain}) differs from From domain ({sender_domain}).",
                        matched_evidence=f"From: {sender_domain} | Reply-To: {reply_domain}",
                        mitre_attack=MITRE_INITIAL_ACCESS_LINK,
                    )
                )

        return inds

    def _generate_recommendations(self, risk_level: str, indicators: list[IndicatorMatch]) -> list[str]:
        """Produce prescriptive DFIR and SOC triage action items."""
        if risk_level == "benign":
            return ["No security action needed; message presents normal communication markers."]

        recs: list[str] = []
        if risk_level in ("high", "critical"):
            recs.append("Isolate recipient endpoint from the enterprise network if links or attachments were opened.")
            recs.append("Quarantine or purge the message from all corporate mailboxes via M365/Google admin API.")
            recs.append("Perform immediate credential reset and revoke active OAuth session tokens for recipient.")

        has_urls = any(ind.category == "url_anomaly" for ind in indicators)
        if has_urls:
            recs.append("Add identified malicious domains/IPs to perimeter DNS sinkhole and proxy blocklists.")

        has_atts = any(ind.category == "attachment_risk" for ind in indicators)
        if has_atts:
            recs.append("Compute SHA-256 hash of attachment and search endpoint EDR telemetry for process executions.")

        recs.append("Verify endpoint process lineage in RansomEye for anomalous child processes (e.g., outlook.exe -> powershell.exe).")
        return recs


def ingest_phishing_finding(
    store: EvidenceStore,
    case_id: str,
    result: PhishingAnalysisResult,
    source_artifact: str = "suspicious_message",
) -> int:
    """Ingest a phishing analysis verdict as an Initial Access finding into a RansomEye case."""
    finding_type = "phishing_initial_access"
    # Prioritize Initial Access (T1566) technique
    primary_technique = MITRE_INITIAL_ACCESS_LINK
    for t in result.mitre_techniques:
        if t.startswith("T1566"):
            primary_technique = t
            break
    else:
        if result.mitre_techniques:
            primary_technique = result.mitre_techniques[0]

    # Compose detailed reason
    top_indicators = [f"{ind.rule_id}: {ind.description}" for ind in result.indicators[:3]]
    reason = (
        f"Phishing/Scam Analysis: Verdict={result.risk_level.upper()} (Score: {result.score}/100). "
        f"Top indicators: {'; '.join(top_indicators) if top_indicators else 'None'}."
    )

    finding_dict = {
        "type": finding_type,
        "score": result.score,
        "confidence": result.confidence,
        "technique": primary_technique,
        "reason": reason,
    }

    finding_id = store.save_finding(
        case_id=case_id,
        finding=finding_dict,
        event_ids=[],
    )

    import hashlib
    artifact_sha256 = hashlib.sha256(source_artifact.encode("utf-8")).hexdigest()
    store.record_custody_event(
        case_id=case_id,
        artifact_path=source_artifact,
        sha256=artifact_sha256,
        action="reviewed",
        analyst="ransomeye-phishing-analyzer",
        note=f"Ingested phishing verdict (Score={result.score}, Level={result.risk_level})",
    )

    return finding_id
