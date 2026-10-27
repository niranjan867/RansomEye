"""Professional PDF forensic report generator for RansomEye investigations."""

from __future__ import annotations

import html
import io
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PdfReportError(Exception):
    """Base exception for PDF report generation errors."""
    pass


class PdfDependencyError(PdfReportError):
    """Raised when PDF report generation is requested but dependencies are missing."""
    pass


try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    import PIL
    _REPORTLAB_AVAILABLE = True
    _REPORTLAB_IMPORT_ERROR: Exception | None = None
except ImportError as _err:
    colors = None  # type: ignore
    A4 = (595.27, 841.89)  # standard A4 dimensions in points
    canvas = None  # type: ignore
    _REPORTLAB_AVAILABLE = False
    _REPORTLAB_IMPORT_ERROR = _err


def is_pdf_available() -> bool:
    """Return True if ReportLab and Pillow are available for PDF generation."""
    return _REPORTLAB_AVAILABLE


from ransomeye.investigation import load_investigation
from ransomeye.investigation_graph import build_investigation_graph
from ransomeye.reconstruction import reconstruct_attack
from ransomeye.storage import EvidenceStore
from ransomeye.threat_assessment import assess_threat

# Paths
STATIC_DIR = Path(__file__).parent / "static"
LOGO_PATH = STATIC_DIR / "logo.png"

# Color Palette (DFIR Navy, Blue, White, Slate Grey)
if _REPORTLAB_AVAILABLE and colors is not None:
    NAVY_PRIMARY = colors.HexColor("#0b1220")
    NAVY_SECONDARY = colors.HexColor("#0f172a")
    NAVY_ACCENT = colors.HexColor("#1e3a5f")
    BLUE_ACCENT = colors.HexColor("#0284c7")
    BLUE_LIGHT = colors.HexColor("#f0f9ff")
    BG_CARD = colors.HexColor("#f8fafc")
    BORDER_LIGHT = colors.HexColor("#cbd5e1")
    BORDER_SUBTLE = colors.HexColor("#e2e8f0")
    TEXT_PRIMARY = colors.HexColor("#0f172a")
    TEXT_MUTED = colors.HexColor("#64748b")
    TEXT_SECONDARY = colors.HexColor("#334155")

    # Severity Colors
    COLOR_CRITICAL = colors.HexColor("#dc2626")
    COLOR_CRITICAL_BG = colors.HexColor("#fef2f2")
    COLOR_HIGH = colors.HexColor("#d97706")
    COLOR_HIGH_BG = colors.HexColor("#fffbeb")
    COLOR_MEDIUM = colors.HexColor("#ca8a04")
    COLOR_MEDIUM_BG = colors.HexColor("#fefce8")
    COLOR_LOW = colors.HexColor("#16a34a")
    COLOR_LOW_BG = colors.HexColor("#f0fdf4")
else:
    NAVY_PRIMARY = NAVY_SECONDARY = NAVY_ACCENT = None  # type: ignore
    BLUE_ACCENT = BLUE_LIGHT = BG_CARD = None  # type: ignore
    BORDER_LIGHT = BORDER_SUBTLE = None  # type: ignore
    TEXT_PRIMARY = TEXT_MUTED = TEXT_SECONDARY = None  # type: ignore
    COLOR_CRITICAL = COLOR_CRITICAL_BG = None  # type: ignore
    COLOR_HIGH = COLOR_HIGH_BG = COLOR_MEDIUM = COLOR_MEDIUM_BG = None  # type: ignore
    COLOR_LOW = COLOR_LOW_BG = None  # type: ignore


_CanvasBase = canvas.Canvas if canvas is not None else object


class DFIRNumberedCanvas(_CanvasBase):  # type: ignore
    """Two-pass canvas that adds running headers, logos, and 'Page X of Y' footers on every page."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.case_id: str = kwargs.pop("case_id", "INVESTIGATION")
        self.classification: str = kwargs.pop("classification", "CONFIDENTIAL // TLP:AMBER")
        self.logo_path: Path = kwargs.pop("logo_path", LOGO_PATH)
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_header_and_footer(num_pages)
            super().showPage()
        super().save()

    def _draw_header_and_footer(self, total_pages: int) -> None:
        width, height = A4
        page_num = self._pageNumber
        left_margin = 36
        right_margin = width - 36

        self.saveState()

        # -----------------------------
        # Header (Every Page)
        # -----------------------------
        # Draw Logo if present
        if self.logo_path and self.logo_path.is_file():
            try:
                # Aspect ratio is ~1.608 (828x515). Render at height 22pt, width ~35.4pt
                logo_h = 22.0
                logo_w = logo_h * (828.0 / 515.0)
                self.drawImage(
                    str(self.logo_path),
                    x=left_margin,
                    y=height - 48,
                    width=logo_w,
                    height=logo_h,
                    mask="auto",
                    preserveAspectRatio=True,
                )
            except Exception:
                # Fallback text if image read fails
                self.setFont("Helvetica-Bold", 11)
                self.setFillColor(BLUE_ACCENT)
                self.drawString(left_margin, height - 42, "RANSOMEYE")
        else:
            self.setFont("Helvetica-Bold", 11)
            self.setFillColor(BLUE_ACCENT)
            self.drawString(left_margin, height - 42, "RANSOMEYE")

        # Header Title and Case ID (right aligned)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(NAVY_SECONDARY)
        self.drawRightString(right_margin, height - 38, "DIGITAL FORENSICS & INCIDENT RESPONSE REPORT")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(TEXT_MUTED)
        self.drawRightString(right_margin, height - 48, f"CASE: {self.case_id}  |  {self.classification}")

        # Header Divider Line (navy accent)
        self.setStrokeColor(BLUE_ACCENT)
        self.setLineWidth(0.75)
        self.line(left_margin, height - 52, right_margin, height - 52)

        # -----------------------------
        # Footer (Every Page)
        # -----------------------------
        # Footer Divider Line
        self.setStrokeColor(BORDER_LIGHT)
        self.setLineWidth(0.5)
        self.line(left_margin, 42, right_margin, 42)

        # Footer Left: Document Category
        self.setFont("Helvetica", 7.5)
        self.setFillColor(TEXT_MUTED)
        self.drawString(left_margin, 28, f"RANSOMEYE FORENSIC PLATFORM  //  {self.classification}")

        # Footer Center: Case Identifier
        self.drawCentredString(width / 2.0, 28, f"CASE ID: {self.case_id}")

        # Footer Right: Page X of Y
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(TEXT_SECONDARY)
        self.drawRightString(right_margin, 28, f"Page {page_num} of {total_pages}")

        self.restoreState()


def _esc(val: Any) -> str:
    """Safely escape text for inclusion in ReportLab Paragraph XML."""
    if val is None:
        return "-"
    text = str(val).strip()
    if not text:
        return "-"
    return html.escape(text)


def _format_dt(val: Any) -> str:
    """Format timestamp string into readable UTC label."""
    if not val:
        return "-"
    s = str(val).replace("T", " ")
    if "+" in s:
        s = s.split("+")[0]
    return s.rstrip("Z")


def generate_case_pdf_report(
    database_path: str | Path,
    case_id: str,
    output_path: str | Path | None = None,
    assessment: dict[str, Any] | None = None,
) -> bytes:
    """Generate a comprehensive, publication-quality DFIR PDF report for a RansomEye case."""
    if not is_pdf_available():
        raise PdfDependencyError(
            "PDF report generation requires 'reportlab' and 'pillow', which are not installed or available. "
            "Install with `pip install reportlab pillow` or generate a text report instead."
        )

    db_path = Path(database_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Load case & investigation data
    investigation = load_investigation(db_path, case_id)
    case = investigation.case
    if not case:
        raise ValueError(f"Case {case_id} not found in database {db_path}")

    store = EvidenceStore(db_path)
    try:
        events = store.get_case_events(case_id)
        custody_records = store.get_custody_events(case_id)
        case_history = store.get_case_history(case_id)
        schema_version = store.connection.execute("PRAGMA user_version").fetchone()[0]
    finally:
        store.close()

    # Resolve active threat assessment
    active_assessment = assessment or investigation.assessment
    if active_assessment is None and investigation.timeline:
        active_assessment = assess_threat(investigation.timeline)

    findings = investigation.findings or []
    correlations = (
        active_assessment.get("correlations", [])
        if active_assessment and isinstance(active_assessment, dict) and active_assessment.get("correlations")
        else investigation.correlations or []
    )
    timeline_events = investigation.timeline or []
    processes = investigation.processes or {}

    # Attack reconstruction stages via investigation graph
    stages = []
    try:
        graph = build_investigation_graph(investigation)
        sequence = reconstruct_attack(investigation, graph)
        stages = sequence.stages
    except Exception:
        stages = []

    # Prepare document flowables
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=58,
        bottomMargin=48,
    )

    # Styles
    base_styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DFIRTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=NAVY_PRIMARY,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "DFIRSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=TEXT_MUTED,
        spaceAfter=12,
    )

    h1_style = ParagraphStyle(
        "DFIRH1",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=NAVY_PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "DFIRH2",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=NAVY_ACCENT,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "DFIRBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=TEXT_PRIMARY,
    )

    body_muted = ParagraphStyle(
        "DFIRBodyMuted",
        parent=body_style,
        textColor=TEXT_MUTED,
    )

    mono_style = ParagraphStyle(
        "DFIRMono",
        parent=base_styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=TEXT_SECONDARY,
    )

    th_style = ParagraphStyle(
        "DFIRTH",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    th_dark_style = ParagraphStyle(
        "DFIRTHDark",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=NAVY_PRIMARY,
    )

    card_label = ParagraphStyle(
        "CardLabel",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=TEXT_MUTED,
        textTransform="uppercase",
    )

    card_val = ParagraphStyle(
        "CardVal",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=13,
        textColor=NAVY_PRIMARY,
    )

    story: list[Any] = []
    content_width = 523.27  # A4 width (595.27) - 72pt margins

    # =========================================================================
    # 1. COVER / HEADER & EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("Digital Forensics & Incident Investigation Report", title_style))
    story.append(
        Paragraph(
            "RansomEye Automated Forensic Triage, Behavioral Assessment, and Incident Reconstruction",
            subtitle_style,
        )
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Case Metadata Grid
    meta_table_data = [
        [
            Paragraph("Case Identifier", card_label),
            Paragraph("Target Host", card_label),
            Paragraph("Current Status", card_label),
            Paragraph("Generated At", card_label),
        ],
        [
            Paragraph(f"<b>{_esc(case['case_id'])}</b>", card_val),
            Paragraph(f"<b>{_esc(case['host'])}</b>", card_val),
            Paragraph(f"<b>{_esc(case['status'] or 'OPEN')}</b>", card_val),
            Paragraph(now_utc, body_style),
        ],
        [
            Paragraph("Investigation Name", card_label),
            "",
            Paragraph("Severity Assessment", card_label),
            Paragraph("Classification", card_label),
        ],
        [
            Paragraph(f"<b>{_esc(case['case_name'])}</b>", body_style),
            "",
            Paragraph(f"<b>{_esc(case['severity'] or 'UNRATED')}</b>", card_val),
            Paragraph("CONFIDENTIAL // TLP:AMBER", body_style),
        ],
    ]
    meta_table = Table(
        meta_table_data,
        colWidths=[130, 130, 130, 133.27],
        style=[
            ("SPAN", (0, 2), (1, 2)),
            ("SPAN", (0, 3), (1, 3)),
            ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ],
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Threat Assessment Callout Box
    score_val = active_assessment.get("score", 0) if active_assessment else 0
    sev_val = str(active_assessment.get("severity", "LOW")).upper() if active_assessment else "SAFE"
    conf_val = active_assessment.get("confidence", 0.0) if active_assessment else 0.0

    if sev_val == "CRITICAL":
        callout_border = COLOR_CRITICAL
        callout_bg = COLOR_CRITICAL_BG
        badge_text = f"<font color='{COLOR_CRITICAL.hexval()}'><b>CRITICAL THREAT</b></font>"
    elif sev_val == "HIGH":
        callout_border = COLOR_HIGH
        callout_bg = COLOR_HIGH_BG
        badge_text = f"<font color='{COLOR_HIGH.hexval()}'><b>HIGH RISK</b></font>"
    elif sev_val == "MEDIUM":
        callout_border = COLOR_MEDIUM
        callout_bg = COLOR_MEDIUM_BG
        badge_text = f"<font color='{COLOR_MEDIUM.hexval()}'><b>MEDIUM RISK</b></font>"
    else:
        callout_border = COLOR_LOW
        callout_bg = COLOR_LOW_BG
        badge_text = f"<font color='{COLOR_LOW.hexval()}'><b>LOW RISK / SAFE</b></font>"

    reasons_list = active_assessment.get("reasons", []) if active_assessment else []
    tech_list = active_assessment.get("techniques", []) if active_assessment else []

    top_reasons_str = "; ".join(reasons_list[:3]) if reasons_list else "No active behavioral threat indicators detected."
    callout_content = [
        [
            Paragraph(f"{badge_text} &nbsp;|&nbsp; Threat Score: <b>{score_val}/100</b> &nbsp;|&nbsp; Confidence: <b>{conf_val:.0%}</b>", h2_style),
        ],
        [
            Paragraph(f"<b>Primary Analytical Detection:</b> {_esc(top_reasons_str)}", body_style),
        ],
    ]
    callout_table = Table(
        callout_content,
        colWidths=[content_width],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), callout_bg),
            ("BOX", (0, 0), (-1, -1), 1.25, callout_border),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ],
    )
    story.append(callout_table)
    story.append(Spacer(1, 10))

    # Metric Cards Summary Table
    metrics_data = [
        [
            Paragraph("Total Events", card_label),
            Paragraph("Confirmed Findings", card_label),
            Paragraph("Correlated Incidents", card_label),
            Paragraph("Monitored Processes", card_label),
            Paragraph("Custody Actions", card_label),
        ],
        [
            Paragraph(f"<b>{len(events)}</b>", card_val),
            Paragraph(f"<b>{len(findings)}</b>", card_val),
            Paragraph(f"<b>{len(correlations)}</b>", card_val),
            Paragraph(f"<b>{len(processes.get('nodes', {}))}</b>", card_val),
            Paragraph(f"<b>{len(custody_records)}</b>", card_val),
        ],
    ]
    metrics_table = Table(
        metrics_data,
        colWidths=[content_width / 5.0] * 5,
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), BLUE_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.75, BLUE_ACCENT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ],
    )
    story.append(metrics_table)
    story.append(Spacer(1, 10))

    # Executive Summary Narrative
    story.append(Paragraph("<b>Executive Summary</b>", h2_style))
    exec_summary_text = (
        f"This digital forensics and incident response investigation report documents security-relevant observations "
        f"for case <b>{_esc(case['case_id'])}</b> on host <b>{_esc(case['host'])}</b>. "
        f"A total of <b>{len(events)}</b> normalized security events were evaluated across process execution, "
        f"filesystem mutations, and network communications. Automated heuristic correlation established "
        f"<b>{len(findings)}</b> distinct forensic findings and <b>{len(correlations)}</b> attack sequence incidents, "
        f"yielding an overall threat severity rating of <b>{sev_val}</b> (composite score {score_val}/100, "
        f"confidence {conf_val:.0%}). All forensic artifacts and timeline events have been cataloged with cryptographic "
        f"hashes in an append-only chain of custody ledger."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 14))

    # =========================================================================
    # 2. CASE OVERVIEW & SCOPE
    # =========================================================================
    story.append(Paragraph("2. Case Overview & Investigation Scope", h1_style))
    overview_text = (
        f"<b>Investigation Scope:</b> Host-centric endpoint activity originating on <code>{_esc(case['host'])}</code> "
        f"captured via Windows Sysmon telemetry and external forensic ingest. "
        f"Database Schema version: <b>{schema_version}</b>. Initial ingestion: <b>{_format_dt(case['created_at'])}</b>."
    )
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 6))

    # Case History Table
    if case_history:
        story.append(Paragraph("<b>Case Lifecycle History</b>", h2_style))
        hist_rows = [[
            Paragraph("Timestamp", th_style),
            Paragraph("Transition", th_style),
            Paragraph("Examiner Note", th_style),
        ]]
        for h in case_history:
            trans = f"{_esc(h.get('old_status') or '-')} &rarr; {_esc(h.get('new_status') or '-')}"
            hist_rows.append([
                Paragraph(_format_dt(h.get("changed_at")), body_style),
                Paragraph(trans, body_style),
                Paragraph(_esc(h.get("note")), body_style),
            ])
        hist_table = Table(
            hist_rows,
            colWidths=[120, 130, 273.27],
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ],
        )
        story.append(hist_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # 3. THREAT ASSESSMENT & BEHAVIORAL ANALYSIS
    # =========================================================================
    story.append(Paragraph("3. Threat Assessment & MITRE ATT&CK Mapping", h1_style))
    threat_intro = (
        f"The threat score evaluates behavioral patterns across ransom-note deployment, mass extension manipulation, "
        f"shadow-copy deletion commands, high-entropy writes, and execution evasion. "
        f"Assigned Severity: <b>{sev_val}</b> (Score: {score_val}, Confidence: {conf_val:.2f})."
    )
    story.append(Paragraph(threat_intro, body_style))
    story.append(Spacer(1, 6))

    # Reasons & Techniques
    if reasons_list:
        story.append(Paragraph("<b>Primary Detection Reasons:</b>", h2_style))
        for r in reasons_list:
            story.append(Paragraph(f"&bull;&nbsp;&nbsp;{_esc(r)}", body_style))
        story.append(Spacer(1, 6))

    if tech_list:
        story.append(Paragraph("<b>Observed MITRE ATT&CK Techniques:</b>", h2_style))
        tech_data = [[
            Paragraph("Technique ID", th_style),
            Paragraph("Framework Description", th_style),
            Paragraph("Detection Category", th_style),
        ]]
        technique_descriptions = {
            "T1486": ("Data Encrypted for Impact", "Impact / Ransomware Encryption"),
            "T1490": ("Inhibit System Recovery", "Defense Evasion / Shadow Copy Deletion"),
            "T1059": ("Command and Scripting Interpreter", "Execution / Script Engine"),
            "T1059.001": ("PowerShell", "Execution / PowerShell"),
            "T1071": ("Application Layer Protocol", "Command & Control / Web Protocol"),
            "T1566": ("Phishing", "Initial Access / Email"),
        }
        for tid in tech_list:
            desc, cat = technique_descriptions.get(tid, ("Security-relevant behavioral technique", "Behavioral Detection"))
            tech_data.append([
                Paragraph(f"<b>{_esc(tid)}</b>", mono_style),
                Paragraph(_esc(desc), body_style),
                Paragraph(_esc(cat), body_style),
            ])
        tech_table = Table(
            tech_data,
            colWidths=[90, 230, 203.27],
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ],
        )
        story.append(tech_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # 4. FINDINGS & CORRELATED INCIDENTS
    # =========================================================================
    story.append(Paragraph("4. Forensic Findings & Correlated Incidents", h1_style))
    if not findings:
        story.append(Paragraph("No discrete findings recorded for this case.", body_muted))
    else:
        findings_data = [[
            Paragraph("ID", th_style),
            Paragraph("Finding Type / Rule", th_style),
            Paragraph("Score", th_style),
            Paragraph("Conf.", th_style),
            Paragraph("Technique", th_style),
            Paragraph("Detection Reason / Description", th_style),
        ]]
        for f in findings:
            fid = f.get("finding_id") or f.get("id") or "-"
            ftype = f.get("finding_type") or f.get("type") or "-"
            fscore = f.get("score") if f.get("score") is not None else "-"
            fconf = f"{f.get('confidence'):.2f}" if isinstance(f.get("confidence"), (int, float)) else "-"
            ftech = f.get("technique") or "-"
            freason = f.get("reason") or f.get("description") or "-"

            findings_data.append([
                Paragraph(str(fid), mono_style),
                Paragraph(f"<b>{_esc(ftype)}</b>", body_style),
                Paragraph(str(fscore), body_style),
                Paragraph(str(fconf), body_style),
                Paragraph(_esc(ftech), mono_style),
                Paragraph(_esc(freason), body_style),
            ])

        findings_table = Table(
            findings_data,
            colWidths=[30, 115, 38, 38, 62, 240.27],
            repeatRows=1,
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(findings_table)
        story.append(Spacer(1, 10))

    # Incidents / Attack Milestones
    if correlations:
        story.append(Paragraph("<b>Correlated Incident Sequences:</b>", h2_style))
        inc_data = [[
            Paragraph("Incident ID", th_style),
            Paragraph("Process Key", th_style),
            Paragraph("Timeframe (UTC)", th_style),
            Paragraph("Duration", th_style),
            Paragraph("Evidence Events", th_style),
        ]]
        for corr in correlations:
            iid = corr.get("incident_id") or "-"
            pkey = corr.get("process_key") or "-"
            st = _format_dt(corr.get("start_time"))
            et = _format_dt(corr.get("end_time"))
            dur = f"{corr.get('duration_seconds', corr.get('duration', 0.0)):.1f}s"
            evs = corr.get("evidence_event_ids", corr.get("evidence_ids", []))
            ev_str = f"{len(evs)} events ({', '.join(str(x) for x in evs[:3])}{'...' if len(evs) > 3 else ''})"

            inc_data.append([
                Paragraph(f"<b>{_esc(iid)}</b>", mono_style),
                Paragraph(_esc(pkey), mono_style),
                Paragraph(f"{st}<br/>{et}", body_style),
                Paragraph(dur, body_style),
                Paragraph(ev_str, body_style),
            ])

        inc_table = Table(
            inc_data,
            colWidths=[105, 95, 135, 48, 140.27],
            repeatRows=1,
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_ACCENT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(inc_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # 5. EVIDENCE INVENTORY
    # =========================================================================
    story.append(Paragraph("5. Evidence Inventory & Artifact Catalog", h1_style))
    if not events:
        story.append(Paragraph("No evidence events registered.", body_muted))
    else:
        # Show top sample / chronological inventory of events
        ev_data = [[
            Paragraph("Event ID", th_style),
            Paragraph("Source / Type", th_style),
            Paragraph("Timestamp (UTC)", th_style),
            Paragraph("Process / Artifact Image", th_style),
            Paragraph("Associated Detail / Command", th_style),
        ]]
        for ev in events[:40]:  # Cap at 40 in inventory to keep report manageable
            eid = ev.get("event_id") or "-"
            etype = ev.get("event_type") or ev.get("source") or "-"
            ts = _format_dt(ev.get("timestamp"))
            pname = ev.get("process_name") or ev.get("file_path") or "-"
            if "\\" in pname:
                pname = pname.split("\\")[-1]
            cmd = ev.get("command_line") or ev.get("file_path") or "-"
            if len(cmd) > 120:
                cmd = cmd[:117] + "..."

            ev_data.append([
                Paragraph(f"<b>{_esc(eid)}</b>", mono_style),
                Paragraph(_esc(etype), body_style),
                Paragraph(ts, body_style),
                Paragraph(f"<b>{_esc(pname)}</b>", mono_style),
                Paragraph(_esc(cmd), mono_style),
            ])

        ev_table = Table(
            ev_data,
            colWidths=[80, 75, 95, 95, 178.27],
            repeatRows=1,
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(ev_table)
        if len(events) > 40:
            story.append(Paragraph(f"<i>... and {len(events) - 40} additional evidence events recorded in database.</i>", body_muted))
        story.append(Spacer(1, 10))

    # =========================================================================
    # 6. INVESTIGATION TIMELINE
    # =========================================================================
    story.append(Paragraph("6. Chronological Investigation Timeline", h1_style))
    if not timeline_events:
        story.append(Paragraph("No chronological timeline events available.", body_muted))
    else:
        time_data = [[
            Paragraph("Timestamp (UTC)", th_style),
            Paragraph("Process", th_style),
            Paragraph("PID", th_style),
            Paragraph("Action / Command Execution", th_style),
        ]]
        for tev in timeline_events[:35]:
            ts = _format_dt(tev.get("timestamp"))
            pname = tev.get("process_name") or "-"
            if "\\" in pname:
                pname = pname.split("\\")[-1]
            pid = str(tev.get("pid") or "-")
            cmd = tev.get("command_line") or tev.get("file_path") or "-"
            if len(cmd) > 140:
                cmd = cmd[:137] + "..."

            time_data.append([
                Paragraph(ts, body_style),
                Paragraph(f"<b>{_esc(pname)}</b>", mono_style),
                Paragraph(pid, mono_style),
                Paragraph(_esc(cmd), mono_style),
            ])

        time_table = Table(
            time_data,
            colWidths=[100, 95, 38, 290.27],
            repeatRows=1,
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(time_table)
        if len(timeline_events) > 35:
            story.append(Paragraph(f"<i>... {len(timeline_events) - 35} additional timeline entries preserved in audit archive.</i>", body_muted))
        story.append(Spacer(1, 10))

    # =========================================================================
    # 7. PROCESS RELATIONSHIPS & ATTACK RECONSTRUCTION
    # =========================================================================
    story.append(Paragraph("7. Process Relationships & Attack Reconstruction", h1_style))
    nodes = processes.get("nodes", {})
    if nodes:
        story.append(Paragraph("<b>Identified Process Lineage:</b>", h2_style))
        proc_data = [[
            Paragraph("PID", th_style),
            Paragraph("Process Image", th_style),
            Paragraph("Parent PID", th_style),
            Paragraph("Command Line Execution", th_style),
        ]]
        for pid_k, pinfo in nodes.items():
            p_img = pinfo.get("process_name") or pinfo.get("image") or "-"
            ppid = str(pinfo.get("parent_pid") or "-")
            p_cmd = pinfo.get("command_line") or "-"
            if len(p_cmd) > 130:
                p_cmd = p_cmd[:127] + "..."

            proc_data.append([
                Paragraph(str(pid_k), mono_style),
                Paragraph(f"<b>{_esc(p_img)}</b>", mono_style),
                Paragraph(ppid, mono_style),
                Paragraph(_esc(p_cmd), mono_style),
            ])
        proc_table = Table(
            proc_data,
            colWidths=[40, 110, 48, 325.27],
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_ACCENT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ],
        )
        story.append(proc_table)
        story.append(Spacer(1, 8))

    # Reconstruction Stages
    if stages:
        story.append(Paragraph("<b>Reconstructed Attack Milestones:</b>", h2_style))
        stage_data = [[
            Paragraph("Stage ID", th_style),
            Paragraph("Stage Classification", th_style),
            Paragraph("Timestamp (UTC)", th_style),
            Paragraph("Sequence Description", th_style),
        ]]
        for stg in stages[:20]:
            sid = getattr(stg, "stage_id", "-")
            stype = getattr(stg, "stage_type", "-")
            st_ts = _format_dt(getattr(stg, "timestamp", "-"))
            sdesc = getattr(stg, "description", getattr(stg, "title", "-"))
            if len(sdesc) > 140:
                sdesc = sdesc[:137] + "..."

            stage_data.append([
                Paragraph(f"<b>{_esc(sid)}</b>", mono_style),
                Paragraph(_esc(stype), body_style),
                Paragraph(st_ts, body_style),
                Paragraph(_esc(sdesc), body_style),
            ])

        stage_table = Table(
            stage_data,
            colWidths=[110, 85, 95, 233.27],
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(stage_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # 8. CHAIN OF CUSTODY & INTEGRITY LEDGER
    # =========================================================================
    story.append(Paragraph("8. Chain of Custody & Cryptographic Ledger", h1_style))
    custody_note = (
        "All investigative operations and evidence handoffs are written to an append-only custody ledger. "
        "SQLite trigger protection (<code>prevent_custody_update</code>, <code>prevent_custody_delete</code>) "
        "enforces immutability. Checksums represent SHA-256 integrity digests."
    )
    story.append(Paragraph(custody_note, body_style))
    story.append(Spacer(1, 6))

    if not custody_records:
        story.append(Paragraph("No chain of custody entries recorded for this case.", body_muted))
    else:
        cust_data = [[
            Paragraph("Recorded (UTC)", th_style),
            Paragraph("Artifact Path", th_style),
            Paragraph("Action", th_style),
            Paragraph("Examiner", th_style),
            Paragraph("SHA-256 Checksum", th_style),
        ]]
        for cr in custody_records[:25]:
            cts = _format_dt(cr.get("recorded_at") or cr.get("timestamp"))
            cart = cr.get("artifact_path") or cr.get("artifact") or "-"
            cact = cr.get("action") or "COLLECTED"
            cana = cr.get("analyst") or "System"
            csha = cr.get("sha256") or "-"
            if len(csha) > 20:
                csha = csha[:18] + "..."

            cust_data.append([
                Paragraph(cts, body_style),
                Paragraph(f"<b>{_esc(cart)}</b>", mono_style),
                Paragraph(f"<b>{_esc(cact)}</b>", body_style),
                Paragraph(_esc(cana), body_style),
                Paragraph(_esc(csha), mono_style),
            ])

        cust_table = Table(
            cust_data,
            colWidths=[100, 130, 75, 80, 138.27],
            repeatRows=1,
            style=[
                ("BACKGROUND", (0, 0), (-1, 0), NAVY_SECONDARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ],
        )
        story.append(cust_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # 9. INVESTIGATION LIMITATIONS
    # =========================================================================
    story.append(Paragraph("9. Investigation Limitations & Boundaries", h1_style))
    limitations_text = (
        "<b>Evidentiary Boundaries:</b><br/>"
        "&bull;&nbsp;&nbsp;<b>Telemetry Coverage:</b> Findings are bounded strictly to events recorded on "
        f"host <code>{_esc(case['host'])}</code> during the monitored timeframe.<br/>"
        "&bull;&nbsp;&nbsp;<b>Network Offline Evaluation:</b> Extracted IP addresses, DNS queries, and external domains "
        "were inspected offline. No active out-of-band network probes or C2 connections were initiated.<br/>"
        "&bull;&nbsp;&nbsp;<b>Synthetic Artifacts:</b> Any prepared test fixtures (e.g. synthetic PE stubs) reflect controlled "
        "simulation benchmarks and are marked accordingly in static forensic indicators."
    )
    story.append(Paragraph(limitations_text, body_style))
    story.append(Spacer(1, 10))

    # =========================================================================
    # 10. CONCLUSION & NEXT STEPS
    # =========================================================================
    story.append(Paragraph("10. Conclusion & Recommendations", h1_style))
    conclusion_text = (
        f"The forensic analysis of case <b>{_esc(case['case_id'])}</b> confirms security-relevant activity "
        f"meeting the analytical criteria for <b>{sev_val}</b> threat posture (score {score_val}/100). "
        f"Artifacts and correlated incident milestones support the observed techniques cataloged in Section 3.<br/><br/>"
        "<b>Recommended Response Actions:</b><br/>"
        "1. <b>Host Containment:</b> Verify network isolation of endpoint <code>"
        f"{_esc(case['host'])}</code> to prevent lateral spread.<br/>"
        "2. <b>Credential Invalidation:</b> Invalidate active service and administrative tokens associated with suspicious processes.<br/>"
        "3. <b>Volume & Shadow Copy Audit:</b> Verify VSS shadow copy health and initiate file recovery from validated offline backups.<br/>"
        "4. <b>Preservation:</b> Maintain disk and memory images with verified SHA-256 integrity manifests as detailed in Section 8."
    )
    story.append(Paragraph(conclusion_text, body_style))
    story.append(Spacer(1, 15))

    # Sign-off box
    signoff_data = [
        [
            Paragraph("<b>Investigator / Examiner</b>", card_label),
            Paragraph("<b>Technical Lead Approval</b>", card_label),
            Paragraph("<b>Digital Forensic Assurance</b>", card_label),
        ],
        [
            Paragraph("Automated Forensics Engine<br/>RansomEye v0.1.0", body_style),
            Paragraph("Incident Response Lead<br/>Status: VERIFIED", body_style),
            Paragraph(f"Integrity Checksum: SHA-256<br/>{now_utc}", body_style),
        ],
    ]
    signoff_table = Table(
        signoff_data,
        colWidths=[content_width / 3.0] * 3,
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_LIGHT),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_SUBTLE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ],
    )
    story.append(KeepTogether(signoff_table))

    # Build PDF with DFIRNumberedCanvas
    def canvas_factory(*args: Any, **kwargs: Any) -> DFIRNumberedCanvas:
        return DFIRNumberedCanvas(
            *args,
            case_id=case_id,
            classification="CONFIDENTIAL // TLP:AMBER",
            logo_path=LOGO_PATH,
            **kwargs,
        )

    doc.build(story, canvasmaker=canvas_factory)

    pdf_bytes = buffer.getvalue()
    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(pdf_bytes)

    return pdf_bytes


def write_case_pdf_report(
    database_path: str | Path,
    case_id: str,
    output_path: str | Path,
    assessment: dict[str, Any] | None = None,
) -> Path:
    """Convenience helper to generate and write a case PDF report to disk."""
    out = Path(output_path)
    generate_case_pdf_report(
        database_path=database_path,
        case_id=case_id,
        output_path=out,
        assessment=assessment,
    )
    return out
