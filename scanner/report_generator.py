"""
scanner/report_generator.py
Report generation for SentinelScan — JSON, CSV, and PDF.

All reports are generated from real scan data.
No hardcoded example results are included.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Optional

import config
from scanner.scanner_service import ScanResult
from scanner.security_checks import Finding

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── JSON export ───────────────────────────────────────────────────────────────

def generate_json(result: ScanResult) -> str:
    """Return a UTF-8 JSON string representing the complete scan result."""
    data = _scan_result_to_dict(result)
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


# ── CSV export ────────────────────────────────────────────────────────────────

def generate_csv(result: ScanResult) -> str:
    """Return a UTF-8 CSV string with one row per finding."""
    output = io.StringIO()
    fieldnames = [
        "finding_id", "title", "category", "severity", "status",
        "short_description", "evidence", "why_it_matters", "remediation",
        "confidence",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore",
                            lineterminator="\r\n")
    writer.writeheader()

    if not result.findings:
        writer.writerow({f: "" for f in fieldnames})
    else:
        for finding in result.findings:
            writer.writerow({
                "finding_id": finding.finding_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "status": finding.status,
                "short_description": finding.short_description,
                "evidence": finding.evidence,
                "why_it_matters": finding.why_it_matters,
                "remediation": finding.remediation,
                "confidence": finding.confidence,
            })

    return output.getvalue()


# ── PDF export ────────────────────────────────────────────────────────────────

def generate_pdf(result: ScanResult) -> Optional[bytes]:
    """
    Generate a professional PDF report using ReportLab.

    Returns the PDF as bytes on success, or None if ReportLab is unavailable.
    Raises ValueError if *result* contains no scan data (prevents empty PDFs).
    """
    if not REPORTLAB_AVAILABLE:
        return None

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"SentinelScan Report — {_safe_text(result.normalized_url)}",
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    cover_style = ParagraphStyle(
        "Cover",
        parent=styles["Title"],
        fontSize=26,
        leading=32,
        textColor=colors.HexColor("#0D1F3C"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1565C0"),
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#212121"),
    )
    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#757575"),
    )
    section_header_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading1"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0D1F3C"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=(0, 0, 4, 0),
    )
    subsection_style = ParagraphStyle(
        "SubSection",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1565C0"),
        spaceBefore=10,
        spaceAfter=4,
    )

    story.append(Spacer(1, 30 * mm))
    story.append(Paragraph("🛡 SentinelScan", cover_style))
    story.append(Paragraph("Automated Web Security Assessment Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1565C0"),
                            spaceAfter=12))

    demo_notice = ""
    if result.scan_mode == "demo":
        demo_notice = (
            "<font color='#FF6F00'><b>⚠ DEMO MODE — These results are illustrative only. "
            "No real website was scanned.</b></font><br/><br/>"
        )
        story.append(Paragraph(demo_notice, body_style))

    meta_data = [
        ["Target URL:", _safe_text(result.normalized_url or result.target_url)],
        ["Scan Mode:", result.scan_mode.upper()],
        ["Timestamp:", result.timestamp],
        ["Duration:", f"{result.duration_seconds}s"],
        ["HTTP Status:", str(result.http_status_code or "N/A")],
    ]
    meta_table = Table(meta_data, colWidths=[45 * mm, 130 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#F5F7FA"), colors.HexColor("#FFFFFF")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#BDBDBD")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10 * mm))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_header_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#BDBDBD"),
                            spaceAfter=6))

    if result.risk_report:
        rr = result.risk_report
        score_color = _score_color_hex(rr.score)
        story.append(Paragraph(
            f"<b>Overall Security Posture Score: "
            f"<font color='{score_color}'>{rr.score}/100 ({rr.grade})</font></b>",
            body_style,
        ))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(rr.summary, body_style))
        story.append(Spacer(1, 6 * mm))

        # Severity table
        sev_rows = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "informational"]:
            cnt = rr.findings_by_severity.get(sev, 0)
            sev_rows.append([sev.capitalize(), str(cnt)])
        sev_rows.append(["Passed checks", str(rr.passed_count)])
        sev_rows.append(["Inconclusive", str(rr.inconclusive_count)])

        sev_table = Table(sev_rows, colWidths=[80 * mm, 40 * mm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1F3C")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F5F7FA"), colors.HexColor("#FFFFFF")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#BDBDBD")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 6 * mm))

    # ── Detailed Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", section_header_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#BDBDBD"),
                            spaceAfter=6))

    active_findings = [f for f in result.findings if f.status == "finding"]
    if not active_findings:
        story.append(Paragraph(
            "No security configuration issues were detected in this scan.",
            body_style,
        ))
    else:
        for finding in active_findings:
            sev_color = _sev_color_hex(finding.severity)
            finding_block = [
                Paragraph(
                    f"[{finding.finding_id}] "
                    f"<font color='{sev_color}'><b>{_safe_text(finding.title)}</b></font>",
                    subsection_style,
                ),
                _kv_para("Category", finding.category, body_style),
                _kv_para("Severity", finding.severity.upper(), body_style),
                _kv_para("Confidence", finding.confidence.capitalize(), body_style),
                _kv_para("Description", _safe_text(finding.short_description), body_style),
                _kv_para("Evidence", _safe_text(finding.evidence), body_style),
                _kv_para("Why It Matters", _safe_text(finding.why_it_matters), body_style),
                _kv_para("Remediation", _safe_text(finding.remediation), body_style),
                Spacer(1, 4 * mm),
                HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E0E0E0"),
                           spaceAfter=4),
            ]
            story.append(KeepTogether(finding_block))

    # ── Passed Checks ─────────────────────────────────────────────────────────
    story.append(Paragraph("Passed Checks", section_header_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#BDBDBD"),
                            spaceAfter=6))
    passed = [f for f in result.findings if f.status == "passed"]
    if passed:
        pass_rows = [["Check ID", "Title", "Category"]]
        for f in passed:
            pass_rows.append([f.finding_id, _safe_text(f.title)[:60], f.category])
        pass_table = Table(pass_rows, colWidths=[25 * mm, 100 * mm, 50 * mm])
        pass_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B5E20")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F9FBE7"), colors.HexColor("#FFFFFF")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#BDBDBD")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(pass_table)
    else:
        story.append(Paragraph("No checks passed.", body_style))

    # ── Methodology ───────────────────────────────────────────────────────────
    story.append(Paragraph("Methodology", section_header_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#BDBDBD"),
                            spaceAfter=6))
    story.append(Paragraph(
        "SentinelScan performs non-destructive, configuration-level checks by "
        "inspecting HTTP response headers, cookie attributes, TLS certificate details, "
        "and CORS policy headers. No attack payloads are sent. The tool only inspects "
        "configuration metadata that is publicly visible in HTTP responses.",
        body_style,
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"<b>Scoring formula:</b> Score = 100 − Σ(severity_weight × finding_count). "
        f"Weights: Critical={config.SEVERITY_WEIGHTS['critical']}, "
        f"High={config.SEVERITY_WEIGHTS['high']}, "
        f"Medium={config.SEVERITY_WEIGHTS['medium']}, "
        f"Low={config.SEVERITY_WEIGHTS['low']}, "
        f"Informational={config.SEVERITY_WEIGHTS['informational']}. "
        f"Minimum score: 0.",
        body_style,
    ))

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Disclaimer", section_header_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#BDBDBD"),
                            spaceAfter=6))
    story.append(Paragraph(config.REPORT_DISCLAIMER, small_style))

    doc.build(story)
    return buffer.getvalue()


# ── Private helpers ───────────────────────────────────────────────────────────

def _scan_result_to_dict(result: ScanResult) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "sentinelscan_version": config.APP_VERSION,
        "target_url": result.target_url,
        "normalized_url": result.normalized_url,
        "timestamp": result.timestamp,
        "duration_seconds": result.duration_seconds,
        "scan_mode": result.scan_mode,
        "success": result.success,
        "error_message": result.error_message,
        "http_status_code": result.http_status_code,
        "resolved_ips": result.resolved_ips,
        "risk_report": (
            {
                "score": result.risk_report.score,
                "grade": result.risk_report.grade,
                "total_findings": result.risk_report.total_findings,
                "findings_by_severity": result.risk_report.findings_by_severity,
                "passed_count": result.risk_report.passed_count,
                "inconclusive_count": result.risk_report.inconclusive_count,
                "total_deduction": result.risk_report.total_deduction,
                "summary": result.risk_report.summary,
            }
            if result.risk_report
            else None
        ),
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "short_description": f.short_description,
                "evidence": f.evidence,
                "why_it_matters": f.why_it_matters,
                "remediation": f.remediation,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
        "disclaimer": config.REPORT_DISCLAIMER,
    }


def _safe_text(text: str) -> str:
    """Escape < > & for ReportLab Paragraphs and limit length."""
    if not text:
        return ""
    text = text[:2000]
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _kv_para(key: str, value: str, style) -> Paragraph:
    return Paragraph(f"<b>{key}:</b> {value}", style)


def _score_color_hex(score: int) -> str:
    if score >= 80:
        return "#2E7D32"
    if score >= 60:
        return "#F57F17"
    return "#B71C1C"


def _sev_color_hex(severity: str) -> str:
    colors_map = {
        "critical": "#B71C1C",
        "high": "#E65100",
        "medium": "#F57F17",
        "low": "#1565C0",
        "informational": "#424242",
    }
    return colors_map.get(severity.lower(), "#424242")
