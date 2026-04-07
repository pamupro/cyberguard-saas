"""
CyberGuard – PDF report generator
Produces a clean, client-ready A4 PDF using ReportLab.
"""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Brand colours
# ---------------------------------------------------------------------------
NAVY   = colors.HexColor("#0a0f1e")
DARK   = colors.HexColor("#0d1526")
BLUE   = colors.HexColor("#2563eb")
LBLUE  = colors.HexColor("#60a5fa")
SLATE  = colors.HexColor("#94a3b8")
WHITE  = colors.HexColor("#f8fafc")
GREEN  = colors.HexColor("#22c55e")
AMBER  = colors.HexColor("#f59e0b")
RED    = colors.HexColor("#ef4444")
LGRAY  = colors.HexColor("#f1f5f9")
MGRAY  = colors.HexColor("#e2e8f0")
DGRAY  = colors.HexColor("#334155")


def _severity_color(sev: str) -> colors.Color:
    return {"High": RED, "Medium": AMBER, "Low": LBLUE, "Info": GREEN}.get(sev, SLATE)


def _rating_color(rating: str) -> colors.Color:
    return {"Strong": GREEN, "Moderate": AMBER, "Needs Improvement": AMBER, "High Risk": RED}.get(rating, SLATE)


# ---------------------------------------------------------------------------
# Custom styles
# ---------------------------------------------------------------------------

def _styles():
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("cg_title", fontSize=26, textColor=WHITE, fontName="Helvetica-Bold",
                                spaceAfter=2, leading=30),
        "subtitle": ParagraphStyle("cg_sub", fontSize=11, textColor=SLATE, fontName="Helvetica",
                                   spaceAfter=0, leading=15),
        "h2": ParagraphStyle("cg_h2", fontSize=13, textColor=DARK, fontName="Helvetica-Bold",
                              spaceBefore=14, spaceAfter=6, leading=18),
        "h3": ParagraphStyle("cg_h3", fontSize=10, textColor=DGRAY, fontName="Helvetica-Bold",
                              spaceBefore=8, spaceAfter=3, leading=14),
        "body": ParagraphStyle("cg_body", fontSize=9, textColor=DGRAY, fontName="Helvetica",
                               leading=14, spaceAfter=4),
        "small": ParagraphStyle("cg_small", fontSize=8, textColor=SLATE, fontName="Helvetica",
                                leading=12),
        "bullet": ParagraphStyle("cg_bullet", fontSize=9, textColor=DGRAY, fontName="Helvetica",
                                  leading=14, spaceAfter=3, leftIndent=10, bulletIndent=0),
    }
    return styles


# ---------------------------------------------------------------------------
# Header / footer callback
# ---------------------------------------------------------------------------

class _HeaderFooter:
    def __init__(self, company: str, target: str, analyst: str, date: str):
        self.company = company
        self.target = target
        self.analyst = analyst
        self.date = date

    def __call__(self, canvas, doc):
        w, h = A4
        canvas.saveState()

        # Header bar
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 52, w, 52, fill=1, stroke=0)
        canvas.setFillColor(BLUE)
        canvas.rect(0, h - 52, 6, 52, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(WHITE)
        canvas.drawString(18*mm, h - 32, "CyberGuard")
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(SLATE)
        canvas.drawString(18*mm, h - 44, "Security Review Platform")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 15*mm, h - 32, self.company)
        canvas.drawRightString(w - 15*mm, h - 44, self.date)

        # Footer
        canvas.setFillColor(LGRAY)
        canvas.rect(0, 0, w, 22, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(15*mm, 8, f"Analyst: {self.analyst}  |  Target: {self.target}  |  Page {doc.page}")
        canvas.drawRightString(w - 15*mm, 8, "AUTHORIZED DEFENSIVE REVIEW ONLY — CONFIDENTIAL")

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_pdf(scan: dict, company: str, analyst: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=58, bottomMargin=30,
    )
    S = _styles()
    cb = _HeaderFooter(company, scan["input_url"], analyst, scan["scanned_at"])
    story = []

    # ── Cover block ──────────────────────────────────────────────────────────
    cover_data = [[
        Paragraph("Security Review Report", S["title"]),
        Paragraph(f"<b>{company}</b>", S["subtitle"]),
    ]]
    cover_tbl = Table(cover_data, colWidths=[None])
    cover_bg = Table(
        [[
            Paragraph("Security Review Report", S["title"]),
        ]],
        colWidths=[doc.width],
    )
    cover_bg.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("PADDING", (0, 0), (-1, -1), 14),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(cover_bg)
    story.append(Spacer(1, 10))

    # Meta info table
    meta = [
        ["Client / Company", company],
        ["Target URL", scan["input_url"]],
        ["Final URL", scan["final_url"]],
        ["Analyst", analyst],
        ["Reviewed At", scan["scanned_at"]],
    ]
    meta_tbl = Table(meta, colWidths=[45*mm, doc.width - 45*mm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LGRAY),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, MGRAY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), DGRAY),
        ("TEXTCOLOR", (1, 0), (1, -1), DARK),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 14))

    # ── Score card ───────────────────────────────────────────────────────────
    rc = _rating_color(scan["rating"])
    score_data = [
        [
            Paragraph(f'<font size="32" color="{rc.hexval()}"><b>{scan["score"]}</b></font><font size="14" color="#94a3b8">/100</font>', S["body"]),
            Paragraph(f'<font size="18" color="{rc.hexval()}"><b>{scan["rating"]}</b></font>', S["body"]),
            Paragraph(f'<font size="16"><b>{scan["status_code"]}</b></font><br/><font size="8" color="#94a3b8">HTTP Status</font>', S["body"]),
            Paragraph(
                f'<font size="16"><b>{"✓ TLS" if scan["ssl_info"].get("enabled") else "✗ TLS"}</b></font><br/><font size="8" color="#94a3b8">{"Active" if scan["ssl_info"].get("enabled") else "Unavailable"}</font>',
                S["body"]
            ),
        ]
    ]
    score_tbl = Table(score_data, colWidths=[doc.width/4]*4)
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 14),
        ("LINEAFTER", (0, 0), (2, 0), 0.5, DGRAY),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 14))

    # ── SSL Details ──────────────────────────────────────────────────────────
    ssl = scan["ssl_info"]
    story.append(Paragraph("TLS / SSL Certificate", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MGRAY, spaceAfter=6))
    if ssl.get("enabled"):
        ssl_rows = [
            ["Issuer", ssl.get("issuer", "—")],
            ["Subject (CN)", ssl.get("subject", "—")],
            ["Valid To", ssl.get("valid_to", "—")],
            ["Days Remaining", str(ssl.get("days_remaining", "—"))],
        ]
        ssl_tbl = Table(ssl_rows, colWidths=[40*mm, doc.width - 40*mm])
        ssl_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LGRAY),
            ("GRID", (0, 0), (-1, -1), 0.4, MGRAY),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ssl_tbl)
    else:
        story.append(Paragraph(f"TLS unavailable: {ssl.get('error', 'Unknown error')}", S["body"]))
    story.append(Spacer(1, 10))

    # ── Executive Summary ────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MGRAY, spaceAfter=6))
    for point in scan["summary"]:
        story.append(Paragraph(f"• {point}", S["bullet"]))
    story.append(Spacer(1, 10))

    # ── Detailed Findings ────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MGRAY, spaceAfter=6))

    table_header = [
        Paragraph("<b>Finding</b>", S["small"]),
        Paragraph("<b>Category</b>", S["small"]),
        Paragraph("<b>Severity</b>", S["small"]),
        Paragraph("<b>Status</b>", S["small"]),
        Paragraph("<b>Recommendation</b>", S["small"]),
    ]
    table_rows = [table_header]
    for f in scan["findings"]:
        sc = _severity_color(f["severity"])
        status_txt = "Present" if f["present"] else "Issue"
        table_rows.append([
            Paragraph(f["name"], S["small"]),
            Paragraph(f["category"], S["small"]),
            Paragraph(f'<font color="{sc.hexval()}"><b>{f["severity"]}</b></font>', S["small"]),
            Paragraph(f'<font color="{"#22c55e" if f["present"] else "#ef4444"}">{"✓" if f["present"] else "✗"} {status_txt}</font>', S["small"]),
            Paragraph(f["recommendation"], S["small"]),
        ])

    find_tbl = Table(table_rows, colWidths=[42*mm, 30*mm, 18*mm, 18*mm, None])
    find_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LGRAY]),
        ("GRID", (0, 0), (-1, -1), 0.3, MGRAY),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(find_tbl)
    story.append(Spacer(1, 14))

    # ── Scope disclaimer ─────────────────────────────────────────────────────
    disclaimer = Table(
        [[Paragraph(
            "SCOPE NOTICE: This report covers passive, defensive web configuration checks only. "
            "It is intended for authorized assessment, portfolio demonstration, and security awareness. "
            "CyberGuard does not perform any offensive, intrusive, or exploitative testing.",
            S["small"]
        )]],
        colWidths=[doc.width],
    )
    disclaimer.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LGRAY),
        ("BORDER", (0, 0), (-1, -1), 0.5, MGRAY),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(disclaimer)

    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    pdf = buf.getvalue()
    buf.close()
    return pdf
