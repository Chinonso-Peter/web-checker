import html
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEVERITY_CONFIG = {
    "critical": {
        "text_color": colors.HexColor("#7f1d1d"),
        "bg_color": colors.HexColor("#fee2e2"),
        "label": "CRITICAL",
    },
    "high": {
        "text_color": colors.HexColor("#991b1b"),
        "bg_color": colors.HexColor("#fef2f2"),
        "label": "HIGH",
    },
    "medium": {
        "text_color": colors.HexColor("#92400e"),
        "bg_color": colors.HexColor("#fef3c7"),
        "label": "MEDIUM",
    },
    "low": {
        "text_color": colors.HexColor("#1e40af"),
        "bg_color": colors.HexColor("#eff6ff"),
        "label": "LOW",
    },
    "info": {
        "text_color": colors.HexColor("#334155"),
        "bg_color": colors.HexColor("#f1f5f9"),
        "label": "INFO",
    },
}
DEFAULT_SEV = {
    "text_color": colors.HexColor("#334155"),
    "bg_color": colors.HexColor("#f1f5f9"),
    "label": "INFO",
}


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to add dynamic 'Page X of Y' footers and top rule."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_decorations(self, page_count):
        self.saveState()
        page_w, page_h = A4

        # Footer divider line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.6)
        self.line(40, 34, page_w - 40, 34)

        # Footer labels
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(40, 22, "Web Checker — Automated Security Audit Report")
        self.drawRightString(page_w - 40, 22, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


def export_pdf(report_data, filename="web_checker_report.pdf"):
    """
    Generates a clean, professionally formatted security audit PDF report.
    Guarantees no overlapping text across columns by wrapping all table cells
    in auto-wrapping Paragraph flowables with explicit column widths.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=45,
    )

    styles = getSampleStyleSheet()

    # Document Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=3,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#64748b"),
    )
    cat_heading_style = ParagraphStyle(
        "CategoryHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=4,
    )
    no_vuln_style = ParagraphStyle(
        "NoVuln",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#16a34a"),
        spaceAfter=6,
    )

    # Table Cell Styles (wordWrap='CJK' allows wrapping unbroken strings like URLs / payloads)
    th_style = ParagraphStyle(
        "TableHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
    )
    th_center_style = ParagraphStyle(
        "TableHeadCenter",
        parent=th_style,
        alignment=TA_CENTER,
    )
    cell_sev_style = ParagraphStyle(
        "CellSev",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=8.5,
        alignment=TA_CENTER,
    )
    cell_url_style = ParagraphStyle(
        "CellUrl",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#334155"),
        wordWrap="CJK",
    )
    cell_detail_style = ParagraphStyle(
        "CellDetail",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        wordWrap="CJK",
    )
    cell_payload_style = ParagraphStyle(
        "CellPayload",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor("#991b1b"),
        wordWrap="CJK",
    )

    elements = []

    # 1. Header Section
    elements.append(Paragraph("Web Checker — Security Audit Report", title_style))
    target_url = report_data.get("targetUrl", "")
    scan_id = report_data.get("scanId", "")
    created_at = report_data.get("createdAt") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    meta_text = (
        f"<b>Target:</b> {html.escape(target_url)} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Scan ID:</b> {html.escape(scan_id)} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Generated:</b> {html.escape(created_at)}"
    )
    elements.append(Paragraph(meta_text, subtitle_style))
    elements.append(Spacer(1, 10))

    # 2. Executive Metric Chips / Summary
    categories = report_data.get("categories", {}) or {}
    total_findings = 0
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for cat_name, findings in categories.items():
        for f in findings or []:
            total_findings += 1
            s = str(f.get("severity", "info")).lower()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["info"] += 1

    summary_data = [
        [
            Paragraph(f"<b>TOTAL FINDINGS:</b> {total_findings}", subtitle_style),
            Paragraph(f"<b>CRITICAL:</b> <font color='#991b1b'>{sev_counts['critical']}</font>", subtitle_style),
            Paragraph(f"<b>HIGH:</b> <font color='#dc2626'>{sev_counts['high']}</font>", subtitle_style),
            Paragraph(f"<b>MEDIUM:</b> <font color='#d97706'>{sev_counts['medium']}</font>", subtitle_style),
            Paragraph(f"<b>LOW:</b> <font color='#2563eb'>{sev_counts['low']}</font>", subtitle_style),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[115, 100, 100, 100, 100])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # 3. Findings per Category
    col_widths = [55, 135, 215, 110]  # Sum = 515pt (Matches printable A4 width)

    for category, findings in categories.items():
        count_str = f"({len(findings)} issue{'s' if len(findings) != 1 else ''})" if findings else "(Clean)"
        elements.append(Paragraph(f"{category} &nbsp;<font color='#64748b' size=8>{count_str}</font>", cat_heading_style))

        if not findings:
            elements.append(Paragraph("&#10003; No vulnerabilities detected in this category.", no_vuln_style))
            elements.append(Spacer(1, 4))
            continue

        # Header Row
        rows = [
            [
                Paragraph("SEVERITY", th_center_style),
                Paragraph("TARGET URL", th_style),
                Paragraph("VULNERABILITY DETAIL", th_style),
                Paragraph("INJECTED PAYLOAD", th_style),
            ]
        ]

        table_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]

        for idx, f in enumerate(findings, start=1):
            sev_key = str(f.get("severity", "info")).lower()
            conf = SEVERITY_CONFIG.get(sev_key, DEFAULT_SEV)

            sev_para = Paragraph(
                f"<font color='{conf['text_color'].hexval()}'><b>{conf['label']}</b></font>",
                cell_sev_style,
            )
            url_text = html.escape(str(f.get("url") or "-"))
            url_para = Paragraph(url_text, cell_url_style)

            detail_text = html.escape(str(f.get("detail") or "-"))
            detail_para = Paragraph(detail_text, cell_detail_style)

            payload_val = f.get("payload")
            payload_text = html.escape(str(payload_val)) if payload_val else "-"
            payload_para = Paragraph(payload_text, cell_payload_style)

            rows.append([sev_para, url_para, detail_para, payload_para])

            # Alternating subtle row background
            bg_color = colors.white if idx % 2 == 1 else colors.HexColor("#f8fafc")
            table_styles.append(("BACKGROUND", (0, idx), (-1, idx), bg_color))

        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle(table_styles))
        elements.append(table)
        elements.append(Spacer(1, 8))

    if not categories:
        elements.append(Paragraph("No categories were reported.", styles["Normal"]))

    doc.build(elements, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer
