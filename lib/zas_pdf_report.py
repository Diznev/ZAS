# ZAS PDF Report Generator
# Executive summary + detailed findings in PDF format

import json
import os
from datetime import datetime


def generate_pdf_report(results, scan_info=None, output_path="zas_report.pdf"):
    """Generate PDF report from scan results.

    Args:
        results: List of result dicts from scan
        scan_info: Dict with date, mode, targets, modules
        output_path: Output PDF file path
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return _generate_html_fallback(results, scan_info, output_path.replace(".pdf", ".html"))

    if not scan_info:
        scan_info = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "exploit",
            "targets": len(set(r.get("url", "") for r in results)),
            "modules": len(set(r.get("cve", "") for r in results)),
        }

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Title2', parent=styles['Title'], fontSize=24, spaceAfter=20))
    styles.add(ParagraphStyle(name='Subtitle', parent=styles['Normal'], fontSize=12, textColor=colors.grey, spaceAfter=30))
    styles.add(ParagraphStyle(name='Section', parent=styles['Heading2'], fontSize=14, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor("#1f6feb")))
    styles.add(ParagraphStyle(name='Finding', parent=styles['Normal'], fontSize=10, spaceBefore=5, spaceAfter=5))
    styles.add(ParagraphStyle(name='Success', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#3fb950")))
    styles.add(ParagraphStyle(name='Fail', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#f85149")))
    styles.add(ParagraphStyle(name='Info', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#8b949e")))

    elements = []

    elements.append(Paragraph("ZAS v5.2 Scan Report", styles['Title2']))
    elements.append(Paragraph(f"Generated: {scan_info.get('date', 'N/A')} | Mode: {scan_info.get('mode', 'N/A')}", styles['Subtitle']))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363d")))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Executive Summary", styles['Section']))

    total = len(results)
    vuln = len([r for r in results if r.get("status") == "vulnerable"])
    exploited = len([r for r in results if r.get("status") == "exploited"])
    errors = len([r for r in results if r.get("status") == "error"])
    unique_targets = len(set(r.get("url", "") for r in results))
    unique_cves = len(set(r.get("cve", "") for r in results))

    summary_data = [
        ["Metric", "Value"],
        ["Total Results", str(total)],
        ["Unique Targets", str(unique_targets)],
        ["Unique CVEs", str(unique_cves)],
        ["Vulnerable", str(vuln)],
        ["Exploited", str(exploited)],
        ["Errors", str(errors)],
        ["Success Rate", f"{(exploited/total*100):.1f}%" if total > 0 else "N/A"],
    ]

    table = Table(summary_data, colWidths=[200, 200])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#161b22")),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor("#c9d1d9")),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#30363d")),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Detailed Findings", styles['Section']))

    successful = [r for r in results if r.get("status") in ("exploited", "vulnerable")]
    failed = [r for r in results if r.get("status") not in ("exploited", "vulnerable")]

    if successful:
        elements.append(Paragraph(f"<b>Successful ({len(successful)})</b>", styles['Finding']))
        for r in successful[:50]:
            cve = r.get("cve", "N/A")
            url = r.get("url", "N/A")
            status = r.get("status", "N/A")
            details = r.get("details", {})
            method = details.get("method", "")
            output = details.get("output", "")[:100]
            text = f"<b>{cve}</b> @ {url} [{status}]"
            if method:
                text += f" via {method}"
            if output:
                text += f" — {output}"
            elements.append(Paragraph(text, styles['Success']))
        if len(successful) > 50:
            elements.append(Paragraph(f"... and {len(successful)-50} more", styles['Info']))

    if failed:
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<b>Failed/Not Vulnerable ({len(failed)})</b>", styles['Finding']))
        for r in failed[:30]:
            cve = r.get("cve", "N/A")
            url = r.get("url", "N/A")
            details = r.get("details", {})
            reason = details.get("reason", "unknown")
            elements.append(Paragraph(f"{cve} @ {url} — {reason}", styles['Fail']))

    doc.build(elements)
    return output_path


def _generate_html_fallback(results, scan_info, output_path):
    """Generate HTML report as fallback when reportlab not installed."""
    if not scan_info:
        scan_info = {"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "mode": "exploit"}

    total = len(results)
    vuln = len([r for r in results if r.get("status") == "vulnerable"])
    exploited = len([r for r in results if r.get("status") == "exploited"])

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ZAS v5.2 Report</title>
<style>
body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 40px; }}
h1 {{ color: #58a6ff; }}
h2 {{ color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
.stat {{ display: inline-block; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 8px; min-width: 120px; text-align: center; }}
.stat-value {{ font-size: 32px; font-weight: bold; }}
.stat-label {{ font-size: 12px; color: #8b949e; }}
.success {{ color: #3fb950; }}
.fail {{ color: #f85149; }}
.info {{ color: #8b949e; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th {{ background: #1f6feb; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #30363d; }}
tr:hover {{ background: #161b22; }}
</style></head><body>
<h1>ZAS v5.2 Scan Report</h1>
<p class="info">{scan_info.get('date', '')} | Mode: {scan_info.get('mode', '')}</p>

<div>
<div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Results</div></div>
<div class="stat"><div class="stat-value">{exploited}</div><div class="stat-label">Exploited</div></div>
<div class="stat"><div class="stat-value">{vuln}</div><div class="stat-label">Vulnerable</div></div>
</div>

<h2>Successful Exploits</h2>
<table><tr><th>CVE</th><th>URL</th><th>Status</th><th>Method</th><th>Output</th></tr>
"""
    for r in results:
        if r.get("status") in ("exploited", "vulnerable"):
            d = r.get("details", {})
            html += f'<tr class="success"><td>{r.get("cve","")}</td><td>{r.get("url","")}</td>'
            html += f'<td>{r.get("status","")}</td><td>{d.get("method","")}</td>'
            html += f'<td>{str(d.get("output",""))[:80]}</td></tr>\n'

    html += "</table>\n<h2>Failed</h2>\n<table><tr><th>CVE</th><th>URL</th><th>Reason</th></tr>\n"
    for r in results:
        if r.get("status") not in ("exploited", "vulnerable"):
            d = r.get("details", {})
            html += f'<tr class="fail"><td>{r.get("cve","")}</td><td>{r.get("url","")}</td>'
            html += f'<td>{d.get("reason","unknown")}</td></tr>\n'

    html += "</table></body></html>"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
