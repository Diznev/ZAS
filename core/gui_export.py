import os
import json
import csv
import html as _html
from datetime import datetime


def export_txt(results, reports_dir, ts):
    path = os.path.join(reports_dir, f"zas_results_{ts}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"ZAS Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        for r in results:
            f.write(f"CVE    : {r['cve']}\n")
            f.write(f"URL    : {r['url']}\n")
            f.write(f"Status : {r['status']}\n")
            for k, v in r.get("details", {}).items():
                if k not in ("cookies",) and v:
                    f.write(f"{k:8}: {v}\n")
            f.write("-" * 60 + "\n\n")
    return path


def export_json(results, reports_dir, ts):
    path = os.path.join(reports_dir, f"zas_results_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    return path


def export_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE", "URL", "Status", "Details"])
        for r in results:
            details = "; ".join(f"{k}={v}" for k, v in r.get("details", {}).items() if k != "cookies" and v)
            writer.writerow([r.get("cve", ""), r.get("url", ""), r.get("status", ""), details])
    return path


def export_sarif(results, path):
    rules = []
    res = []
    rule_ids = set()
    for r in results:
        cve = r.get("cve", "")
        rule_id = cve.replace("CVE-", "CVE_")
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": r.get("details", {}).get("name", cve),
                "shortDescription": {"text": r.get("details", {}).get("name", cve)},
                "defaultConfiguration": {"level": "error" if r.get("status") == "exploited" else "warning"},
            })
        res.append({
            "ruleId": rule_id,
            "level": "error" if r.get("status") == "exploited" else "warning",
            "message": {"text": f"{r.get('status', '').upper()}: {r.get('url', '')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.get("url", "")}}}],
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ZAS", "version": "5.2", "rules": rules}}, "results": res}],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    return path


def generate_html(data, scan_info):
    vuln_count = sum(1 for r in data if r["status"] == "vulnerable")
    expl_count = sum(1 for r in data if r["status"] == "exploited")
    installed_count = sum(1 for r in data if r["status"] == "installed")
    total_targets = scan_info.get("targets", 0)
    total_modules = scan_info.get("modules", 0)
    mode = scan_info.get("mode", "exploit")

    cards = ""
    for r in data:
        if r["status"] == "exploited":
            status_class, status_icon = "success", "&#10004;"
        elif r["status"] == "installed":
            status_class, status_icon = "info", "&#9432;"
        else:
            status_class, status_icon = "warning", "&#9888;"
        details_html = ""
        for k, v in r.get("details", {}).items():
            if k not in ("cookies",) and v:
                details_html += f'<div class="detail"><span class="key">{_html.escape(str(k))}</span> <span class="val">{_html.escape(str(v))}</span></div>'
        cards += f'''
        <div class="card {status_class}">
            <div class="card-header">
                <span class="badge">{_html.escape(r["cve"])}</span>
                <span class="status">{status_icon} {_html.escape(r["status"].upper())}</span>
            </div>
            <div class="card-url">{_html.escape(r["url"])}</div>
            <div class="card-details">{details_html}</div>
        </div>'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZAS Report - {_html.escape(str(scan_info.get("date", "")))}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;padding:24px}}
.container{{max-width:960px;margin:0 auto}}
h1{{color:#58a6ff;font-size:28px;margin-bottom:4px}}
.subtitle{{color:#8b949e;font-size:14px;margin-bottom:24px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.stat-value{{font-size:32px;font-weight:700;color:#39d353}}
.stat-value.warning{{color:#d29922}}
.stat-value.danger{{color:#f85149}}
.stat-value.info{{color:#58a6ff}}
.stat-label{{font-size:12px;color:#8b949e;margin-top:4px;text-transform:uppercase}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:12px;overflow:hidden}}
.card.success{{border-left:3px solid #3fb950}}
.card.warning{{border-left:3px solid #d29922}}
.card.info{{border-left:3px solid #58a6ff}}
.card-header{{padding:12px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #21262d}}
.badge{{background:#1f6feb;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}}
.status{{font-size:13px;font-weight:600}}
.card.success .status{{color:#3fb950}}
.card.warning .status{{color:#d29922}}
.card.info .status{{color:#58a6ff}}
.card-url{{padding:8px 16px;font-family:Consolas,monospace;font-size:13px;color:#58a6ff}}
.card-details{{padding:8px 16px 12px}}
.detail{{font-size:12px;margin:2px 0}}
.key{{color:#8b949e;display:inline-block;min-width:100px}}
.val{{color:#c9d1d9;font-family:Consolas,monospace}}
.footer{{margin-top:32px;padding-top:16px;border-top:1px solid #21262d;color:#484f58;font-size:12px;text-align:center}}
</style>
</head>
<body>
<div class="container">
    <h1>ZAS v5.2 Scan Report</h1>
    <div class="subtitle">{_html.escape(str(scan_info.get("date", "")))} | Mode: {_html.escape(str(mode))}</div>
    <div class="stats">
        <div class="stat"><div class="stat-value info">{total_targets}</div><div class="stat-label">Targets</div></div>
        <div class="stat"><div class="stat-value info">{total_modules}</div><div class="stat-label">Modules</div></div>
        <div class="stat"><div class="stat-value {"danger" if vuln_count else ""}">{vuln_count}</div><div class="stat-label">Vulnerable</div></div>
        <div class="stat"><div class="stat-value {"warning" if expl_count else ""}">{expl_count}</div><div class="stat-label">Exploited</div></div>
    </div>
    {cards}
    <div class="footer">ZAS v5.2 | Generated {_html.escape(str(scan_info.get("date", "")))}</div>
</div>
</body>
</html>'''
