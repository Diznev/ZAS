"""Offline comparison of ZAS JSON reports; never contacts audit targets."""

from collections import Counter
from html import escape
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit


POSITIVE_STATUSES = frozenset({"exploited", "vulnerable"})
CHANGE_LABELS = {
    "new": "New finding",
    "repeated": "Repeated finding",
    "not_reconfirmed": "Not reconfirmed",
}
COMPARISON_NOTE = (
    "Comparison reflects report contents and does not revalidate evidence. "
    "A missing finding in the current report does not prove remediation: "
    "targets, modules, access or scan conditions may have differed. "
    "URL query values and credentials are hidden in the comparison."
)


def _url_identity(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("URL must include HTTP(S) and a host name")
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
            host += f":{port}"
        # Keep query values in the identity: different endpoint parameters can
        # identify different findings. Never include userinfo in the identity.
        return urlunsplit((scheme, host, parsed.path.rstrip("/") or "/", parsed.query, ""))
    except ValueError as exc:
        raise ValueError("Invalid URL in report") from exc


def _display_url(identity):
    parsed = urlsplit(identity)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       "[parameters hidden]" if parsed.query else "", ""))


def report_target_id(url):
    """Stable endpoint identity for linking local history and comparison."""
    return hashlib.sha256(_url_identity(url).encode("utf-8")).hexdigest()


def display_report_url(url):
    """Display an endpoint without userinfo or query values."""
    return _display_url(_url_identity(url))


def report_cve(row):
    """Prefer the executed chain's CVE over the facade's catalogue."""
    cve = row.get("details", {}).get("cve_used") or row["cve"]
    return ", ".join(sorted({part.strip().upper() for part in cve.split(",") if part.strip()}))


def _validate_records(records):
    if not isinstance(records, list):
        raise ValueError("Expected a ZAS JSON report containing an array of results")
    for index, row in enumerate(records, 1):
        if not isinstance(row, dict):
            raise ValueError(f"Result #{index}: expected an object")
        for key in ("cve", "url", "status"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f"Result #{index}: missing text field {key}")
        if not isinstance(row.get("details", {}), dict):
            raise ValueError(f"Result #{index}: details must be an object")
        used = row.get("details", {}).get("cve_used")
        if used is not None and (not isinstance(used, str) or not used.strip()):
            raise ValueError(f"Result #{index}: invalid cve_used field")
        _url_identity(row["url"])
    return records


def load_report(path, max_bytes=16 * 1024 * 1024, max_records=50_000):
    """Read a bounded native JSON export; reject malformed input explicitly."""
    with open(path, "rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Report exceeds the size limit (16 MiB by default)")
    try:
        records = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Could not read report as UTF-8 JSON") from exc
    if isinstance(records, list) and len(records) > max_records:
        raise ValueError("Too many results (50,000 maximum by default)")
    return _validate_records(records)


def _index(records):
    indexed = {}
    for row in records:
        cve = report_cve(row)
        key = (cve, _url_identity(row["url"]))
        entry = indexed.setdefault(key, {"statuses": set(), "records": 0, "positive": False})
        status = row["status"].strip().lower()
        entry["statuses"].add(status)
        entry["records"] += 1
        entry["positive"] |= status in POSITIVE_STATUSES
    return indexed


def compare_reports(baseline, current, target_id=None):
    """Match by CVE (actual chain where available) and normalized endpoint.

    Only exploited/vulnerable records count as findings. Credentials, pivot,
    exfiltration and failed results do not become new vulnerability findings.
    Duplicate results are aggregated without counting them as new issues.
    """
    baseline, current = _validate_records(baseline), _validate_records(current)
    if target_id is not None:
        baseline = [row for row in baseline if report_target_id(row["url"]) == target_id]
        current = [row for row in current if report_target_id(row["url"]) == target_id]
    previous = _index(baseline)
    latest = _index(current)
    empty = {"statuses": set(), "records": 0, "positive": False}
    rows = []
    for key in sorted(previous.keys() | latest.keys()):
        old, new = previous.get(key, empty), latest.get(key, empty)
        if not old["positive"] and not new["positive"]:
            continue
        change = ("repeated" if old["positive"] else "new") if new["positive"] else "not_reconfirmed"
        cve, url = key
        rows.append({
            "change": change, "cve": cve, "url": _display_url(url),
            "baseline_statuses": sorted(old["statuses"]),
            "current_statuses": sorted(new["statuses"]),
            "baseline_records": old["records"], "current_records": new["records"],
        })
    counts = Counter(row["change"] for row in rows)
    return {
        "rows": rows,
        "counts": {key: counts[key] for key in CHANGE_LABELS},
        "baseline_records": len(baseline), "current_records": len(current),
        "note": COMPARISON_NOTE,
        "scope": display_report_url((current or baseline)[0]["url"]) if target_id is not None and (current or baseline) else None,
        "scoped": target_id is not None,
    }


def generate_comparison_html(comparison):
    """Create a self-contained report containing comparison metadata only."""
    cards = " · ".join(f"{label}: {comparison['counts'][key]}" for key, label in CHANGE_LABELS.items())
    rows = []
    for row in comparison["rows"]:
        values = [CHANGE_LABELS[row["change"]], row["cve"], row["url"],
                  ", ".join(row["baseline_statuses"]) or "No record",
                  ", ".join(row["current_statuses"]) or "No record"]
        rows.append("<tr>" + "".join(f"<td>{escape(value)}</td>" for value in values) + "</tr>")
    scope = "All targets in the selected reports"
    if comparison.get("scoped"):
        scope = f"Target only: {comparison['scope']}" if comparison.get("scope") else "Selected target: no records"
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>ZAS — audit comparison</title><style>"
            "body{font:15px system-ui,sans-serif;margin:32px;color:#202830}"
            "table{border-collapse:collapse;width:100%}td,th{padding:10px;border:1px solid #ccd2d8;"
            "text-align:left;overflow-wrap:anywhere}th{background:#edf2f5}"
            "p{max-width:1000px;line-height:1.5}</style></head><body>"
            f"<h1>ZAS — audit comparison</h1><p>{escape(cards)}</p>"
            f"<p>{escape(scope)}</p>"
            f"<p>{escape(COMPARISON_NOTE)}</p><table><thead><tr>"
            "<th>Change</th><th>CVE / ID</th><th>Target</th><th>Before</th><th>After</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></body></html>")
