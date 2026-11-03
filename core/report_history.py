"""Bounded, read-only target history reconstructed from native JSON exports."""

from collections import Counter
from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path

from core.report_comparison import (
    POSITIVE_STATUSES, display_report_url, load_report, report_cve, report_target_id,
)


HISTORY_NOTE = (
    "History contains only saved report records. A missing record "
    "does not mean the target was tested or the vulnerability was remediated. "
    "Dates are file modification times (UTC); copying files may change their order."
)


def discover_reports(directory, max_reports=200, max_entries=20_000):
    """Read only the chosen directory and its immediate children, no symlinks."""
    root = Path(directory)
    if not root.is_dir():
        raise OSError("Report directory not found")
    directories = [root]
    candidates = []
    errors = []
    inspected = 0
    limited = False
    for folder in directories:
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    inspected += 1
                    if inspected > max_entries:
                        limited = True
                        break
                    if entry.is_symlink():
                        continue
                    if folder == root and entry.is_dir(follow_symlinks=False):
                        directories.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and fnmatch.fnmatch(entry.name, "zas_results_*.json"):
                        stat = entry.stat(follow_symlinks=False)
                        candidates.append({"path": str(Path(entry.path).absolute()),
                                           "mtime": stat.st_mtime, "bytes": stat.st_size})
        except OSError:
            errors.append({"file": str(folder.relative_to(root)) or ".", "reason": "Directory is not accessible"})
        if limited:
            break
    candidates.sort(key=lambda item: (-item["mtime"], item["path"]))
    return {"reports": candidates[:max_reports], "discovered": len(candidates),
            "limited": limited or len(candidates) > max_reports, "errors": errors}


def build_target_history(directory, max_reports=200, max_records=100_000,
                         max_total_bytes=64 * 1024 * 1024):
    """Summarize saved outcomes, omitting command output and credential fields."""
    discovered = discover_reports(directory, max_reports=max_reports)
    targets = {}
    errors = list(discovered["errors"])
    loaded = 0
    record_count = 0
    byte_count = 0
    limited = discovered["limited"]
    for report_index, item in enumerate(discovered["reports"]):
        path = Path(item["path"])
        if item["bytes"] > 16 * 1024 * 1024:
            errors.append({"file": path.name, "reason": "Report exceeds the 16 MiB size limit"})
            continue
        if byte_count + item["bytes"] > max_total_bytes:
            limited = True
            errors.append({"file": path.name, "reason": "Total report size limit reached"})
            break
        try:
            records = load_report(path, max_records=50_000,
                                  max_bytes=min(16 * 1024 * 1024, max_total_bytes - byte_count))
        except (OSError, ValueError, RecursionError) as exc:
            errors.append({"file": path.name, "reason": str(exc)})
            # Invalid reports still consume the I/O budget, preventing a large
            # directory of malformed JSON from creating an unbounded read.
            byte_count += item["bytes"]
            continue
        byte_count += item["bytes"]
        if record_count + len(records) > max_records:
            limited = True
            errors.append({"file": path.name, "reason": "Total record limit reached"})
            break
        record_count += len(records)
        loaded += 1
        by_target = {}
        for row in records:
            identity = report_target_id(row["url"])
            targets.setdefault(identity, {
                "id": identity, "url": display_report_url(row["url"]), "runs": [],
            })
            grouped = by_target.setdefault(identity, {})
            cve = report_cve(row)
            finding = grouped.setdefault(cve, {"cve": cve, "statuses": set(), "methods": set(), "records": 0})
            finding["statuses"].add(row["status"].strip().lower())
            method = row.get("details", {}).get("method")
            if isinstance(method, str) and method.strip():
                finding["methods"].add(method.strip()[:200])
            finding["records"] += 1
        for identity, grouped in by_target.items():
            entries = [dict(row, statuses=sorted(row["statuses"]), methods=sorted(row["methods"]))
                       for _, row in sorted(grouped.items())]
            positive = sum(bool(set(row["statuses"]) & POSITIVE_STATUSES) for row in entries)
            targets[identity]["runs"].append({
                "path": str(path), "report": path.name,
                "saved_at": datetime.fromtimestamp(item["mtime"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "mtime": item["mtime"], "findings": entries, "positive_findings": positive,
                "records": sum(row["records"] for row in entries),
            })
        if record_count >= max_records:
            limited = report_index + 1 < len(discovered["reports"]) or limited
            break
    result = []
    for target in targets.values():
        positive_cves = {row["cve"] for run in target["runs"] for row in run["findings"]
                         if set(row["statuses"]) & POSITIVE_STATUSES}
        statuses = Counter(status for run in target["runs"] for row in run["findings"] for status in row["statuses"])
        target.update(report_count=len(target["runs"]), unique_findings=len(positive_cves),
                      statuses=dict(statuses), latest_saved_at=target["runs"][0]["saved_at"])
        result.append(target)
    result.sort(key=lambda target: (-target["runs"][0]["mtime"], target["url"], target["id"]))
    return {"targets": result, "loaded_reports": loaded, "records": record_count,
            "errors": errors, "limited": limited, "note": HISTORY_NOTE,
            "discovered_reports": discovered["discovered"]}
