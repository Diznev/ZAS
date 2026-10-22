"""
ZAS audit log — append-only JSONL of scan events (who/when/what/target).
"""

import json
import os
import threading
from datetime import datetime, timezone


class AuditLog:
    """Thread-safe JSONL audit trail under reports/."""

    def __init__(self, path=None):
        self._lock = threading.Lock()
        self._path = path
        self._enabled = path is not None

    def open(self, base_dir, run_id=None):
        """Open audit file for this run. Returns path or None."""
        if run_id is None:
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logs_dir = os.path.join(base_dir, "reports")
        try:
            os.makedirs(logs_dir, exist_ok=True)
            path = os.path.join(logs_dir, f"audit_{run_id}.jsonl")
            # touch to ensure writable
            with open(path, "a", encoding="utf-8"):
                pass
            with self._lock:
                self._path = path
                self._enabled = True
            return path
        except OSError:
            with self._lock:
                self._path = None
                self._enabled = False
            return None

    @property
    def path(self):
        return self._path

    def close(self):
        with self._lock:
            self._enabled = False

    def write(self, event, **fields):
        """Append one event. Silent if not opened."""
        with self._lock:
            if not self._enabled or not self._path:
                return
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
            }
            record.update(fields)
            try:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            except OSError:
                pass

    def scan_start(self, mode, targets, modules, threads, ignore_ssl):
        self.write(
            "scan_start",
            mode=mode,
            targets=targets,
            modules=modules,
            threads=threads,
            ignore_ssl=ignore_ssl,
        )

    def scan_end(self, status, vuln=0, exploited=0, errors=0, findings=0):
        self.write(
            "scan_end",
            status=status,
            vuln=vuln,
            exploited=exploited,
            errors=errors,
            findings=findings,
        )

    def finding(self, cve, url, status, **details):
        self.write("finding", cve=cve, url=url, status=status, **details)

    def error(self, cve, url, error):
        self.write("error", cve=cve, url=url, error=str(error)[:500])

    def info(self, message, **fields):
        self.write("info", message=str(message)[:500], **fields)


# Process-wide audit log used by the GUI scan worker
audit_log = AuditLog()
