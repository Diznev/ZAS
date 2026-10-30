"""Tests for core/gui_export.py — report exporters."""

import csv
import json
import os

import pytest

from gui_export import export_csv, export_json, export_sarif, export_txt, generate_html

RESULTS = [
    {"cve": "CVE-2026-1357", "url": "https://a.example",
     "status": "exploited", "details": {"ok": True, "output": "uid=33"}},
    {"cve": "CVE-2026-33017", "url": "https://b.example",
     "status": "failed", "details": {"ok": False, "reason": "no token"}},
    {"cve": "EXFIL-001", "url": "https://a.example",
     "status": "exfiltration", "details": {"sensitive_files": {"env": "x"}}},
]

SCAN_INFO = {"date": "2026-10-29 12:00:00", "mode": "exploit",
             "targets": 2, "modules": 5}


@pytest.fixture
def out(tmp_path):
    return str(tmp_path)


class TestExportCsv:
    def test_writes_a_file(self, out):
        path = export_csv(RESULTS, os.path.join(out, "r.csv"))
        assert path and os.path.isfile(path)

    def test_has_a_header_and_one_row_per_result(self, out):
        path = export_csv(RESULTS, os.path.join(out, "r.csv"))
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        assert len(rows) == len(RESULTS) + 1

    def test_carries_cve_and_url(self, out):
        path = export_csv(RESULTS, os.path.join(out, "r.csv"))
        text = open(path, encoding="utf-8").read()
        assert "CVE-2026-1357" in text
        assert "https://a.example" in text


class TestExportJson:
    def test_writes_valid_json(self, out):
        path = export_json(RESULTS, out, "run1")
        assert os.path.isfile(path)
        json.load(open(path, encoding="utf-8"))

    def test_round_trips_results(self, out):
        path = export_json(RESULTS, out, "run2")
        data = json.load(open(path, encoding="utf-8"))
        assert len(data) == len(RESULTS)


class TestExportTxt:
    def test_writes_a_file(self, out):
        path = export_txt(RESULTS, out, "run3")
        assert os.path.isfile(path)

    def test_mentions_findings(self, out):
        path = export_txt(RESULTS, out, "run4")
        text = open(path, encoding="utf-8").read()
        assert "CVE-2026-1357" in text


class TestExportSarif:
    def test_writes_valid_sarif(self, out):
        path = export_sarif(RESULTS, os.path.join(out, "r.sarif"))
        assert os.path.isfile(path)
        data = json.load(open(path, encoding="utf-8"))
        assert data["$schema"].startswith("https://")
        assert data["version"] == "2.1.0"

    def test_names_the_tool(self, out):
        path = export_sarif(RESULTS, os.path.join(out, "r.sarif"))
        data = json.load(open(path, encoding="utf-8"))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ZAS"
        assert driver["version"], "SARIF driver must carry a version"

    def test_has_one_result_per_finding(self, out):
        path = export_sarif(RESULTS, os.path.join(out, "r.sarif"))
        data = json.load(open(path, encoding="utf-8"))
        assert len(data["runs"][0]["results"]) == len(RESULTS)


class TestGenerateHtml:
    def test_returns_html(self):
        html = generate_html(RESULTS, SCAN_INFO)
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_includes_findings(self):
        html = generate_html(RESULTS, SCAN_INFO)
        assert "CVE-2026-1357" in html
        assert "https://a.example" in html

    def test_includes_scan_info(self):
        html = generate_html(RESULTS, SCAN_INFO)
        assert "exploit" in html
        assert "2026-10-29" in html

    def test_carries_version_banner(self):
        html = generate_html(RESULTS, SCAN_INFO)
        assert "ZAS v" in html

    def test_no_audit_mode_leftovers(self):
        # the Audit mode was removed; its "Installed" stat must not render
        html = generate_html(RESULTS, SCAN_INFO)
        assert "Installed" not in html

    def test_escapes_input(self):
        evil = [{"cve": "<script>alert(1)</script>", "url": "https://x",
                 "status": "failed", "details": {}}]
        html = generate_html(evil, SCAN_INFO)
        assert "<script>alert(1)</script>" not in html
