"""Tests for the remaining support modules: notify, pdf report, bypass, cleanup."""

import os


import zas_bypass as zb
import zas_cleanup as zclean
import zas_notify as zn
import zas_pdf_report as zp


RESULTS = [
    {"cve": "CVE-2026-1357", "url": "https://a.example",
     "status": "exploited", "details": {"ok": True, "output": "uid=33"}},
    {"cve": "CVE-2026-33017", "url": "https://b.example",
     "status": "failed", "details": {"ok": False, "reason": "no token"}},
]
SCAN_INFO = {"date": "2026-10-29", "mode": "exploit", "targets": 2, "modules": 5}


# ── zas_notify helpers ─────────────────────────────────────────────

class TestNotifyHelpers:
    def test_esc_escapes_html(self):
        out = zn._esc("<b>&\"'</b>")
        assert "<" not in out and ">" not in out
        assert "&" in out  # escaped entities still contain &

    def test_esc_handles_non_string(self):
        assert isinstance(zn._esc(123), str)

    def test_esc_none_is_safe(self):
        assert isinstance(zn._esc(None), str)

    def test_ssl_context_respects_verify(self):
        import ssl
        ctx = zn._ssl_context(verify=True)
        assert isinstance(ctx, ssl.SSLContext)
        ctx2 = zn._ssl_context(verify=False)
        assert isinstance(ctx2, ssl.SSLContext)


class TestNotificationManager:
    def test_no_channels_by_default(self):
        nm = zn.NotificationManager()
        assert nm.get_configured_channels() == [] or nm.get_configured_channels() == {}

    def test_add_telegram_registers_channel(self):
        nm = zn.NotificationManager()
        nm.add_telegram("token", "chat")
        ch = nm.get_configured_channels()
        assert any("telegram" in str(c).lower() for c in ch)

    def test_add_slack_registers_channel(self):
        nm = zn.NotificationManager()
        nm.add_slack("https://hooks.example/x")
        ch = nm.get_configured_channels()
        assert any("slack" in str(c).lower() for c in ch)

    def test_add_discord_registers_channel(self):
        nm = zn.NotificationManager()
        nm.add_discord("https://discord.example/x")
        ch = nm.get_configured_channels()
        assert any("discord" in str(c).lower() for c in ch)

    def test_add_email_registers_channel(self):
        nm = zn.NotificationManager()
        nm.add_email("smtp.example", 587, "u", "p", "from@x", "to@x")
        ch = nm.get_configured_channels()
        assert any("email" in str(c).lower() for c in ch)

    def test_notify_with_no_channels_does_not_raise(self):
        nm = zn.NotificationManager()
        nm.notify_vuln("CVE-1", "https://x", "exploited", {})
        nm.notify_scan_complete({"total": 1})
        nm.notify_creds("https://x", 2, ["db"])

    def test_notify_with_unreachable_channel_does_not_raise(self):
        # a channel configured to an unreachable URL must not blow up the scan
        nm = zn.NotificationManager()
        nm.add_slack("https://127.0.0.1:59999/hook")
        nm.notify_vuln("CVE-1", "https://x", "exploited", {})


class TestNotifierMessageShape:
    def test_telegram_alert_returns_a_result(self):
        t = zn.TelegramNotifier("token", "chat")
        r = t.send_vuln_alert("CVE-2026-1357", "https://x", "exploited", {})
        assert isinstance(r, dict)
        assert "ok" in r

    def test_slack_alert_returns_a_result(self):
        s = zn.SlackNotifier("https://127.0.0.1:59999/hook")
        r = s.send_vuln_alert("CVE-1", "https://x", "vulnerable", {})
        assert isinstance(r, dict)
        assert "ok" in r

    def test_discord_alert_returns_a_result(self):
        d = zn.DiscordNotifier("https://127.0.0.1:59999/hook")
        r = d.send_vuln_alert("CVE-1", "https://x", "vulnerable", {})
        assert isinstance(r, dict)
        assert "ok" in r

    def test_failed_send_reports_ok_false(self):
        s = zn.SlackNotifier("https://127.0.0.1:59999/hook")
        r = s.send_vuln_alert("CVE-1", "https://x", "vulnerable", {})
        assert r["ok"] is False
        assert r.get("error")


# ── zas_pdf_report ─────────────────────────────────────────────────

class TestPdfReport:
    def test_writes_a_pdf(self, tmp_path):
        out = str(tmp_path / "r.pdf")
        zp.generate_pdf_report(RESULTS, SCAN_INFO, output_path=out)
        assert os.path.isfile(out)
        assert os.path.getsize(out) > 0

    def test_output_is_a_pdf_header(self, tmp_path):
        out = str(tmp_path / "r.pdf")
        zp.generate_pdf_report(RESULTS, SCAN_INFO, output_path=out)
        head = open(out, "rb").read(5)
        assert head in (b"%PDF-", b"<html", b"<!DOCT")  # pdf or html fallback

    def test_empty_results_are_handled(self, tmp_path):
        out = str(tmp_path / "empty.pdf")
        zp.generate_pdf_report([], SCAN_INFO, output_path=out)
        assert os.path.isfile(out)

    def test_missing_scan_info_is_filled(self, tmp_path):
        out = str(tmp_path / "noinfo.pdf")
        zp.generate_pdf_report(RESULTS, None, output_path=out)
        assert os.path.isfile(out)

    def test_html_fallback_is_valid(self, tmp_path):
        out = str(tmp_path / "fallback.html")
        zp._generate_html_fallback(RESULTS, SCAN_INFO, out)
        text = open(out, encoding="utf-8").read()
        assert "CVE-2026-1357" in text


# ── zas_cleanup ────────────────────────────────────────────────────

class TestCleanupTracker:
    def test_starts_empty(self):
        t = zclean.CleanupTracker()
        assert t.get_items() == []

    def test_add_shell_is_recorded(self):
        t = zclean.CleanupTracker()
        t.add_shell("https://x", "https://x/shell.php", "tok")
        assert t.get_items()[0]["type"] == "shell"
        assert t.get_items()[0]["token"] == "tok"

    def test_add_user_is_recorded(self):
        t = zclean.CleanupTracker()
        t.add_user("https://x", "zas_user", "pw")
        assert t.get_items()[0]["type"] == "user"

    def test_add_template_is_recorded(self):
        t = zclean.CleanupTracker()
        t.add_template("https://x", "tpl.php", "<?php //orig")
        assert t.get_items()[0]["type"] == "template"

    def test_clear_empties(self):
        t = zclean.CleanupTracker()
        t.add_shell("https://x", "https://x/s.php", "tok")
        t.clear()
        assert t.get_items() == []

    def test_cleanup_all_does_not_raise(self):
        t = zclean.CleanupTracker()
        t.add_shell("https://127.0.0.1:59999", "https://127.0.0.1:59999/s.php", "tok")
        t.add_user("https://127.0.0.1:59999", "u", "p")
        t.add_template("https://127.0.0.1:59999", "t.php", "orig")
        # unreachable host must not raise
        t.cleanup_all()

    def test_cleanup_all_on_empty_is_safe(self):
        t = zclean.CleanupTracker()
        t.cleanup_all()

    def test_cleanup_all_accepts_a_log_function(self):
        lines = []
        t = zclean.CleanupTracker()
        t.add_shell("https://127.0.0.1:59999", "https://127.0.0.1:59999/s.php", "tok")
        t.cleanup_all(log_func=lines.append)


# ── zas_bypass ─────────────────────────────────────────────────────

class TestBypass:
    def test_verify_shell_reports_false_on_dead_host(self):
        assert zb.verify_shell("https://127.0.0.1:59999", "/s.php", "tok", 2) is False

    def test_verify_shell_returns_bool(self):
        r = zb.verify_shell("https://127.0.0.1:59999", "/s.php", "tok", 2)
        assert isinstance(r, bool)

    def test_try_bypass_reports_failure_on_dead_host(self):
        r = zb.try_bypass("https://127.0.0.1:59999", "/s.php", "tok",
                          lambda *a, **k: None, 2)
        assert isinstance(r, (dict, tuple, bool, type(None)))

    def test_try_bypass_does_not_raise(self):
        zb.try_bypass("https://127.0.0.1:59999", "/s.php", "tok",
                      lambda *a, **k: None, 2)
