"""Tests for the lib/ helper modules — fingerprint, WAF, pivot, creds.

These are pure or near-pure functions over response data, so they are the
cheapest place to get real coverage.
"""

import pytest

import zas_creds as zc
import zas_fingerprint as zf
import zas_pivot as zp
import zas_waf as zw


WP_HTML = (
    '<html><head><meta name="generator" content="WordPress 6.4.2" />'
    '<link rel="stylesheet" href="/wp-content/themes/x/style.css" />'
    '</head><body></body></html>'
)
JOOMLA_HTML = (
    '<html><head><meta name="generator" content="Joomla! - Open Source '
    'Content Management - Version 3.9.20" /></head><body></body></html>'
)


# ── zas_fingerprint ────────────────────────────────────────────────

class TestFingerprintCms:
    def test_detects_wordpress(self):
        r = zf.fingerprint_cms(WP_HTML, {})
        assert "wordpress" in str(r).lower()

    def test_extracts_wp_version(self):
        r = zf.fingerprint_cms(WP_HTML, {})
        assert "6.4.2" in str(r.get("version", ""))

    def test_detects_joomla(self):
        r = zf.fingerprint_cms(JOOMLA_HTML, {})
        assert "joomla" in str(r).lower()

    def test_no_cms_is_honest(self):
        r = zf.fingerprint_cms("<html><body>hello</body></html>", {})
        assert "wordpress" not in str(r).lower()
        assert "joomla" not in str(r).lower()

    def test_empty_input_does_not_raise(self):
        assert isinstance(zf.fingerprint_cms("", {}), dict)

    def test_headers_are_considered(self):
        r = zf.fingerprint_cms("", {"X-Powered-By": "PHP/8.2"})
        assert isinstance(r, dict)


class TestVersionExtractors:
    def test_wp_version(self):
        assert zf._extract_wp_version(WP_HTML) == "6.4.2"

    def test_wp_version_absent_is_unknown(self):
        assert zf._extract_wp_version("<html></html>") == "unknown"

    def test_wp_version_empty_input(self):
        assert zf._extract_wp_version("") == "unknown"

    def test_joomla_meta_generator(self):
        # the most common Joomla version disclosure
        assert zf._extract_joomla_version(JOOMLA_HTML) == "3.9.20"

    def test_joomla_manifest_format(self):
        xml = "<extension><version>4.2.1</version></extension>"
        assert zf._extract_joomla_version(xml) == "4.2.1"

    def test_joomla_version_absent_is_unknown(self):
        assert zf._extract_joomla_version("<html></html>") == "unknown"


class TestFingerprintTech:
    def test_detects_jquery_from_body(self):
        r = zf.fingerprint_technologies('<script src="jquery.min.js"></script>', {})
        assert "jquery" in r

    def test_detects_react(self):
        r = zf.fingerprint_technologies('<div data-reactroot></div>', {})
        assert "react" in r

    def test_detects_security_headers(self):
        r = zf.fingerprint_technologies("", {"Strict-Transport-Security": "max-age=31536000"})
        assert any(t.startswith("header:") for t in r)

    def test_detects_analytics(self):
        r = zf.fingerprint_technologies('<script src="https://www.googletagmanager.com/gtag/js"></script>', {})
        assert "google_tag_manager" in r

    def test_empty_is_empty_list(self):
        assert zf.fingerprint_technologies("", {}) == []


class TestShodanQuery:
    def test_generates_a_query(self):
        r = zf.fingerprint_cms(WP_HTML, {})
        q = zf.generate_shodan_query(r)
        assert isinstance(q, str) and q.strip()

    def test_empty_result_is_none(self):
        # nothing to search on -> no query rather than a bogus one
        assert zf.generate_shodan_query({}) is None


# ── zas_waf ────────────────────────────────────────────────────────

class TestDetectWaf:
    def test_cloudflare(self):
        r = zw.detect_waf("", {"Server": "cloudflare"})
        assert "cloudflare" in str(r).lower()

    def test_mod_security_body(self):
        r = zw.detect_waf("ModSecurity: Access denied", {})
        assert r is not None

    def test_empty_is_a_structured_no_waf_result(self):
        r = zw.detect_waf("<html>hi</html>", {})
        assert isinstance(r, dict)
        assert r.get("waf") in (None, "")
        assert not r.get("blocked")


class TestWafBypass:
    @pytest.mark.parametrize("name", ["cloudflare", "aws", "akamai",
                                      "modsecurity", "imperva", "unknown-waf"])
    def test_returns_a_list_for_any_name(self, name):
        out = zw.get_waf_bypass_techniques(name)
        assert isinstance(out, (list, tuple, dict))

    def test_known_waf_has_techniques(self):
        out = zw.get_waf_bypass_techniques("cloudflare")
        assert len(out) >= 2

    def test_unknown_waf_gets_a_fallback_not_a_crash(self):
        out = zw.get_waf_bypass_techniques("definitely-not-a-waf")
        assert out, "unknown WAF should still return guidance"


# ── zas_pivot ──────────────────────────────────────────────────────

FLAT = {"raw": "eth0: 10.0.0.5", "parsed": [
    {"type": "internal_ip", "ip": "10.0.0.7"},
    {"type": "internal_ip", "ip": "127.0.0.1"},
    {"type": "arp_entry", "ip": "10.0.0.9"},
    {"type": "listening_port", "ip": "10.0.0.7", "port": 22},
    {"type": "known_host", "host": "fileserver"},
]}
NESTED = {"network": {"arp-scan": FLAT}}


class TestParsePivot:
    def test_returns_raw_and_parsed(self):
        r = zp.parse_pivot_output("network", "arp-scan", "10.0.0.7\n10.0.0.9")
        assert set(r) == {"raw", "parsed"}
        assert isinstance(r["parsed"], list)

    def test_empty_output_is_safe(self):
        r = zp.parse_pivot_output("network", "cmd", "")
        assert isinstance(r["parsed"], list)

    def test_none_output_is_safe(self):
        assert isinstance(zp.parse_pivot_output("n", "c", None), dict)


class TestGeneratePivotTargets:
    def test_accepts_flat_shape(self):
        t = zp.generate_pivot_targets(FLAT)
        assert isinstance(t, list)

    def test_accepts_nested_shape(self):
        t = zp.generate_pivot_targets(NESTED)
        assert isinstance(t, list)

    def test_collects_internal_hosts(self):
        t = zp.generate_pivot_targets(FLAT)
        ips = {x["ip"] for x in t}
        assert "10.0.0.7" in ips

    def test_skips_loopback(self):
        t = zp.generate_pivot_targets(FLAT)
        assert all(x["ip"] != "127.0.0.1" for x in t)

    def test_collects_services(self):
        t = zp.generate_pivot_targets(FLAT)
        assert any(x["type"] == "service" and x["port"] == 22 for x in t)

    def test_collects_known_hosts(self):
        t = zp.generate_pivot_targets(FLAT)
        assert any(x.get("ip") == "fileserver" for x in t)

    def test_deduplicates(self):
        dup = {"raw": "", "parsed": [{"type": "internal_ip", "ip": "10.0.0.7"},
                                     {"type": "internal_ip", "ip": "10.0.0.7"}]}
        t = zp.generate_pivot_targets(dup)
        assert len([x for x in t if x["ip"] == "10.0.0.7"]) == 1

    def test_empty_dict_is_empty_list(self):
        assert zp.generate_pivot_targets({}) == []

    def test_garbage_values_do_not_crash(self):
        # the crash this guards against: a str value where a dict was expected
        assert zp.generate_pivot_targets({"raw": "x", "parsed": []}) == []
        assert zp.generate_pivot_targets({"cat": "not-a-dict"}) == []
        assert zp.generate_pivot_targets(None) == []

    def test_bad_items_are_skipped(self):
        bad = {"raw": "", "parsed": ["not-a-dict", None, {"type": "unknown"}]}
        assert zp.generate_pivot_targets(bad) == []


class TestPivotReport:
    def test_formats_flat(self):
        out = zp.format_pivot_report(FLAT, zp.generate_pivot_targets(FLAT))
        assert isinstance(out, str)

    def test_formats_nested(self):
        out = zp.format_pivot_report(NESTED, zp.generate_pivot_targets(NESTED))
        assert isinstance(out, str)

    def test_empty_is_safe(self):
        assert isinstance(zp.format_pivot_report({}, []), str)


# ── zas_creds ──────────────────────────────────────────────────────

CREDS_OUT = """DB_USER=admin
DB_PASSWORD=s3cret
define('DB_NAME', 'prod');"""


class TestParseCreds:
    def test_finds_credentials(self):
        r = zc.parse_credential_output("wp-config.php", CREDS_OUT)
        assert r, "a config with DB_USER should yield credentials"

    def test_reports_the_source(self):
        r = zc.parse_credential_output("wp-config.php", CREDS_OUT)
        assert "wp-config.php" in str(r)

    def test_empty_output_is_empty(self):
        assert not zc.parse_credential_output("src", "")

    def test_none_output_is_safe(self):
        assert not zc.parse_credential_output("src", None)

    def test_output_type(self):
        r = zc.parse_credential_output("src", CREDS_OUT)
        assert isinstance(r, (list, dict))


class TestCredsReport:
    def test_formats(self):
        creds = zc.parse_credential_output("wp-config.php", CREDS_OUT)
        out = zc.format_creds_report(creds)
        assert isinstance(out, str)

    def test_empty_is_safe(self):
        assert isinstance(zc.format_creds_report([]), str)
        assert isinstance(zc.format_creds_report({}), str)
