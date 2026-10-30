"""Tests for exploits/zas_core.py — the shared helper every module uses."""


import zas_core as zc


# ── parse_header_string ────────────────────────────────────────────

class TestParseHeaderString:
    def test_empty(self):
        assert zc.parse_header_string("") == {}
        assert zc.parse_header_string(None) == {}

    def test_single(self):
        assert zc.parse_header_string("X-A: b") == {"X-A": "b"}

    def test_semicolon_separated(self):
        assert zc.parse_header_string("X-A: b; X-C: d") == {"X-A": "b", "X-C": "d"}

    def test_newline_separated(self):
        assert zc.parse_header_string("X-A: b\nX-C: d") == {"X-A": "b", "X-C": "d"}

    def test_value_may_contain_colons(self):
        assert zc.parse_header_string("Host: a.example:8443") == {"Host": "a.example:8443"}

    def test_value_may_contain_colons_beyond_port(self):
        assert zc.parse_header_string("X-K: a:b:c") == {"X-K": "a:b:c"}

    def test_strips_whitespace(self):
        assert zc.parse_header_string("  X-N:  v with spaces  ") == {"X-N": "v with spaces"}

    def test_skips_malformed_entries(self):
        assert zc.parse_header_string("bad") == {}
        assert zc.parse_header_string("bad; X-A: b") == {"X-A": "b"}

    def test_skips_empty_key(self):
        assert zc.parse_header_string(": novalue") == {}


# ── custom headers on sessions ─────────────────────────────────────

class TestCustomHeaders:
    def teardown_method(self):
        zc.set_custom_headers(None)

    def test_set_and_get_roundtrip(self):
        zc.set_custom_headers({"X-T": "1"})
        assert zc.get_custom_headers() == {"X-T": "1"}

    def test_clear_with_none(self):
        zc.set_custom_headers({"X-T": "1"})
        zc.set_custom_headers(None)
        assert zc.get_custom_headers() == {}

    def test_get_returns_a_copy(self):
        zc.set_custom_headers({"X-T": "1"})
        got = zc.get_custom_headers()
        got["X-T"] = "mutated"
        assert zc.get_custom_headers() == {"X-T": "1"}

    def test_reaches_session(self):
        zc.set_custom_headers({"X-Session-Test": "yes"})
        s = zc.create_session()
        assert s.headers.get("X-Session-Test") == "yes"

    def test_cleared_headers_not_on_session(self):
        zc.set_custom_headers({"X-Gone": "1"})
        zc.set_custom_headers(None)
        s = zc.create_session()
        assert "X-Gone" not in s.headers


# ── validate_shell_response ────────────────────────────────────────

class TestValidateShellResponse:
    def test_accepts_marker_plus_output(self):
        assert zc.validate_shell_response("tok123\nuid=0(root)", "tok123") is True

    def test_rejects_missing_marker(self):
        assert zc.validate_shell_response("uid=0(root)", "tok123") is False

    def test_rejects_empty_response(self):
        assert zc.validate_shell_response("", "tok") is False
        assert zc.validate_shell_response(None, "tok") is False

    def test_rejects_empty_marker(self):
        assert zc.validate_shell_response("anything", "") is False

    def test_rejects_html_document(self):
        body = "tok\n<!DOCTYPE html><html>hi</html>"
        assert zc.validate_shell_response(body, "tok") is False

    def test_rejects_php_source(self):
        body = "tok\n<?php echo 1; ?>"
        assert zc.validate_shell_response(body, "tok") is False

    def test_rejects_oversized_body(self):
        body = "tok\n" + "x" * 6000
        assert zc.validate_shell_response(body, "tok") is False

    def test_rejects_html_tags_in_first_500(self):
        body = "tok\n<div>nope</div>"
        assert zc.validate_shell_response(body, "tok") is False

    def test_accepts_marker_inside_longer_output(self):
        body = "line1\nmytok\nline3"
        assert zc.validate_shell_response(body, "mytok") is True


# ── get_shell_content ──────────────────────────────────────────────

class TestGetShellContent:
    def test_emits_token(self):
        s = zc.get_shell_content(None, "abc123")
        assert 'abc123' in s

    def test_echoes_token_before_output(self):
        # regression: the shell used to echo only command output, so
        # validate_shell_response() could never pass
        s = zc.get_shell_content(None, "abc123")
        assert 'echo $t' in s

    def test_default_token(self):
        assert 'zas' in zc.get_shell_content(None, None)

    def test_valid_php(self):
        s = zc.get_shell_content(None, "t")
        assert s.startswith("<?php")
        assert s.rstrip().endswith("?>")

    def test_cookie_stealer_variant(self):
        s = zc.get_shell_content("cookie_stealer", "t")
        assert "PHPSESSID" in s


# ── normalize_url ──────────────────────────────────────────────────

class TestNormalizeUrl:
    def test_adds_https(self):
        assert zc.normalize_url("example.com") == "https://example.com"

    def test_keeps_http(self):
        assert zc.normalize_url("http://example.com") == "http://example.com"

    def test_strips_trailing_slash(self):
        assert zc.normalize_url("https://example.com/") == "https://example.com"

    def test_rejects_empty(self):
        assert zc.normalize_url("") == ""
        assert zc.normalize_url(None) == ""

    def test_rejects_javascript_scheme(self):
        assert zc.normalize_url("javascript:alert(1)") == ""

    def test_rejects_file_scheme(self):
        assert zc.normalize_url("file:///etc/passwd") == ""

    def test_keeps_host_port(self):
        assert zc.normalize_url("localhost:8080") == "https://localhost:8080"

    def test_keeps_path(self):
        out = zc.normalize_url("https://example.com/app/")
        assert out == "https://example.com/app"


# ── proxies ────────────────────────────────────────────────────────

class TestProxies:
    def teardown_method(self):
        zc.load_proxy_list([])

    def test_empty_by_default(self):
        zc.load_proxy_list([])
        assert zc.proxy_count() == 0
        assert zc.get_next_proxy() is None

    def test_round_robin(self):
        zc.load_proxy_list(["http://a:1", "http://b:2"])
        assert zc.proxy_count() == 2
        first = zc.get_next_proxy()
        second = zc.get_next_proxy()
        third = zc.get_next_proxy()
        assert first != second
        assert first == third

    def test_bare_host_becomes_http(self):
        zc.load_proxy_list(["1.2.3.4:8080"])
        assert zc.get_next_proxy() == {"http": "http://1.2.3.4:8080",
                                       "https": "http://1.2.3.4:8080"}


# ── misc ───────────────────────────────────────────────────────────

class TestMisc:
    def test_random_string_length_and_charset(self):
        s = zc.random_string(12)
        assert len(s) == 12
        assert s.isalpha() and s.islower()

    def test_get_verify_tracks_ignore_ssl(self):
        zc.set_ignore_ssl(True)
        assert zc.get_verify() is False
        zc.set_ignore_ssl(False)
        assert zc.get_verify() is True
        zc.set_ignore_ssl(True)

    def test_set_jitter_controls_sleep(self):
        import time
        zc.set_jitter(0.0, 0.0)
        t = time.time()
        zc.jitter()
        assert time.time() - t < 0.05
        zc.set_jitter()
