"""Tests for exploits/other_langflow_rce.py — the version-dispatching facade."""

import pytest

import other_langflow_rce as facade


class TestInfo:
    def test_lists_every_chain_cve(self):
        listed = facade.info()["cve"]
        for _, cve, *_ in facade.CHAINS:
            assert cve in listed, f"{cve} missing from info()"

    def test_chain_count_matches_table(self):
        assert len(facade.CHAINS) == 12

    def test_names_the_dispatch(self):
        assert "version" in facade.info()["name"].lower()

    def test_shape(self):
        info = facade.info()
        for k in ("cve", "name", "plugin", "severity", "description", "tags"):
            assert info.get(k), k


class TestParseVer:
    @pytest.mark.parametrize("s,want", [
        ("1.10.3", (1, 10, 3)),
        ("1.3.2", (1, 3, 2)),
        ("1.4", (1, 4, 0)),
        ("v1.10.3", (1, 10, 3)),
        ("1.10.3-snapshot", (1, 10, 3)),
    ])
    def test_parses(self, s, want):
        assert facade._parse_ver(s) == want

    @pytest.mark.parametrize("s", [None, "", "abc", "not-a-version"])
    def test_bad_input_is_none(self, s):
        assert facade._parse_ver(s) is None


class TestInRange:
    def test_none_version_never_matches(self):
        assert facade._in_range(None, (1, 0, 0), None) is False

    def test_unbounded(self):
        assert facade._in_range((1, 9, 0), None, None) is True

    def test_lower_bound(self):
        assert facade._in_range((1, 4, 0), (1, 5, 0), None) is False
        assert facade._in_range((1, 5, 0), (1, 5, 0), None) is True

    def test_upper_bound_inclusive(self):
        assert facade._in_range((1, 7, 3), (1, 0, 0), (1, 7, 3)) is True
        assert facade._in_range((1, 7, 4), (1, 0, 0), (1, 7, 3)) is False


class TestDispatch:
    """The version->chain table is the whole point of the facade, so the
    boundaries are pinned here."""

    def test_exact_version_chains_fire_first(self):
        c = facade._candidates((1, 3, 2), has_creds=False)
        assert c, "1.3.2 must match something"
        assert c[0][3] == "CVE-2026-0769"

    def test_exact_1_4_2(self):
        c = facade._candidates((1, 4, 2), has_creds=False)
        assert c[0][3] == "CVE-2026-0768"

    def test_unauthenticated_before_authenticated(self):
        c = facade._candidates((1, 9, 0), has_creds=True)
        flags = [t[0] for t in c]
        assert flags == sorted(flags), "pre-auth chains must come first"

    def test_authenticated_chains_excluded_without_creds(self):
        c = facade._candidates((1, 10, 0), has_creds=False)
        cves = [t[3] for t in c]
        assert "CVE-2026-7873" not in cves   # auth-only
        assert "CVE-2026-18729" not in cves  # auth-only

    def test_authenticated_chains_included_with_creds(self):
        c = facade._candidates((1, 10, 0), has_creds=True)
        cves = [t[3] for t in c]
        assert "CVE-2026-7873" in cves

    def test_patched_version_matches_nothing(self):
        assert facade._candidates((1, 12, 0), has_creds=True) == []

    def test_blind_chain_flagged(self):
        c = facade._candidates((1, 6, 0), has_creds=True)
        labels = {t[3]: t[4] for t in c}
        assert "blind" in labels.get("CVE-2026-93674", "")

    def test_cve_93674_window(self):
        # 1.5.0-1.9.0 only, per the upstream module
        assert any(t[3] == "CVE-2026-93674"
                   for t in facade._candidates((1, 5, 0), True))
        assert any(t[3] == "CVE-2026-93674"
                   for t in facade._candidates((1, 9, 0), True))
        assert not any(t[3] == "CVE-2026-93674"
                       for t in facade._candidates((1, 4, 9), True))
        assert not any(t[3] == "CVE-2026-93674"
                       for t in facade._candidates((1, 9, 1), True))


class TestExploit:
    def test_dead_host_reports_no_version(self):
        r = facade.exploit("http://127.0.0.1:59999", timeout=2)
        assert r["ok"] is False
        assert r["version"] == "unknown"
        assert "could not read" in r["reason"]

    def test_result_shape(self):
        r = facade.exploit("http://127.0.0.1:59999", timeout=2)
        for k in ("ok", "url", "method", "reason"):
            assert k in r, k

    def test_url_is_normalized(self):
        r = facade.exploit("http://127.0.0.1:59999/", timeout=2)
        assert r["url"] == "http://127.0.0.1:59999"

    def test_all_internals_are_importable(self, langflow_internal_names):
        import importlib
        for n in langflow_internal_names:
            importlib.import_module(n)
