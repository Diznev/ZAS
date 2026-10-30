"""Tests for exploits/registry.py — plugin name classification."""

import pytest

import registry


class TestClassify:
    @pytest.mark.parametrize("name,expect", [
        ("wpvivid-backuprestore", "wordpress"),
        ("forminator", "wordpress"),
        ("wpforms-pro", "wordpress"),
        ("wordpress-core", "wordpress"),
        ("drag-and-drop-file-upload-for-elementor-forms", "wordpress"),
        ("blocksy-companion", "wordpress"),
        ("simple-file-list", "wordpress"),
        ("joomla com_media", "joomla"),
        ("com_baforms", "joomla"),
        ("mod_login", "joomla"),
        ("com_acym", "joomla"),
        ("langflow", "other"),
        ("n8n", "other"),
        ("next.js", "other"),
        ("vbulletin", "other"),
        ("struts", "other"),
        ("teamcity", "other"),
    ])
    def test_known_names(self, name, expect):
        assert registry.classify(name) == expect

    def test_case_insensitive(self):
        assert registry.classify("WPVIVID-BACKUPRESTORE") == "wordpress"

    def test_unknown_falls_back_to_other(self):
        assert registry.classify("some-unknown-product") == "other"

    def test_empty_is_other(self):
        assert registry.classify("") == "other"

    def test_substring_matching_for_registered_keys(self):
        # the registry matches by substring, so a plugin slug embedded in a
        # longer name still classifies
        assert registry.classify("premium-wpforms-pro-extension") == "wordpress"

    def test_returns_a_string(self):
        assert isinstance(registry.classify("anything"), str)


class TestRegister:
    def test_register_makes_classify_aware(self):
        registry.register("tmp-test-plugin-xyz", "wordpress")
        try:
            assert registry.classify("tmp-test-plugin-xyz") == "wordpress"
        finally:
            registry._CATEGORIES.pop("tmp-test-plugin-xyz", None)

    def test_register_lowercases(self):
        registry.register("TMP-Upper", "joomla")
        try:
            assert registry.classify("tmp-upper") == "joomla"
        finally:
            registry._CATEGORIES.pop("tmp-upper", None)
