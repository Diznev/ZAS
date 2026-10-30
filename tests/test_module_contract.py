"""Contract tests every ZAS exploit module must satisfy.

The honesty rule is the point of this suite: a module may only claim
success it can prove, and it must never crash on a dead target.
"""

import inspect

import pytest


REQUIRED_INFO_KEYS = {"cve", "name", "plugin", "severity", "description", "tags"}
SEVERITIES = {"critical", "high"}


@pytest.mark.parametrize("name", __import__("conftest").module_names())
class TestModuleContract:
    def test_loads(self, name, module_loader):
        mod = module_loader(name)
        assert mod is not None

    def test_info_is_callable(self, name, module_loader):
        assert callable(module_loader(name).info)

    def test_exploit_is_callable(self, name, module_loader):
        assert callable(module_loader(name).exploit)

    def test_no_detect_left(self, name, module_loader):
        # Detect/Audit modes were removed; modules must not expose detect()
        assert not hasattr(module_loader(name), "detect")

    def test_info_shape(self, name, module_loader):
        info = module_loader(name).info()
        assert isinstance(info, dict)
        missing = REQUIRED_INFO_KEYS - set(info)
        assert not missing, f"{name} info() missing keys: {missing}"

    def test_info_values_are_strings(self, name, module_loader):
        info = module_loader(name).info()
        for k in ("cve", "name", "plugin", "severity", "description"):
            assert isinstance(info[k], str) and info[k].strip(), f"{name}.{k} empty"
        assert isinstance(info["tags"], list)

    def test_severity_is_known(self, name, module_loader):
        sev = module_loader(name).info()["severity"]
        assert sev in SEVERITIES, f"{name} severity {sev!r}"

    def test_exploit_signature(self, name, module_loader):
        sig = inspect.signature(module_loader(name).exploit)
        params = list(sig.parameters)
        assert params[0] == "url"
        assert "timeout" in params
        assert "proxies" in params
        # must accept the GUI's extra_args without TypeError
        assert any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())

    def test_cve_field_is_not_a_placeholder(self, name, module_loader):
        cve = module_loader(name).info()["cve"]
        assert "PLACEHOLDER" not in cve.upper()
        assert "TODO" not in cve.upper()


@pytest.mark.slow
@pytest.mark.parametrize("name", __import__("conftest").module_names())
class TestDeadHostSafety:
    """A dead target must never be reported as a success.

    One combined test per module rather than three: each call has to make a
    network round trip, and 85 x 3 of them made this suite take longer than
    the whole rest of the test run put together.
    """

    def test_dead_host_never_yields_success(self, name, module_loader):
        try:
            r = module_loader(name).exploit("http://127.0.0.1:59999", timeout=1)
        except Exception as e:
            pytest.fail(f"{name} raised {type(e).__name__}: {e}")
        assert isinstance(r, dict), f"{name} returned {type(r).__name__}, not a dict"
        assert r.get("ok") is False, f"{name} claimed success on a dead host: {r}"
        assert r.get("reason") or r.get("note"), f"{name} gave no reason for failure"
