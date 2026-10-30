"""Shared fixtures for the ZAS test suite."""

import importlib.util
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXPLOITS = os.path.join(ROOT, "exploits")
LIB = os.path.join(ROOT, "lib")
CORE = os.path.join(ROOT, "core")

for p in (ROOT, EXPLOITS, LIB, CORE):
    if p not in sys.path:
        sys.path.insert(0, p)

SKIP = {"zas_core", "base", "registry", "zas_bypass", "zas_cleanup"}


def module_names():
    """Every GUI-visible exploit module, minus the shared internals."""
    out = []
    for f in sorted(os.listdir(EXPLOITS)):
        if not f.endswith(".py") or f.startswith("_"):
            continue
        m = f[:-3]
        if m in SKIP:
            continue
        out.append(m)
    return out


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(EXPLOITS, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def all_modules():
    return module_names()


@pytest.fixture(scope="session")
def module_loader():
    return load_module


@pytest.fixture(scope="session")
def langflow_internal_names():
    return sorted(f[:-3] for f in os.listdir(EXPLOITS)
                  if f.startswith("_lf_") and f.endswith(".py"))


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: hits the network; deselect with -m 'not slow'")
