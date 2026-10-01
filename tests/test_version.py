"""The application version must come from exactly one place.

Four modules used to carry their own "0.1.0" literal: ``__init__``,
``devices.Device``, the FastAPI schema in ``server.app``, and ``pyproject.toml``.
They drifted silently. These tests fail if any of them diverges again.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import seltransfer
from seltransfer.devices import Device

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version_is_a_usable_release_string() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+([-+].*)?", seltransfer.__version__), (
        seltransfer.__version__)


def test_version_matches_pyproject() -> None:
    """pyproject is the real source of truth for a source install."""
    declared = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert seltransfer.__version__ == declared, (
        f"__version__={seltransfer.__version__!r} but pyproject declares {declared!r}. "
        "Reinstall the package so importlib.metadata is current.")


def test_no_hardcoded_version_literals_remain() -> None:
    """Guard against a module reintroducing its own copy of the version."""
    sources = sorted((REPO_ROOT / "src" / "seltransfer").rglob("*.py"))
    offenders: list[str] = []
    for path in sources:
        if path.name == "__init__.py":
            continue  # the single source, plus its documented fallback
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(r'["\']\d+\.\d+\.\d+["\']', line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, "hardcoded version literals found:\n" + "\n".join(offenders)


def test_device_version_matches_package() -> None:
    assert Device(device_id="x" * 8, name="n", type="computer").version == \
        seltransfer.__version__


def test_fastapi_schema_version_matches_package() -> None:
    from seltransfer.server.app import create_app

    assert create_app(server_port=8999, local_address="127.0.0.1").version == \
        seltransfer.__version__


def test_status_endpoint_reports_the_same_version(client) -> None:
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json()["version"] == seltransfer.__version__


def test_frozen_fallback_is_defined_and_pinned() -> None:
    """A PyInstaller build is not an installed distribution.

    The metadata lookup therefore raises PackageNotFoundError and the module
    falls back to FALLBACK_VERSION. That path is what a frozen exe depends on, so
    the value must stay a real release string.
    """
    assert re.fullmatch(r"\d+\.\d+\.\d+([-+].*)?", seltransfer.FALLBACK_VERSION)
    assert seltransfer.FALLBACK_VERSION == tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"], (
        "the frozen fallback drifted from pyproject; update both together")


def test_fallback_is_used_when_metadata_is_unavailable(monkeypatch) -> None:
    """Simulate the frozen case by making the metadata lookup fail."""
    import importlib
    import importlib.metadata

    def boom(_name: str) -> str:
        raise PackageNotFoundError("seltransfer")

    monkeypatch.setattr(importlib.metadata, "version", boom)
    reloaded = importlib.reload(seltransfer)
    try:
        assert reloaded.__version__ == seltransfer.FALLBACK_VERSION
    finally:
        monkeypatch.undo()
        importlib.reload(seltransfer)


def test_cli_version_command_uses_the_package_version() -> None:
    from seltransfer import cli

    assert cli.__version__ == seltransfer.__version__
