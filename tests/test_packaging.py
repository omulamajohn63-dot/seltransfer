"""Verify the distribution actually ships the browser client.

A non-editable install previously lost ``web/`` entirely, which made ``/`` fall
back to a JSON stub and made ``/static/*`` 404. These tests build a real wheel
from a copy of the tree so a packaging regression fails here rather than on a
user's machine.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seltransfer.server.app import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS = ("seltransfer/web/templates/index.html", "seltransfer/web/static/app.js",
          "seltransfer/web/static/style.css")


def _stage_source_tree(destination: Path) -> Path:
    """Copy only what a build needs so the real tree is never mutated."""
    shutil.copy2(REPO_ROOT / "pyproject.toml", destination / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "README.md", destination / "README.md")
    shutil.copy2(REPO_ROOT / "MANIFEST.in", destination / "MANIFEST.in")
    license_file = REPO_ROOT / "LICENSE"
    if license_file.exists():
        shutil.copy2(license_file, destination / "LICENSE")
    shutil.copytree(
        REPO_ROOT / "src" / "seltransfer",
        destination / "src" / "seltransfer",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
    )
    return destination


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> zipfile.ZipFile:
    build_root = _stage_source_tree(tmp_path_factory.mktemp("dist"))
    from setuptools import build_meta

    previous_cwd = Path.cwd()
    os.chdir(build_root)
    try:
        name = build_meta.build_wheel(str(build_root / "wheel"))
    finally:
        os.chdir(previous_cwd)
    return zipfile.ZipFile(build_root / "wheel" / name)


def test_wheel_contains_browser_assets(built_wheel: zipfile.ZipFile) -> None:
    names = set(built_wheel.namelist())
    missing = [asset for asset in ASSETS if asset not in names]
    assert not missing, f"wheel is missing browser assets: {missing}"


def test_wheel_omits_bytecode_and_egginfo(built_wheel: zipfile.ZipFile) -> None:
    offenders = [
        name for name in built_wheel.namelist()
        if "__pycache__" in name or name.endswith((".pyc", ".pyo"))
    ]
    assert not offenders, f"wheel contains build cruft: {offenders[:5]}"


def test_installed_app_serves_html_and_static_assets() -> None:
    """The app must find its web assets through the installed package path."""
    app = create_app(server_port=8799, local_address="127.0.0.1")
    client = TestClient(app)

    index = client.get("/")
    assert index.status_code == 200
    assert index.headers["content-type"].startswith("text/html")
    assert "SELTRANSFER" in index.text

    for asset, content_type in (("/static/app.js", "javascript"),
                                ("/static/style.css", "text/css")):
        response = client.get(asset)
        assert response.status_code == 200, f"{asset} returned {response.status_code}"
        assert content_type in response.headers["content-type"]


def test_declared_package_data_covers_web_assets() -> None:
    """Guard the declaration itself so a rename cannot silently drop assets."""
    config = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.setuptools.package-data]" in config
    assert "web/templates/*.html" in config
    assert "web/static/*" in config
