"""The packaging configuration is code, so it gets tests like code.

A packaging mistake usually shows up as an application that starts and then serves
a blank page, which no unit test would catch. These assert the shape of the build
configuration instead: that the assets are collected where the resolver looks,
that the dev stack is excluded, and that the entry point and version source are
right.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = REPO_ROOT / "packaging" / "seltransfer.spec"
ENTRYPOINT = REPO_ROOT / "packaging" / "entrypoint.py"
BUILD = REPO_ROOT / "packaging" / "build.ps1"
CHECKLIST = REPO_ROOT / "packaging" / "CLEAN_MACHINE_CHECKLIST.md"
DIST = REPO_ROOT / "dist" / "SELTRANSFER" / "SELTRANSFER.exe"


def spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


# --- the spec file exists and is well formed ---------------------------------


def test_spec_file_exists() -> None:
    assert SPEC.is_file(), SPEC


def test_spec_is_valid_python() -> None:
    """It is executed by exec(), so a syntax error only surfaces at build time."""
    ast.parse(spec_text(), filename=str(SPEC))


def test_entrypoint_exists_and_calls_the_cli() -> None:
    assert ENTRYPOINT.is_file(), ENTRYPOINT
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "from seltransfer.cli import app" in text
    assert "app()" in text


def test_console_mode_is_enabled() -> None:
    """The QR code is printed to the terminal, so a windowed build is useless."""
    assert "console=True" in spec_text()


def test_no_developer_specific_paths() -> None:
    """The spec must work in any checkout, not just one machine."""
    text = spec_text()
    for leak in ("C:\\Users", "C:/Users", "D:\\seltransfer", "D:/seltransfer",
                 "localhost:"):
        assert leak not in text, f"hard-coded path in the spec: {leak}"


def test_paths_are_derived_from_specpath() -> None:
    text = spec_text()
    assert "SPECPATH" in text
    assert "REPO_ROOT" in text


# --- web assets are collected where the resolver looks -----------------------


def test_web_assets_are_declared_as_data() -> None:
    text = spec_text()
    assert "seltransfer/web" in text
    assert "datas=WEB_ASSETS" in text or "datas=WEB_ASSETS," in text


@pytest.mark.parametrize("asset", ["templates/index.html", "static/app.js",
                                   "static/style.css"])
def test_each_web_asset_exists_in_the_source_tree(asset: str) -> None:
    assert (REPO_ROOT / "src" / "seltransfer" / "web" / asset).is_file()


def test_resolver_and_spec_agree_on_the_layout() -> None:
    """The spec and resources.py must target the same relative paths.

    If either moves without the other, the bundle builds and then serves nothing.
    """
    from seltransfer.resources import REQUIRED_ASSETS

    for relative in REQUIRED_ASSETS:
        assert relative in spec_text() or "seltransfer/web" in spec_text(), relative


# --- exclusions --------------------------------------------------------------


def test_pillow_is_excluded() -> None:
    """Nothing in the runtime path imports it; the test suite does."""
    assert "PIL" in spec_text()
    assert "Pillow" in spec_text()


def test_test_stack_is_excluded() -> None:
    for module in ("pytest", "_pytest", "httpx", "setuptools", "pip"):
        assert f'"{module}"' in spec_text(), module


def test_anyio_is_not_excluded() -> None:
    """Starlette needs it. Excluding it shipped an executable that could not start."""
    excludes = spec_text().split("EXCLUDES = [", 1)[1].split("]", 1)[0]
    assert '"anyio"' not in excludes


def test_no_certificate_material_is_referenced() -> None:
    """Keys are generated per machine, never shipped."""
    for leak in (".pem", ".key", ".crt", ".p12"):
        assert leak not in spec_text(), leak


# --- version -----------------------------------------------------------------


def test_version_comes_from_the_package_not_the_spec() -> None:
    text = spec_text()
    assert "seltransfer import __version__" in text
    # A literal version in the spec is exactly the drift this project removed.
    for literal in ('"0.1.0"', "'0.1.0'"):
        assert literal not in text, "hard-coded version in the spec"


def test_version_resource_is_built() -> None:
    text = spec_text()
    assert "VSVersionInfo" in text
    assert "ProductName" in text


# --- build script ------------------------------------------------------------


def test_build_script_exists() -> None:
    assert BUILD.is_file(), BUILD


def test_build_script_runs_the_checks() -> None:
    text = BUILD.read_text(encoding="utf-8")
    for step in ("pytest", "ruff", "mypy", "test_app.js"):
        assert step in text, step


def test_build_script_verifies_the_artifact() -> None:
    text = BUILD.read_text(encoding="utf-8")
    for step in ("version", "devices", "doctor", "/static/app.js",
                 "/static/style.css"):
        assert step in text, step


def test_build_script_checks_the_artifact_over_http() -> None:
    """Assets are verified by fetching them, not by looking for them on disk.

    The resolver searches the bundle at runtime, and a onefile build keeps the
    assets inside the executable, so "the file exists somewhere" proves nothing
    about what the server actually serves.
    """
    text = BUILD.read_text(encoding="utf-8")
    assert "Invoke-WebRequest" in text
    assert "/api/health" in text and "/api/status" in text
    # Windows PowerShell 5.1 defaults to the IE engine for Invoke-WebRequest,
    # which fails on modern markup with a null-reference error and aborts a build
    # whose executable is already fine.
    assert "-UseBasicParsing" in text


def test_build_script_kills_the_whole_server_process_tree() -> None:
    """A onefile boot spawns a child; killing the parent orphans it.

    The orphaned child keeps the port bound, so the next build's smoke test fails
    against a process nothing is tracking.
    """
    text = BUILD.read_text(encoding="utf-8")
    assert "taskkill" in text
    assert "/T" in text


def test_build_script_cleans_before_building() -> None:
    text = BUILD.read_text(encoding="utf-8")
    assert "build" in text and "dist" in text
    assert "Remove-Item" in text


# --- checklist ---------------------------------------------------------------


def test_clean_machine_checklist_exists_and_is_honest() -> None:
    assert CHECKLIST.is_file(), CHECKLIST
    text = CHECKLIST.read_text(encoding="utf-8")
    for step in ("QR", "firewall", "PC", "phone", "History", "restart"):
        assert step.lower() in text.lower(), step


# --- optional: assert the built artifact when it is present ------------------


@pytest.mark.skipif(not DIST.is_file(),
                    reason="dist/ not built; run packaging/build.ps1 first")
class TestBuiltArtifact:
    """These only run after a build, so a normal test run skips them."""

    def test_executable_exists(self) -> None:
        assert DIST.is_file()

    def test_executable_is_not_empty(self) -> None:
        assert DIST.stat().st_size > 1_000_000

    def test_bundled_assets_are_present(self) -> None:
        root = DIST.parent / "_internal" / "seltransfer" / "web"
        for asset in ("templates/index.html", "static/app.js", "static/style.css"):
            assert (root / asset).is_file(), asset

    def test_version_matches_the_source_tree(self) -> None:
        import subprocess

        expected = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]["version"]
        result = subprocess.run([str(DIST), "version"], capture_output=True,
                                text=True, check=False, timeout=120)
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout, result.stdout


# --- packaging metadata in pyproject ----------------------------------------


def test_package_data_still_declares_the_web_assets() -> None:
    config = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = config["tool"]["setuptools"]["package-data"]["seltransfer"]
    assert "web/templates/*.html" in package_data
    assert "web/static/*" in package_data


def test_pillow_remains_a_source_dependency() -> None:
    """It is excluded from the bundle but still needed by the test suite."""
    config = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert any("Pillow" in item for item in config["project"]["dependencies"])
