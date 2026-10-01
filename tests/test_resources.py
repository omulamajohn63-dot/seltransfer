"""Asset resolution must work in a source install and in a frozen bundle.

A packaging bug here is silent: the server starts and serves a blank page.
These tests pin both halves of the contract - finding the real assets, and
failing loudly when they are absent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from seltransfer import resources


def test_web_root_contains_every_required_asset() -> None:
    root = resources.web_root()
    assert root.is_dir(), root
    for name in resources.REQUIRED_ASSETS:
        assert (root / name).is_file(), f"missing {name} under {root}"


def test_static_and_templates_agree_with_web_root() -> None:
    assert resources.static_root() == resources.web_root() / "static"
    assert resources.templates_root() == resources.web_root() / "templates"
    assert resources.index_file() == resources.web_root() / "templates" / "index.html"
    assert resources.index_file().is_file()


def test_frozen_onefile_prefers_the_extraction_directory(tmp_path, monkeypatch) -> None:
    """A PyInstaller one-file build extracts to a temp dir holding the datas."""
    bundle = tmp_path / "_MEI12345"
    for name in resources.REQUIRED_ASSETS:
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("stub", encoding="utf-8")

    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    assert resources.web_root() == bundle


def test_frozen_onedir_uses_the_executable_directory(tmp_path, monkeypatch) -> None:
    """A one-dir build keeps the collected data next to the executable."""
    exe_dir = tmp_path / "SELTRANSFER"
    bundle = exe_dir / "_internal"
    for name in resources.REQUIRED_ASSETS:
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("stub", encoding="utf-8")

    fake_exe = exe_dir / "SELTRANSFER.exe"
    fake_exe.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", "", raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe))
    assert resources.web_root() == bundle


def test_missing_assets_raise_a_clear_error(tmp_path, monkeypatch) -> None:
    """An incomplete bundle must fail at startup, not serve a blank page."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(sys, "_MEIPASS", str(empty), raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(empty / "SELTRANSFER.exe"))
    # Also disable the source-tree fallback so nothing complete can be found.
    monkeypatch.setattr(resources, "_candidate_roots", lambda: [empty])

    with pytest.raises(RuntimeError, match="web assets"):
        resources.web_root()


def test_incomplete_bundle_names_the_missing_files(tmp_path, monkeypatch) -> None:
    partial = tmp_path / "partial"
    (partial / "static").mkdir(parents=True)
    (partial / "static" / "app.js").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(resources, "_candidate_roots", lambda: [partial])

    with pytest.raises(RuntimeError) as error:
        resources.web_root()
    message = str(error.value)
    assert "index.html" in message
    assert "style.css" in message


def test_describe_reports_asset_status() -> None:
    described = resources.describe()
    assert set(described) == {"web_root", "frozen", "executable", "assets"}
    assert "MISSING" not in described["assets"], described


def test_server_serves_the_resolved_index(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "SELTRANSFER" in response.text


def test_server_serves_the_resolved_static_files(client) -> None:
    for path, expected in (("/static/style.css", "text/css"),
                           ("/static/app.js", "javascript")):
        response = client.get(path)
        assert response.status_code == 200, path
        assert expected in response.headers["content-type"], path
        assert response.content, path


def test_app_no_longer_derives_paths_from_dunder_file() -> None:
    """Guard the specific bug: the resolver, not __file__, owns asset paths."""
    source = Path("src/seltransfer/server/app.py")
    if not source.exists():  # pragma: no cover - run from elsewhere
        pytest.skip("source tree not available")
    text = source.read_text(encoding="utf-8")
    assert "__file__" not in text, (
        "app.py must not build asset paths from __file__; use resources.py")
