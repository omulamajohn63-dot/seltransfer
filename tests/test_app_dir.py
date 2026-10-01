"""Where user data lives, and what creates it.

Two changes are pinned here. The default moved to the platform-correct
per-user location (``%LOCALAPPDATA%\\SELTRANSFER`` on Windows) so a packaged
build never writes beside its own executable, and directory creation moved out of
import time so that merely importing the package touches nothing on disk.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

from seltransfer import config
from seltransfer.config import (
    Settings,
    ensure_app_dir,
    get_settings,
    resolve_app_dir,
)


def test_env_override_wins(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SELTRANSFER_APP_DIR", str(tmp_path / "custom"))
    assert resolve_app_dir() == tmp_path / "custom"


def test_env_override_is_expanded(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("SELTRANSFER_APP_DIR", "~/somewhere")
    assert "~" not in str(resolve_app_dir())


def test_windows_default_uses_localappdata(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SELTRANSFER_APP_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    expected = tmp_path / "AppData" / "Local" / "SELTRANSFER"
    assert resolve_app_dir() == expected


def test_windows_falls_back_when_localappdata_is_unset(monkeypatch, tmp_path) -> None:
    """A service context with no LOCALAPPDATA must not crash the app."""
    monkeypatch.delenv("SELTRANSFER_APP_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert resolve_app_dir() == tmp_path / ".seltransfer"


@pytest.mark.parametrize("platform_value", ["linux", "darwin", "freebsd13"])
def test_posix_default_uses_dot_directory(monkeypatch, tmp_path, platform_value) -> None:
    monkeypatch.delenv("SELTRANSFER_APP_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", platform_value)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert resolve_app_dir() == tmp_path / ".seltransfer"


def test_platform_hint_is_ignored_everywhere(monkeypatch, tmp_path) -> None:
    """An untrusted hint must never redirect the data directory."""
    monkeypatch.delenv("SELTRANSFER_APP_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    baseline = resolve_app_dir()
    for hint in ("Android", "iOS", "Windows", "../../etc", ""):
        assert resolve_app_dir(hint) == baseline


def test_importing_config_creates_no_directory(monkeypatch, tmp_path) -> None:
    """The import-time mkdir side effect is gone.

    It used to mean that any process importing the package - including the test
    suite - created a directory in the user's real home.
    """
    home = tmp_path / "home"
    home.mkdir()
    target = home / ".seltransfer"
    monkeypatch.delenv("SELTRANSFER_APP_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    importlib.reload(config)
    importlib.reload(config)
    assert not target.exists(), "importing the module must not touch the filesystem"


def test_ensure_app_dir_creates_the_directory(monkeypatch, tmp_path) -> None:
    target = tmp_path / "made" / "on" / "demand"
    monkeypatch.setenv("SELTRANSFER_APP_DIR", str(target))
    assert not target.exists()
    assert ensure_app_dir() == target
    assert target.is_dir()


def test_ensure_app_dir_is_idempotent(monkeypatch, tmp_path) -> None:
    target = tmp_path / "again"
    monkeypatch.setenv("SELTRANSFER_APP_DIR", str(target))
    ensure_app_dir()
    marker = target / "marker"
    marker.write_text("keep", encoding="utf-8")
    ensure_app_dir()
    assert marker.read_text(encoding="utf-8") == "keep"


def test_settings_derive_history_path_from_app_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SELTRANSFER_APP_DIR", str(tmp_path))
    settings = get_settings()
    assert settings.app_dir == tmp_path
    assert settings.transfer_history_db == tmp_path / "history.db"


def test_app_dir_is_not_inside_the_source_tree() -> None:
    """Data must never be written beside the code, packaged or not."""
    source = Path(__file__).resolve().parents[1]
    resolved = resolve_app_dir().resolve()
    assert source not in resolved.parents, resolved
    assert resolved != source, resolved


# --- new limit settings ------------------------------------------------------


def test_resource_limit_settings_exist_with_safe_defaults() -> None:
    settings = Settings()
    assert settings.max_tracked_transfers > 0
    assert settings.max_pending_incoming > 0
    assert settings.max_browser_sessions > 0
    assert settings.max_webrtc_sessions > 0
    assert settings.expose_paths is False
    assert settings.pairing_code_ttl_seconds > 0
    assert settings.pairing_ttl_seconds > 0


def test_limits_are_overridable_by_environment(monkeypatch) -> None:
    monkeypatch.setenv("SELTRANSFER_MAX_PENDING_INCOMING", "3")
    monkeypatch.setenv("SELTRANSFER_MAX_TRACKED_TRANSFERS", "7")
    settings = Settings()
    assert settings.max_pending_incoming == 3
    assert settings.max_tracked_transfers == 7


def test_settings_env_prefix_is_unchanged() -> None:
    """A prefix change would silently break every existing override."""
    assert Settings.model_config["env_prefix"] == "SELTRANSFER_"


def test_app_dir_constant_matches_folder_name() -> None:
    assert config.APP_DIR_NAME == "SELTRANSFER"
    assert os.path.sep in str(resolve_app_dir()) or sys.platform == "win32"
