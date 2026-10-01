"""Test-suite isolation guards.

Before ``tests/conftest.py`` the suite had no isolation at all: every
``create_app()`` call read and wrote the real ``~/.seltransfer``, so a test run
created a real ``device-id``, wrote history rows, and left received files on the
developer's disk. These tests fail if that ever comes back.
"""

from __future__ import annotations

import os
from pathlib import Path

from seltransfer.config import get_settings, resolve_app_dir
from tests.conftest import make_app


def test_app_dir_is_redirected_for_the_whole_session(isolated_app_dir: Path) -> None:
    """The autouse fixture must win over the real home directory."""
    assert os.environ["SELTRANSFER_APP_DIR"] == str(isolated_app_dir)
    assert Path(get_settings().app_dir) == isolated_app_dir
    assert resolve_app_dir() == isolated_app_dir


def test_app_dir_is_not_the_real_home(isolated_app_dir: Path) -> None:
    """A test must never resolve to the genuine ~/.seltransfer."""
    real = Path.home() / ".seltransfer"
    assert isolated_app_dir != real
    assert not str(isolated_app_dir).startswith(str(real))


def test_creating_an_app_writes_only_inside_the_temp_dir(tmp_path) -> None:
    """Device identity lands under the redirected app dir, not the real home."""
    make_app(tmp_path)
    root = Path(get_settings().app_dir)
    # create_local_device writes the persistent identity here.
    assert (root / "device-id").is_file()
    assert root != Path.home() / ".seltransfer"


def test_history_db_is_confined_to_the_test_directory(tmp_path) -> None:
    """make_app repoints the history store at the test's own tmp_path."""
    app = make_app(tmp_path)
    assert Path(app.state.history.path) == tmp_path / "history.db"
    assert not Path(app.state.history.path).is_relative_to(Path.home() / ".seltransfer")


def test_downloads_are_confined_to_the_test_directory(tmp_path) -> None:
    app = make_app(tmp_path)
    assert app.state.transfers.download_root == tmp_path / "downloads"
    assert not app.state.transfers.download_root.is_relative_to(
        Path.home() / ".seltransfer")


def test_received_files_land_in_the_test_directory(tmp_path) -> None:
    """The strongest form: a real transfer writes nowhere near the real home."""
    from tests.conftest import make_app as _make_app

    app = _make_app(tmp_path)
    manager = app.state.transfers
    transfer = manager.create("sender", "receiver",
                              [{"name": "x.txt", "size": 3, "sha256": None}])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")

    import asyncio

    async def stream():
        yield b"abc"

    token = manager.get(transfer["transfer_id"])["token"]
    asyncio.run(manager.receive_file(transfer["transfer_id"], 0, stream(), token))

    written = list(manager.download_root.rglob("x.txt"))
    assert written, "file was not written"
    for path in written:
        assert path.is_relative_to(tmp_path)


def test_device_identity_is_created_in_the_temp_dir(tmp_path) -> None:
    """The identity file the app creates must be the temp one, never the real one."""
    make_app(tmp_path)
    assert (Path(get_settings().app_dir) / "device-id").is_file()
    assert not (Path(get_settings().app_dir) / "device-id").is_relative_to(
        Path.home() / ".seltransfer")
