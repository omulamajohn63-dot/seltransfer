"""Shared pytest fixtures.

The suite used to construct the application nine different ways and, with no
conftest at all, every run wrote ``device-id``, ``history.db`` rows, and received
files into the developer's real ``~/.seltransfer``. The autouse fixture below
redirects ``SELTRANSFER_APP_DIR`` for the whole session, and ``make_app`` gives
every test module one way to build an isolated app.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from seltransfer.server.app import create_app
from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager

# Ports are decorative: TestClient never binds them. They only end up in the
# device record, so each fixture uses a distinct one to keep assertions readable.
DEFAULT_TEST_PORT = 8765


@pytest.fixture(autouse=True)
def isolated_app_dir(tmp_path_factory, monkeypatch) -> Path:
    """Point SELTRANSFER_APP_DIR at a temporary directory for the whole session.

    ``monkeypatch`` is function-scoped, so this is applied per test. It has to run
    before any ``create_app`` call, which autouse ordering guarantees.
    """
    root = tmp_path_factory.mktemp("seltransfer-session")
    monkeypatch.setenv("SELTRANSFER_APP_DIR", str(root))
    return root


def make_app(tmp_path: Path, port: int = DEFAULT_TEST_PORT,
             local_address: str = "127.0.0.1", **kwargs: Any):
    """Build an app whose mutable state is confined to ``tmp_path``.

    Replaces the per-module copies of this fixture. The app is created normally so
    that real wiring (device identity, CORS, middleware) is exercised, then its
    history and transfer stores are repointed at the temporary directory.
    """
    app = create_app(server_port=port, local_address=local_address, **kwargs)
    history = HistoryStore(tmp_path / "history.db")
    app.state.history = history
    app.state.transfers = TransferManager(tmp_path / "downloads", history)
    return app


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


# A TestClient's peer address decides what the server believes about the caller:
# a loopback peer is this machine's own user, anything else is a device on the LAN.
# `_is_local_user` turns that into the authority to pair, so tests that care about
# pairing must pick the right one deliberately.
LOOPBACK_CLIENT = ("127.0.0.1", 51000)
LAN_CLIENT = ("192.168.1.99", 51000)


@pytest.fixture
def client(app):
    """A client on this machine, as the user's own browser would be."""
    return TestClient(app, client=LOOPBACK_CLIENT)


@pytest.fixture
def lan_client(app):
    """A client somewhere on the LAN - a device with no standing here."""
    return TestClient(app, client=LAN_CLIENT)


@pytest.fixture
def local_headers(app) -> dict[str, str]:
    """Headers that identify a caller as the local CLI.

    Routes that touch pairing, history, or transfer state require an identity, so
    tests that are not specifically about rejection need to present one.
    """
    return {"x-seltransfer-local": app.state.local_token}


def pair(app, device_id: str) -> None:
    """Pair a device the way a trusted caller would.

    Replaces the direct ``app.state.paired_devices.add(...)`` that the suite used
    throughout, which bypassed the endpoint entirely and hid the fact that the
    endpoint had no authentication.
    """
    app.state.pairing.grant_directly(device_id, "test-fixture", "test")
