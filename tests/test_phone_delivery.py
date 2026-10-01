"""End-to-end coverage for the PC-to-phone delivery path.

The phone is a browser client of the PC's server, so the whole transfer lives on
one server: the PC announces it, the phone accepts, the PC pushes the bytes, and
the phone pulls them back. This is the flow that was broken, so it is exercised
end to end rather than one endpoint at a time.
"""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from seltransfer.devices import Device
from seltransfer.server.app import create_app
from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager
from tests.conftest import make_app, pair


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path, port=8790)


@pytest.fixture
def client(app):
    return TestClient(app)


def register(client, device_id, name, **extra):
    payload = {"device_id": device_id, "name": name, "type": "phone"}
    payload.update(extra)
    response = client.post("/api/browser/register", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def session_header(session):
    return {"x-seltransfer-session": session["session_id"]}


def test_pc_to_phone_over_http_end_to_end(client, app):
    """The full default path, exactly as the browser client drives it."""
    sender = register(client, "pc-browser-sender", "Workstation")
    phone = register(client, "phone-browser-receiver", "Pixel")
    pair(client.app, "phone-browser-receiver")

    payload = b"the actual file contents\n" * 64
    metadata = {
        "name": "report.pdf",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    # 1. The PC announces the transfer on its own server.
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "phone-browser-receiver", "files": [metadata]},
        headers=session_header(sender),
    )
    assert created.status_code == 200, created.text
    transfer = created.json()
    assert transfer["transfer_transport"] == "http", "HTTP must be the default"

    # 2. It becomes visible to the phone as a pending incoming transfer.
    incoming = client.get("/api/incoming-transfers", headers=session_header(phone))
    assert [item["transfer_id"] for item in incoming.json()["transfers"]] == [
        transfer["transfer_id"]]

    # 3. The phone accepts.
    accepted = client.post(
        f"/api/incoming-transfers/{transfer['transfer_id']}/accept",
        headers=session_header(phone))
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "ACCEPTED"
    assert accepted.json()["transfer_transport"] == "http"

    # 4. The PC reads back the token it is allowed to push with.
    state = client.get(f"/api/incoming-transfers/{transfer['transfer_id']}",
                       headers=session_header(sender))
    token = state.json()["transfer_token"]
    assert token

    # 5. The PC pushes the bytes.
    uploaded = client.put(
        f"/api/incoming-transfers/{transfer['transfer_id']}/files/0",
        content=payload,
        headers={"x-seltransfer-token": token})
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["status"] == "VERIFIED"

    # 6. The phone pulls the file back and gets exactly what was sent.
    downloaded = client.get(
        f"/api/incoming-transfers/{transfer['transfer_id']}/files/0",
        headers=session_header(phone))
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert hashlib.sha256(downloaded.content).hexdigest() == metadata["sha256"]


def test_phone_can_resume_polling_until_the_upload_lands(client):
    """The phone must be able to see progress before it can download anything."""
    sender = register(client, "pc-poller", "Workstation")
    phone = register(client, "phone-poller", "Pixel")
    pair(client.app, "phone-poller")
    metadata = {"name": "a.bin", "size": 4,
                "sha256": hashlib.sha256(b"data").hexdigest()}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "phone-poller", "files": [metadata]},
        headers=session_header(sender)).json()
    client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                headers=session_header(phone))

    # Accepted but not yet uploaded: the download is not available, and the
    # phone can tell "not yet" apart from "denied".
    early = client.get(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        headers=session_header(phone))
    assert early.status_code == 404

    state = client.get(f"/api/incoming-transfers/{created['transfer_id']}",
                       headers=session_header(sender)).json()
    client.put(f"/api/incoming-transfers/{created['transfer_id']}/files/0",
               content=b"data",
               headers={"x-seltransfer-token": state["transfer_token"]})

    late = client.get(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        headers=session_header(phone))
    assert late.status_code == 200
    assert late.content == b"data"


def test_sender_cannot_download_the_phone_copy(client):
    """The download endpoint is for the receiver, not the sender."""
    sender = register(client, "pc-nosy-device", "Workstation")
    phone = register(client, "phone-target", "Pixel")
    pair(client.app, "phone-target")
    metadata = {"name": "secret.txt", "size": 6,
                "sha256": hashlib.sha256(b"secret").hexdigest()}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "phone-target", "files": [metadata]},
        headers=session_header(sender)).json()
    client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                headers=session_header(phone))
    state = client.get(f"/api/incoming-transfers/{created['transfer_id']}",
                       headers=session_header(sender)).json()
    client.put(f"/api/incoming-transfers/{created['transfer_id']}/files/0",
               content=b"secret",
               headers={"x-seltransfer-token": state["transfer_token"]})

    denied = client.get(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        headers=session_header(sender))
    assert denied.status_code == 403


def _two_server_pair(tmp_path):
    """A sender server and a destination server, as a real PC-to-PC transfer has.

    The local device id is derived per machine, so two apps in one process would
    otherwise share it and every transfer would look self-directed. Give each
    server its own identity, which is what two real machines would have.
    """
    sender_app = create_app(server_port=8791, local_address="127.0.0.1")
    sender_app.state.history = HistoryStore(tmp_path / "sender.db")
    sender_app.state.transfers = TransferManager(
        tmp_path / "sender-downloads", sender_app.state.history)
    _set_local_device_id(sender_app, "11111111-1111-4111-8111-111111111111")

    receiver_app = create_app(server_port=8793, local_address="127.0.0.1")
    receiver_app.state.history = HistoryStore(tmp_path / "receiver.db")
    receiver_app.state.transfers = TransferManager(
        tmp_path / "receiver-downloads", receiver_app.state.history)
    _set_local_device_id(receiver_app, "22222222-2222-4222-8222-222222222222")
    return sender_app, receiver_app


def _set_local_device_id(app, device_id):
    registry = app.state.registry
    previous = registry.local_device.device_id
    registry._devices.pop(previous, None)
    registry.local_device.device_id = device_id
    registry._devices[device_id] = registry.local_device
    pair(app, device_id)


def _local(app):
    """Headers that identify this server's own CLI, as `seltransfer` would send."""
    return {"x-seltransfer-local": app.state.local_token}


def test_push_token_from_a_native_sender_is_honoured(tmp_path):
    """A remote sender supplies its own token and can push with it.

    This is the CLI path. The destination will never hand a token to the remote
    sender, because only its own node may read one, so the announced token has to
    be the one that is accepted.
    """
    sender_app, receiver_app = _two_server_pair(tmp_path)
    sender_client = TestClient(sender_app)
    receiver_client = TestClient(receiver_app)
    sender_headers = _local(sender_app)
    receiver_headers = _local(receiver_app)

    peer = receiver_app.state.registry.local_device.device_id
    sender_app.state.registry.upsert(
        Device(device_id=peer, name="Native PC", type="computer",
               ip="127.0.0.1", port=8793, node_type="server"))
    pair(sender_app, peer)

    payload = b"native bytes"
    metadata = {"name": "from-cli.bin", "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()}
    token = "cli-supplied-upload-token-value"

    created = sender_client.post(
        "/api/transfers", json={"receiver_id": peer, "files": [metadata]},
        headers=sender_headers)
    assert created.status_code == 200, created.text
    transfer = created.json()

    announced = receiver_client.post(
        "/api/incoming-transfers",
        json={"transfer_id": transfer["transfer_id"],
              "sender": transfer["sender"],
              "files": [metadata],
              "total_bytes": len(payload),
              "token": token})
    assert announced.status_code == 200, announced.text

    accepted = receiver_client.post(
        f"/api/incoming-transfers/{transfer['transfer_id']}/accept",
        headers=receiver_headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "ACCEPTED"

    # The receiver's own view must not leak the sender's push token.
    assert "transfer_token" not in accepted.json()
    assert "token" not in json.dumps(accepted.json())

    uploaded = receiver_client.put(
        f"/api/incoming-transfers/{transfer['transfer_id']}/files/0",
        content=payload,
        headers={"x-seltransfer-token": token})
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["status"] == "VERIFIED"
    assert (tmp_path / "receiver-downloads" / "from-cli.bin").read_bytes() == payload


def test_announcement_with_wrong_token_cannot_push(tmp_path):
    sender_app, receiver_app = _two_server_pair(tmp_path)
    sender_client = TestClient(sender_app)
    receiver_client = TestClient(receiver_app)
    sender_headers = _local(sender_app)
    receiver_headers = _local(receiver_app)
    peer = receiver_app.state.registry.local_device.device_id
    sender_app.state.registry.upsert(
        Device(device_id=peer, name="Native PC", type="computer",
               ip="127.0.0.1", port=8793, node_type="server"))
    pair(sender_app, peer)

    metadata = {"name": "x.bin", "size": 4, "sha256": None}
    created = sender_client.post(
        "/api/transfers", json={"receiver_id": peer, "files": [metadata]},
        headers=sender_headers).json()
    receiver_client.post("/api/incoming-transfers",
                         json={"transfer_id": created["transfer_id"],
                               "sender": created["sender"], "files": [metadata],
                               "total_bytes": 4,
                               "token": "the-real-token-value-here"})
    receiver_client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                         headers=receiver_headers)

    bad = receiver_client.put(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        content=b"data",
        headers={"x-seltransfer-token": "guessing-the-token"})
    assert bad.status_code == 401


def test_sender_cannot_read_the_token_from_another_server(tmp_path):
    """The sender gets no token from the destination's API at all."""
    sender_app, receiver_app = _two_server_pair(tmp_path)
    sender_client = TestClient(sender_app)
    receiver_client = TestClient(receiver_app)
    sender_headers = _local(sender_app)
    receiver_headers = _local(receiver_app)
    peer = receiver_app.state.registry.local_device.device_id
    sender_app.state.registry.upsert(
        Device(device_id=peer, name="Native PC", type="computer",
               ip="127.0.0.1", port=8793, node_type="server"))
    pair(sender_app, peer)

    metadata = {"name": "y.bin", "size": 2, "sha256": None}
    created = sender_client.post(
        "/api/transfers", json={"receiver_id": peer, "files": [metadata]},
        headers=sender_headers).json()
    receiver_client.post("/api/incoming-transfers",
                         json={"transfer_id": created["transfer_id"],
                               "sender": created["sender"], "files": [metadata],
                               "total_bytes": 2,
                               "token": "the-real-token-value-here"})
    receiver_client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                         headers=receiver_headers)

    # Anonymous on the destination the caller has no identity at all, which is
    # stronger than the old behaviour: it used to be treated as the destination's
    # own node, and the token was withheld only by an explicit check. Now the
    # request never gets far enough to consider disclosing anything.
    state = receiver_client.get(
        f"/api/incoming-transfers/{created['transfer_id']}")
    assert state.status_code == 401
    assert "transfer_token" not in state.text
