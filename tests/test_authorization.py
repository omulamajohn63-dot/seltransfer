"""Authorization tests.

Every transfer endpoint must be scoped to the two devices involved. These tests
exist because five state-mutating routes previously had no authorization at all,
so any peer on the LAN could accept, reject, cancel, pause, or resume somebody
else's transfer.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_app, pair


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path, port=8781)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def sessions(client):
    """Register browsers once and reuse their sessions.

    Re-registering a device_id without its session_id is rejected with 409, so
    the token has to be carried forward.
    """
    issued: dict[str, dict] = {}

    def register(device_id):
        if device_id not in issued:
            payload = {"device_id": device_id, "name": device_id, "type": "phone"}
            if device_id in issued:  # pragma: no cover - defensive
                payload["session_id"] = issued[device_id]["session_id"]
            response = client.post("/api/browser/register", json=payload)
            assert response.status_code == 200, response.text
            issued[device_id] = response.json()
        return issued[device_id]

    def headers(device_id):
        return {"x-seltransfer-session": register(device_id)["session_id"]}

    register.headers = headers
    return register


@pytest.fixture
def pending_transfer(client, sessions):
    """A PENDING transfer owned by browser-sender, addressed to browser-receiver."""
    content = b"payload"
    sessions("browser-receiver")
    pair(client.app, "browser-receiver")
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver",
              "files": [{"name": "f.txt", "size": len(content),
                         "sha256": hashlib.sha256(content).hexdigest()}]},
        headers=sessions.headers("browser-sender"),
    )
    assert created.status_code == 200, created.text
    transfer = created.json()
    client.post(
        "/api/incoming-transfers",
        json={"transfer_id": transfer["transfer_id"], "sender": transfer["sender"],
              "receiver_id": "browser-receiver", "files": transfer["files"],
              "total_bytes": len(content)},
        headers=sessions.headers("browser-sender"),
    )
    return transfer


def test_sender_cannot_accept_or_reject_own_transfer(client, sessions, pending_transfer):
    """Accept/reject belong to the receiver, even for the sender's own transfer."""
    headers = sessions.headers("browser-sender")
    transfer_id = pending_transfer["transfer_id"]

    assert client.post(f"/api/transfers/{transfer_id}/accept",
                       headers=headers).status_code == 403
    assert client.post(f"/api/transfers/{transfer_id}/reject",
                       headers=headers).status_code == 403
    assert client.post(f"/api/transfers/{transfer_id}/cancel",
                       headers=headers).status_code == 200


def test_third_party_cannot_mutate_a_transfer(client, sessions, pending_transfer):
    """An unrelated device must not be able to touch the transfer."""
    headers = sessions.headers("browser-stranger")
    transfer_id = pending_transfer["transfer_id"]

    for action in ("accept", "reject", "cancel", "pause", "resume"):
        assert client.post(f"/api/transfers/{transfer_id}/{action}",
                           headers=headers).status_code == 403, action


def test_receiver_accepts_and_sender_owns_pause_and_resume(client, sessions, pending_transfer):
    transfer_id = pending_transfer["transfer_id"]
    receiver_headers = sessions.headers("browser-receiver")
    sender_headers = sessions.headers("browser-sender")

    assert client.post(f"/api/transfers/{transfer_id}/accept",
                       headers=receiver_headers).json()["status"] == "ACCEPTED"
    assert client.post(f"/api/transfers/{transfer_id}/pause",
                       headers=sender_headers).json()["status"] == "PAUSED"
    assert client.post(f"/api/transfers/{transfer_id}/resume",
                       headers=sender_headers).json()["status"] == "ACCEPTED"
    assert client.post(f"/api/transfers/{transfer_id}/pause",
                       headers=receiver_headers).status_code == 403


def test_third_party_cannot_read_transfer_or_progress(client, sessions, pending_transfer):
    headers = sessions.headers("browser-stranger")
    transfer_id = pending_transfer["transfer_id"]

    assert client.get(f"/api/transfers/{transfer_id}", headers=headers).status_code == 403
    assert client.get(f"/api/transfers/{transfer_id}/progress",
                      headers=headers).status_code == 403


def test_transfer_list_is_scoped_to_the_caller(client, sessions, pending_transfer,
                                               local_headers):
    """History is 'my transfers', not 'everything this server has ever seen'.

    An anonymous caller used to be silently treated as the local node, so this
    endpoint answered their request instead of refusing it. It must now reject
    them outright: no identity means no history.
    """
    anonymous = client.get("/api/transfers")
    assert anonymous.status_code == 401, anonymous.text
    assert "session" in anonymous.json()["detail"].lower()

    for participant in ("browser-sender", "browser-receiver"):
        listed = client.get("/api/transfers", headers=sessions.headers(participant))
        assert len(listed.json()["transfers"]) == 1, participant

    assert client.get(
        "/api/transfers", headers=sessions.headers("browser-bystander")
    ).json()["transfers"] == []


def test_history_clear_also_requires_an_identity(client, app):
    """Clearing history is a state change, so it cannot be anonymous."""
    assert client.delete("/api/transfers/history").status_code == 401
    assert client.post("/api/transfers/history/clear").status_code == 401


def test_clear_history_only_removes_the_callers_rows(client, app, local_headers):
    local_id = app.state.registry.local_device.device_id
    for sender, receiver in ((local_id, "peer-node"), ("peer-node", local_id), ("x", "y")):
        app.state.history.record({
            "transfer_id": f"t-{sender}-{receiver}", "sender_id": sender,
            "receiver_id": receiver, "direction": "outgoing",
            "files": [{"name": "f.txt", "size": 1}], "total_bytes": 1,
            "status": "VERIFIED"})

    assert client.delete("/api/transfers/history",
                         headers=local_headers).status_code == 200

    remaining = {row["transfer_id"] for row in app.state.history.list_recent()}
    assert remaining == {"t-x-y"}


def test_sender_receives_upload_token_after_accept(tmp_path):
    """The native CLI can only learn the token from its own server."""
    from seltransfer.devices import Device

    sender_app = make_app(tmp_path, port=8782)
    headers = {"x-seltransfer-local": sender_app.state.local_token}
    sender_client = TestClient(sender_app)
    peer_id = "peer-node-1234"
    sender_app.state.registry.upsert(
        Device(device_id=peer_id, name="Peer", type="computer", ip="127.0.0.1",
               port=8765, node_type="server"))
    pair(sender_app, peer_id)

    created = sender_client.post(
        "/api/transfers", json={"receiver_id": peer_id,
                                "files": [{"name": "f.txt", "size": 1}]},
        headers=headers)
    assert created.status_code == 200, created.text
    transfer_id = created.json()["transfer_id"]

    # No token before acceptance.
    assert "transfer_token" not in sender_client.get(
        f"/api/transfers/{transfer_id}", headers=headers).json()

    sender_app.state.transfers.update_state(transfer_id, "ACCEPTED")
    response = sender_client.get(f"/api/transfers/{transfer_id}", headers=headers)

    assert response.status_code == 200
    assert response.json()["transfer_token"]


def test_browser_receiver_gets_no_push_token_on_webrtc(client, sessions):
    """On the WebRTC path the receiver pulls, so it must not get a push token."""
    sessions("browser-receiver")
    pair(client.app, "browser-receiver")
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver",
              "files": [{"name": "f.txt", "size": 1}],
              "transport": "webrtc"},
        headers=sessions.headers("browser-sender"),
    )
    transfer_id = created.json()["transfer_id"]
    client.app.state.transfers.update_state(transfer_id, "ACCEPTED")

    state = client.get(f"/api/transfers/{transfer_id}",
                       headers=sessions.headers("browser-sender"))

    assert created.json()["transfer_transport"] == "webrtc"
    assert "transfer_token" not in state.json()


def test_browser_receiver_does_get_a_push_token_on_http(client, sessions):
    """On the default HTTP path the sender must be able to push to the phone."""
    sessions("browser-receiver")
    pair(client.app, "browser-receiver")
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver",
              "files": [{"name": "f.txt", "size": 1}]},
        headers=sessions.headers("browser-sender"),
    )
    transfer_id = created.json()["transfer_id"]
    client.app.state.transfers.update_state(transfer_id, "ACCEPTED")

    state = client.get(f"/api/transfers/{transfer_id}",
                       headers=sessions.headers("browser-sender"))

    assert created.json()["transfer_transport"] == "http"
    assert state.json()["transfer_token"]


def test_third_party_cannot_read_a_pushed_file(client, sessions):
    """The download endpoint is scoped to the intended receiver."""
    sessions("browser-receiver")
    pair(client.app, "browser-receiver")
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver",
              "files": [{"name": "f.txt", "size": 1}]},
        headers=sessions.headers("browser-sender"),
    ).json()
    client.app.state.transfers.update_state(created["transfer_id"], "ACCEPTED")

    denied = client.get(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        headers=sessions.headers("browser-outsider"),
    )
    assert denied.status_code == 403


def test_device_id_must_match_the_allowed_alphabet(client):
    """Reject rather than sanitize: an ID is a key, not display text."""
    for bad in ("<img src=x onerror=alert(1)>", "has space", "a" * 129, "short"):
        response = client.post(
            "/api/browser/register", json={"device_id": bad, "type": "phone"})
        assert response.status_code == 422, bad

    assert client.post(
        "/api/browser/register",
        json={"device_id": "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "type": "phone"},
    ).status_code == 200
