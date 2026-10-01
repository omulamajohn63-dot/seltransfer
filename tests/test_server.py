"""Tests for FastAPI server and routes."""

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seltransfer.devices import resolve_device_display_name, validate_device_name
from seltransfer.qr import connection_qr_svg
from seltransfer.server.app import create_app
from seltransfer.storage import HistoryStore
from tests.conftest import make_app, pair


@pytest.fixture
def client(tmp_path):
    """Create a test client whose state is isolated from the real app directory.

    Without this the suite wrote device-id, history rows, and received files into
    the developer's own ~/.seltransfer.
    """
    return TestClient(make_app(tmp_path))


def test_get_status(client):
    """Test /api/status endpoint."""
    response = client.get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "online"
    assert "version" in data
    assert "message" in data


def test_connection_info_uses_configured_address_and_port():
    response = TestClient(create_app(server_port=9000, local_address="172.16.4.22")).get(
        "/api/connection"
    )
    data = response.json()
    assert data["local_address"] == "172.16.4.22"
    assert data["server_port"] == 9000
    assert data["qr"]["url"] == "http://172.16.4.22:9000"


def test_health_check(client):
    """Test /api/health endpoint."""
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_resolve_device_display_name_priority():
    assert resolve_device_display_name(
        "SILAS PHONE", "Samsung Galaxy A03", "Phone", "Android") == "SILAS PHONE"
    assert resolve_device_display_name(
        None, "Samsung Galaxy A03", "Phone", "Android") == "Samsung Galaxy A03"
    assert resolve_device_display_name(
        None, None, "Phone", "Android") == "Android Phone"
    assert resolve_device_display_name(
        None, None, "computer", hostname="SELLECTOR-PC") == "SELLECTOR-PC"


def test_validate_device_name_rejects_invalid_inputs():
    for invalid in ["", "   ", "a" * 51, "bad\tvalue", "bad\nvalue", "<script>alert(1)</script>"]:
        assert validate_device_name(invalid) is None
    for valid, expected in [
        (" SILAS PHONE ", "SILAS PHONE"),
        ("My Galaxy A03", "My Galaxy A03"),
        ("SELLECTOR-PC", "SELLECTOR-PC"),
        ("Office Laptop", "Office Laptop"),
        ("Dad's Phone", "Dad's Phone"),
    ]:
        assert validate_device_name(valid) == expected


def test_qr_svg_encodes_exactly_the_advertised_address(client):
    """The panel shows the image and the URL together, so they must be one payload.

    Comparing against a render of the advertised URL is stronger than looking for
    the URL inside the SVG: the code is drawn as path data, so the address is not
    readable in the document text, and a drifting endpoint would still pass a
    substring check on some other change.
    """
    qr = client.get("/api/qr.svg")
    assert qr.status_code == 200
    assert qr.headers["content-type"] == "image/svg+xml"
    assert "<svg" in qr.text

    advertised = client.get("/api/connection").json()["qr"]["url"]
    assert qr.text == connection_qr_svg(advertised)


def test_qr_svg_takes_no_input_from_the_caller(client):
    """A peer probing for reflected strings has nothing to reflect.

    The payload is built from the detected address, the port, and the configured
    scheme. Keeping the caller's query out of it is what makes this endpoint a
    fixed amount of work for an unauthenticated caller, rather than an encoder
    they can hand arbitrary strings to.
    """
    hostile = "javascript:alert(1)"
    qr = client.get(f"/api/qr.svg?bad={hostile}")

    assert qr.status_code == 200
    assert hostile not in qr.text
    advertised = client.get("/api/connection").json()["qr"]["url"]
    assert qr.text == connection_qr_svg(advertised)

    payload = {
        "device_id": "browser-device-display-name",
        "display_name": "SILAS PHONE",
        "device_hint": "Samsung Galaxy A03",
        "device_type": "Phone",
        "platform": "Android",
        "browser": "Chrome",
        "capabilities": ["webrtc"],
    }
    response = client.post("/api/browser/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["display_name"] == "SILAS PHONE"
    assert data["device_type"] == "Phone"

    browser = next(item for item in client.get("/api/devices").json()
                   ["devices"] if item["device_id"] == payload["device_id"])
    assert browser["display_name"] == "SILAS PHONE"
    assert browser["device_type"] == "Phone"


def test_browser_registration_heartbeat_and_persistent_session(client):
    payload = {"device_id": "browser-device-1", "name": "Test Phone", "type": "phone",
               "platform": "Android", "browser": "Chrome", "capabilities": ["webrtc"]}
    registered = client.post("/api/browser/register", json=payload)
    assert registered.status_code == 200
    session = registered.json()
    assert session["session_id"]
    assert session["device_id"] == payload["device_id"]

    headers = {"x-seltransfer-session": session["session_id"]}
    listed = client.get("/api/devices").json()
    browser = next(
        item for item in listed["devices"] if item["device_id"] == payload["device_id"])
    assert browser["node_type"] == "browser"
    assert browser["transport"] == ["webrtc"]
    assert browser["port"] is None

    refreshed = client.post("/api/browser/register", json={**payload,
                                                           "session_id": session["session_id"]})
    assert refreshed.status_code == 200
    assert refreshed.json()["session_id"] == session["session_id"]
    heartbeat = client.post("/api/browser/heartbeat",
                            json=session, headers=headers)
    assert heartbeat.status_code == 200


def test_browser_transfer_uses_browser_as_sender(client):
    payload = {"device_id": "browser-sender-1",
               "name": "Phone", "type": "phone"}
    session = client.post("/api/browser/register", json=payload).json()
    headers = {"x-seltransfer-session": session["session_id"]}
    receiver_id = client.app.state.registry.local_device.device_id
    pair(client.app, receiver_id)
    metadata = {"name": "report.txt", "size": 4}

    response = client.post("/api/transfers", json={"receiver_id": receiver_id,
                                                   "files": [metadata]}, headers=headers)

    assert response.status_code == 200
    assert response.json()["sender"]["device_id"] == payload["device_id"]


def test_browser_session_requires_token_and_expires(client):
    payload = {"device_id": "browser-device-2",
               "name": "Expiring Phone", "type": "phone"}
    session = client.post("/api/browser/register", json=payload).json()
    assert client.post("/api/browser/heartbeat",
                       json=session).status_code == 401
    client.app.state.registry.timeout = 0
    devices = client.get("/api/devices").json()["devices"]
    browser = next(
        item for item in devices if item["device_id"] == payload["device_id"])
    assert browser["status"] == "offline"


def test_get_connection_info(client):
    """Test /api/connection endpoint."""
    response = client.get("/api/connection")

    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert data["connected"] is True
    assert "device_name" in data
    assert "local_address" in data
    assert "server_port" in data


def test_clear_transfer_history_does_not_remove_downloads(client, tmp_path,
                                                         local_headers):
    client.app.state.history = HistoryStore(tmp_path / "history.db")
    received = tmp_path / "downloads" / "report.txt"
    received.parent.mkdir(parents=True, exist_ok=True)
    received.write_bytes(b"received")
    local_id = client.app.state.registry.local_device.device_id
    client.app.state.history.record({
        "transfer_id": "history-test",
        "sender_id": local_id,
        "receiver_id": "receiver",
        "direction": "outgoing",
        "files": [{"name": "report.txt", "size": 8}],
        "total_bytes": 8,
        "status": "VERIFIED",
    })
    assert [item["transfer_id"] for item in client.get(
        "/api/transfers", headers=local_headers).json()["transfers"]] == ["history-test"]

    cleared = client.delete("/api/transfers/history", headers=local_headers)

    assert cleared.status_code == 200
    assert client.get(
        "/api/transfers", headers=local_headers).json()["transfers"] == []
    assert received.read_bytes() == b"received"


def test_clear_transfer_history_post_compatibility(client, local_headers):
    response = client.post("/api/transfers/history/clear", headers=local_headers)

    assert response.status_code == 200
    assert response.json() == {"status": "cleared"}


def test_root_endpoint(client):
    """Test root endpoint returns HTML or JSON."""
    response = client.get("/")

    assert response.status_code == 200


def test_connect_device_endpoint_is_not_exposed(client):
    """The stub endpoint that accepted and discarded a device dict is gone."""
    assert client.post("/api/connect", json={"device_id": "test_device"}).status_code == 404


def test_created_at_is_preserved_across_state_changes(client, tmp_path):
    """History must record when a transfer was first seen, not last touched."""
    store = HistoryStore(tmp_path / "history.db")
    transfer = {"transfer_id": "created-at-test", "sender_id": "a", "receiver_id": "b",
                "direction": "outgoing", "files": [{"name": "f.txt", "size": 1}],
                "total_bytes": 1, "status": "PENDING"}
    store.record(transfer)
    first = store.list_recent()[0]["created_at"]

    transfer["status"] = "ACCEPTED"
    store.record(transfer)
    updated = store.list_recent()[0]

    assert updated["created_at"] == first
    assert updated["status"] == "ACCEPTED"


def test_two_nodes_negotiate_and_receive_bytes(tmp_path):
    sender = make_app(tmp_path, port=8765)
    receiver = make_app(tmp_path, port=8767)
    sender_headers = {"x-seltransfer-local": sender.state.local_token}
    receiver_headers = {"x-seltransfer-local": receiver.state.local_token}
    sender.state.registry.local_device.device_id = "sender-id"
    receiver.state.registry.local_device.device_id = "receiver-id"
    sender.state.registry.upsert(receiver.state.registry.local_device)
    pair(sender, "receiver-id")
    sender_client, receiver_client = TestClient(sender), TestClient(receiver)
    content = b"direct device-to-device bytes"
    metadata = {"name": "folder/report.txt", "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest()}

    created = sender_client.post(
        "/api/transfers", json={"receiver_id": "receiver-id", "files": [metadata]},
        headers=sender_headers)
    assert created.status_code == 200
    token = "sender-supplied-upload-token-value"
    request = {"transfer_id": created.json()["transfer_id"], "sender": created.json()["sender"],
               "files": [metadata], "total_bytes": len(content), "token": token}
    incoming = receiver_client.post("/api/incoming-transfers", json=request)
    assert incoming.status_code == 200
    assert incoming.json()["status"] == "PENDING"
    accepted = receiver_client.post(
        f"/api/incoming-transfers/{request['transfer_id']}/accept",
        headers=receiver_headers)
    assert accepted.json()["status"] == "ACCEPTED"
    # The receiver is not given the sender's push token.
    assert "transfer_token" not in accepted.json()
    upload = receiver_client.put(f"/api/incoming-transfers/{request['transfer_id']}/files/0",
                                 content=content,
                                 headers={"x-seltransfer-token": token})
    assert upload.status_code == 200
    assert upload.json()["status"] == "VERIFIED"
    received = Path(list(receiver.state.transfers.get(
        request["transfer_id"])["received_files"].values())[0])
    assert received.read_bytes() == content
    assert hashlib.sha256(received.read_bytes()
                          ).hexdigest() == metadata["sha256"]


def test_incoming_transfer_rejects_invalid_token(tmp_path):
    app = make_app(tmp_path, port=8767)
    headers = {"x-seltransfer-local": app.state.local_token}
    client = TestClient(app)
    metadata = {"name": "report.txt", "size": 4,
                "sha256": hashlib.sha256(b"test").hexdigest()}
    request = {"transfer_id": "transfer-token-test",
               "sender": {"device_id": "sender-id", "name": "PC"},
               "files": [metadata], "total_bytes": 4}
    assert client.post("/api/incoming-transfers",
                       json=request).status_code == 200
    accepted = client.post(
        "/api/incoming-transfers/transfer-token-test/accept", headers=headers).json()
    response = client.put("/api/incoming-transfers/transfer-token-test/files/0", content=b"test",
                          headers={"x-seltransfer-token": "wrong"})
    assert response.status_code == 401
    assert accepted["status"] == "ACCEPTED"


def test_incoming_transfer_can_receive_multiple_files(tmp_path):
    app = make_app(tmp_path, port=8767)
    headers = {"x-seltransfer-local": app.state.local_token}
    client = TestClient(app)
    contents = [b"one", b"two"]
    files = [{"name": f"folder/file-{index}.txt", "size": len(content),
              "sha256": hashlib.sha256(content).hexdigest()}
             for index, content in enumerate(contents)]
    request = {"transfer_id": "transfer-multi-test",
               "sender": {"device_id": "sender-id", "name": "PC"},
               "files": files, "total_bytes": 6,
               "token": "multi-file-upload-token-value"}
    client.post("/api/incoming-transfers", json=request)
    client.post("/api/incoming-transfers/transfer-multi-test/accept", headers=headers)
    token = request["token"]
    for index, content in enumerate(contents):
        response = client.put(
            f"/api/incoming-transfers/transfer-multi-test/files/{index}",
            content=content, headers={"x-seltransfer-token": token})
        assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"
    received = app.state.transfers.get("transfer-multi-test")["received_files"]
    # Keyed by declared index, so ordering follows the metadata rather than the
    # order the bytes happened to arrive in.
    assert Path(received["0"]).read_bytes() == contents[0]
    assert Path(received["1"]).read_bytes() == contents[1]


def test_browser_receiver_sees_pending_transfer_and_can_accept(client):
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender",
              "name": "Sender Phone", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver",
              "name": "Receiver Phone", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver")
    metadata = {"name": "notes.txt", "size": 7,
                "sha256": hashlib.sha256(b"pending").hexdigest()}
    transfer = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert transfer.status_code == 200
    transfer_id = transfer.json()["transfer_id"]

    listed = client.get(
        "/api/incoming-transfers",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )
    assert listed.status_code == 200
    transfers = listed.json()["transfers"]
    assert len(transfers) == 1
    assert transfers[0]["transfer_id"] == transfer_id
    assert transfers[0]["direction"] == "incoming"
    assert transfers[0]["status"] == "PENDING"
    assert transfers[0]["receiver_id"] == "browser-receiver"

    before_accept = client.get(
        f"/api/incoming-transfers/{transfer_id}",
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert "transfer_token" not in before_accept.json()

    accepted = client.post(
        f"/api/incoming-transfers/{transfer_id}/accept",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "ACCEPTED"

    sender_state = client.get(
        f"/api/incoming-transfers/{transfer_id}",
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert sender_state.status_code == 200
    assert sender_state.json()["status"] == "ACCEPTED"


def test_browser_receiver_can_reject_pending_transfer(client):
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-reject",
              "name": "Sender Phone", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver-reject",
              "name": "Receiver Phone", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver-reject")
    metadata = {"name": "notes.txt", "size": 7,
                "sha256": hashlib.sha256(b"reject").hexdigest()}
    transfer = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver-reject", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert transfer.status_code == 200
    transfer_id = transfer.json()["transfer_id"]
    client.post(
        "/api/incoming-transfers",
        json={
            "transfer_id": transfer_id,
            "sender": transfer.json()["sender"],
            "receiver_id": "browser-receiver-reject",
            "files": [metadata],
            "total_bytes": 7,
        },
        headers={"x-seltransfer-session": sender["session_id"]},
    )

    rejected = client.post(
        f"/api/incoming-transfers/{transfer_id}/reject",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"

    sender_state = client.get(
        f"/api/incoming-transfers/{transfer_id}",
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert sender_state.status_code == 200
    assert sender_state.json()["status"] == "REJECTED"


def test_browser_sender_uploads_to_browser_receiver_over_http(client):
    """The PC-to-phone path: a browser sender pushes bytes for a phone receiver.

    This is the case that used to fail with 409 "browser transfers use the WebRTC
    data channel", which is why files never reached a phone.
    """
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-upload",
              "name": "Sender", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver-upload",
              "name": "Receiver", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver-upload")
    metadata = {"name": "upload.txt", "size": 6,
                "sha256": hashlib.sha256(b"upload").hexdigest()}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver-upload", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    transfer = created.json()
    assert transfer["transfer_transport"] == "http"
    client.post(
        "/api/incoming-transfers",
        json={"transfer_id": transfer["transfer_id"], "sender": transfer["sender"],
              "receiver_id": "browser-receiver-upload", "files": [metadata],
              "total_bytes": 6},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    accepted = client.post(
        f"/api/incoming-transfers/{transfer['transfer_id']}/accept",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )
    assert accepted.status_code == 200
    assert accepted.json()["transfer_transport"] == "http"

    state = client.get(
        f"/api/incoming-transfers/{transfer['transfer_id']}",
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert state.status_code == 200
    token = state.json()["transfer_token"]

    uploaded = client.put(
        f"/api/incoming-transfers/{transfer['transfer_id']}/files/0",
        content=b"upload",
        headers={"x-seltransfer-token": token},
    )
    assert uploaded.status_code == 200
    assert uploaded.json()["status"] == "VERIFIED"


def test_browser_receiver_downloads_the_file_over_http(client):
    """The phone pulls the uploaded bytes back with its own session."""
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-dl", "name": "Sender", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver-dl", "name": "Receiver", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver-dl")
    payload = b"downloaded bytes"
    metadata = {"name": "grab.txt", "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver-dl", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    ).json()
    client.post(
        "/api/incoming-transfers",
        json={"transfer_id": created["transfer_id"], "sender": created["sender"],
              "receiver_id": "browser-receiver-dl", "files": [metadata],
              "total_bytes": len(payload)},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                headers={"x-seltransfer-session": receiver["session_id"]})
    state = client.get(f"/api/incoming-transfers/{created['transfer_id']}",
                       headers={"x-seltransfer-session": sender["session_id"]}).json()
    client.put(f"/api/incoming-transfers/{created['transfer_id']}/files/0",
               content=payload,
               headers={"x-seltransfer-token": state["transfer_token"]})

    # The receiver can read it...
    got = client.get(f"/api/incoming-transfers/{created['transfer_id']}/files/0",
                     headers={"x-seltransfer-session": receiver["session_id"]})
    assert got.status_code == 200
    assert got.content == payload

    # ...but a third party cannot.
    stranger = client.post(
        "/api/browser/register",
        json={"device_id": "browser-stranger-dl", "name": "Nosy", "type": "phone"},
    ).json()
    denied = client.get(f"/api/incoming-transfers/{created['transfer_id']}/files/0",
                        headers={"x-seltransfer-session": stranger["session_id"]})
    assert denied.status_code == 403


def test_webrtc_transfer_to_non_browser_receiver_is_refused(client):
    """WebRTC needs a browser on the receiving end, so refuse the request early."""
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-wr", "name": "Sender", "type": "phone"},
    ).json()
    metadata = {"name": "f.txt", "size": 3,
                "sha256": hashlib.sha256(b"abc").hexdigest()}
    response = client.post(
        "/api/transfers",
        json={"receiver_id": "some-native-device", "files": [metadata],
              "transport": "webrtc"},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    assert response.status_code in {404, 422}


def test_webrtc_sessions_are_capped(tmp_path):
    """Each session buffers signalling messages, so the table must be bounded.

    `max_webrtc_sessions` existed and was never read, so a paired peer could grow
    it without limit. At the cap the server refuses and points at HTTP rather than
    evicting a live connection out from under someone.
    """
    app = make_app(tmp_path)
    app.state.settings.max_webrtc_sessions = 2
    client = TestClient(app)

    client.post("/api/browser/register",
                json={"device_id": "browser-peer-01", "name": "Peer", "type": "phone"})
    sender = client.post("/api/browser/register",
                         json={"device_id": "browser-owner-01", "name": "Owner",
                               "type": "computer"}).json()
    headers = {"x-seltransfer-session": sender["session_id"]}

    for _ in range(2):
        created = client.post("/api/webrtc/session",
                              json={"peer_device_id": "browser-peer-01"},
                              headers=headers)
        assert created.status_code == 200, created.text

    refused = client.post("/api/webrtc/session",
                          json={"peer_device_id": "browser-peer-01"},
                          headers=headers)
    assert refused.status_code == 503, refused.text
    assert "HTTP" in refused.json()["detail"]
    assert len(app.state.webrtc_sessions) == 2


def test_an_expired_webrtc_session_frees_its_slot(tmp_path):
    """The cap must not deadlock the server once a session ages out."""
    app = make_app(tmp_path)
    app.state.settings.max_webrtc_sessions = 1
    client = TestClient(app)
    sender = client.post("/api/browser/register",
                         json={"device_id": "browser-owner-02", "name": "Owner",
                               "type": "computer"}).json()
    client.post("/api/browser/register",
                json={"device_id": "browser-peer-02", "name": "Peer", "type": "phone"})
    headers = {"x-seltransfer-session": sender["session_id"]}

    first = client.post("/api/webrtc/session",
                        json={"peer_device_id": "browser-peer-02"},
                        headers=headers)
    assert first.status_code == 200
    assert client.post("/api/webrtc/session",
                       json={"peer_device_id": "browser-peer-02"},
                       headers=headers).status_code == 503

    # Age it out the way the sweeper would.
    session_id = first.json()["session_id"]
    app.state.webrtc_sessions[session_id]["created_at"] = 0

    again = client.post("/api/webrtc/session",
                        json={"peer_device_id": "browser-peer-02"},
                        headers=headers)
    assert again.status_code == 200, again.text


def test_webrtc_upload_endpoint_refuses_http_sender(client):
    """A transfer explicitly on WebRTC must not accept a plain HTTP upload."""
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-wr2", "name": "Sender", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver-wr2",
              "name": "Receiver", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver-wr2")
    payload = b"abc"
    metadata = {"name": "f.txt", "size": 3,
                "sha256": hashlib.sha256(payload).hexdigest()}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver-wr2", "files": [metadata],
              "transport": "webrtc"},
        headers={"x-seltransfer-session": sender["session_id"]},
    ).json()
    assert created["transfer_transport"] == "webrtc"
    client.post(
        "/api/incoming-transfers",
        json={"transfer_id": created["transfer_id"], "sender": created["sender"],
              "receiver_id": "browser-receiver-wr2", "files": [metadata],
              "total_bytes": 3, "transport": "webrtc"},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    client.post(f"/api/incoming-transfers/{created['transfer_id']}/accept",
                headers={"x-seltransfer-session": receiver["session_id"]})

    blocked = client.put(
        f"/api/incoming-transfers/{created['transfer_id']}/files/0",
        content=payload,
        headers={"x-seltransfer-token": "anything"},
    )
    assert blocked.status_code == 409


def test_duplicate_incoming_request_is_idempotent(client):
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-sender-dup",
              "name": "Sender Phone", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-receiver-dup",
              "name": "Receiver Phone", "type": "phone"},
    ).json()
    pair(client.app, "browser-receiver-dup")
    metadata = {"name": "dup.txt", "size": 3,
                "sha256": hashlib.sha256(b"abc").hexdigest()}
    transfer = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-receiver-dup", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    transfer_id = transfer.json()["transfer_id"]
    payload = {
        "transfer_id": transfer_id,
        "sender": transfer.json()["sender"],
        "receiver_id": "browser-receiver-dup",
        "files": [metadata],
        "total_bytes": 3,
    }

    first = client.post("/api/incoming-transfers", json=payload,
                        headers={"x-seltransfer-session": sender["session_id"]})
    second = client.post("/api/incoming-transfers", json=payload,
                         headers={"x-seltransfer-session": sender["session_id"]})
    assert first.status_code == 200
    assert second.status_code == 200

    listed = client.get("/api/incoming-transfers",
                        headers={"x-seltransfer-session": receiver["session_id"]})
    assert listed.status_code == 200
    assert len(listed.json()["transfers"]) == 1
    assert listed.json()["transfers"][0]["transfer_id"] == transfer_id


def test_browser_sessions_cannot_access_other_browser_pending_transfers(client):
    alice = client.post(
        "/api/browser/register",
        json={"device_id": "browser-alice", "name": "Alice", "type": "phone"},
    ).json()
    bob = client.post(
        "/api/browser/register",
        json={"device_id": "browser-bob", "name": "Bob", "type": "phone"},
    ).json()
    pair(client.app, "browser-bob")
    metadata = {"name": "secret.txt", "size": 6,
                "sha256": hashlib.sha256(b"secret").hexdigest()}
    transfer = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-bob", "files": [metadata]},
        headers={"x-seltransfer-session": alice["session_id"]},
    )
    transfer_id = transfer.json()["transfer_id"]
    client.post(
        "/api/incoming-transfers",
        json={
            "transfer_id": transfer_id,
            "sender": transfer.json()["sender"],
            "receiver_id": "browser-bob",
            "files": [metadata],
            "total_bytes": 6,
        },
        headers={"x-seltransfer-session": alice["session_id"]},
    )

    secret_list = client.get("/api/incoming-transfers",
                             headers={"x-seltransfer-session": alice["session_id"]})
    assert secret_list.status_code == 200
    assert all(item["receiver_id"] !=
               "browser-bob" for item in secret_list.json()["transfers"])

    bob_list = client.get("/api/incoming-transfers",
                          headers={"x-seltransfer-session": bob["session_id"]})
    assert bob_list.status_code == 200
    assert len(bob_list.json()["transfers"]) == 1
    assert bob_list.json()["transfers"][0]["receiver_id"] == "browser-bob"

    unauthorized_accept = client.post(
        f"/api/incoming-transfers/{transfer_id}/accept",
        headers={"x-seltransfer-session": alice["session_id"]},
    )
    assert unauthorized_accept.status_code == 403

    unauthorized_reject = client.post(
        f"/api/incoming-transfers/{transfer_id}/reject",
        headers={"x-seltransfer-session": alice["session_id"]},
    )
    assert unauthorized_reject.status_code == 403

    carol = client.post(
        "/api/browser/register",
        json={"device_id": "browser-carol", "name": "Carol", "type": "phone"},
    ).json()
    unauthorized_view = client.get(
        f"/api/incoming-transfers/{transfer_id}",
        headers={"x-seltransfer-session": carol["session_id"]},
    )
    assert unauthorized_view.status_code == 403


def test_expired_browser_session_cannot_access_pending_transfer(client):
    sender = client.post(
        "/api/browser/register",
        json={"device_id": "browser-expired-sender",
              "name": "Sender", "type": "phone"},
    ).json()
    receiver = client.post(
        "/api/browser/register",
        json={"device_id": "browser-expired-receiver",
              "name": "Receiver", "type": "phone"},
    ).json()
    pair(client.app, "browser-expired-receiver")
    metadata = {"name": "expired.txt", "size": 1}
    created = client.post(
        "/api/transfers",
        json={"receiver_id": "browser-expired-receiver", "files": [metadata]},
        headers={"x-seltransfer-session": sender["session_id"]},
    )
    transfer_id = created.json()["transfer_id"]
    client.app.state.browser_sessions[receiver["session_id"]]["expires_at"] = 0

    listed = client.get(
        "/api/incoming-transfers",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )
    accepted = client.post(
        f"/api/incoming-transfers/{transfer_id}/accept",
        headers={"x-seltransfer-session": receiver["session_id"]},
    )

    assert listed.status_code == 401
    assert accepted.status_code == 401
    # Previously the listing answered 200 with an empty list, so a phone whose
    # session had lapsed simply believed nothing was pending and never renewed.
    # 401 is what the browser client watches for, so it re-registers instead.
