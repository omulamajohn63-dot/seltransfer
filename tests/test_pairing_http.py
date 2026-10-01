"""Pairing and caller identity at the HTTP boundary.

The unit tests in ``test_pairing.py`` cover the credential. These cover the three
things that actually made it exploitable:

* the endpoint used to accept a pairing from anybody;
* ``/pair/request`` used to hand the code straight back to the requester, which
  made the whole out-of-band flow self-service; and
* an unauthenticated caller used to be silently treated as the local node.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seltransfer.devices import Device
from tests.conftest import LOOPBACK_CLIENT

DEVICE = "target-device-0001"
STRANGER = "stranger-device-99"


@pytest.fixture
def wired(app, client):
    """An app with one known peer device, plus a helper to register browsers."""
    app.state.registry.upsert(
        Device(device_id=DEVICE, name="Target", type="phone",
               ip="192.168.1.50", port=None, node_type="browser"))
    return app


def register(client, device_id):
    """Register a browser session with whatever client is passed in.

    Which client matters: a session registered from loopback is this machine's own
    user and may pair, and one registered from the LAN may not.
    """
    response = client.post("/api/browser/register",
                           json={"device_id": device_id, "name": device_id,
                                 "type": "phone"})
    assert response.status_code == 200, response.text
    return {"x-seltransfer-session": response.json()["session_id"]}


def read_code(client, headers, device_id=DEVICE):
    """Read a pending code the way the destination's interface does."""
    listed = client.get("/api/pairing/pending", headers=headers)
    assert listed.status_code == 200, listed.text
    for request in listed.json()["requests"]:
        if request["device_id"] == device_id:
            return str(request["code"])
    raise AssertionError(f"no pending pairing request for {device_id}")


def test_a_pending_code_is_never_written_to_disk(wired, lan_client, local_headers):
    """The clear code exists only in memory.

    It is held so the destination can display it, and the destination is the only
    reader. Persisting it would leave a short-lived credential on disk, where any
    later process running as this user could read it.
    """
    from seltransfer.config import get_settings

    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    code = read_code(lan_client, local_headers)
    assert code

    data_dir = Path(get_settings().app_dir)
    needles = {code, code.lower()}
    offenders = []
    for path in data_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        if any(needle.encode() in blob for needle in needles):
            offenders.append(path)

    assert not offenders, f"pairing code found in {offenders}"


# --- the vulnerability that was fixed ----------------------------------------


def test_anonymous_peer_cannot_pair_a_device(wired, client):
    """The original bug: no authentication at all on the pairing endpoint."""
    response = client.post(f"/api/devices/{DEVICE}/pair")

    assert response.status_code == 403, response.text
    assert not wired.state.pairing.is_paired(DEVICE)


def test_anonymous_peer_cannot_unpair_a_device(wired, client, local_headers):
    wired.state.pairing.grant_directly(DEVICE, "test", "test")
    response = client.delete(f"/api/devices/{DEVICE}/pair")

    assert response.status_code == 403
    assert wired.state.pairing.is_paired(DEVICE)


def test_a_bogus_local_token_cannot_pair(wired, client):
    """The local token must be checked, not merely present."""
    response = client.post(f"/api/devices/{DEVICE}/pair",
                           headers={"x-seltransfer-local": "not-the-real-token"})

    assert response.status_code == 403
    assert not wired.state.pairing.is_paired(DEVICE)


def test_a_browser_session_from_the_lan_cannot_pair(wired, lan_client):
    """Registration is unauthenticated, so a session is not authority to pair.

    This was the live hole: `POST /api/browser/register` hands out a session token
    to any peer that asks, so accepting any session on the pairing endpoint meant
    any device on the network could pair any device - the pairing code was
    decorative, because the requester could simply skip it.
    """
    headers = register(lan_client, "attacker-browser-01")
    response = lan_client.post(f"/api/devices/{DEVICE}/pair", headers=headers)

    assert response.status_code == 403, response.text
    assert not wired.state.pairing.is_paired(DEVICE)


def test_a_peer_session_cannot_unpair(wired, lan_client):
    """Otherwise a peer could deny the user the ability to send, for free."""
    wired.state.pairing.grant_directly(DEVICE, "test", "test")
    headers = register(lan_client, "attacker-browser-01")

    response = lan_client.delete(f"/api/devices/{DEVICE}/pair", headers=headers)

    assert response.status_code == 403
    assert wired.state.pairing.is_paired(DEVICE)


def test_the_local_user_can_pair_from_its_own_browser(wired, client):
    """The one-click path is preserved for the interface's own user."""
    headers = register(client, "local-browser-01")
    response = client.post(f"/api/devices/{DEVICE}/pair", headers=headers)

    assert response.status_code == 200, response.text
    assert wired.state.pairing.is_paired(DEVICE)


def test_the_local_cli_can_pair(wired, client, local_headers):
    response = client.post(f"/api/devices/{DEVICE}/pair", headers=local_headers)

    assert response.status_code == 200, response.text
    assert wired.state.pairing.is_paired(DEVICE)


# --- the code flow -----------------------------------------------------------


def test_request_does_not_hand_the_code_to_the_requester(wired, lan_client):
    """The requester must never learn the code from its own response.

    This was the second live hole. `request()` returned the code alongside the
    request, so an anonymous peer could call `/pair/request`, read the code out of
    the JSON, and immediately call `/pair/confirm` with it: pairing done in two
    unauthenticated requests, with no out-of-band step anywhere.
    """
    response = lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                               json={"device_id": DEVICE})

    assert response.status_code == 200, response.text
    body = response.json()
    assert "code" not in body
    assert "code_hash" not in body
    assert body["device_id"] == DEVICE
    assert body["status"] == "pending"
    assert not wired.state.pairing.is_paired(DEVICE)


def test_a_requester_cannot_confirm_a_pairing_it_cannot_read(wired, lan_client,
                                                             local_headers):
    """The end-to-end consequence: a LAN peer cannot pair on its own."""
    requested = lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                                json={"device_id": DEVICE})
    assert "code" not in requested.json()

    # It has to guess. It has 5 attempts, and there is nothing to confirm against.
    for _ in range(6):
        lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                        json={"device_id": DEVICE, "code": "GUESS1234"})
    assert not wired.state.pairing.is_paired(DEVICE)


def test_a_peer_cannot_read_a_pending_code(wired, lan_client, local_headers):
    """Codes are for display at the destination, and only there."""
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    code = read_code(destination, local_headers)

    peer = lan_client.get("/api/pairing/pending")
    local = destination.get("/api/pairing/pending", headers=local_headers)

    assert peer.status_code == 403, peer.text
    assert code not in peer.text
    assert local.status_code == 200
    assert local.json()["requests"][0]["code"] == code


def test_the_out_of_band_flow_pairs_the_device(wired, lan_client, local_headers):
    """Request, the user reads the code off the destination, confirm."""
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    code = read_code(TestClient(wired, client=LOOPBACK_CLIENT), local_headers)

    confirmed = lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                                json={"device_id": DEVICE, "code": code})

    assert confirmed.status_code == 200, confirmed.text
    assert wired.state.pairing.is_paired(DEVICE)


def test_confirm_with_a_wrong_code_is_refused(wired, lan_client, local_headers):
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    response = lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                               json={"device_id": DEVICE, "code": "WRONG123"})

    assert response.status_code == 403
    assert not wired.state.pairing.is_paired(DEVICE)


def read_request_id(client, headers, device_id=DEVICE):
    """Find the pending request id, the way the destination's panel does."""
    listed = client.get("/api/pairing/pending", headers=headers)
    assert listed.status_code == 200, listed.text
    for request in listed.json()["requests"]:
        if request["device_id"] == device_id:
            return str(request["request_id"])
    raise AssertionError(f"no pending pairing request for {device_id}")


# --- approval ---------------------------------------------------------------


def test_the_destination_user_can_approve_without_reading_a_code(
        wired, lan_client, local_headers):
    """The click is the intent, so nothing has to be transcribed."""
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    request_id = read_request_id(destination, local_headers)

    approved = destination.post(f"/api/pairing/requests/{request_id}/approve",
                                headers=local_headers)

    assert approved.status_code == 200, approved.text
    assert wired.state.pairing.is_paired(DEVICE)
    assert approved.json()["pairing"]["method"] == "approved"


def test_the_requester_never_receives_the_code_or_may_approve(
        wired, lan_client, local_headers):
    """Approval must not become the self-service flow the code was built to stop.

    The requester can ask and can learn that it was approved, but it cannot approve
    its own request and cannot read the code - so flooding requests still yields
    nothing without a person at the destination.
    """
    requested = lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                                json={"device_id": DEVICE})
    assert requested.status_code == 200
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    code = read_code(destination, local_headers)
    request_id = read_request_id(destination, local_headers)

    attempted = lan_client.post(f"/api/pairing/requests/{request_id}/approve")

    assert attempted.status_code == 403, attempted.text
    assert code not in attempted.text
    assert code not in requested.text
    assert not wired.state.pairing.is_paired(DEVICE)


def test_a_browser_session_from_the_lan_cannot_approve(wired, lan_client,
                                                       local_headers):
    """A self-registered session proves a peer asked for a session, nothing more."""
    headers = register(lan_client, "approver-from-the-lan")
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    request_id = read_request_id(destination, local_headers)

    refused = lan_client.post(f"/api/pairing/requests/{request_id}/approve",
                              headers=headers)

    assert refused.status_code == 403, refused.text
    assert not wired.state.pairing.is_paired(DEVICE)


def test_approving_consumes_the_request_and_its_code(wired, lan_client,
                                                     local_headers):
    """One approval is one pairing; the code must not survive it."""
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    request_id = read_request_id(destination, local_headers)
    code = read_code(destination, local_headers)

    destination.post(f"/api/pairing/requests/{request_id}/approve",
                     headers=local_headers)
    destination.post(f"/api/pairing/requests/{request_id}/approve",
                     headers=local_headers)

    assert not wired.state.pairing.pending_for(DEVICE)
    replayed = lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                               json={"device_id": DEVICE, "code": code})
    # 404, not a code error: approving deleted the request, so there is nothing
    # left for the code to match.
    assert replayed.status_code == 404, replayed.text


def test_a_requester_polls_for_approval_without_seeing_the_code(
        wired, lan_client, local_headers):
    """Approval has to be observable, and it carries nothing secret."""
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    destination = TestClient(wired, client=LOOPBACK_CLIENT)
    before = lan_client.get(f"/api/pairing/status/{DEVICE}")
    code = read_code(destination, local_headers)
    request_id = read_request_id(destination, local_headers)

    destination.post(f"/api/pairing/requests/{request_id}/approve",
                     headers=local_headers)
    after = lan_client.get(f"/api/pairing/status/{DEVICE}")

    assert before.status_code == 200 and before.json()["paired"] is False
    assert after.status_code == 200 and after.json()["paired"] is True
    assert code not in after.text
    assert "code" not in after.json()


def test_pairing_status_for_an_unknown_device_is_refused(wired, lan_client):
    assert lan_client.get("/api/pairing/status/not-a-real-device").status_code == 404


def test_confirm_for_an_unknown_device_is_refused(wired, client, local_headers):
    response = client.post(f"/api/devices/{DEVICE}/pair/confirm",
                           json={"device_id": DEVICE, "code": "12345678"},
                           headers=local_headers)
    assert response.status_code == 404


def test_request_body_must_match_the_path(wired, client, local_headers):
    response = client.post(f"/api/devices/{DEVICE}/pair/request",
                           json={"device_id": "different-device-1"},
                           headers=local_headers)
    assert response.status_code == 422


def test_request_for_an_unknown_device_is_refused(client, local_headers):
    response = client.post("/api/devices/not-a-real-device/pair/request",
                           json={"device_id": "not-a-real-device"},
                           headers=local_headers)
    assert response.status_code == 404


def test_a_code_cannot_be_replayed_over_http(wired, lan_client, local_headers):
    lan_client.post(f"/api/devices/{DEVICE}/pair/request",
                    json={"device_id": DEVICE})
    code = read_code(TestClient(wired, client=LOOPBACK_CLIENT), local_headers)

    first = lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                            json={"device_id": DEVICE, "code": code})
    assert first.status_code == 200

    second = lan_client.post(f"/api/devices/{DEVICE}/pair/confirm",
                             json={"device_id": DEVICE, "code": code})
    assert second.status_code == 404


def test_an_expired_pairing_cannot_send(wired, client, local_headers, monkeypatch):
    """A pairing that has aged out must stop authorising a transfer."""
    client.post(f"/api/devices/{DEVICE}/pair", headers=local_headers)
    assert wired.state.pairing.is_paired(DEVICE)

    expired = wired.state.pairing.get(DEVICE)
    expired.expires_at = 0  # as if the TTL had elapsed

    response = client.post("/api/transfers",
                           json={"receiver_id": DEVICE,
                                 "files": [{"name": "f.txt", "size": 1}]},
                           headers=local_headers)
    assert response.status_code == 403


# --- unpaired senders --------------------------------------------------------


def test_transfer_to_an_unpaired_device_is_refused(wired, client, local_headers):
    response = client.post("/api/transfers",
                           json={"receiver_id": DEVICE,
                                 "files": [{"name": "f.txt", "size": 1}]},
                           headers=local_headers)

    assert response.status_code == 403
    assert "pair" in response.json()["detail"].lower()


def test_transfer_works_once_paired(wired, client, local_headers):
    client.post(f"/api/devices/{DEVICE}/pair", headers=local_headers)
    response = client.post("/api/transfers",
                           json={"receiver_id": DEVICE,
                                 "files": [{"name": "f.txt", "size": 1}]},
                           headers=local_headers)
    assert response.status_code == 200, response.text


# --- anonymous callers have no identity --------------------------------------


@pytest.mark.parametrize("method,path", [
    ("get", "/api/transfers"),
    ("get", "/api/incoming-transfers"),
    ("delete", "/api/transfers/history"),
    ("post", "/api/transfers/history/clear"),
])
def test_anonymous_callers_are_refused(client, method, path):
    """Previously these answered as the local node."""
    response = getattr(client, method)(path)
    assert response.status_code == 401, f"{method.upper()} {path}"


def test_anonymous_caller_cannot_mutate_a_transfer(wired, client, local_headers):
    client.post(f"/api/devices/{DEVICE}/pair", headers=local_headers)
    created = client.post("/api/transfers",
                          json={"receiver_id": DEVICE,
                                "files": [{"name": "f.txt", "size": 1}]},
                          headers=local_headers).json()

    for action in ("accept", "reject", "cancel", "pause", "resume"):
        response = client.post(f"/api/transfers/{created['transfer_id']}/{action}")
        assert response.status_code == 401, action

    assert client.get(
        f"/api/transfers/{created['transfer_id']}").status_code == 401
    assert client.get(
        f"/api/transfers/{created['transfer_id']}/progress").status_code == 401


def test_anonymous_caller_cannot_read_history(client):
    assert client.get("/api/transfers").status_code == 401


def test_anonymous_caller_cannot_create_a_transfer_as_the_local_node(
        wired, lan_client, local_headers):
    """An anonymous peer must not be able to send files *as this machine*.

    `create_transfer` used to fall back to `registry.local_device.device_id` when
    the caller had no session. Combined with the pair-request code leak, that let a
    peer with no credentials at all create a transfer whose sender was this PC: a
    forged sender in the victim's history, and an upload token handed to the peer.
    """
    wired.state.pairing.grant_directly(DEVICE, "test-fixture", "test")

    response = lan_client.post("/api/transfers",
                               json={"receiver_id": DEVICE,
                                     "files": [{"name": "f.txt", "size": 1}]})

    assert response.status_code == 401, response.text
    assert not wired.state.history.list_for(wired.state.registry.local_device.device_id)


def test_the_local_cli_sends_as_itself(wired, lan_client, local_headers):
    """The legitimate path still works, and attributes the transfer correctly."""
    wired.state.pairing.grant_directly(DEVICE, "test-fixture", "test")

    response = lan_client.post("/api/transfers",
                               json={"receiver_id": DEVICE,
                                     "files": [{"name": "f.txt", "size": 1}]},
                               headers=local_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sender_id"] == wired.state.registry.local_device.device_id
    assert body["sender_id"] != DEVICE


def test_paired_device_list_is_hidden_from_anonymous_callers(wired, client,
                                                             local_headers):
    """The pairing map says who may be contacted, so it is not public."""
    client.post(f"/api/devices/{DEVICE}/pair", headers=local_headers)

    anonymous = client.get("/api/devices")
    trusted = client.get("/api/devices", headers=local_headers)

    assert anonymous.json()["paired_devices"] == []
    assert DEVICE in trusted.json()["paired_devices"]
