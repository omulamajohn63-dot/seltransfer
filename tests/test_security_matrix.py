"""The endpoint matrix in SECURITY.md must match the running application.

Documentation that claims an endpoint is closed when it is actually open is worse
than no documentation, so this test parses the table and exercises every row
anonymously from a LAN peer. Two things are checked:

* coverage - every route in ``routes.py`` appears in the table, so a new route
  cannot ship undocumented;
* behaviour - the status codes the table claims are what the app returns.

The probe sends a body valid enough to reach the authorization check. Without
that, FastAPI rejects with 422 and the authorization result is never exercised,
which is how an "everything is refused" claim can be made to pass vacuously.
"""

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from seltransfer.devices import Device
from seltransfer.server.routes import router
from tests.conftest import LAN_CLIENT, LOOPBACK_CLIENT

SECURITY_MD = Path(__file__).resolve().parents[1] / "SECURITY.md"
ROW = re.compile(r"^\|\s*`(GET|POST|PUT|DELETE)\s(\S+)`\s*\|"
                 r"\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")
CODES = re.compile(r"\b(401|403|404|409|410|503)\b")
SHA = "a" * 64

BODIES = {
    "/api/browser/register": {"device_id": "matrix-device-01", "name": "Matrix"},
    "/api/browser/heartbeat": {"device_id": "matrix-device-01", "session_id": "x" * 32},
    "/api/browser/unregister": {"device_id": "matrix-device-01", "session_id": "x" * 32},
    "/api/transfers": {"receiver_id": "matrix-target-01",
                       "files": [{"name": "f.txt", "size": 0}]},
    "/api/incoming-transfers": {
        "transfer_id": "matrix-transfer-01",
        "sender": {"device_id": "matrix-sender-01", "name": "Matrix"},
        "files": [{"name": "f.txt", "size": 0}],
        "total_bytes": 0,
    },
    "/api/devices/{device_id}/pair/request": {"device_id": "matrix-target-01"},
    "/api/devices/{device_id}/pair/confirm": {"device_id": "matrix-target-01",
                                              "code": "12345678"},
    "/api/webrtc/session": {"peer_device_id": "matrix-target-01", "payload": {}},
    "/api/webrtc/{session_id}/{signal_type}": {"payload": {}},
    "/api/webrtc/{session_id}/files/{index}/complete": {"size": 0, "sha256": SHA},
}

ANON_200 = {"200, liveness only",
            "200; version, identity of this node, no secrets",
            "200; address, port, and QR payload",
            "200; QR code for this server's own URL, no caller input",
            "200; device list, but `paired_devices` empty and `local_user` false",
            "200; starts UDP discovery", "200; issues a session (bounded)",
            "200; returns **no code**",
            "200; pairing state, **no code**",
            "200; creates a bounded, inert pending record aimed at the local node"}

TARGET = Device(device_id="matrix-target-01", name="Target", type="phone",
                ip="192.168.1.50", port=None, node_type="browser")


def parse_matrix():
    """Return (method, path, needs, anonymous_cell) for each documented row."""
    text = SECURITY_MD.read_text(encoding="utf-8")
    start = text.index("## Endpoint matrix")
    end = text.index("## Transfer tokens")
    rows = []
    for line in text[start:end].splitlines():
        match = ROW.match(line.strip())
        if match:
            rows.append(match.groups())
    return rows


def sample_path(path: str) -> str:
    path = path.replace("{device_id}", "matrix-target-01")
    path = path.replace("{transfer_id}", "no-such-transfer-01")
    path = path.replace("{session_id}", "no-such-session-01")
    path = path.replace("{request_id}", "no-such-request-01")
    path = path.replace("{signal_type}", "offer")
    return path.replace("{n}", "0")


def implemented_routes() -> set[str]:
    routes = set()
    for route in router.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            routes.add(f"{method.lower()} {path}")
    return routes


def test_matrix_documents_every_route():
    """A route that ships without a documented outcome is an unowned attack surface."""
    documented = {f"{method.lower()} {path.replace('{n}', '{index}')}"
                  for method, path, _needs, _anon in parse_matrix()}
    missing = implemented_routes() - documented
    assert not missing, f"undocumented routes: {sorted(missing)}"


def test_documented_anonymous_results_match(app):
    """Exercise each row as an anonymous LAN peer and compare status codes."""
    rows = parse_matrix()
    assert len(rows) >= 30, "the matrix lost rows; did the table get truncated?"

    app.state.registry.upsert(TARGET)

    failures = []
    with TestClient(app, client=LAN_CLIENT) as peer:
        for method, path, _needs, anonymous in rows:
            url = sample_path(path)
            body = BODIES.get(path.replace("{n}", "{index}"))
            if body is None:
                headers, content = {}, b"" if method in {"POST", "PUT"} else None
            else:
                headers = {"content-type": "application/json"}
                content = json.dumps(body).encode()

            status = peer.request(method, url, content=content,
                                  headers=headers).status_code

            if anonymous in ANON_200:
                if status != 200:
                    failures.append((method, url, anonymous, status))
                continue

            accepted = {int(code) for code in CODES.findall(anonymous)}
            assert accepted, f"unparsable matrix cell: {anonymous!r}"
            if status not in accepted:
                failures.append((method, url, anonymous, status))

    assert not failures, "\n".join(
        f"{method} {url}: documented {anon!r}, actual {got}" + (
            "  <- 422 means the probe body was invalid, so authorization was "
            "never exercised" if got == 422 else "")
        for method, url, anon, got in failures)


def register(client, device_id: str) -> dict:
    return client.post("/api/browser/register",
                       json={"device_id": device_id, "name": "Matrix"}).json()


def collect_keys(value):
    """Every mapping key anywhere in a decoded JSON payload."""
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from collect_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from collect_keys(nested)


def test_pairing_code_is_never_echoed_to_the_requester(app):
    """A self-service pairing flow is no pairing at all.

    The requester must not learn the code from its own response, or the code
    proves nothing about a second channel.
    """
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LAN_CLIENT)
    requested = client.post("/api/devices/matrix-target-01/pair/request",
                            json={"device_id": "matrix-target-01"})
    assert requested.status_code == 200, requested.text

    pending = app.state.pairing.reveal_pending()
    assert pending and pending[0]["code"]
    code = pending[0]["code"]

    # The word "code" may appear in instructions; a code value may not appear,
    # under any key, anywhere in the payload.
    assert "code" not in set(collect_keys(requested.json()))
    assert code not in json.dumps(requested.json())


def test_a_lan_session_cannot_read_pending_codes(app):
    """A session proves a peer asked for a session, not that it is this machine."""
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LAN_CLIENT)
    session = register(client, "matrix-lan-01")
    app.state.pairing.request("matrix-target-01", "")

    refused = client.get("/api/pairing/pending",
                         headers={"x-seltransfer-session": session["session_id"]})
    assert refused.status_code == 403
    assert app.state.pairing.reveal_pending()[0]["code"] not in refused.text


def test_a_lan_peer_cannot_approve_its_own_request(app):
    """Approval is the whole point of the flow, so a peer must not reach it.

    If a requester could approve itself, nothing about pairing would require the
    destination's user to be present - and the code would be decoration.
    """
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LAN_CLIENT)
    requested = client.post("/api/devices/matrix-target-01/pair/request",
                            json={"device_id": "matrix-target-01"})
    request_id = requested.json()["request_id"]

    refused = client.post(f"/api/pairing/requests/{request_id}/approve")

    assert refused.status_code == 403, refused.text
    assert not app.state.pairing.is_paired("matrix-target-01")


def test_approval_never_returns_a_code_to_the_requester(app):
    """The local user approves; the requester learns only that it happened."""
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LAN_CLIENT)
    requested = client.post("/api/devices/matrix-target-01/pair/request",
                            json={"device_id": "matrix-target-01"})
    request_id = requested.json()["request_id"]
    code = app.state.pairing.reveal_pending()[0]["code"]

    # A loopback browser is this machine's own user only once it has a session:
    # the TestClient's address alone does not grant authority.
    local = TestClient(app, client=LOOPBACK_CLIENT)
    session = register(local, "matrix-approver-01")
    approved = local.post(f"/api/pairing/requests/{request_id}/approve",
                          headers={"x-seltransfer-session": session["session_id"]})

    assert approved.status_code == 200, approved.text
    assert approved.json()["pairing"]["method"] == "approved"
    assert code not in approved.text
    assert "code" not in set(collect_keys(approved.json()))

    status = client.get("/api/pairing/status/matrix-target-01")
    assert status.status_code == 200
    assert status.json()["paired"] is True
    assert code not in status.text


def test_a_lan_session_cannot_pair_directly(app):
    """Otherwise 'pairing' is a click any peer can make on any target."""
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LAN_CLIENT)
    session = register(client, "matrix-lan-02")
    headers = {"x-seltransfer-session": session["session_id"]}

    assert client.post("/api/devices/matrix-target-01/pair",
                       headers=headers).status_code == 403
    assert client.delete("/api/devices/matrix-target-01/pair",
                         headers=headers).status_code == 403


def test_a_loopback_browser_may_read_pending_codes(app):
    """The destination has to be able to display the code somehow."""
    app.state.registry.upsert(TARGET)
    client = TestClient(app, client=LOOPBACK_CLIENT)
    session = register(client, "matrix-local-01")
    app.state.pairing.request("matrix-target-01", "")

    shown = client.get("/api/pairing/pending",
                       headers={"x-seltransfer-session": session["session_id"]})
    assert shown.status_code == 200, shown.text
    revealed = shown.json()["requests"]
    assert revealed[0]["code"] == app.state.pairing.reveal_pending()[0]["code"]
