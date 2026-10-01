"""HTTP API for discovery, pairing, and LAN transfers."""

from __future__ import annotations

import ipaddress
import secrets
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from seltransfer.config import verify_local_token
from seltransfer.devices import Device, resolve_device_display_name
from seltransfer.transfers import sweep_expired_transfers

router = APIRouter()

# Device IDs are surfaced in the browser client and in the CLI, and are chosen by
# the peer rather than issued by us. Restricting the alphabet keeps them inert in
# any rendering context and matches the UUIDs the web client generates.
DEVICE_ID_PATTERN = r"^[A-Za-z0-9._-]{8,128}$"


class StatusResponse(BaseModel):
    status: str
    message: str
    version: str
    device_id: str | None = None


class ConnectionResponse(BaseModel):
    connected: bool
    device_name: str
    local_address: str
    server_port: int
    platform: str
    device_id: str | None = None
    download_directory: str
    qr: dict
    # Which scheme the QR and the printed URL must use. "http" unless TLS is
    # actually configured and readable.
    scheme: str = "http"
    https_enabled: bool = False


class TransferFile(BaseModel):
    name: str = Field(min_length=1, max_length=1024)
    size: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class TransferCreate(BaseModel):
    receiver_id: str = Field(min_length=1, max_length=128, pattern=DEVICE_ID_PATTERN)
    files: list[TransferFile] = Field(min_length=1, max_length=10000)
    # HTTP is the default because it works everywhere, including to a phone
    # browser. WebRTC is a deliberate opt-in for users who want the peer-to-peer
    # path and accept its extra failure modes.
    transport: Literal["http", "webrtc"] = "http"


class IncomingTransfer(BaseModel):
    transfer_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)
    # Previously a bare ``dict``. Anything could be posted here and it was stored
    # verbatim in the history row, which made this an unbounded metadata sink and
    # let a peer inject arbitrary keys into the transfer record.
    sender: SenderIdentity
    files: list[TransferFile] = Field(min_length=1, max_length=10000)
    total_bytes: int = Field(ge=0)
    receiver_id: str | None = Field(default=None, max_length=128, pattern=DEVICE_ID_PATTERN)
    transport: Literal["http", "webrtc"] = "http"
    # The announcing sender supplies the token it will present when pushing bytes.
    token: str | None = Field(default=None, min_length=16, max_length=128)


class SenderIdentity(BaseModel):
    """The subset of sender metadata a peer is allowed to assert.

    Device IDs and names are attacker-controlled, so they are constrained to the
    same shape as everywhere else and stripped of control characters before they
    reach storage, logs, or the browser.
    """

    device_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)
    name: str = Field(default="Unknown device", min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    type: str = Field(default="computer", max_length=32)
    node_type: Literal["browser", "server"] = "server"
    ip: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("name", "display_name")
    @classmethod
    def _no_control_characters(cls, value: str | None) -> str | None:
        """Strip control characters so nothing can forge a log line."""
        if value is None:
            return None
        cleaned = "".join(
            character for character in value
            if character.isprintable() and character not in "\r\n\t"
        ).strip()
        return cleaned or "Unknown device"


IncomingTransfer.model_rebuild()


class PairingRequestBody(BaseModel):
    """Ask a device to be paired. The code comes back in the response."""

    device_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)


class PairingConfirmBody(BaseModel):
    device_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)
    code: str = Field(min_length=4, max_length=32)


class BrowserRegistration(BaseModel):
    device_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)
    name: str | None = Field(default=None, min_length=1, max_length=128)
    display_name: str | None = Field(
        default=None, min_length=1, max_length=128)
    device_hint: str | None = Field(default=None, min_length=1, max_length=128)
    type: str = Field(default="phone", min_length=1, max_length=32)
    device_type: str | None = Field(default=None, min_length=1, max_length=32)
    platform: str | None = Field(default=None, max_length=128)
    browser: str | None = Field(default=None, max_length=128)
    capabilities: list[str] = Field(default_factory=lambda: ["webrtc"])
    session_id: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]{16,128}")


class BrowserSessionRequest(BaseModel):
    device_id: str = Field(min_length=8, max_length=128, pattern=DEVICE_ID_PATTERN)
    session_id: str = Field(min_length=16, max_length=256, pattern=r"^[A-Za-z0-9._-]{16,256}$")


class WebRTCSessionRequest(BaseModel):
    peer_device_id: str = Field(min_length=1, max_length=128, pattern=DEVICE_ID_PATTERN)
    transfer_id: str | None = Field(default=None, max_length=128)



class WebRTCSignal(BaseModel):
    payload: dict[str, Any]


class WebRTCFileCompletion(BaseModel):
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


def _services(request: Request):
    return request.app.state.registry, request.app.state.transfers


def settings_max_sessions(request: Request) -> int:
    return int(getattr(request.app.state.settings, "max_browser_sessions", 500))


def settings_max_webrtc_sessions(request: Request) -> int:
    return int(getattr(request.app.state.settings, "max_webrtc_sessions", 200))


def _browser_auth(request: Request, device_id: str) -> bool:
    token = request.headers.get("x-seltransfer-session", "")
    session = request.app.state.browser_sessions.get(token)
    return bool(session and session["device_id"] == device_id and
                session["expires_at"] > time.time())


def _local_token_valid(request: Request) -> bool:
    """True when the caller presented this machine's local CLI token.

    The token is written to the per-user application directory, so it is readable
    by the CLI on this machine and by nothing on the network.
    """
    return verify_local_token(
        request.headers.get("x-seltransfer-local", ""),
        getattr(request.app.state, "local_token", None),
    )


def _session_device_id(request: Request) -> str | None:
    token = request.headers.get("x-seltransfer-session", "")
    session = request.app.state.browser_sessions.get(token)
    if session and session["expires_at"] > time.time():
        return str(session["device_id"])
    return None


def _peer_is_this_machine(request: Request) -> bool:
    """True when the TCP peer is this machine.

    ``request.client.host`` is the address the connection actually came from, which
    a remote peer cannot forge. It is the only thing that separates the user's own
    browser from a device on the LAN, and therefore the only thing that can decide
    who counts as "this machine's user".
    """
    host = request.client.host if request.client else ""
    if not host:
        return False
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        return False
    # The user may also open the interface via this machine's own LAN address, which
    # is a peer address but still this host.
    return host == getattr(request.app.state, "local_address", None)


def _is_local_user(request: Request) -> bool:
    """True for the machine's own user: the local CLI, or a browser on this host.

    A session token alone is *not* enough. ``POST /api/browser/register`` is
    unauthenticated by necessity - a phone has to be able to announce itself before
    anything else can be trusted - so "has a session" only means "some peer asked
    for one". Treating that as authority let any device on the LAN pair any device,
    which is the exact hole the code flow was added to close.
    """
    if _local_token_valid(request):
        return True
    token = request.headers.get("x-seltransfer-session", "")
    session = request.app.state.browser_sessions.get(token)
    return bool(session and session["expires_at"] > time.time()
                and session.get("local"))


def _effective_receiver_id(request: Request, payload_receiver_id: str | None = None) -> str:
    return (payload_receiver_id or _session_device_id(request)
            or request.app.state.registry.local_device.device_id)


def _caller(request: Request) -> str:
    """Resolve the acting device.

    A browser session identifies itself with ``x-seltransfer-session``. The native
    CLI presents ``x-seltransfer-local`` with a token that only this machine can
    read. Anything else is anonymous and gets no identity at all.

    The previous version fell back to the local device ID for unauthenticated
    callers, which meant any peer on the LAN silently inherited the local node's
    identity: it could read local history, cancel local transfers, and obtain
    upload tokens. Anonymous callers now get an empty identity, and the routes
    that need one reject them.
    """
    device_id = _session_device_id(request)
    if device_id:
        return device_id
    if _local_token_valid(request):
        return str(request.app.state.registry.local_device.device_id)
    return ""


def _is_trusted_local_or_session(request: Request) -> bool:
    """True when the caller has proven identity as a session or the local CLI."""
    return bool(_session_device_id(request) or _local_token_valid(request))


def _assert_transfer_visibility(request: Request, transfer: dict[str, Any]) -> None:
    """Restrict a transfer to the two devices involved in it."""
    caller = _caller(request)
    if not caller:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    if transfer.get("sender_id") != caller and transfer.get("receiver_id") != caller:
        raise HTTPException(403, "transfer is not visible to this device")


def _assert_receiver_authorized(request: Request, transfer: dict[str, Any]) -> None:
    """Only the intended receiver may accept or reject."""
    caller = _caller(request)
    if not caller:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    if transfer.get("receiver_id") != caller:
        raise HTTPException(
            403, "only the intended receiver can accept or reject this transfer")


def _assert_sender_authorized(request: Request, transfer: dict[str, Any]) -> None:
    """Only the sender may pause, resume, or cancel its own transfer."""
    caller = _caller(request)
    if not caller:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    if transfer.get("sender_id") != caller:
        raise HTTPException(
            403, "only the sender can pause, resume, or cancel this transfer")



def _transfer_transport(transfer: dict[str, Any]) -> str:
    """The transport chosen for this transfer, defaulting to HTTP."""
    return str(transfer.get("transport") or "http")


def _is_upload_authorized(request: Request, transfer: dict[str, Any]) -> bool:
    """True when this caller may push bytes for the transfer.

    Only the sender qualifies, and only once the receiver has accepted. A browser
    receiver is allowed on the HTTP path: the bytes land on this server and the
    phone pulls them back over the download endpoint. Only the WebRTC path is
    exclusive to a browser receiver, because there the receiver pulls directly
    from the sender.
    """
    if transfer.get("status") != "ACCEPTED" or transfer.get("sender_id") != _caller(request):
        return False
    if _transfer_transport(transfer) == "http":
        return True
    receiver = request.app.state.registry.get(transfer.get("receiver_id", ""))
    return receiver is None or receiver.node_type != "browser"


def _sweep_sessions(request: Request) -> None:
    """Drop expired browser sessions and WebRTC sessions.

    Expiry used to be checked lazily on lookup only, which meant the dictionaries
    kept every session ever issued. ``POST /api/browser/register`` is
    unauthenticated and needs no secret, so a peer could grow the process without
    bound. Deleting on access plus the periodic timer in the lifespan closes that.
    """
    now = time.time()
    sessions = request.app.state.browser_sessions
    for token in [token for token, data in sessions.items()
                  if data["expires_at"] <= now]:
        del sessions[token]
    webrtc = request.app.state.webrtc_sessions
    for session_id in [key for key, data in webrtc.items()
                       if now - data["created_at"] > request.app.state.browser_timeout]:
        del webrtc[session_id]
    request.app.state.pairing.sweep(now)
    sweep_expired_transfers(
        request.app.state.transfers, request.app.state.browser_timeout)


@router.get("/api/status", response_model=StatusResponse)
async def get_status(request: Request):
    from seltransfer import __version__
    _sweep_sessions(request)
    device = request.app.state.registry.local_device
    return StatusResponse(
        status="online", message="SELTRANSFER server is running",
        version=__version__, device_id=device.device_id)


@router.get("/api/health")
async def health_check():
    return {"status": "ok"}


@router.get("/api/connection", response_model=ConnectionResponse)
async def get_connection_info(request: Request):
    """Describe how to reach this server.

    The absolute download path is withheld unless the operator opted in. It was
    previously returned to any unauthenticated caller, which told a peer on the
    LAN exactly where to look on this filesystem for received files. The web
    interface degrades to a generic message when it is hidden.
    """
    device = request.app.state.registry.local_device
    expose = bool(getattr(request.app.state.settings, "expose_paths", False))
    settings = request.app.state.settings
    scheme = settings.scheme()
    return ConnectionResponse(
        connected=True, device_name=device.name, local_address=device.ip,
        server_port=device.port, platform=sys.platform,
        device_id=device.device_id,
        scheme=scheme,
        https_enabled=settings.https_enabled,
        download_directory=(
            str(request.app.state.transfers.download_root.resolve())
            if expose else "hidden; set SELTRANSFER_EXPOSE_PATHS=true to show"),
        qr={"url": f"{scheme}://{device.ip}:{device.port}",
            "service": "seltransfer", "version": 1, **device.public()})


@router.get("/api/devices")
async def get_devices(request: Request):
    registry, _ = _services(request)
    return {"devices": registry.list(), "local_device_id": registry.local_device.device_id,
            "server_device": registry.local_device.public(),
            # Whether this caller is the machine's own user. The client uses it to
            # decide whether to offer one-click pairing or the out-of-band code
            # flow; it describes the caller, so disclosing it discloses nothing.
            "local_user": _is_local_user(request),
            # Which devices this server has paired. Only meaningful to a caller
            # with an identity; an anonymous peer is told nothing, since the list
            # is a map of who may be contacted.
            "paired_devices": sorted(
                request.app.state.pairing.paired_devices())
            if _is_trusted_local_or_session(request) else [],
            "browser_session_device_id": next(
                (item["device_id"] for item in request.app.state.browser_sessions.values()
                 if item["expires_at"] > time.time()), None)}


@router.post("/api/browser/register")
async def register_browser(payload: BrowserRegistration, request: Request):
    registry, _ = _services(request)
    token = payload.session_id or secrets.token_urlsafe(32)
    existing_session = request.app.state.browser_sessions.get(token)
    if existing_session and (existing_session["device_id"] != payload.device_id or
                             existing_session["expires_at"] <= time.time()):
        token = secrets.token_urlsafe(32)

    device_type = payload.device_type or payload.type or "phone"
    resolved_name = resolve_device_display_name(
        user_name=payload.display_name or payload.name,
        device_hint=payload.device_hint,
        device_type=device_type,
        platform=payload.platform,
        hostname=registry.local_device.name,
    )
    device = Device(device_id=payload.device_id, name=resolved_name, type=device_type,
                    node_type="browser", transport=["webrtc"], ip=request.client.host
                    if request.client else None, port=None, platform=payload.platform,
                    browser=payload.browser, capabilities=payload.capabilities,
                    session_id=token, display_name=resolved_name)
    _sweep_sessions(request)
    # Bound the table. Registering is unauthenticated, so without a cap it is a
    # cheap way to make the process grow.
    if len(request.app.state.browser_sessions) >= settings_max_sessions(request):
        oldest = sorted(
            request.app.state.browser_sessions.items(),
            key=lambda item: item[1]["expires_at"],
        )
        for stale, _data in oldest[:len(oldest) // 4 + 1]:
            del request.app.state.browser_sessions[stale]
    try:
        registry.register_browser(device)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    expires_at = time.time() + request.app.state.browser_timeout
    request.app.state.browser_sessions[token] = {
        "device_id": payload.device_id, "expires_at": expires_at,
        # Whether this session belongs to the machine's own user. See
        # `_is_local_user`: a session from a LAN peer is not authority to pair.
        "local": _peer_is_this_machine(request),
    }
    logger = request.app.state.logger
    logger.info("BROWSER registered device=%s", payload.device_id)
    return {"device_id": payload.device_id, "session_id": token,
            "server_device_id": registry.local_device.device_id,
            "display_name": resolved_name,
            "device_type": device_type,
            "expires_at": datetime.fromtimestamp(expires_at, UTC).isoformat()}


@router.post("/api/browser/heartbeat")
async def browser_heartbeat(payload: BrowserSessionRequest, request: Request):
    if not _browser_auth(request, payload.device_id) or payload.session_id != request.headers.get(
            "x-seltransfer-session"):
        raise HTTPException(401, "invalid browser session")
    device = request.app.state.registry.heartbeat_browser(
        payload.device_id, payload.session_id)
    if not device:
        raise HTTPException(401, "invalid browser session")
    expires_at = time.time() + request.app.state.browser_timeout
    request.app.state.browser_sessions[payload.session_id]["expires_at"] = expires_at
    return {"status": "online", "expires_at": datetime.fromtimestamp(
        expires_at, UTC).isoformat()}


@router.post("/api/browser/unregister")
async def unregister_browser(payload: BrowserSessionRequest, request: Request):
    if not _browser_auth(request, payload.device_id) or payload.session_id != request.headers.get(
            "x-seltransfer-session"):
        raise HTTPException(401, "invalid browser session")
    request.app.state.registry.unregister_browser(
        payload.device_id, payload.session_id)
    request.app.state.browser_sessions.pop(payload.session_id, None)
    return {"status": "unregistered"}


@router.post("/api/webrtc/session")
async def create_webrtc_session(payload: WebRTCSessionRequest, request: Request):
    peer = request.app.state.registry.get(payload.peer_device_id)
    if not peer:
        raise HTTPException(404, "peer device is unavailable")
    if peer.node_type != "browser":
        raise HTTPException(409, "WebRTC sessions require a browser receiver")
    owner_device_id = _session_device_id(request)
    local_device_id = request.app.state.registry.local_device.device_id
    if not owner_device_id:
        transfer = request.app.state.transfers.transfers.get(payload.transfer_id or "")
        if transfer and transfer.get("sender_id") == local_device_id:
            owner_device_id = local_device_id
    if not owner_device_id:
        raise HTTPException(401, "valid browser session required")
    _sweep_sessions(request)
    sessions = request.app.state.webrtc_sessions
    limit = settings_max_webrtc_sessions(request)
    if len(sessions) >= limit:
        # A session row holds buffered signalling messages, so this table is a
        # memory sink a paired peer can grow without bound. Refuse rather than
        # evict someone's live connection.
        raise HTTPException(
            503, f"too many WebRTC sessions ({limit}); try HTTP instead")
    session_id = secrets.token_urlsafe(24)
    sessions[session_id] = {
        "owner": request.headers.get("x-seltransfer-session"),
        "owner_device_id": owner_device_id,
        "peer_device_id": payload.peer_device_id,
        "transfer_id": payload.transfer_id,
        "signals": [], "created_at": time.time()}
    if payload.transfer_id:
        try:
            transfer = request.app.state.transfers.get(payload.transfer_id)
            if transfer["status"] == "ACCEPTED":
                request.app.state.transfers.update_state(payload.transfer_id, "CONNECTING")
        except KeyError as error:
            raise HTTPException(404, "transfer not found") from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
    return {"session_id": session_id, "peer_device_id": payload.peer_device_id,
            "transfer_id": payload.transfer_id, "status": "CONNECTING"}


@router.get("/api/webrtc/sessions")
async def list_webrtc_sessions(request: Request):
    token = request.headers.get("x-seltransfer-session", "")
    browser = request.app.state.browser_sessions.get(token)
    if not browser or browser["expires_at"] <= time.time():
        raise HTTPException(401, "invalid browser session")
    device_id = browser["device_id"]
    sessions = [
        {"session_id": session_id, "peer_device_id": data["owner_device_id"],
         "transfer_id": data["transfer_id"]}
        for session_id, data in request.app.state.webrtc_sessions.items()
        if data["peer_device_id"] == device_id and data["created_at"] > time.time() - 300
    ]
    return {"sessions": sessions}


@router.post("/api/webrtc/{session_id}/{signal_type}")
async def relay_webrtc_signal(session_id: str, signal_type: str, payload: WebRTCSignal,
                              request: Request):
    session = request.app.state.webrtc_sessions.get(session_id)
    if not session or signal_type not in {"offer", "answer", "ice", "close"}:
        raise HTTPException(404, "WebRTC session not found")
    if _caller(request) not in {session["owner_device_id"], session["peer_device_id"]}:
        raise HTTPException(401, "valid session required")
    if signal_type == "close":
        request.app.state.webrtc_sessions.pop(session_id, None)
        return {"status": "closed"}
    session["signals"].append({"type": signal_type, "payload": payload.payload,
                               "created_at": time.time()})
    return {"status": "accepted"}


@router.get("/api/webrtc/{session_id}")
async def get_webrtc_signals(session_id: str, request: Request):
    session = request.app.state.webrtc_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "WebRTC session not found")
    if _caller(request) not in {session["owner_device_id"], session["peer_device_id"]}:
        raise HTTPException(401, "valid session required")
    return {"session_id": session_id, "signals": session["signals"]}


@router.post("/api/webrtc/{session_id}/files/{index}/complete")
async def complete_webrtc_file(session_id: str, index: int,
                               payload: WebRTCFileCompletion, request: Request):
    session = request.app.state.webrtc_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "WebRTC session not found")
    caller = _session_device_id(request)
    if caller != session["peer_device_id"]:
        raise HTTPException(401, "receiver browser session required")
    try:
        return request.app.state.transfers.complete_browser_file(
            session["transfer_id"], index, payload.size, payload.sha256)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    except (ValueError, IndexError) as error:
        raise HTTPException(400, str(error)) from error


@router.post("/api/devices/discover")
async def discover_devices(request: Request):
    registry, _ = _services(request)
    request.app.state.discovery.start()
    return {"devices": registry.list()}


@router.post("/api/devices/{device_id}/pair/request")
async def request_pairing(device_id: str, payload: PairingRequestBody,
                          request: Request):
    """Begin pairing by producing a code the destination must read.

    The response deliberately does **not** contain the code. An earlier version
    did, which made the whole flow self-service: an anonymous peer could call this
    endpoint, read the code out of the response, and immediately confirm it. Two
    requests, no out-of-band element, pairing complete - and pairing is the
    precondition for creating a transfer.

    The code is displayed by the destination instead, via
    ``GET /api/pairing/pending``, and the requester reads it off that screen.
    """
    registry, _ = _services(request)
    if device_id != payload.device_id:
        raise HTTPException(422, "device_id in the path and body must match")
    device = registry.get(device_id)
    if not device:
        raise HTTPException(404, "device is unavailable")
    pairing = request.app.state.pairing
    try:
        pending = pairing.request(device_id, _caller(request))
    except LookupError as error:
        raise HTTPException(429, str(error)) from error
    # No code, and no hash. The requester now has to be told one by the user.
    return {
        **pending.public(),
        "next": ("ask the user of this machine to read the code it is showing, "
                 "then POST it to /api/devices/{device_id}/pair/confirm"),
    }


@router.get("/api/pairing/status/{device_id}")
async def pairing_status(device_id: str, request: Request):
    """Whether a device is paired, so a requester can poll for approval.

    Available to anyone, deliberately. The requester has to learn that the
    destination's user approved, and there is nothing secret here to learn: the
    code is never returned, and the same pairing state is already published by
    ``GET /api/devices`` as ``paired_devices``. If this were restricted to the
    local user, the requester could only find out by asking that user, which is
    the interaction approval exists to remove.
    """
    registry, _ = _services(request)
    if not registry.get(device_id):
        raise HTTPException(404, "device is unavailable")
    pairing = request.app.state.pairing.get(device_id)
    return {
        "device_id": device_id,
        "paired": pairing is not None,
        "method": pairing.method if pairing else None,
        "expires_at": pairing.expires_at if pairing else None,
    }


@router.post("/api/pairing/requests/{request_id}/approve")
async def approve_pairing(request_id: str, request: Request):
    """Grant a pairing because this machine's own user clicked Approve.

    The click is the intent, so nothing has to be read out and no code reaches
    the requester. That makes this path stronger than confirming a code: flooding
    requests cannot produce a pairing, because approving one is an action only
    this machine's user can take.

    Local user only, and that check comes first so the response cannot be used to
    probe which request ids exist.
    """
    if not _is_local_user(request):
        raise HTTPException(
            403, "approving a pairing requires this machine's own user")
    _sweep_sessions(request)
    pairing = request.app.state.pairing
    try:
        granted = pairing.approve(request_id, _caller(request))
    except LookupError as error:
        # Expired and already-approved ids land here too, so the 404 does not
        # double as a "that request existed once" oracle.
        raise HTTPException(404, str(error)) from error
    request.app.state.logger.info(
        "PAIRING APPROVED device_id=%s granted_by=%s method=%s",
        granted.device_id, granted.granted_by, granted.method)
    return {"status": "paired", "pairing": granted.public()}


@router.get("/api/pairing/pending")
async def list_pending_pairings(request: Request):
    """Pending pairing requests with their codes, for display at the destination.

    Restricted to this machine's own user: a browser session registered from
    loopback, or the local CLI token. A peer on the LAN has no local session, so
    it can create a request (and see only that it did) but can never read the
    code that request generated - which is what keeps ``/pair/confirm`` a real
    proof of intent rather than a formality.
    """
    if not _is_local_user(request):
        raise HTTPException(
            403, "pending pairing codes are only shown to this machine's own user")
    _sweep_sessions(request)
    return {"requests": request.app.state.pairing.reveal_pending()}


@router.post("/api/devices/{device_id}/pair/confirm")
async def confirm_pairing(device_id: str, payload: PairingConfirmBody,
                          request: Request):
    """Exchange a code for a pairing."""
    if device_id != payload.device_id:
        raise HTTPException(422, "device_id in the path and body must match")
    registry, _ = _services(request)
    if not registry.get(device_id):
        raise HTTPException(404, "device is unavailable")
    pairing = request.app.state.pairing
    try:
        granted = pairing.confirm(device_id, _caller(request), payload.code)
    except LookupError as error:
        raise HTTPException(404, str(error)) from error
    except PermissionError as error:
        # 403 rather than 401: the caller is identified, they just cannot prove
        # intent for this device. No hint about which codes exist is given.
        raise HTTPException(403, str(error)) from error
    request.app.state.logger.info(
        "PAIRING CONFIRMED device_id=%s granted_by=%s method=%s",
        device_id, granted.granted_by, granted.method)
    return {"status": "paired", "pairing": granted.public()}


@router.post("/api/devices/{device_id}/pair")
async def pair_device(device_id: str, request: Request):
    """Pair a device, given proof of intent.

    Two callers are trusted, and no others:

    * the local CLI, via the token only a process on this machine can read; and
    * a browser session registered *from this machine* - the user is looking at
      the destination in this interface and clicking is the explicit interaction.

    Requiring the local session specifically matters. Registration is
    unauthenticated, so a peer can obtain a session token for free; accepting any
    session here would let a device on the LAN pair any device, which is precisely
    the hole the pairing code was introduced to close.

    Anyone else gets 403 and must read a code off the destination's screen.
    """
    registry, _ = _services(request)
    device = registry.get(device_id)
    if not device:
        raise HTTPException(404, "device is unavailable")
    if not _is_local_user(request):
        raise HTTPException(
            403,
            "pairing requires this machine's own user or a pairing code; "
            "request one with POST /api/devices/{id}/pair/request")
    granted = request.app.state.pairing.grant_directly(
        device_id, _caller(request), "session")
    request.app.state.logger.info(
        "PAIRING GRANTED device_id=%s granted_by=%s method=%s",
        device_id, granted.granted_by, granted.method)
    return {"status": "paired", "device": device.public(),
            "pairing": granted.public()}


@router.delete("/api/devices/{device_id}/pair")
async def unpair_device(device_id: str, request: Request):
    """Revoke a pairing.

    Local user only. Allowing any session here would let a peer revoke pairings
    and so deny the user the ability to send, which needs no credential worth
    stealing - a self-registered session is enough.
    """
    if not _is_local_user(request):
        raise HTTPException(403, "unpairing requires this machine's own user")
    request.app.state.pairing.unpair(device_id)
    request.app.state.logger.info("PAIRING REVOKED device_id=%s", device_id)
    return {"status": "unpaired", "device_id": device_id}


@router.post("/api/transfers")
async def create_transfer(payload: TransferCreate, request: Request):
    registry, transfers = _services(request)
    if not registry.get(payload.receiver_id):
        raise HTTPException(404, "destination device is unavailable")
    if not request.app.state.pairing.is_paired(payload.receiver_id):
        raise HTTPException(
            403,
            "pair with the destination device first: request a code with "
            "POST /api/devices/{id}/pair/request and confirm it")
    try:
        sender_id = _caller(request)
        if not sender_id:
            # Falling back to the local device here let any anonymous peer create a
            # transfer *as this machine*, which put a forged sender in the victim's
            # history and hands out an upload token for it.
            raise HTTPException(
                401, "a browser session or the local CLI token is required")
        if sender_id == payload.receiver_id:
            raise HTTPException(400, "sender and receiver must differ")
        sender = registry.get(sender_id) or registry.local_device
        device = registry.get(payload.receiver_id)
        if payload.transport == "webrtc" and device is not None and device.node_type != "browser":
            raise HTTPException(
                422, "the WebRTC transport requires a browser receiver")
        result = transfers.create(sender_id, payload.receiver_id,
                                  [file.model_dump()
                                   for file in payload.files],
                                  sender=sender.public(),
                                  transport=payload.transport)
        request.app.state.logger.info(
            "TRANSFER CREATE sender_id=%s receiver_id=%s transfer_id=%s status=%s",
            sender_id, payload.receiver_id, result["transfer_id"], result["status"])
        result["destination"] = device.public()
        result["transfer_transport"] = payload.transport
        result["sender"] = sender.public()
        return result
    except ValueError as error:
        raise HTTPException(422, str(error)) from error


@router.get("/api/transfers")
async def list_transfers(request: Request):
    """Return only the transfers the calling device participates in."""
    caller = _caller(request)
    if not caller:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    return {"transfers": request.app.state.history.list_for(caller)}


async def _clear_transfer_history(request: Request):
    caller = _caller(request)
    if not caller:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    request.app.state.history.clear_for(caller)
    return {"status": "cleared"}



@router.delete("/api/transfers/history")
async def clear_transfer_history(request: Request):
    return await _clear_transfer_history(request)


@router.post("/api/transfers/history/clear")
async def clear_transfer_history_compat(request: Request):
    return await _clear_transfer_history(request)


@router.post("/api/incoming-transfers")
async def receive_transfer_request(payload: IncomingTransfer, request: Request):
    """Accept a transfer announced by a peer.

    Reachable without authentication, because a remote sender has no session on
    this server. That is why the pending count is capped and why every field is
    validated: an anonymous peer gets to create bounded, well-formed, inert
    records, and nothing more. It cannot read them back, accept them, or upload
    bytes without a token it chose and must present.
    """
    registry, transfers = _services(request)
    sender = payload.sender.model_dump()
    if sender["device_id"] == registry.local_device.device_id:
        raise HTTPException(400, "sender and receiver must differ")
    if payload.total_bytes != sum(file.size for file in payload.files):
        raise HTTPException(422, "total_bytes does not match file metadata")
    try:
        existing = transfers.get_or_none(payload.transfer_id)
        authenticated_sender = _session_device_id(request)
        if (existing and authenticated_sender and
                existing.get("sender_id") == authenticated_sender):
            receiver_id = existing["receiver_id"]
        else:
            receiver_id = _effective_receiver_id(request, payload.receiver_id)
        # Anonymous callers may not name a receiver, or they could aim pending
        # transfers at whichever device they choose. A session may.
        if not authenticated_sender and payload.receiver_id:
            receiver_id = registry.local_device.device_id
        request.app.state.logger.info(
            "INCOMING REQUEST transfer_id=%s authenticated_receiver=%s "
            "payload_receiver=%s stored_receiver=%s",
            payload.transfer_id, _session_device_id(
                request), payload.receiver_id,
            existing.get("receiver_id") if existing else receiver_id)
        if existing:
            if (existing.get("sender_id") == sender["device_id"]
                    and existing.get("receiver_id") == receiver_id):
                result = transfers.public(existing)
                result["direction"] = "incoming"
                return result
            raise HTTPException(
                409, "transfer already exists for a different receiver context")
        if receiver_id != registry.local_device.device_id and not registry.get(receiver_id):
            raise HTTPException(404, "receiver device is unavailable")
        _enforce_pending_cap(request, receiver_id)
        created = transfers.create(sender["device_id"], receiver_id,
                                   [file.model_dump()
                                    for file in payload.files], "incoming",
                                   payload.transfer_id, sender,
                                   payload.transport, payload.token)
        created["direction"] = "incoming"
        return created
    except (KeyError, ValueError) as error:
        raise HTTPException(422, str(error)) from error


def _enforce_pending_cap(request: Request, receiver_id: str) -> None:
    """Refuse unbounded pending announcements.

    Every one of these is an unauthenticated write that also touches SQLite, so
    without a cap a single peer can fill the disk with history rows.
    """
    settings = request.app.state.settings
    pending = sum(
        1 for transfer in request.app.state.transfers.transfers.values()
        if transfer.get("receiver_id") == receiver_id
        and transfer.get("status") == "PENDING"
    )
    if pending >= settings.max_pending_incoming:
        raise HTTPException(
            429,
            f"too many pending incoming transfers (limit "
            f"{settings.max_pending_incoming}); accept or reject one first")



@router.get("/api/incoming-transfers")
async def list_incoming_transfers(request: Request):
    receiver_id = _caller(request)
    if not receiver_id:
        raise HTTPException(
            401, "a browser session or the local CLI token is required")
    transfers = []
    for item in request.app.state.transfers.transfers.values():
        if item.get("receiver_id") != receiver_id:
            continue
        if item.get("status") != "PENDING":
            continue
        result = request.app.state.transfers.public(item)
        result["direction"] = "incoming"
        transfers.append(result)
    request.app.state.logger.info(
        "INCOMING LIST authenticated_receiver=%s pending_transfer_ids=%s",
        receiver_id, [item["transfer_id"] for item in transfers])
    return {"transfers": transfers}


@router.get("/api/incoming-transfers/{transfer_id}")
async def get_incoming_transfer(transfer_id: str, request: Request):
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_transfer_visibility(request, transfer)
    result = request.app.state.transfers.public(transfer)
    caller = _caller(request)
    result["direction"] = "incoming" if transfer.get(
        "receiver_id") == caller else "outgoing"
    if _is_upload_authorized(request, transfer):
        result["transfer_token"] = transfer["token"]
    return result


@router.post("/api/incoming-transfers/{transfer_id}/accept")
async def accept_incoming_transfer(transfer_id: str, request: Request):
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_receiver_authorized(request, transfer)
    status_before = transfer["status"]
    try:
        transfer = request.app.state.transfers.update_state(
            transfer_id, "ACCEPTED")
        request.app.state.logger.info(
            "TRANSFER ACCEPT transfer_id=%s authenticated_receiver=%s "
            "stored_receiver=%s status_before=%s status_after=%s",
            transfer_id, _session_device_id(request), transfer["receiver_id"],
            status_before, transfer["status"])
        transport = _transfer_transport(transfer)
        result = {**transfer, "status": "ACCEPTED",
                  "transfer_transport": transport}
        if transport == "http":
            # Only the address the sender should PUT to. The upload token is
            # deliberately not returned here: the sender learns it from its own
            # server's state view, or already chose it when it announced the
            # transfer. Handing it to the receiver would let the receiver push
            # bytes that look like they came from the sender.
            result["upload_url"] = f"/api/incoming-transfers/{transfer_id}/files"
        result["direction"] = "incoming"
        return result
    except ValueError as error:
        raise HTTPException(409, str(error)) from error


@router.post("/api/incoming-transfers/{transfer_id}/reject")
async def reject_incoming_transfer(transfer_id: str, request: Request):
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_receiver_authorized(request, transfer)
    status_before = transfer["status"]
    result = await _change_transfer_state(transfer_id, "REJECTED", request, "receiver")
    request.app.state.logger.info(
        "TRANSFER REJECT transfer_id=%s authenticated_receiver=%s "
        "stored_receiver=%s status_before=%s status_after=%s",
        transfer_id, _session_device_id(request), transfer["receiver_id"],
        status_before, result["status"])
    return result


@router.put("/api/incoming-transfers/{transfer_id}/files/{index}")
async def upload_incoming_file(transfer_id: str, index: int, request: Request):
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    receiver = request.app.state.registry.get(transfer["receiver_id"])
    is_browser = receiver is not None and receiver.node_type == "browser"
    if is_browser and _transfer_transport(transfer) == "webrtc":
        raise HTTPException(409, "this transfer uses the WebRTC data channel")
    token = request.headers.get("x-seltransfer-token", "")
    try:
        return await request.app.state.transfers.receive_file(
            transfer_id, index, request.stream(), token)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    except PermissionError as error:
        raise HTTPException(401, str(error)) from error
    except (ValueError, IndexError) as error:
        raise HTTPException(400, str(error)) from error


@router.get("/api/incoming-transfers/{transfer_id}/files/{index}")
async def download_incoming_file(transfer_id: str, index: int, request: Request):
    """Let the receiver pull a file that was uploaded to this server.

    This is the missing half of the PC-to-phone HTTP path: the sender pushes the
    bytes here, and a phone browser retrieves them with its own session rather
    than needing a shared secret. Only the intended receiver may read.
    """
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_receiver_authorized(request, transfer)
    if index < 0 or index >= len(transfer["files"]):
        raise HTTPException(404, "file not found")
    received = transfer.get("received_files") or {}
    stored = received.get(str(index))
    if stored is None:
        raise HTTPException(404, "file has not been received yet")
    path = Path(str(stored))
    # Defend against a stale or tampered record pointing outside the download
    # tree, even though nothing should write one.
    try:
        resolved = path.resolve()
        root = request.app.state.transfers.download_root.resolve()
    except OSError as error:
        raise HTTPException(500, "stored file is unreadable") from error
    if not resolved.is_relative_to(root):
        raise HTTPException(400, "invalid stored file path")
    if not resolved.is_file():
        raise HTTPException(404, "file has been removed from the server")
    metadata = transfer["files"][index]
    return FileResponse(
        resolved,
        media_type="application/octet-stream",
        filename=Path(str(metadata["name"])).name,
    )


@router.get("/api/transfers/{transfer_id}")
async def get_transfer(transfer_id: str, request: Request):
    """Read one transfer as a participant.

    Once the receiver has accepted, the sender is handed the credential it needs
    to push bytes; without this the native CLI has no way to obtain it, because
    polling the *destination* resolves the caller to the receiver.
    """
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_transfer_visibility(request, transfer)
    result = request.app.state.transfers.public(transfer)
    if _is_upload_authorized(request, transfer):
        result["transfer_token"] = transfer["token"]
    return result


async def _change_transfer_state(transfer_id: str, state: str, request: Request,
                                 role: str) -> dict[str, Any]:
    """Apply a state change after checking the caller owns the transition.

    The role is passed explicitly rather than inferred from the target state:
    both 'accept' and 'resume' land on ACCEPTED, but only the receiver may accept
    while only the sender may resume.
    """
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    if role == "receiver":
        _assert_receiver_authorized(request, transfer)
    else:
        _assert_sender_authorized(request, transfer)
    try:
        result: dict[str, Any] = request.app.state.transfers.update_state(
            transfer_id, state)
        return result
    except ValueError as error:
        raise HTTPException(409, str(error)) from error


@router.post("/api/transfers/{transfer_id}/accept")
async def accept_transfer(transfer_id: str, request: Request):
    return await _change_transfer_state(transfer_id, "ACCEPTED", request, "receiver")


@router.post("/api/transfers/{transfer_id}/reject")
async def reject_transfer(transfer_id: str, request: Request):
    return await _change_transfer_state(transfer_id, "REJECTED", request, "receiver")


@router.post("/api/transfers/{transfer_id}/cancel")
async def cancel_transfer(transfer_id: str, request: Request):
    return await _change_transfer_state(transfer_id, "CANCELLED", request, "sender")


@router.post("/api/transfers/{transfer_id}/pause")
async def pause_transfer(transfer_id: str, request: Request):
    return await _change_transfer_state(transfer_id, "PAUSED", request, "sender")


@router.post("/api/transfers/{transfer_id}/resume")
async def resume_transfer(transfer_id: str, request: Request):
    return await _change_transfer_state(transfer_id, "ACCEPTED", request, "sender")


@router.put("/api/transfers/{transfer_id}/files/{index}")
async def upload_file(transfer_id: str, index: int, request: Request):
    raise HTTPException(
        410, "upload to the destination device via /api/incoming-transfers")


@router.get("/api/transfers/{transfer_id}/progress")
async def transfer_progress(transfer_id: str, request: Request):
    try:
        transfer = request.app.state.transfers.get(transfer_id)
    except KeyError as error:
        raise HTTPException(404, "transfer not found") from error
    _assert_transfer_visibility(request, transfer)
    total = int(transfer["total_bytes"])
    transferred = int(transfer["transferred_bytes"])
    return {
        "transfer_id": transfer_id,
        "status": transfer["status"],
        "transferred_bytes": transferred,
        "total_bytes": total,
        # A zero-byte transfer is trivially complete, not 0%.
        "percent": round(transferred * 100 / total, 2) if total else 100,
    }
