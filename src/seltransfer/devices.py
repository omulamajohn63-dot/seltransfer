"""LAN device identity, registry, and lightweight UDP discovery."""

from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field

from . import __version__
from .network import get_all_interfaces

logger = logging.getLogger("seltransfer.discovery")
DISCOVERY_PORT = 8766

_NAME_ALLOWED_PATTERN = re.compile(r"^[\w\s'\-._()&/]+$")


def validate_device_name(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if len(candidate) > 50:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        return None
    if any(ch in {"<", ">"} for ch in candidate):
        return None
    lowered = candidate.casefold()
    if any(marker in lowered for marker in ["<script", "javascript:", "onerror", "onload"]):
        return None
    if not _NAME_ALLOWED_PATTERN.fullmatch(candidate):
        return None
    return candidate


_PLATFORM_LABELS = (
    (("android",), "Android Phone"),
    (("ipad", "ios"), "iPad"),
    (("iphone",), "iPhone"),
    (("win",), "Windows PC"),
    (("mac",), "Mac"),
    (("linux",), "Linux PC"),
)
_COMPUTER_TYPES = {"computer", "desktop", "laptop", "pc"}
_PHONE_TYPES = {"phone", "mobile"}


def _platform_label(platform: str) -> str | None:
    for markers, label in _PLATFORM_LABELS:
        if any(marker in platform for marker in markers):
            return label
    return None


def generic_device_fallback(device_type: str | None = None, platform: str | None = None) -> str:
    device_type = (device_type or "").strip().lower()
    platform = (platform or "").strip().lower()
    from_platform = _platform_label(platform)

    if device_type in _PHONE_TYPES:
        return from_platform if from_platform == "Android Phone" else "Phone"
    if device_type == "tablet":
        return "iPad" if from_platform == "iPad" else "Tablet"
    if device_type in _COMPUTER_TYPES:
        return from_platform if from_platform and from_platform.endswith("PC") else "Computer"
    if from_platform:
        return from_platform
    if device_type in _PHONE_TYPES:
        return "Phone"
    return "Computer"


def resolve_device_display_name(
    user_name: str | None = None,
    device_hint: str | None = None,
    device_type: str | None = None,
    platform: str | None = None,
    hostname: str | None = None,
) -> str:
    custom_name = validate_device_name(user_name)
    if custom_name:
        return custom_name

    if device_hint:
        cleaned_hint = validate_device_name(device_hint)
        if cleaned_hint:
            return cleaned_hint

    if hostname:
        cleaned_hostname = validate_device_name(hostname)
        if cleaned_hostname and cleaned_hostname.lower() not in {"unknown", "browser", "computer"}:
            return cleaned_hostname

    return generic_device_fallback(device_type, platform)


@dataclass
class Device:
    device_id: str
    name: str
    type: str
    ip: str | None = None
    port: int | None = None
    node_type: str = "server"
    transport: list[str] = field(default_factory=lambda: ["http", "webrtc"])
    platform: str | None = None
    browser: str | None = None
    session_id: str | None = field(default=None, repr=False)
    status: str = "online"
    version: str = __version__
    capabilities: list[str] = field(default_factory=lambda: [
        "send", "receive", "multiple_files", "folders"])
    display_name: str | None = None
    last_seen: float = field(default_factory=time.time, repr=False)

    def public(self) -> dict:
        result = asdict(self)
        result["display_name"] = result.get(
            "display_name") or result.get("name")
        result["device_type"] = result.get("type")
        result.pop("last_seen", None)
        result.pop("session_id", None)
        return result


class DeviceRegistry:
    def __init__(self, local_device: Device, timeout: int = 30) -> None:
        self.local_device = local_device
        self.timeout = timeout
        self._devices: dict[str, Device] = {
            local_device.device_id: local_device}
        self._lock = threading.RLock()

    def upsert(self, device: Device) -> None:
        if device.device_id == self.local_device.device_id:
            return
        with self._lock:
            device.last_seen = time.time()
            self._devices[device.device_id] = device

    def register_browser(self, device: Device) -> Device:
        if device.node_type != "browser" or not device.session_id:
            raise ValueError("browser registration requires a session")
        device.last_seen = time.time()
        with self._lock:
            existing = self._devices.get(device.device_id)
            if existing and existing.node_type == "browser":
                if existing.session_id != device.session_id:
                    raise ValueError("device ID is already registered")
                existing.name = device.name
                existing.display_name = device.display_name or device.name
                existing.type = device.type
                existing.ip = device.ip
                existing.platform = device.platform
                existing.browser = device.browser
                existing.capabilities = device.capabilities
                existing.transport = device.transport
                existing.last_seen = device.last_seen
                return existing
            if existing:
                raise ValueError("device ID belongs to a server node")
            self._devices[device.device_id] = device
            return device

    def unregister_browser(self, device_id: str, session_id: str) -> bool:
        with self._lock:
            device = self._devices.get(device_id)
            if not device or device.node_type != "browser" or device.session_id != session_id:
                return False
            del self._devices[device_id]
            return True

    def heartbeat_browser(self, device_id: str, session_id: str) -> Device | None:
        with self._lock:
            device = self._devices.get(device_id)
            if not device or device.node_type != "browser" or device.session_id != session_id:
                return None
            device.last_seen = time.time()
            device.status = "online"
            return device

    def list(self) -> list[dict]:
        now = time.time()
        with self._lock:
            for device in self._devices.values():
                if device.device_id != self.local_device.device_id:
                    device.status = (
                        "online" if now - device.last_seen <= self.timeout else "offline")
            return [device.public() for device in self._devices.values()]

    def get(self, device_id: str) -> Device | None:
        with self._lock:
            device = self._devices.get(device_id)
            return device if device and device.status == "online" else None


class DiscoveryService:
    def __init__(self, registry: DeviceRegistry, interval: int = 5) -> None:
        self.registry = registry
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="seltransfer-discovery", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

    def _run(self) -> None:
        local = self.registry.local_device
        payload = json.dumps(
            {"service": "seltransfer", "device": local.public()}).encode()
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", DISCOVERY_PORT))
            sock.settimeout(1)
            broadcasts = {iface.broadcast for iface in get_all_interfaces()
                          if iface.is_usable() and iface.broadcast}
            if not broadcasts:
                broadcasts = {"255.255.255.255"}
            while not self._stop.is_set():
                try:
                    for broadcast in broadcasts:
                        sock.sendto(payload, (broadcast, DISCOVERY_PORT))
                    while True:
                        data, address = sock.recvfrom(8192)
                        message = json.loads(data.decode())
                        device_data = message.get("device", {})
                        if message.get("service") == "seltransfer" and device_data.get("device_id"):
                            device_data["ip"] = address[0]
                            self.registry.upsert(Device(**device_data))
                except (TimeoutError, OSError, ValueError, TypeError) as error:
                    if not self._stop.is_set():
                        logger.debug("Discovery cycle failed: %s", error)
                self._stop.wait(self.interval)
        except OSError as error:
            logger.warning("LAN discovery unavailable: %s", error)
        finally:
            sock.close()


def create_local_device(ip: str, port: int, name: str | None = None, identity_path=None) -> Device:
    if identity_path is not None:
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        if identity_path.exists():
            device_id = identity_path.read_text(encoding="ascii").strip()
        else:
            device_id = str(uuid.uuid4())
            identity_path.write_text(device_id, encoding="ascii")
    else:
        device_id = str(uuid.uuid4())
    resolved_name = resolve_device_display_name(
        user_name=name, hostname=socket.gethostname(), device_type="computer")
    return Device(device_id=device_id, name=resolved_name, type="computer",
                  ip=ip, port=port, node_type="server", transport=["http", "webrtc"],
                  display_name=resolved_name)
