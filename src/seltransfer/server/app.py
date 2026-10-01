"""FastAPI application initialization and configuration."""

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse

from seltransfer import __version__, resources
from seltransfer.config import ensure_local_token, get_settings
from seltransfer.devices import DeviceRegistry, DiscoveryService, create_local_device
from seltransfer.network.detection import detect_network
from seltransfer.pairing import PairingRegistry
from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager, sweep_expired_transfers

from . import routes

logger = logging.getLogger("seltransfer.server")

SWEEP_INTERVAL_SECONDS = 60.0


class PrivateHostMiddleware:
    """Reject requests whose Host header is not a local address.

    Starlette's own TrustedHostMiddleware only understands ``*.example.com``
    wildcards, not address ranges, so the ranges are evaluated here instead.

    This exists for DNS rebinding. CORS prevents a page on the internet from
    *reading* this API, but it does not stop the browser from *sending* a request,
    and a public domain whose DNS resolves to 192.168.x.x makes the call
    same-origin, so the origin policy never applies to it. Requiring the Host
    header to name a loopback, private, or link-local address - the only hosts
    that could legitimately be this machine on a LAN - closes that hole while
    still letting a phone reach the PC over any of its interfaces.

    Set ``allowed_hosts=["*"]`` to disable, or list exact hostnames to allow
    something else. Configuring the list makes it *strict*: only the listed names
    (plus the address this server is serving) are answered, because a security
    control that silently widens itself is worse than none.
    """

    def __init__(self, app, allowed_hosts: list[str],
                 allow_private: bool = True) -> None:
        self.app = app
        self.allowed = [host.lower() for host in allowed_hosts]
        self.allow_private = allow_private

    def _permitted(self, host: str) -> bool:
        if "*" in self.allowed or "*" in host:
            return True
        host = host.lower()
        if host in self.allowed:
            return True
        if not self.allow_private:
            return False
        # Strip the port and any IPv6 brackets before judging the address.
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        name = name.strip("[]")
        if name in {"localhost", ""}:
            return True
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            return False
        return (address.is_loopback or address.is_private
                or address.is_link_local)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        host = headers.get("host", "")
        if not self._permitted(host):
            response = PlainTextResponse(
                "Invalid Host header. This server only answers to local "
                "addresses; a request naming a public host is refused.",
                status_code=400,
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _sweep_loop(app: FastAPI) -> None:
    """Periodically drop expired sessions, pairings, and finished transfers.

    These are all bounded, but nothing deletes them unless an endpoint happens to
    be touched, and a server can sit idle indefinitely.
    """
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        try:
            app.state.pairing.sweep()
            sweep_expired_transfers(app.state.transfers,
                                    app.state.browser_timeout)
        except Exception:  # noqa: BLE001 - a failed sweep must not stop the server
            logger.exception("scheduled cleanup failed")

# Loopback plus RFC1918 / link-local IPv4 and IPv6 loopback, with an optional
# port. Anchored and escaped so a lookalike host such as
# "http://192.168.1.5.evil.com" or "https://evil.com" cannot match.
PRIVATE_ORIGIN_PATTERN = (
    r"^https?://("
    r"localhost|127\.0\.0\.1|\[::1\]|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")(?::\d{1,5})?$"
)


def create_app(server_port: int | None = None, local_address: str | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan context manager."""
        app.state.discovery.start()
        # Sweep expired state on a timer as well as on access. Sessions, pairing
        # requests, and finished transfers are all bounded, but nothing deletes
        # them unless something touches the relevant endpoint, and a server can
        # sit idle indefinitely.
        sweeper = asyncio.create_task(_sweep_loop(app))
        print("✓ SELTRANSFER server started")
        try:
            yield
        finally:
            sweeper.cancel()
            with suppress(asyncio.CancelledError):
                await sweeper
            app.state.discovery.stop()
            print("\n✓ SELTRANSFER server stopped")

    app = FastAPI(
        title="SELTRANSFER",
        description="Offline file transfer for local networks",
        version=__version__,
        lifespan=lifespan,
    )
    settings = get_settings()
    port = server_port or settings.server_port
    detected = detect_network(settings.preferred_interface)
    address = local_address or (detected.address if detected else "127.0.0.1")
    local_device = create_local_device(
        address, port, identity_path=settings.app_dir / "device-id")
    app.state.server_port = port
    app.state.local_address = address
    app.state.registry = DeviceRegistry(
        local_device, settings.device_discovery_timeout_seconds)
    app.state.discovery = DiscoveryService(app.state.registry)
    app.state.history = HistoryStore(settings.transfer_history_db)
    app.state.transfers = TransferManager(
        settings.app_dir / "downloads", app.state.history,
        max_file_bytes=settings.max_file_bytes,
        max_transfer_bytes=settings.max_transfer_bytes,
        max_files_per_transfer=settings.max_files_per_transfer,
        max_tracked=settings.max_tracked_transfers)
    app.state.pairing = PairingRegistry(
        code_ttl=settings.pairing_code_ttl_seconds,
        pairing_ttl=settings.pairing_ttl_seconds)
    # The local node is always paired with itself. It was previously seeded into
    # app.state.paired_devices, which was an unauthenticated global set with no
    # expiry - see the PairingRegistry for the replacement.
    app.state.pairing.grant_directly(
        local_device.device_id, local_device.device_id, "self")
    app.state.settings = settings
    app.state.local_token = ensure_local_token()
    app.state.browser_sessions = {}
    app.state.browser_timeout = settings.device_discovery_timeout_seconds
    app.state.webrtc_sessions = {}
    app.state.logger = logger

    @app.middleware("http")
    async def log_connection(request, call_next):
        response = await call_next(request)
        logger.info(
            "DEVICE CONNECTED client=%s method=%s path=%s user_agent=%s",
            request.client.host if request.client else "unknown",
            request.method,
            request.url.path,
            request.headers.get("user-agent", "unknown"),
        )
        return response

    @app.middleware("http")
    async def security_headers(request, call_next):
        """Attach conservative headers to every response.

        The page renders peer-supplied values, and while the client builds those
        with text nodes rather than markup, a content security policy means a
        mistake in the client cannot become script execution. The inline
        stylesheet is what style.css uses via the style attribute on a few
        elements, hence 'unsafe-inline' for styles only - never for scripts.
        """
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' http: https:; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'none'",
        )
        # This is a local, single-user service; a shared cache has no business
        # holding a transfer listing or a file response.
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    # CORS is restricted to private-network origins. The browser client is served
    # by this server, so same-origin calls never need CORS at all; the one
    # genuine cross-origin call is the direct upload to a *peer's* server, which
    # is always a LAN address. Restricting to RFC1918 + loopback therefore keeps
    # peer-to-peer transfers working while stopping any website on the internet
    # from driving this API through the user's browser.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=PRIVATE_ORIGIN_PATTERN,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["content-type", "x-seltransfer-session",
                       "x-seltransfer-token", "x-seltransfer-local"],
    )

    # CORS only stops a *cross-origin* read; it does not stop a request being
    # sent. DNS rebinding is the attack that gets around it: a public domain
    # resolves to 127.0.0.1, so a page on the internet can reach this server as a
    # same-origin request from the browser's point of view, and the origin policy
    # never applies to it.
    #
    # The defence is to require the Host header to name something that could
    # plausibly be this machine. The default accepts loopback and every private
    # or link-local address, so a phone reaching the PC over any of its
    # interfaces still works, while a public domain pointed at the LAN address is
    # refused. Setting SELTRANSFER_ALLOWED_HOSTS=["*"] disables the check.
    configured = list(settings.allowed_hosts or [])
    if configured:
        allowed_hosts = list(configured)
        if address and address not in allowed_hosts:
            allowed_hosts.append(address)
        allow_private = False
    else:
        allowed_hosts = [
            "localhost", "127.0.0.1", "[::1]",
            # The host name an ASGI test client sends. It names nothing public, and
            # allowing it keeps the test suite exercising the real middleware.
            "testserver",
        ]
        if address and address not in allowed_hosts:
            allowed_hosts.append(address)
        allow_private = True
    if "*" not in allowed_hosts:
        app.add_middleware(PrivateHostMiddleware, allowed_hosts=allowed_hosts,
                           allow_private=allow_private)

    if not settings.expose_docs:
        for path in ("/docs", "/redoc", "/openapi.json"):
            app.router.routes = [
                route for route in app.router.routes
                if getattr(route, "path", None) != path
            ]

    # Include API routes
    app.include_router(routes.router)

    # Locate bundled assets through one resolver so a frozen build and a source
    # install are handled by the same tested code path.
    static_path = resources.static_root()

    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)),
                  name="static")

    # Serve index.html as root
    from fastapi.responses import FileResponse

    @app.get("/", include_in_schema=False)
    async def serve_root():
        """Serve the web interface."""
        return FileResponse(str(resources.index_file()),
                            headers={"Cache-Control": "no-store"})


    return app
