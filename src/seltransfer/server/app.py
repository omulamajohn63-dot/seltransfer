"""FastAPI application initialization and configuration."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from seltransfer.config import get_settings
from seltransfer.devices import DeviceRegistry, DiscoveryService, create_local_device
from seltransfer.network.detection import detect_network
from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager

from . import routes

logger = logging.getLogger("seltransfer.server")

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
        print("✓ SELTRANSFER server started")
        yield
        app.state.discovery.stop()
        print("\n✓ SELTRANSFER server stopped")

    app = FastAPI(
        title="SELTRANSFER",
        description="Offline file transfer for local networks",
        version="0.1.0",
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
        max_files_per_transfer=settings.max_files_per_transfer)
    app.state.paired_devices = {local_device.device_id}
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
        allow_headers=["content-type", "x-seltransfer-session", "x-seltransfer-token"],
    )

    if not settings.expose_docs:
        for path in ("/docs", "/redoc", "/openapi.json"):
            app.router.routes = [
                route for route in app.router.routes
                if getattr(route, "path", None) != path
            ]

    # Include API routes
    app.include_router(routes.router)

    # Mount static files
    static_path = Path(__file__).parent.parent / "web" / "static"
    templates_path = Path(__file__).parent.parent / "web" / "templates"

    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)),
                  name="static")

    # Serve index.html as root
    from fastapi.responses import FileResponse

    @app.get("/", include_in_schema=False)
    async def serve_root():
        """Serve the root HTML page."""
        index_file = templates_path / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file), headers={"Cache-Control": "no-store"})
        return {"message": "SELTRANSFER - Offline File Transfer"}

    return app
