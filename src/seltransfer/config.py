"""Configuration module for SELTRANSFER."""

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

APP_DIR_NAME = "SELTRANSFER"


def _windows_app_dir() -> Path | None:
    """``%LOCALAPPDATA%\\SELTRANSFER`` when running on Windows.

    LOCALAPPDATA is per-user and never roaming, which is the right scope for a
    transfer history and for files the user chose to download. ``Path.home()`` is
    not used on Windows because it can resolve to a network-redirected profile
    that a service or a low-privilege process cannot write to.
    """
    if not sys.platform.startswith("win"):
        return None
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        # LOCALAPPDATA is absent in some service and sandbox contexts. Falling
        # back to the home directory keeps the tool working rather than failing.
        return None
    return Path(base) / APP_DIR_NAME


def resolve_app_dir(platform: str | None = None) -> Path:
    """Choose the directory for user-generated data.

    Precedence:

    1. ``SELTRANSFER_APP_DIR`` - an explicit override, always honoured.
    2. ``%LOCALAPPDATA%\\SELTRANSFER`` on Windows.
    3. ``~/.seltransfer`` everywhere else.

    This holds application *data* (history, downloads, device identity, the local
    token). Read-only application *resources* are never stored here; those live
    beside the code, resolved by :mod:`seltransfer.resources`.

    Args:
        platform: An optional platform hint. It is deliberately ignored: an
            Android storage hint must never redirect the native app, and the real
            platform is read from the interpreter instead of trusting a caller.
    """
    del platform  # see docstring; kept for callers that pass a detected hint

    env_override = os.environ.get("SELTRANSFER_APP_DIR")
    if env_override:
        return Path(env_override).expanduser()

    windows = _windows_app_dir()
    if windows is not None:
        return windows

    return Path.home() / f".{APP_DIR_NAME.lower()}"


def ensure_app_dir() -> Path:
    """Create the app directory if needed and return it.

    Called by the application at startup rather than at import time. Creating a
    directory as an import side effect meant that merely importing the package -
    including from the test suite - wrote to the user's real home directory.
    """
    directory = resolve_app_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def local_token_path() -> Path:
    """Where the local CLI credential lives."""
    return resolve_app_dir() / "local.token"


def ensure_local_token() -> str:
    """Return the machine's local CLI token, generating it on first run.

    This is what distinguishes the native CLI from an anonymous peer. The server
    hands the token to a CLI running on the same machine and to nobody else, so a
    process on the LAN cannot present it.

    On Windows ``os.chmod`` cannot express a real ACL, so the 0600 mode below is
    advisory only. The file lives under the per-user application directory, which
    is the actual access boundary there; on POSIX the mode is enforced properly.
    """
    path = local_token_path()
    if path.is_file():
        existing = path.read_text(encoding="ascii").strip()
        if existing:
            return existing
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token, encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Not fatal: on Windows the mode is advisory anyway, and on POSIX a
        # failure here is worth noticing but not worth refusing to start over.
        pass
    return token


def read_local_token() -> str | None:
    """Read the local CLI token, or ``None`` if the server has never started."""
    path = local_token_path()
    if not path.is_file():
        return None
    token = path.read_text(encoding="ascii").strip()
    return token or None


def verify_local_token(candidate: str | None, expected: str | None) -> bool:
    """Constant-time comparison of a presented local token."""
    if not candidate or not expected:
        return False
    return secrets.compare_digest(candidate, expected)


def _split_csv(value: Any) -> Any:
    """Accept a comma-separated environment variable for a list setting.

    Without this, pydantic-settings insists on JSON in the environment, so
    ``SELTRANSFER_ALLOWED_HOSTS=*`` raises a SettingsError at startup instead of
    doing what the operator meant. A comma-separated value is what someone typing
    into a .env file would naturally write, and JSON is still accepted.
    """
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return [item.strip() for item in text.strip("[]").split(",")
                        if item.strip()]
        return [item.strip() for item in text.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    """Application settings."""

    # Server
    server_host: str = "0.0.0.0"
    server_port: int = 8765

    # Network
    preferred_interface: str | None = None
    exclude_interfaces: list[str] = [
        "Loopback",
        "VirtualBox",
        "VMware",
        "Hyper-V",
        "Docker",
        "vEthernet",
    ]

    # Security
    # Extra literal origins permitted in addition to the private-network
    # pattern. Empty by default: a public site is never a valid peer.
    cors_origins: list[str] = []
    expose_docs: bool = False
    # Returning the server's absolute download path to the browser tells an
    # unauthenticated peer where files are written. Off by default; the web
    # interface degrades to a generic message when it is hidden.
    expose_paths: bool = False
    # Hosts the server answers to, matched against the Host header. Empty means
    # "loopback plus every private and link-local address", which blocks DNS
    # rebinding from a public domain while still letting a phone reach the PC on
    # any of its interfaces. "*" disables the check entirely.
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated host names, or * to disable the check.",
    )

    # TLS
    # Off by default. HTTP is plaintext, which is documented rather than hidden.
    # Supplying a certificate and key is what turns it on.
    tls_enabled: bool = False
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None

    # Resource limits
    # These bound what an unauthenticated peer can make the server allocate.
    max_file_bytes: int = 8 * 1024 * 1024 * 1024
    max_transfer_bytes: int = 64 * 1024 * 1024 * 1024
    max_files_per_transfer: int = 1000
    # Total transfers held in memory. Beyond this the oldest finished ones are
    # dropped, so a peer cannot grow the process without bound.
    max_tracked_transfers: int = 2000
    # Pending incoming requests an unauthenticated caller may have outstanding.
    max_pending_incoming: int = 50
    # Browser sessions retained at once; the oldest expire first.
    max_browser_sessions: int = 500
    max_webrtc_sessions: int = 200

    # Paths
    app_name: str = "SELTRANSFER"
    platform: str | None = None
    app_dir: Path = Field(default_factory=resolve_app_dir)
    transfer_history_db: Path = Field(
        default_factory=lambda: resolve_app_dir() / "history.db")

    # Timeouts
    device_discovery_timeout_seconds: int = 120

    # Pairing
    # An unauthenticated caller must present a pairing code. A registered
    # browser session does not, because the user is already looking at the
    # destination in its own interface and clicking is the explicit interaction.
    pairing_code_ttl_seconds: int = 120
    pairing_ttl_seconds: int = 86_400

    model_config = SettingsConfigDict(
        env_prefix="SELTRANSFER_", env_file=".env", case_sensitive=False)

    @field_validator("allowed_hosts", "cors_origins", "exclude_interfaces",
                     mode="before")
    @classmethod
    def _accept_comma_separated(cls, value: Any) -> Any:
        return _split_csv(value)

    @property
    def https_enabled(self) -> bool:
        """True only when TLS is both requested and actually usable."""
        return bool(self.tls_enabled and self.tls_certfile and self.tls_keyfile)

    def scheme(self) -> str:
        return "https" if self.https_enabled else "http"

    def validate_tls(self) -> str | None:
        """Return a human-readable problem with the TLS configuration, if any.

        Returns ``None`` when TLS is off or the configuration is usable, so the
        caller can start a plain HTTP server without inspecting certificates.
        """
        if not self.tls_enabled:
            return None
        missing = [
            name for name, value in (("tls_certfile", self.tls_certfile),
                                     ("tls_keyfile", self.tls_keyfile))
            if not value
        ]
        if missing:
            return (
                "TLS is enabled but no " + " and no ".join(missing) +
                " was configured. Set SELTRANSFER_TLS_CERTFILE and "
                "SELTRANSFER_TLS_KEYFILE, or set SELTRANSFER_TLS_ENABLED=false."
            )
        for name, value in (("certificate", self.tls_certfile),
                            ("private key", self.tls_keyfile)):
            if value is not None and not Path(value).is_file():
                return f"TLS {name} not found: {value}"
        return None


def get_settings() -> Settings:
    """Get application settings, with derived paths resolved."""
    settings = Settings()
    settings.app_dir = resolve_app_dir(settings.platform)
    settings.transfer_history_db = settings.app_dir / "history.db"
    return settings
