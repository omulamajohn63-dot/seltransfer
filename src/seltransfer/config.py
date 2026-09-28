"""Configuration module for SELTRANSFER."""

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def resolve_app_dir(platform: str | None = None) -> Path:
    """Choose a stable directory for the native Python application.

    ``platform`` is accepted so callers can pass a detected platform hint, but it
    is deliberately ignored: the native app must use one directory on every OS,
    and an Android storage hint must never redirect it somewhere else.
    """
    env_override = os.environ.get("SELTRANSFER_APP_DIR")
    if env_override:
        return Path(env_override).expanduser()

    return Path.home() / ".seltransfer"


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

    # Limits
    max_file_bytes: int = 8 * 1024 * 1024 * 1024
    max_transfer_bytes: int = 64 * 1024 * 1024 * 1024
    max_files_per_transfer: int = 1000

    # Paths
    app_name: str = "SELTRANSFER"
    platform: str | None = None
    app_dir: Path = Field(default_factory=resolve_app_dir)
    transfer_history_db: Path = Field(
        default_factory=lambda: resolve_app_dir() / "history.db")

    # Timeouts
    device_discovery_timeout_seconds: int = 120

    model_config = SettingsConfigDict(
        env_prefix="SELTRANSFER_", env_file=".env", case_sensitive=False)


def get_settings() -> Settings:
    """Get application settings."""
    settings = Settings()
    settings.app_dir = resolve_app_dir(settings.platform)
    settings.transfer_history_db = settings.app_dir / "history.db"
    return settings


# Ensure app directory exists
settings = get_settings()
settings.app_dir.mkdir(parents=True, exist_ok=True)
