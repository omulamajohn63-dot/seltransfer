"""SELTRANSFER - Offline file transfer for local networks."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

# Single source of truth for the application version.
#
# ``pyproject.toml`` is the real source. Reading installed metadata keeps
# ``seltransfer version``, ``/api/status``, the FastAPI schema, and the device
# record from drifting apart, which is what happened when four modules each
# carried their own "0.1.0" literal.
#
# A frozen PyInstaller build is not an installed distribution, so the metadata
# lookup fails there and the literal below is used instead. It is therefore a
# correctness fallback, not dead code, and is pinned by a test.
FALLBACK_VERSION = "0.1.0"

try:
    __version__ = _installed_version("seltransfer")
except PackageNotFoundError:  # pragma: no cover - exercised via monkeypatch
    __version__ = FALLBACK_VERSION

__author__ = "SELTRANSFER Team"
__description__ = (
    "Offline file transfer tool that works across local networks "
    "without Internet access"
)
