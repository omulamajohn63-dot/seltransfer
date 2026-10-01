"""Locating bundled web assets in both a source install and a frozen build.

``server.app`` used to build its asset paths from ``__file__``. That happens to
work for a source install, but under a PyInstaller one-file build ``__file__``
points inside a temporary extraction directory, and under one-dir it points at a
directory the bundler controls. Guessing wrong does not raise: the server starts
happily and serves a blank page, which is the hardest kind of packaging bug to
diagnose from the outside.

This module is the single place that knows how to find ``web/``, so there is
exactly one rule to get right and exactly one place to test.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Files that must exist for the web interface to work at all. Used both to locate
# the right directory and to fail loudly when a bundle is missing them.
REQUIRED_ASSETS = ("templates/index.html", "static/app.js", "static/style.css")


def _is_complete(root: Path) -> bool:
    return all((root / relative).is_file() for relative in REQUIRED_ASSETS)


def _candidate_roots() -> list[Path]:
    """Ordered by how much we should trust them.

    The frozen extraction directory comes first because a bundle deliberately
    ships the current assets there, and the source tree is only a fallback.
    """
    candidates: list[Path] = []

    # PyInstaller sets __file__ inside sys._MEIPASS for one-file builds, and
    # sys.frozen with a sibling layout for one-dir builds. Checking both covers
    # every bundler that follows the documented convention.
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass))
    if getattr(sys, "frozen", False):
        # one-dir: the executable sits next to the collected data directory
        candidates.append(Path(sys.executable).resolve().parent)
        candidates.append(Path(sys.executable).resolve().parent / "_internal")

    # Source install: src/seltransfer/resources.py -> src/seltransfer/web
    candidates.append(Path(__file__).resolve().parent / "web")
    # A build tree that flattened the package.
    candidates.append(Path(__file__).resolve().parents[2] / "seltransfer" / "web")
    return candidates


def web_root() -> Path:
    """Return the directory that contains ``templates/`` and ``static/``.

    Raises:
        RuntimeError: if no candidate holds the web assets. Failing here is
            deliberate: a clear error at startup beats a blank page at runtime.
    """
    for candidate in _candidate_roots():
        if _is_complete(candidate):
            return candidate
    tried = "\n  ".join(str(path) for path in _candidate_roots())
    raise RuntimeError(
        "Could not locate the SELTRANSFER web assets. The application package is "
        f"incomplete. Looked in:\n  {tried}\n"
        "Expected to find: " + ", ".join(REQUIRED_ASSETS)
    )


def static_root() -> Path:
    return web_root() / "static"


def templates_root() -> Path:
    return web_root() / "templates"


def index_file() -> Path:
    return templates_root() / "index.html"


def describe() -> dict[str, str]:
    """Diagnostics for `doctor`, so a packaging problem is explainable."""
    root = web_root()
    return {
        "web_root": str(root),
        "frozen": str(getattr(sys, "frozen", False)),
        "executable": str(getattr(sys, "executable", "")),
        "assets": ", ".join(
            f"{name}={'ok' if (root / name).is_file() else 'MISSING'}"
            for name in REQUIRED_ASSETS
        ),
    }
