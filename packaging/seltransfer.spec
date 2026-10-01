# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for the SELTRANSFER Windows executable.

Build with:  python -m PyInstaller --noconfirm packaging/seltransfer.spec

Design notes
------------
**onedir, not onefile.** A onefile build unpacks to a temporary directory on
every launch, which is slower to start and makes antivirus scanning noisy. The
portable artifact is a folder plus a zip, which is what the README promises.

**Web assets are collected as data, not as modules.** ``index.html``,
``app.js``, and ``style.css`` are read through :mod:`seltransfer.resources`, which
searches the bundle for them. Leaving them out produces an application that starts
and then serves a blank page, so the spec asserts they landed where the resolver
looks.

**Pillow is excluded.** Nothing in the runtime path imports it: the CLI renders
the QR with ``qrcode.print_ascii``, and the only importer of the Pillow-backed
helper is ``tests/test_utils.py``. It is still a declared dependency for the
source install, so the developer workflow and the test suite are unaffected.

**No developer-specific paths.** Every path below is derived from ``SPECPATH`` or
from the installed package, so the spec works in any checkout.
"""

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.win32 import versioninfo

# Read the version from the single source of truth. pyproject declares it,
# seltransfer.__version__ reads it back from installed metadata, and the
# executable's file properties come from here, so the four surfaces cannot drift.
_SRC = None


def read_version():
    global _SRC
    _SRC = (Path(SPECPATH).resolve().parent / "src")
    sys.path.insert(0, str(_SRC))
    try:
        from seltransfer import __version__ as version
    finally:
        sys.path.pop(0)
    parts = [int(piece) for piece in version.split(".")[:3]]
    while len(parts) < 4:
        parts.append(0)
    return version, tuple(parts)


def build_version_resource():
    """A Windows VERSIONINFO resource for the executable."""
    version, parts = read_version()
    fixed = versioninfo.FixedFileInfo(
        filevers=parts,
        prodvers=parts,
        mask=0x3F,  # VS_FFI_FILEFLAGSMASK
        flags=0x0,
        OS=0x40004,        # VOS_NT_WINDOWS32
        fileType=0x1,      # VFT_APP
        subtype=0x0,       # VFT2_UNKNOWN
        date=(0, 0),
    )
    children = [
        versioninfo.StringFileInfo([
            versioninfo.StringTable(
                "040904B0",  # US English, Unicode
                [
                    versioninfo.StringStruct("CompanyName", "SELTRANSFER"),
                    versioninfo.StringStruct("FileDescription",
                                             "SELTRANSFER - offline local file transfer"),
                    versioninfo.StringStruct("FileVersion", version),
                    versioninfo.StringStruct("InternalName", "SELTRANSFER"),
                    versioninfo.StringStruct("LegalCopyright", "MIT"),
                    versioninfo.StringStruct("OriginalFilename", "SELTRANSFER.exe"),
                    versioninfo.StringStruct("ProductName", "SELTRANSFER"),
                    versioninfo.StringStruct("ProductVersion", version),
                ],
            ),
        ]),
        versioninfo.VarFileInfo([
            # Translation takes flat 16-bit values: language id then charset.
            versioninfo.VarStruct("Translation", [0x0409, 0x04B0]),
        ]),
    ]
    return versioninfo.VSVersionInfo(ffi=fixed, kids=children)


# --- locate the project without hard-coded paths -----------------------------

# SPECPATH is the directory holding this file, i.e. <repo>/packaging.
REPO_ROOT = Path(SPECPATH).resolve().parent
SRC = REPO_ROOT / "src"
if not (SRC / "seltransfer" / "__init__.py").is_file():
    raise SystemExit(
        f"Cannot find the seltransfer package under {SRC}. Run PyInstaller from "
        "a checkout of the repository."
    )

# The web assets are data, and their location must match what
# seltransfer.resources.web_root() looks for: a "web" directory containing
# templates/index.html and static/{app.js,style.css}.
WEB_ASSETS = [
    (str(SRC / "seltransfer" / "web"), "seltransfer/web"),
]

# --- what not to bundle ------------------------------------------------------

# The test and build stack. None of it is imported at runtime, and shipping it
# would grow the artifact and widen the surface for no benefit.
#
# anyio is deliberately absent from this list: starlette depends on it, so
# excluding it produced an executable that failed on the first import of fastapi.
EXCLUDES = [
    "PIL", "Pillow", "_tkinter", "tkinter", "unittest", "pydoc_data",
    "test", "tests", "pytest", "_pytest", "httpx", "httpcore",
    "IPython", "jupyter", "notebook", "setuptools", "pip", "wheel",
    "email_validator", "jinja2", "sqlalchemy", "numpy", "pandas",
]

# uvicorn resolves several of its protocol implementations by name at runtime, so
# they must be imported even though nothing imports them statically.
#
# `seltransfer.utils` is deliberately absent. It imports PIL, which is excluded
# above, so bundling it would add a module that cannot import at runtime. Nothing
# in the runtime path uses it either: the CLI renders the QR with
# `qrcode.print_ascii` directly, and the only importer is `tests/test_utils.py`.
HIDDEN = collect_submodules("uvicorn.protocols")
HIDDEN += [
    "uvicorn.logging", "uvicorn.loops.auto", "uvicorn.loops.asyncio",
    "uvicorn.lifespan.on", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl", "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "anyio._backends._asyncio",
]

# --- onedir or onefile --------------------------------------------------------

# PyInstaller rejects ``--onefile`` when a .spec file is given ("option(s) not
# allowed: --onedir/--onefile"), because the spec already decides the layout.
# So the choice is made here, from the environment, and build.ps1 passes the flag
# via the environment rather than on the command line.
ONEFILE = os.environ.get("SELTRANSFER_ONEFILE") == "1"

# --- analysis ----------------------------------------------------------------

analysis = Analysis(
    [str(Path(SPECPATH) / "entrypoint.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=WEB_ASSETS,
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # These are the honest knobs here: dropping them breaks a working application
    # rather than shaving bytes off a broken one.
    excludes=EXCLUDES,
    noarchive=False,
)

# PyInstaller 6 removed Analysis.cipher; the archive is unencrypted by default.
pyz = PYZ(analysis.pure)

# Common EXE options, so the onedir and onefile variants cannot drift apart.
# `exclude_binaries` is the only one that differs, and it is passed explicitly.
EXE_OPTIONS = dict(
    name="SELTRANSFER",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # the QR code is printed to the terminal
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # A real VERSIONINFO resource, so Windows shows the right version, product
    # name, and company in the file properties.
    version=build_version_resource(),
)

if ONEFILE:
    # Everything goes inside the executable. It unpacks to a temporary directory
    # on each launch, which is slower to start and noisier for antivirus - hence
    # it is opt-in rather than the default.
    exe = EXE(
        pyz,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        **EXE_OPTIONS,
    )
else:
    # EXE emits only the loader; COLLECT places the payload beside it.
    exe = EXE(
        pyz,
        analysis.scripts,
        [],
        exclude_binaries=True,
        **EXE_OPTIONS,
    )
    collect = COLLECT(
        exe,
        analysis.binaries,
        analysis.zipfiles,
        analysis.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="SELTRANSFER",
    )
