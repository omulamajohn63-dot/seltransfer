"""Tests for the Pillow-free QR renderer used by the share panel."""

from __future__ import annotations

import ast
from pathlib import Path
from xml.etree import ElementTree

from seltransfer.qr import connection_qr_svg

MODULE_SOURCE = Path(__file__).resolve().parents[1] / "src" / "seltransfer" / "qr.py"


def test_renders_a_well_formed_svg_document():
    """The browser parses this as XML, so well-formedness is not optional."""
    svg = connection_qr_svg("http://192.168.1.5:8765")

    assert svg.lstrip().startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    root = ElementTree.fromstring(svg)
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    # A viewBox is what lets the phone scale the code to its screen without
    # resampling it into something a scanner cannot read.
    assert root.get("viewBox")
    assert root.findall("{http://www.w3.org/2000/svg}path")


def test_the_same_address_always_renders_the_same_code():
    """Two devices showing the panel side by side must show the same code."""
    url = "http://192.168.1.5:8765"

    assert connection_qr_svg(url) == connection_qr_svg(url)


def test_different_addresses_render_different_codes():
    assert (connection_qr_svg("http://192.168.1.5:8765")
            != connection_qr_svg("http://192.168.1.6:8765"))


def test_module_size_and_border_are_configurable():
    """The panel reserves a fixed square, so the size has to be predictable."""
    small = ElementTree.fromstring(connection_qr_svg("http://192.168.1.5:8765", box_size=4))
    large = ElementTree.fromstring(connection_qr_svg("http://192.168.1.5:8765", box_size=12))

    assert small.get("width") != large.get("width")


def test_the_runtime_module_does_not_import_pillow():
    """The frozen build excludes Pillow, and this module is now on that path.

    ``packaging/seltransfer.spec`` keeps both ``PIL`` and ``seltransfer.utils`` out
    of the bundle, so the QR code the server renders over HTTP lives in its own
    module. Importing the Pillow-backed helper from a route would have put a
    module that cannot import into the executable. The imports are read from the
    syntax tree rather than the text, so prose about Pillow in the docstring
    cannot mask a real import.
    """
    tree = ast.parse(MODULE_SOURCE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")

    assert not any(name == "PIL" or name.startswith("PIL.") for name in imported)
    assert "seltransfer.utils" not in imported
