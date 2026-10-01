"""QR rendering for the connection URL, without the Pillow dependency.

This lives apart from :mod:`seltransfer.utils` on purpose. That module imports
Pillow at import time, and the PyInstaller spec deliberately excludes both
``PIL`` and ``seltransfer.utils`` from the frozen bundle, so anything on the
runtime path that imported it would drag a module that cannot import into the
executable. The QR image is served over HTTP now, which makes it part of the
runtime path, so it gets its own Pillow-free module.
"""

from __future__ import annotations

from typing import cast

import qrcode
from qrcode.image.svg import SvgPathImage

# A screen is a worse scanner than a good camera pointed at paper: reflections,
# a thumb over the corner, and a dim phone screen all cost error correction.
# The payload is one short URL, so the denser code costs nothing worth saving.
ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_M
DEFAULT_BOX_SIZE = 8
DEFAULT_BORDER = 4


def connection_qr_svg(
    data: str,
    box_size: int = DEFAULT_BOX_SIZE,
    border: int = DEFAULT_BORDER,
) -> str:
    """
    Render data as a QR code in SVG.

    SVG rather than PNG on purpose. It needs no rasteriser, it is a few
    kilobytes for a short URL, and it stays sharp when the phone scales the
    image up to fill its screen, which a fixed-size bitmap does not.

    Args:
        data: The text to encode, typically the connection URL.
        box_size: Size of each module in the SVG's user units.
        border: Quiet-zone width in modules, as the specification requires.

    Returns:
        A complete SVG document as text.
    """
    qr = qrcode.QRCode(
        error_correction=ERROR_CORRECTION,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    return cast(str, image.to_string(encoding="unicode"))
