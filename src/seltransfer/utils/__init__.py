"""Utility functions for SELTRANSFER."""

import io
from typing import cast

import qrcode
from PIL import Image


def generate_qr_code(data: str, size: int = 10) -> Image.Image:
    """
    Generate a QR code image.

    Args:
        data: The data to encode in the QR code (typically a URL).
        size: The size of each box in pixels.

    Returns:
        A PIL Image object containing the QR code.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=size,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # qrcode returns a wrapper whose get_image() yields the real PIL image.
    img = qr.make_image(fill_color="black", back_color="white")
    return cast(Image.Image, img.get_image())


def save_qr_code(data: str, filepath: str) -> None:
    """
    Generate and save a QR code to a file.

    Args:
        data: The data to encode in the QR code.
        filepath: Path where to save the QR code image.
    """
    img = generate_qr_code(data)
    img.save(filepath)


def get_qr_code_bytes(data: str) -> bytes:
    """
    Generate a QR code and return as bytes.

    Args:
        data: The data to encode in the QR code.

    Returns:
        PNG image data as bytes.
    """
    img = generate_qr_code(data)
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    return img_bytes.getvalue()
