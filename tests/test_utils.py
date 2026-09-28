"""Tests for utility functions."""

from PIL import Image

from seltransfer.utils import generate_qr_code, get_qr_code_bytes


def test_generate_qr_code():
    """Test QR code generation."""
    test_data = "http://192.168.1.100:8765"

    img = generate_qr_code(test_data)

    assert isinstance(img, Image.Image)
    assert img.width > 0
    assert img.height > 0


def test_get_qr_code_bytes():
    """Test QR code as bytes."""
    test_data = "http://192.168.1.100:8765"

    qr_bytes = get_qr_code_bytes(test_data)

    assert isinstance(qr_bytes, bytes)
    assert len(qr_bytes) > 0
    # PNG files start with specific magic bytes
    assert qr_bytes.startswith(b'\x89PNG')


def test_qr_code_different_urls_produce_different_codes():
    """Test that different URLs produce different QR codes."""
    url1 = "http://192.168.1.100:8765"
    url2 = "http://192.168.1.101:8765"

    bytes1 = get_qr_code_bytes(url1)
    bytes2 = get_qr_code_bytes(url2)

    # Different URLs should produce different QR codes
    assert bytes1 != bytes2


def test_qr_code_same_url_produces_same_code():
    """Test that the same URL always produces the same QR code."""
    url = "http://192.168.1.100:8765"

    bytes1 = get_qr_code_bytes(url)
    bytes2 = get_qr_code_bytes(url)

    # Same URL should produce identical QR codes
    assert bytes1 == bytes2
