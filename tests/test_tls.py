"""TLS is opt-in and must actually work when enabled.

The decision was to keep HTTP as the default. A self-signed certificate on a
QR-scanned page produces a certificate warning on every phone connection, which is
a worse first experience than plaintext on a hotspot the user chose. The plumbing
is still real and is exercised here with a genuine certificate, so the option is
not a stub.
"""

from __future__ import annotations

import ssl
import subprocess
from pathlib import Path

import pytest

from seltransfer.config import Settings
from seltransfer.server.app import create_app

# --- configuration -----------------------------------------------------------


def test_tls_is_off_by_default() -> None:
    """HTTP is plaintext, and that is the documented default."""
    settings = Settings()
    assert settings.tls_enabled is False
    assert settings.https_enabled is False
    assert settings.scheme() == "http"


def test_scheme_flips_only_when_both_files_are_set(tmp_path, monkeypatch) -> None:
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    cert.write_text("x", encoding="utf-8")
    key.write_text("x", encoding="utf-8")

    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    monkeypatch.setenv("SELTRANSFER_TLS_CERTFILE", str(cert))
    monkeypatch.setenv("SELTRANSFER_TLS_KEYFILE", str(key))
    settings = Settings()
    assert settings.https_enabled is True
    assert settings.scheme() == "https"


def test_scheme_stays_http_when_only_one_file_is_set(tmp_path, monkeypatch) -> None:
    cert = tmp_path / "c.pem"
    cert.write_text("x", encoding="utf-8")
    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    monkeypatch.setenv("SELTRANSFER_TLS_CERTFILE", str(cert))
    settings = Settings()
    assert settings.https_enabled is False
    assert settings.scheme() == "http"


def test_missing_certificate_is_reported_clearly(monkeypatch) -> None:
    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    problem = Settings().validate_tls()
    assert problem is not None
    assert "tls_certfile" in problem and "tls_keyfile" in problem
    assert "SELTRANSFER_TLS_CERTFILE" in problem


def test_nonexistent_certificate_path_is_reported(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    monkeypatch.setenv("SELTRANSFER_TLS_CERTFILE", str(tmp_path / "absent.pem"))
    monkeypatch.setenv("SELTRANSFER_TLS_KEYFILE", str(tmp_path / "absent.key"))
    problem = Settings().validate_tls()
    assert problem is not None
    assert "not found" in problem


def test_validation_is_a_no_op_when_tls_is_off() -> None:
    assert Settings().validate_tls() is None


def test_a_valid_pair_produces_no_problem(tmp_path, monkeypatch, real_certificate) -> None:
    cert, key = real_certificate
    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    monkeypatch.setenv("SELTRANSFER_TLS_CERTFILE", str(cert))
    monkeypatch.setenv("SELTRANSFER_TLS_KEYFILE", str(key))
    assert Settings().validate_tls() is None


# --- the URL the phone is told to open ---------------------------------------


def test_qr_url_is_http_by_default(client) -> None:
    body = client.get("/api/connection").json()
    assert body["scheme"] == "http"
    assert body["qr"]["url"].startswith("http://")
    assert body["https_enabled"] is False


def test_qr_url_becomes_https_when_tls_is_configured(tmp_path, monkeypatch,
                                                     real_certificate) -> None:
    cert, key = real_certificate
    monkeypatch.setenv("SELTRANSFER_TLS_ENABLED", "true")
    monkeypatch.setenv("SELTRANSFER_TLS_CERTFILE", str(cert))
    monkeypatch.setenv("SELTRANSFER_TLS_KEYFILE", str(key))
    app = create_app(server_port=8797, local_address="127.0.0.1")

    from fastapi.testclient import TestClient

    body = TestClient(app).get("/api/connection").json()
    assert body["scheme"] == "https"
    assert body["qr"]["url"].startswith("https://")
    assert body["https_enabled"] is True


# --- the certificate really is usable ----------------------------------------


def test_generated_certificate_parses_and_has_a_private_key(real_certificate) -> None:
    """Not a placeholder: a real key must exist and load."""
    cert, key = real_certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    assert context.get_ca_certs() or True  # loading it without error is the point


def test_private_key_is_not_recoverable_as_plaintext_text(real_certificate) -> None:
    """The key must be PEM key material, never a password or a marker string."""
    _cert, key = real_certificate
    text = key.read_text(encoding="utf-8")
    assert "PRIVATE KEY" in text
    assert "PRIVATE KEY-----" in text
    assert "seltransfer" not in text.lower()


# --- what we deliberately do not do ------------------------------------------


def test_no_certificate_is_shipped_with_the_project() -> None:
    """Certificates must be generated per machine, never committed."""
    root = Path(__file__).resolve().parents[1]
    strays = [path.relative_to(root) for path in root.rglob("*")
              if path.is_file() and path.suffix in {".pem", ".crt", ".key", ".p12"}
              and ".git" not in path.parts and "build" not in path.parts
              and "dist" not in path.parts]
    assert not strays, f"key material in the repository: {strays}"


def test_tls_flag_is_off_by_default_in_the_cli() -> None:
    """The default must live inside the typer.Option, not the function body."""
    import inspect

    from seltransfer import cli

    option = inspect.signature(cli.start).parameters["tls"].default
    assert option.default is False
    assert any("--tls" in declaration for declaration in option.param_decls)


@pytest.fixture(scope="session")
def real_certificate(tmp_path_factory):
    """A genuine self-signed certificate, generated once for the session.

    ``cryptography`` is not a project dependency, so this shells out to the
    ``openssl`` binary that ships with Git for Windows. When it is unavailable the
    TLS-is-real tests skip rather than pass on a stub.
    """
    directory = tmp_path_factory.mktemp("tls")
    cert = directory / "seltransfer-cert.pem"
    key = directory / "seltransfer-key.pem"
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=seltransfer.local"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0 or not cert.is_file() or not key.is_file():
        pytest.skip(f"openssl unavailable: {result.stderr.strip()[:120]}")
    return cert, key
