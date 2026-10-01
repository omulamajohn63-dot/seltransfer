"""HTTP-level hardening: host validation, headers, and information disclosure.

The significant one here is DNS rebinding. CORS stops a page on the internet from
*reading* this API, but it does not stop the browser from *sending* a request. A
public domain whose DNS resolves to 192.168.x.x makes the request same-origin, so
the origin-based policy never applies. Requiring the Host header to name an
address this server actually serves is what closes that.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from seltransfer.config import Settings
from tests.conftest import make_app


def test_rebinding_host_header_is_rejected(client):
    """A public domain pointed at the LAN address must not be served."""
    response = client.get("/api/status", headers={"host": "evil.example.com"})

    assert response.status_code == 400, response.text


def test_lookalike_lan_host_is_rejected(client):
    response = client.get("/api/status", headers={"host": "192.168.1.5.evil.com"})
    assert response.status_code == 400


def test_private_and_loopback_hosts_are_accepted(client):
    for host in ("127.0.0.1", "localhost", "192.168.1.5", "10.0.0.7",
                 "172.16.4.4", "[::1]"):
        response = client.get("/api/status", headers={"host": host})
        assert response.status_code == 200, f"{host}: {response.text}"


def test_the_serving_address_is_allowed_even_if_unusual(tmp_path):
    """A detected address outside the usual ranges must still work."""
    app = make_app(tmp_path, local_address="100.64.0.7")
    response = TestClient(app).get("/api/status", headers={"host": "100.64.0.7"})
    assert response.status_code == 200, response.text


def test_host_check_can_be_disabled(tmp_path, monkeypatch):
    """'*' is the documented escape hatch for unusual deployments."""
    monkeypatch.setenv("SELTRANSFER_ALLOWED_HOSTS", "*")
    app = make_app(tmp_path)
    # No TrustedHostMiddleware means an arbitrary Host is served.
    assert app.user_middleware == [] or all(
        "TrustedHost" not in getattr(m.cls, "__name__", "") for m in app.user_middleware)
    assert TestClient(app).get(
        "/api/status", headers={"host": "anything.example.com"}
    ).status_code == 200


def test_explicit_host_list_is_honoured(tmp_path, monkeypatch):
    """A configured list is strict, not a widening of the default."""
    monkeypatch.setenv("SELTRANSFER_ALLOWED_HOSTS", "seltransfer.local")
    app = make_app(tmp_path)
    client = TestClient(app)
    # An arbitrary private address is no longer accepted: the operator named the
    # hosts they wanted.
    assert client.get("/api/status", headers={"host": "192.168.1.5"}).status_code == 400
    assert client.get(
        "/api/status", headers={"host": "seltransfer.local"}).status_code == 200


def test_comma_separated_host_list_is_accepted(tmp_path, monkeypatch):
    """An operator writing a .env file types commas, not JSON."""
    monkeypatch.setenv("SELTRANSFER_ALLOWED_HOSTS", "a.local, b.local ,c.local")
    app = make_app(tmp_path)
    client = TestClient(app)
    for host in ("a.local", "b.local", "c.local"):
        assert client.get("/api/status", headers={"host": host}).status_code == 200
    assert client.get("/api/status", headers={"host": "d.local"}).status_code == 400


def test_json_host_list_is_still_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("SELTRANSFER_ALLOWED_HOSTS", '["x.local", "y.local"]')
    app = make_app(tmp_path)
    assert TestClient(app).get(
        "/api/status", headers={"host": "y.local"}).status_code == 200


def test_rebinding_is_refused_even_for_a_state_changing_route(client):
    response = client.post(
        "/api/transfers/history/clear", headers={"host": "evil.example.com"})
    assert response.status_code == 400


# --- response headers --------------------------------------------------------


def test_security_headers_are_present(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_csp_never_allows_inline_script(client):
    """Styles may be inline; scripts must not be, or a client bug becomes XSS."""
    csp = client.get("/").headers["Content-Security-Policy"]
    script_src = next(part for part in csp.split(";") if "script-src" in part)
    assert "'self'" in script_src
    assert "unsafe-inline" not in script_src
    assert "unsafe-eval" not in script_src


def test_csp_forbids_framing_and_base_tag_injection(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp


def test_responses_are_not_cached(client):
    response = client.get("/api/status")
    assert response.headers["Cache-Control"] == "no-store"


def test_headers_appear_on_error_responses(client):
    response = client.get("/api/transfers")
    assert response.status_code == 401
    assert response.headers["X-Content-Type-Options"] == "nosniff"


# --- information disclosure --------------------------------------------------


def test_download_path_is_hidden_by_default(client):
    response = client.get("/api/connection")
    assert response.status_code == 200
    directory = response.json()["download_directory"]
    assert "hidden" in directory
    assert "downloads" not in directory


def test_download_path_is_revealed_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("SELTRANSFER_EXPOSE_PATHS", "true")
    app = make_app(tmp_path)
    response = TestClient(app).get("/api/connection")
    directory = response.json()["download_directory"]
    assert "hidden" not in directory
    assert "downloads" in directory


def test_no_traceback_or_path_leaks_in_errors(client):
    for path in ("/api/transfers/does-not-exist-1234/accept",
                 "/api/incoming-transfers/nope-1234/files/0"):
        response = client.get(path)
        body = response.text
        assert "Traceback" not in body
        assert "seltransfer\\" not in body
        assert "site-packages" not in body


def test_error_detail_is_a_clean_string(client):
    response = client.get("/api/transfers")
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert isinstance(detail, str)
    assert "\n" not in detail


# --- docs stay closed --------------------------------------------------------


def test_docs_are_absent_by_default(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path


def test_docs_can_be_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SELTRANSFER_EXPOSE_DOCS", "true")
    app = make_app(tmp_path)
    assert TestClient(app).get("/openapi.json").status_code == 200


# --- settings that govern the above -----------------------------------------


def test_expose_paths_defaults_to_false() -> None:
    assert Settings().expose_paths is False


def test_allowed_hosts_default_is_auto_not_wildcard() -> None:
    """The default must actually enable the check, not disable it with '*'."""
    assert Settings().allowed_hosts == []
