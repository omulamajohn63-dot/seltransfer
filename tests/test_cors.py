"""CORS policy tests.

The browser client is served by this same server, so its own API calls are
same-origin and need no CORS at all. The only legitimate cross-origin call is a
direct upload to a *peer's* server, which is always a LAN address. That means the
policy must accept private origins and reject everything on the public internet,
which is what stops a random website from driving the API through the user's
browser.
"""

import re

import pytest
from fastapi.testclient import TestClient

from seltransfer.server.app import PRIVATE_ORIGIN_PATTERN, create_app

ACCEPTED = [
    "http://192.168.1.5:8765",
    "http://192.168.1.5",
    "http://10.0.0.7:9000",
    "http://172.16.4.22:8765",
    "http://172.20.1.1:8765",
    "http://172.31.255.254:8765",
    "http://169.254.10.10:8765",
    "http://127.0.0.1:8765",
    "http://localhost:8765",
    "http://[::1]:8765",
    "https://192.168.1.5:8765",
]

REJECTED = [
    "https://evil.com",
    "http://evil.com",
    "https://sub.evil.co.uk",
    "null",
    # Lookalike hosts must not slip through the prefix.
    "http://192.168.1.5.evil.com",
    "http://192.168.1.5:8765.evil.com",
    "http://localhost.evil.com",
    "http://127.0.0.1.evil.com",
    "http://notlocalhost",
    # Outside RFC1918: 172.32/12 is public space.
    "http://172.32.0.1:8765",
    "http://172.15.0.1:8765",
    "http://8.8.8.8:8765",
    "http://[2001:db8::1]:8765",
]


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(server_port=8783, local_address="127.0.0.1"))


@pytest.mark.parametrize("origin", ACCEPTED)
def test_private_origins_are_allowed(origin):
    assert re.match(PRIVATE_ORIGIN_PATTERN, origin), origin


@pytest.mark.parametrize("origin", REJECTED)
def test_public_origins_are_rejected(origin):
    assert not re.match(PRIVATE_ORIGIN_PATTERN, origin), origin


def test_peer_origin_is_allowed_by_the_server(client):
    response = client.get("/api/status", headers={"Origin": "http://192.168.1.5:8765"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://192.168.1.5:8765"


def test_public_origin_gets_no_cors_grant(client):
    response = client.get("/api/status", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_public_origin_preflight_is_refused(client):
    response = client.options(
        "/api/transfers",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_peer_preflight_is_accepted_for_the_methods_the_client_uses(client):
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = client.options(
            "/api/transfers",
            headers={
                "Origin": "http://192.168.1.9:8765",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "content-type,x-seltransfer-token",
            },
        )
        assert response.headers.get(
            "access-control-allow-origin") == "http://192.168.1.9:8765", method
        assert method in response.headers.get("access-control-allow-methods", ""), method


def test_credentials_are_not_wildcarded(client):
    response = client.get("/api/status", headers={"Origin": "http://192.168.1.5:8765"})
    assert response.headers.get("access-control-allow-credentials") != "true"


def test_api_docs_are_not_exposed_by_default(client):
    """/docs would otherwise enumerate the whole unauthenticated surface."""
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_api_docs_can_be_enabled(monkeypatch):
    monkeypatch.setenv("SELTRANSFER_EXPOSE_DOCS", "true")
    client = TestClient(create_app(server_port=8784, local_address="127.0.0.1"))
    assert client.get("/openapi.json").status_code == 200
