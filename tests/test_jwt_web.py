"""End-to-end web tests for the JWT verifier routes and three-state UI."""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import main
from app.jwks import JwksCache, RefreshError, public_key_to_rsa_jwk
from app.verifier import make_signed_jwt

ISSUER = main.settings.issuer
AUDIENCE = main.settings.audience
KID = "demo-key-1"


class StubCache:
    def __init__(self):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys = {KID: self.private.public_key()}
        self.url = main.settings.jwks_url
        self.fail: Exception | None = None

    async def get_key(self, kid):
        if self.fail is not None:
            raise self.fail
        return self.keys[kid]

    def snapshot(self):
        class S:
            kids = list(self.keys)

        return S()


@pytest.fixture
def client(monkeypatch):
    stub = StubCache()
    monkeypatch.setattr(main, "jwks_cache", stub)
    return TestClient(main.app), stub


def _token(stub, **claim_overrides):
    now = int(time.time())
    c = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u",
        "iat": now,
        "exp": now + 300,
    }
    c.update(claim_overrides)
    return make_signed_jwt(stub.private, KID, c)


# --------------------------------------------------------------------- routes

def test_verify_page_renders_and_index_links():
    page = TestClient(main.app).get("/verify")
    assert page.status_code == 200
    assert "JWT 签名核验" in page.text
    assert ISSUER in page.text
    index = TestClient(main.app).get("/")
    assert "/verify" in index.text


def test_valid_token_html_and_json(client):
    c, stub = client
    token = _token(stub)
    resp = c.post("/api/verify", json={"token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "valid"
    assert body["kid"] == KID

    html = c.post("/verify", data={"token": token})
    assert html.status_code == 200
    assert "核验通过" in html.text


def test_invalid_token_returns_400_state(client):
    c, stub = client
    resp = c.post("/api/verify", json={"token": "a.b.c"})
    assert resp.status_code == 400
    assert resp.json()["status"] == "invalid"

    html = c.post("/verify", data={"token": "a.b.c"})
    assert html.status_code == 400
    assert "令牌无效" in html.text


def test_unknown_state_returns_503(client):
    c, stub = client
    stub.fail = RefreshError("HTTP 500")
    resp = c.post("/api/verify", json={"token": _token(stub)})
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "unknown"
    assert "暂时无法核验" in body["reason"]

    html = c.post("/verify", data={"token": _token(stub)})
    assert html.status_code == 503
    assert "暂时无法核验" in html.text


def test_expired_token_is_invalid_not_unknown(client):
    c, stub = client
    now = int(time.time())
    token = _token(stub, exp=now - 10, iat=now - 100)
    resp = c.post("/api/verify", json={"token": token})
    assert resp.status_code == 400
    assert resp.json()["reason_code"] == "token_expired"


def test_api_malformed_bodies_are_400_not_422(client):
    c, _ = client
    # Non-JSON / non-dict / missing token must all map to the invalid state.
    assert c.post("/api/verify", content="not json",
                  headers={"Content-Type": "application/json"}).status_code == 400
    assert c.post("/api/verify", json=[1, 2]).status_code == 400
    assert c.post("/api/verify", json={}).status_code == 400
    assert c.post("/api/verify", json={"token": 123}).status_code == 400
    body = c.post("/api/verify", content="",
                  headers={"Content-Type": "application/json"}).json()
    assert body["status"] == "invalid"


def test_cache_diagnostic_endpoint(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = public_key_to_rsa_jwk(private.public_key(), KID)
    real_cache = JwksCache(
        main.settings.jwks_url,
        ttl_seconds=60,
        min_interval=5,
        fetcher=lambda url: _async({"keys": [jwk]}),
    )
    monkeypatch.setattr(main, "jwks_cache", real_cache)
    c = TestClient(main.app)
    # Prime the cache through a full verification.
    token = make_signed_jwt(private, KID, {
        "iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60
    })
    assert c.post("/api/verify", json={"token": token}).status_code == 200
    state = c.get("/api/jwks/cache").json()
    assert state["fresh"] is True
    assert state["cached_kids"] == [KID]
    assert state["fetch_count"] == 1
    assert state["ttl_seconds"] == 60


async def _async(value):
    return value


# ------------------------------------------------------------- demo proxying

def test_demo_proxy_roundtrip(monkeypatch):
    import dataclasses

    monkeypatch.setattr(
        main,
        "settings",
        dataclasses.replace(main.settings, mock_base="http://mock-jwks:8090"),
    )
    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"ok": True, "mode": "ok"}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, **kw):
            captured["method"] = method
            captured["url"] = url
            return FakeResponse()

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    c = TestClient(main.app)
    resp = c.post("/demo/mode/http500")
    assert resp.status_code == 200
    assert captured == {
        "method": "POST",
        "url": "http://mock-jwks:8090/__admin/mode?mode=http500",
    }


def test_demo_proxy_reports_unreachable(monkeypatch):
    import dataclasses

    monkeypatch.setattr(
        main,
        "settings",
        dataclasses.replace(main.settings, mock_base="http://mock-jwks:8090"),
    )

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **kw):
            raise main.httpx.ConnectError("nope")

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    resp = TestClient(main.app).post("/demo/reset")
    assert resp.status_code == 502
    assert "演示源不可达" in resp.json()["error"]


def test_demo_endpoints_absent_when_not_configured(monkeypatch):
    import dataclasses

    monkeypatch.setattr(
        main, "settings", dataclasses.replace(main.settings, mock_base=None)
    )
    resp = TestClient(main.app).get("/demo/state")
    assert resp.status_code == 404
