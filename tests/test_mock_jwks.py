"""Tests for the local switchable JWKS demo source (mock_jwks)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import mock_jwks
from app.mock_jwks import app, state
from app.jwks import parse_jwks_document
from app.verifier import verify_token


@pytest.fixture(autouse=True)
def reset_mock():
    state.active = mock_jwks.KEYSET_A
    state.mode = "ok"
    state.request_count = 0
    yield


client = TestClient(app)


def test_jwks_serves_valid_rsa_document_with_unique_kids():
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    doc = resp.json()
    parsed = parse_jwks_document(doc)  # must pass the verifier's own validator
    assert set(parsed) == set(mock_jwks.KEY_KIDS)


def test_keyset_switch_changes_public_keys():
    before = client.get("/.well-known/jwks.json").json()
    resp = client.post("/__admin/keyset/keyset-b")
    assert resp.status_code == 200
    after = client.get("/.well-known/jwks.json").json()
    assert before != after
    # Both documents remain independently valid.
    parse_jwks_document(before)
    parse_jwks_document(after)


def test_unknown_keyset_404():
    assert client.post("/__admin/keyset/nope").status_code == 404


@pytest.mark.parametrize(
    "mode,check",
    [
        ("http500", lambda r: r.status_code == 500),
        ("empty-keys", lambda r: r.json() == {"keys": []}),
        ("duplicate-kid", lambda r: _is_duplicate(r.json())),
        ("invalid-json", lambda r: _is_invalid_json(r)),
    ],
)
def test_failure_modes(mode, check):
    client.post(f"/__admin/mode?mode={mode}")
    assert check(client.get("/.well-known/jwks.json"))


def test_timeout_mode_sleeps_beyond_verifier_budget():
    import time as _time

    client.post("/__admin/mode?mode=timeout")
    start = _time.monotonic()
    resp = client.get("/.well-known/jwks.json")
    elapsed = _time.monotonic() - start
    # Verifier timeout is 2s; the mock must sleep clearly beyond that.
    assert elapsed >= 2.5
    assert resp.status_code == 200


def test_invalid_mode_rejected():
    resp = client.post("/__admin/mode?mode=bogus")
    assert resp.status_code == 400


def test_reset_restores_defaults():
    client.post("/__admin/keyset/keyset-b")
    client.post("/__admin/mode?mode=http500")
    client.post("/__admin/reset")
    info = client.get("/__admin/state").json()
    assert info["active_keyset"] == mock_jwks.KEYSET_A
    assert info["mode"] == "ok"


def test_example_tokens_cover_all_scenarios():
    scenarios = [s[0] for s in client.get("/tokens").json()["scenarios"]]
    for scenario in scenarios:
        body = client.get(f"/tokens/{scenario}").json()
        assert body["token"]
        assert body["scenario"] == scenario
    assert client.get("/tokens/nope").status_code == 404


def test_valid_scenario_token_verifies_against_served_jwks():
    class StaticCache:
        url = "mock"

        def __init__(self):
            self.keys = parse_jwks_document(
                client.get("/.well-known/jwks.json").json()
            )

        async def get_key(self, kid):
            return self.keys[kid]

        def snapshot(self):
            class S:
                kids = list(self.keys)

            return S()

    token = client.get("/tokens/valid").json()["token"]
    import asyncio

    result = asyncio.run(
        verify_token(
            token,
            StaticCache(),
            mock_jwks.DEMO_ISSUER,
            mock_jwks.DEMO_AUDIENCE,
        )
    )
    assert result.status == "valid"


def test_tokens_signed_by_old_keyset_fail_after_rotation():
    # A token minted under keyset A must no longer verify once B is active:
    # the same kid now carries different key material -> signature failure.
    token_a = client.get("/tokens/valid").json()["token"]
    client.post("/__admin/keyset/keyset-b")
    b_keys = parse_jwks_document(client.get("/.well-known/jwks.json").json())

    class StaticCache:
        url = "mock"

        async def get_key(self, kid):
            return b_keys[kid]  # B public key for the same kid

        def snapshot(self):
            class S:
                kids = list(b_keys)

            return S()

    import asyncio

    result = asyncio.run(
        verify_token(
            token_a,
            StaticCache(),
            mock_jwks.DEMO_ISSUER,
            mock_jwks.DEMO_AUDIENCE,
        )
    )
    assert result.status == "invalid"
    assert result.reason_code == "bad_signature"

    # A freshly minted B token verifies against the B document.
    token_b = client.get("/tokens/valid").json()["token"]
    ok = asyncio.run(
        verify_token(
            token_b,
            StaticCache(),
            mock_jwks.DEMO_ISSUER,
            mock_jwks.DEMO_AUDIENCE,
        )
    )
    assert ok.status == "valid"


# --------------------------------------------------------------------- helpers

def _is_duplicate(doc) -> bool:
    kids = [k["kid"] for k in doc["keys"]]
    return len(kids) != len(set(kids))


def _is_invalid_json(resp) -> bool:
    import json

    try:
        json.loads(resp.text)
    except ValueError:
        return True
    return False
