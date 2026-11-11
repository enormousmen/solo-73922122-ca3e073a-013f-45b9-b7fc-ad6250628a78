"""Tests for strict RS256 JWT verification: header, claims, signature, states."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.jwks import JwksCache, RefreshError, public_key_to_rsa_jwk
from app.verifier import (
    INVALID_ALG,
    INVALID_AUD,
    INVALID_EXP_EXPIRED,
    INVALID_EXP_MISSING,
    INVALID_EXP_TYPE,
    INVALID_ISS,
    INVALID_KID,
    INVALID_MALFORMED,
    INVALID_SIGNATURE,
    UNKNOWN_KEY_SOURCE,
    VALID_OK,
    make_signed_jwt,
    verify_token,
)

ISSUER = "https://login.intranet.example/realms/ops"
AUDIENCE = "intranet-console"
KID = "demo-key-1"


class StubCache:
    """In-memory cache replacement with forced failure injection."""

    def __init__(self, keys: dict, url: str = "http://source/jwks.json") -> None:
        self._keys = keys
        self.url = url
        self.fail: Exception | None = None
        self.requested: list[str] = []

    async def get_key(self, kid: str):
        self.requested.append(kid)
        if self.fail is not None:
            raise self.fail
        return self._keys[kid]

    def snapshot(self):
        class S:
            kids = list(self._keys)

        return S()


@pytest.fixture
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def cache(private_key):
    pub = private_key.public_key()
    return StubCache({KID: pub})


def claims(**overrides):
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    base.update(overrides)
    return base


def run(coro):
    return asyncio_run(coro)


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)


# ----------------------------------------------------------------- happy path

def test_valid_token_passes(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims())
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "valid"
    assert result.reason_code == VALID_OK
    assert result.kid == KID


def test_audience_list_containing_expected_passes(cache, private_key):
    token = make_signed_jwt(
        private_key, KID, claims(aud=["other", AUDIENCE])
    )
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "valid"


def test_second_kid_in_same_cached_document(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims())
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "valid"
    assert cache.requested == [KID]


# ------------------------------------------------------------- header policy

def test_alg_must_be_rs256(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(), alg="HS256")
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_ALG
    assert cache.requested == []  # rejected before touching the key source


def test_missing_kid_rejected(cache, private_key):
    token = make_signed_jwt(private_key, None, claims())
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_KID


def test_empty_kid_rejected(cache, private_key):
    token = make_signed_jwt(private_key, "  ", claims())
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_KID


def test_token_jku_header_is_ignored(cache, private_key):
    # A jku pointing elsewhere must not influence key selection.
    token = make_signed_jwt(
        private_key, KID, claims(), extra_headers={"jku": "https://evil/jwks"}
    )
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "valid"
    assert result.key_source == cache.url


# --------------------------------------------------------------------- claims

def test_exp_mandatory(cache, private_key):
    token = make_signed_jwt(
        private_key, KID, {k: v for k, v in claims().items() if k != "exp"}
    )
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_EXP_MISSING
    assert result.status == "invalid"


def test_exp_must_be_numeric(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(exp="soon"))
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_EXP_TYPE


def test_boolean_exp_rejected(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(exp=True))
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_EXP_TYPE


def test_expired_token_rejected_with_invalid_state(cache, private_key):
    now = int(time.time())
    token = make_signed_jwt(
        private_key, KID, claims(exp=now - 1, iat=now - 300)
    )
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_EXP_EXPIRED


def test_iss_mismatch(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(iss="https://evil"))
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_ISS
    assert result.status == "invalid"


def test_aud_mismatch(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(aud="nope"))
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_AUD


# ------------------------------------------------------------------ signature

def test_tampered_payload_fails_signature(cache, private_key):
    # Flip a claim byte while keeping the segment decodable: the signature no
    # longer matches the signing input.
    token = make_signed_jwt(private_key, KID, claims(sub="victim"))
    head, payload, sig = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["sub"] = "attacker"
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    tampered = f"{head}.{tampered_payload}.{sig}"
    result = run(verify_token(tampered, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_SIGNATURE


def test_signature_with_wrong_key_is_invalid(cache):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_signed_jwt(other, KID, claims())  # kid matches, key differs
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_SIGNATURE
    assert result.status == "invalid"


def test_token_with_none_alg_rejected(cache, private_key):
    # Forge an alg=none token with an empty signature; header policy must
    # reject it before any signature/JWKS work happens.
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "kid": KID, "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(claims()).encode()
    ).rstrip(b"=").decode()
    result = run(verify_token(f"{header}.{payload}.", cache, ISSUER, AUDIENCE))
    assert result.reason_code == INVALID_ALG
    assert cache.requested == []


# ------------------------------------------------------------------ malformed

@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "only.two",
        "a.b.c.d",
        "a b.c.d",
        "not a jwt at all",
    ],
)
def test_malformed_inputs_are_invalid(cache, raw):
    result = run(verify_token(raw, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == INVALID_MALFORMED


def test_undecodable_segment_is_invalid(cache):
    result = run(verify_token("###.###.###", cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert result.reason_code == "bad_json_segment"


def test_bad_json_header(cache):
    def seg(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    token = f"{seg(b'{not json')}.{seg(b'{}')}.{seg(b'sig')}"
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"


# ------------------------------------------------------------- key source 3rd

def test_key_source_failure_yields_unknown_state(cache, private_key):
    cache.fail = RefreshError("连接被拒绝")
    token = make_signed_jwt(private_key, KID, claims())
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "unknown"
    assert result.reason_code == UNKNOWN_KEY_SOURCE
    assert "暂时无法核验" in result.reason


def test_unknown_kid_refresh_failure_is_unknown_not_invalid(private_key):
    # Even though the token itself is well-formed, an unresolvable kid during a
    # source outage must surface as "temporarily unverifiable".
    empty_cache = StubCache({})
    empty_cache.fail = RefreshError("JWKS 源返回 HTTP 500")
    token = make_signed_jwt(private_key, KID, claims())
    result = run(verify_token(token, empty_cache, ISSUER, AUDIENCE))
    assert result.status == "unknown"


def test_claim_checks_happen_before_network(cache, private_key):
    token = make_signed_jwt(private_key, KID, claims(iss="wrong"))
    result = run(verify_token(token, cache, ISSUER, AUDIENCE))
    assert result.status == "invalid"
    assert cache.requested == []  # never reached the JWKS source


def test_jwk_roundtrip_verifies_real_signature(private_key):
    pub_jwk = public_key_to_rsa_jwk(private_key.public_key(), KID)
    full_cache = JwksCache(
        "http://source/jwks.json",
        fetcher=lambda url: _async_return({"keys": [pub_jwk]}),
    )
    token = make_signed_jwt(private_key, KID, claims())
    result = run(verify_token(token, full_cache, ISSUER, AUDIENCE))
    assert result.status == "valid"


async def _async_return(value):
    return value
