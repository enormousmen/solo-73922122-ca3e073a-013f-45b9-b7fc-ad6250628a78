"""Local switchable JWKS source for the JWT verification demo.

This is a *separate* process in ``docker compose`` (port 8090).  It keeps three
RSA key pairs in memory and serves:

* two switchable key sets — rotating the source simulates "签名公钥更换";
* failure modes (HTTP 500, empty/invalid document, slow response) so the
  verifier page can demonstrate the "暂时无法核验" state;
* on-demand signed example JWTs covering every verifier outcome.

State is in-memory and resets with the container.  The module is imported only
by the mock process, never by the verifier itself.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa

from .jwks import public_key_to_rsa_jwk
from .verifier import make_signed_jwt

# Fixed demo contract — the verifier is configured with the same values.
DEMO_ISSUER = "https://login.intranet.example/realms/ops"
DEMO_AUDIENCE = "intranet-console"
KEYSET_A = "keyset-a"
KEYSET_B = "keyset-b"
KEY_KIDS = ("demo-key-1", "demo-key-2")
EXTRA_KID = "demo-extra"

# Failure modes accepted by /__admin/mode.
MODES = ("ok", "http500", "empty-keys", "invalid-json", "duplicate-kid", "timeout")


def _gen_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class MockState:
    def __init__(self) -> None:
        # Two full key sets (each two kids) plus an out-of-band key.
        self.keysets: dict[str, dict[str, rsa.RSAPrivateKey]] = {
            KEYSET_A: {kid: _gen_rsa() for kid in KEY_KIDS},
            KEYSET_B: {kid: _gen_rsa() for kid in KEY_KIDS},
        }
        self.unknown_key = _gen_rsa()
        self.es256_ish_key = _gen_rsa()  # signed by an RSA key but tagged HS256
        self.active = KEYSET_A
        self.mode = "ok"
        self.request_count = 0
        self.started_at = time.time()

    def public_jwks(self, keyset: str) -> dict[str, Any]:
        privates = self.keysets[keyset]
        return {
            "keys": [
                public_key_to_rsa_jwk(privates[kid].public_key(), kid)
                for kid in KEY_KIDS
            ]
        }

    def sign(self, keyset: str, kid: str, claims: dict[str, Any], **kw: Any) -> str:
        return make_signed_jwt(self.keysets[keyset][kid], kid, claims, **kw)


state = MockState()
app = FastAPI(title="本地 JWKS 演示源", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _base_claims() -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": DEMO_ISSUER,
        "aud": DEMO_AUDIENCE,
        "sub": "ops-user@intranet",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": f"demo-{now}-{state.request_count}",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "uptime": round(time.time() - state.started_at, 1)}


@app.get("/.well-known/jwks.json")
async def jwks() -> Any:
    state.request_count += 1
    if state.mode == "http500":
        raise HTTPException(status_code=500, detail="模拟 JWKS 源故障（HTTP 500）")
    if state.mode == "timeout":
        # Verifier uses a 2s timeout; sleep beyond it to force a timeout.
        await asyncio.sleep(3.0)
        return state.public_jwks(state.active)
    if state.mode == "invalid-json":
        from fastapi.responses import Response

        return Response(
            content='{"keys": [this is not json', media_type="application/json"
        )
    if state.mode == "empty-keys":
        return {"keys": []}
    if state.mode == "duplicate-kid":
        doc = state.public_jwks(state.active)
        doc["keys"].append(dict(doc["keys"][0]))  # duplicated kid -> whole doc invalid
        return doc
    return state.public_jwks(state.active)


@app.get("/__admin/state")
def admin_state() -> dict[str, Any]:
    return {
        "active_keyset": state.active,
        "mode": state.mode,
        "request_count": state.request_count,
        "keysets": list(state.keysets),
        "kids": list(KEY_KIDS),
        "issuer": DEMO_ISSUER,
        "audience": DEMO_AUDIENCE,
    }


@app.post("/__admin/keyset/{name}")
def switch_keyset(name: str) -> dict[str, Any]:
    if name not in state.keysets:
        raise HTTPException(status_code=404, detail=f"未知密钥套：{name}")
    state.active = name
    return {"ok": True, "active_keyset": state.active}


@app.post("/__admin/mode")
def set_mode(mode: str = Query(..., description=f"之一：{MODES}")) -> dict[str, Any]:
    if mode not in MODES:
        raise HTTPException(status_code=400, detail=f"未知故障模式：{mode}")
    state.mode = mode
    return {"ok": True, "mode": state.mode}


@app.post("/__admin/reset")
def reset_state() -> dict[str, Any]:
    state.active = KEYSET_A
    state.mode = "ok"
    state.request_count = 0
    return {"ok": True}


@app.get("/tokens/{scenario}")
def example_token(scenario: str) -> dict[str, str]:
    """Return a ready-to-paste JWT for each verifier outcome."""
    now = int(time.time())
    keyset = state.active
    kid = KEY_KIDS[0]
    claims = _base_claims()
    token: str

    if scenario == "valid":
        token = state.sign(keyset, kid, claims)
    elif scenario == "valid-key2":
        token = state.sign(keyset, KEY_KIDS[1], claims)
    elif scenario == "expired":
        bad = dict(claims, exp=now - 60, iat=now - 360)
        token = state.sign(keyset, kid, bad)
    elif scenario == "no-exp":
        bad = {k: v for k, v in claims.items() if k != "exp"}
        token = state.sign(keyset, kid, bad)
    elif scenario == "bad-iss":
        bad = dict(claims, iss="https://evil.example/another-realm")
        token = state.sign(keyset, kid, bad)
    elif scenario == "bad-aud":
        bad = dict(claims, aud="some-other-service")
        token = state.sign(keyset, kid, bad)
    elif scenario == "unknown-kid":
        token = make_signed_jwt(state.unknown_key, EXTRA_KID, claims)
    elif scenario == "tampered":
        # Decode, change a claim, re-encode while keeping the old signature:
        # the segment stays valid JSON but signature verification must fail.
        import base64 as _b64
        import json as _json

        good = state.sign(keyset, kid, claims)
        head, payload_b64, sig = good.split(".")
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = _json.loads(_b64.urlsafe_b64decode(padded))
        payload["sub"] = "attacker@intruder"
        payload["role"] = "admin"
        new_payload = _b64.urlsafe_b64encode(
            _json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        token = f"{head}.{new_payload}.{sig}"
    elif scenario == "alg-hs256":
        # Header claims RS256 is required; present a different alg instead.
        token = make_signed_jwt(
            state.es256_ish_key, kid, claims, alg="HS256"
        )
    elif scenario == "no-kid":
        # Well-formed RS256 signature but the header carries no kid at all.
        token = make_signed_jwt(state.keysets[keyset][kid], None, claims)
    elif scenario == "malformed":
        token = "not.a.jwt.enough"
    elif scenario == "garbage":
        token = "Bearer abc123!!!"
    else:
        raise HTTPException(status_code=404, detail=f"未知示例场景：{scenario}")

    return {
        "scenario": scenario,
        "token": token,
        "signed_by_keyset": keyset,
        "issuer": DEMO_ISSUER,
        "audience": DEMO_AUDIENCE,
    }


@app.get("/tokens")
def list_scenarios() -> dict[str, Any]:
    return {
        "scenarios": [
            ("valid", "正常令牌（当前密钥套 key-1 签名）"),
            ("valid-key2", "正常令牌（同套 key-2，缓存内另一 kid）"),
            ("expired", "已过期令牌（exp 在过去）"),
            ("no-exp", "缺少 exp 声明"),
            ("bad-iss", "iss 与固定配置不符"),
            ("bad-aud", "aud 与固定配置不符"),
            ("unknown-kid", "kid 不在 JWKS（触发刷新后仍找不到）"),
            ("tampered", "内容被篡改导致签名失败"),
            ("alg-hs256", "header alg=HS256（非 RS256 直接拒绝）"),
            ("no-kid", "header 缺少 kid"),
            ("malformed", "结构损坏（4 段）"),
            ("garbage", "完全无法解析的文本"),
        ],
        "issuer": DEMO_ISSUER,
        "audience": DEMO_AUDIENCE,
    }
