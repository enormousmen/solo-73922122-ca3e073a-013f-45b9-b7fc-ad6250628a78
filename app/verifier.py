"""Strict RS256 JWT verification against a fixed-configuration JWKS source.

The verifier deliberately trusts *nothing* inside the token about where keys
live: the JWKS URL, expected issuer and audience come from process start-up
configuration only.  A token must

* parse as a compact JWS with three segments;
* carry header ``alg=RS256`` and a non-empty string ``kid``;
* carry the mandatory numeric ``exp`` claim that is still in the future;
* match the fixed ``iss`` and ``aud``;
* have a valid RSASSA-PKCS1-v1_5 SHA-256 signature under the JWK selected by
  ``kid`` from the configured source.

Outcomes map to the three page states:

* ``valid``   -> 核验通过
* ``invalid`` -> 令牌无效（deterministic token-side failures）
* ``unknown`` -> 暂时无法核验（key source unavailable/unusable）
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .jwks import JwksCache, RefreshError

ALLOWED_ALG = "RS256"

# Machine-readable reason codes, stable for tests and the JSON API.
VALID_OK = "ok"
INVALID_MALFORMED = "malformed_token"
INVALID_BAD_JSON = "bad_json_segment"
INVALID_ALG = "alg_not_rs256"
INVALID_KID = "missing_or_empty_kid"
INVALID_CLAIMS = "claims_not_object"
INVALID_EXP_MISSING = "exp_missing"
INVALID_EXP_TYPE = "exp_not_numeric"
INVALID_EXP_EXPIRED = "token_expired"
INVALID_ISS = "iss_mismatch"
INVALID_AUD = "aud_mismatch"
INVALID_SIGNATURE = "bad_signature"
UNKNOWN_KEY_SOURCE = "key_source_unavailable"


class TokenInvalid(Exception):
    """Raised for deterministic token-side rejections (page state: invalid)."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass
class VerifyResult:
    """Three-state result rendered by the page and returned by the API."""

    status: str  # "valid" | "invalid" | "unknown"
    reason_code: str
    reason: str
    header: dict[str, Any] | None = None
    claims: dict[str, Any] | None = None
    kid: str | None = None
    key_source: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "kid": self.kid,
            "header": self.header,
            "claims": self.claims,
            "key_source": self.key_source,
            "detail": self.detail,
        }


def _b64url_decode(raw: str) -> bytes:
    try:
        padded = raw + "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise TokenInvalid(
            INVALID_MALFORMED, "令牌段不是合法的 base64url 编码"
        ) from exc


def _decode_json_segment(raw: str, segment: str) -> Any:
    if not raw:
        raise TokenInvalid(INVALID_MALFORMED, f"令牌的 {segment} 段为空")
    try:
        return json.loads(_b64url_decode(raw))
    except json.JSONDecodeError as exc:
        raise TokenInvalid(
            INVALID_BAD_JSON, f"令牌的 {segment} 段不是合法 JSON"
        ) from exc


def parse_unverified(token: str) -> tuple[bytes, dict[str, Any], dict[str, Any], str]:
    """Split and lightly parse a compact JWS without any trust decisions."""
    if not isinstance(token, str):
        raise TokenInvalid(INVALID_MALFORMED, "令牌必须是文本字符串")
    text = token.strip()
    if not text:
        raise TokenInvalid(INVALID_MALFORMED, "令牌为空")
    if any(ch.isspace() for ch in text):
        raise TokenInvalid(INVALID_MALFORMED, "令牌内部不允许包含空白字符")
    parts = text.split(".")
    if len(parts) != 3:
        raise TokenInvalid(
            INVALID_MALFORMED,
            f"紧凑 JWS 必须恰好有 3 段，实际为 {len(parts)} 段",
        )
    header_b64, payload_b64, signature_b64 = parts
    header = _decode_json_segment(header_b64, "header")
    if not isinstance(header, dict):
        raise TokenInvalid(INVALID_BAD_JSON, "令牌 header 不是 JSON 对象")
    claims = _decode_json_segment(payload_b64, "payload")
    if not isinstance(claims, dict):
        raise TokenInvalid(INVALID_CLAIMS, "令牌 claims 必须是 JSON 对象")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(signature_b64)
    # Note: an empty signature is rejected later at the signature stage, so an
    # alg=none token still fails on the algorithm policy first.
    return signing_input, header, claims, signature


def _check_header(header: dict[str, Any]) -> str:
    alg = header.get("alg")
    if alg != ALLOWED_ALG:
        raise TokenInvalid(
            INVALID_ALG,
            f"仅接受 {ALLOWED_ALG}，令牌声明 alg={alg!r}",
        )
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise TokenInvalid(INVALID_KID, "令牌 header 缺少非空字符串 kid")
    # jku/jwk/x5u inside the token are intentionally ignored: key location is
    # fixed by service configuration, never taken from the token.
    return kid


def _check_claims(
    claims: dict[str, Any],
    expected_iss: str,
    expected_aud: str,
    now: float,
) -> None:
    # exp: mandatory and numeric (RFC 7519 §2.2.1; bool is a Python int -> reject).
    if "exp" not in claims:
        raise TokenInvalid(INVALID_EXP_MISSING, "缺少必填的 exp 声明")
    exp = claims["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise TokenInvalid(INVALID_EXP_TYPE, "exp 必须是 Unix 时间戳数值")
    if now >= exp:
        raise TokenInvalid(
            INVALID_EXP_EXPIRED,
            f"令牌已过期：exp={exp}，当前时间={int(now)}",
        )
    if claims.get("iss") != expected_iss:
        raise TokenInvalid(
            INVALID_ISS,
            f"iss 不匹配：期望 {expected_iss!r}，令牌为 {claims.get('iss')!r}",
        )
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud_ok = aud == expected_aud
    elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        aud_ok = expected_aud in aud
    else:
        aud_ok = False
    if not aud_ok:
        raise TokenInvalid(
            INVALID_AUD,
            f"aud 不匹配：期望包含 {expected_aud!r}，令牌为 {aud!r}",
        )


def _verify_signature(
    public_key: rsa.RSAPublicKey, signing_input: bytes, signature: bytes
) -> None:
    if not signature:
        raise TokenInvalid(INVALID_SIGNATURE, "令牌签名段为空，无法通过 RS256 验签")
    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise TokenInvalid(
            INVALID_SIGNATURE, "签名验证失败：令牌内容或签名与 JWKS 公钥不匹配"
        ) from exc
    except Exception as exc:  # malformed signature bytes etc.
        raise TokenInvalid(INVALID_SIGNATURE, f"签名无法验证：{exc}") from exc


async def verify_token(
    token: str,
    cache: JwksCache,
    expected_iss: str,
    expected_aud: str,
    *,
    clock: Callable[[], float] = time.time,
) -> VerifyResult:
    """Verify a user-supplied JWT and return a three-state result."""
    header: dict[str, Any] | None = None
    claims: dict[str, Any] | None = None
    kid: str | None = None
    try:
        signing_input, header, claims, signature = parse_unverified(token)
        kid = _check_header(header)
        assert claims is not None
        _check_claims(claims, expected_iss, expected_aud, clock())
    except TokenInvalid as exc:
        return VerifyResult(
            status="invalid",
            reason_code=exc.code,
            reason=exc.reason,
            header=header,
            claims=claims,
            kid=kid,
            key_source=cache.url,
        )

    # All token-side checks passed; only now touch the key source.
    try:
        assert kid is not None
        public_key = await cache.get_key(kid)
    except RefreshError as exc:
        return VerifyResult(
            status="unknown",
            reason_code=UNKNOWN_KEY_SOURCE,
            reason=f"暂时无法核验：{exc}",
            header=header,
            claims=claims,
            kid=kid,
            key_source=cache.url,
        )

    try:
        _verify_signature(public_key, signing_input, signature)
    except TokenInvalid as exc:
        return VerifyResult(
            status="invalid",
            reason_code=exc.code,
            reason=exc.reason,
            header=header,
            claims=claims,
            kid=kid,
            key_source=cache.url,
        )

    return VerifyResult(
        status="valid",
        reason_code=VALID_OK,
        reason="核验通过：签名、iss、aud、exp 均符合固定配置",
        header=header,
        claims=claims,
        kid=kid,
        key_source=cache.url,
        detail={"jwks_kids": cache.snapshot().kids},
    )


def make_signed_jwt(
    private_key: rsa.RSAPrivateKey,
    kid: str | None,
    claims: dict[str, Any],
    *,
    alg: str = ALLOWED_ALG,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    """Sign a JWT locally (used by the demo source and the test suite).

    ``kid=None`` omits the header field entirely; ``kid=""`` emits an empty
    value. Both must be rejected by the verifier.
    """
    header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    if extra_headers:
        header.update(extra_headers)

    def encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header_b64 = encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{encode(signature)}"


__all__ = [
    "VerifyResult",
    "TokenInvalid",
    "verify_token",
    "parse_unverified",
    "make_signed_jwt",
    "ALLOWED_ALG",
    "VALID_OK",
    "UNKNOWN_KEY_SOURCE",
]
