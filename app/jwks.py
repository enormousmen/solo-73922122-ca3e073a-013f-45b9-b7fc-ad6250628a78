"""JWKS fetching, validation and single-flight caching.

The verifier runs as a single process, so one :class:`JwksCache` instance is
shared by every request.  Rules implemented here (see the operations brief):

* the whole JWKS document is cached and stays valid for ``ttl_seconds`` after a
  successful refresh (default 60s);
* a request hitting a still-valid cache never waits on a refresh;
* a refresh happens only when the cache is expired **or** the token ``kid`` is
  unknown to the current cache;
* concurrent refresh attempts collapse into one HTTP request (single flight);
* across every ``kid`` combined, at most one fetch is started per
  ``min_interval`` seconds (default 5s);
* a single fetch times out after ``timeout_seconds`` (default 2s);
* a new document replaces the cache only when *every* key is an RSA public key
  with a unique non-empty ``kid``; parse/validation failures keep the old cache
  untouched and never extend its lifetime.
"""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

#: Type of the pluggable fetching coroutine: URL -> decoded JSON body.
Fetcher = Callable[[str], Awaitable[Any]]


class JwksError(Exception):
    """Base class for JWKS sourcing failures."""


class RefreshError(JwksError):
    """A refresh could not produce a usable key set (network/timeout/HTTP)."""


class JwksInvalid(JwksError):
    """The fetched document failed whole-document validation."""


def _b64url_uint(value: int) -> bytes:
    """Encode a non-negative integer as a base64url big-endian byte string."""
    if value < 0:
        raise JwksInvalid("RSA 参数出现负整数")
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def public_key_to_rsa_jwk(key: RSAPublicKey, kid: str) -> dict[str, str]:
    """Serialise an RSA public key as a public JWK (used by the local source)."""
    numbers = key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n).decode("ascii"),
        "e": _b64url_uint(numbers.e).decode("ascii"),
    }


def _decode_b64url_uint(raw: str) -> int:
    if not isinstance(raw, str) or not raw:
        raise JwksInvalid("RSA JWK 缺少 n/e 参数")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise JwksInvalid("RSA JWK 的 n/e 不是合法 base64url") from exc
    if not data:
        raise JwksInvalid("RSA JWK 的 n/e 为空")
    return int.from_bytes(data, "big")


def parse_rsa_jwk(jwk: Any) -> tuple[str, RSAPublicKey]:
    """Validate one JWK and return ``(kid, public_key)``.

    Only RSA public keys are accepted.  An optional ``alg`` must be RS256 to
    avoid silently trusting keys advertised for another algorithm.
    """
    if not isinstance(jwk, dict):
        raise JwksInvalid("JWKS 中的每个 key 必须是 JSON 对象")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise JwksInvalid("JWK 缺少非空 kid")
    if jwk.get("kty") != "RSA":
        raise JwksInvalid(f"kid={kid} 的 kty 不是 RSA")
    alg = jwk.get("alg")
    if alg is not None and alg != "RS256":
        raise JwksInvalid(f"kid={kid} 声明了不支持的 alg={alg}（仅 RS256）")
    if "d" in jwk:
        raise JwksInvalid(f"kid={kid} 携带私钥参数 d，JWKS 只能包含公钥")
    try:
        n = _decode_b64url_uint(jwk.get("n"))
        e = _decode_b64url_uint(jwk.get("e"))
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key()
    except JwksInvalid:
        raise
    except (ValueError, TypeError, OverflowError) as exc:
        raise JwksInvalid(f"kid={kid} 的 RSA 参数无法构成公钥") from exc
    return kid, public_key


def parse_jwks_document(payload: Any) -> dict[str, RSAPublicKey]:
    """Validate the whole document; all keys must be valid with unique kids."""
    if not isinstance(payload, dict):
        raise JwksInvalid("JWKS 响应不是 JSON 对象")
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        raise JwksInvalid('JWKS 缺少非空 "keys" 数组')
    parsed: dict[str, RSAPublicKey] = {}
    for jwk in keys:
        kid, public_key = parse_rsa_jwk(jwk)
        if kid in parsed:
            raise JwksInvalid(f"JWKS 中 kid 重复：{kid}")
        parsed[kid] = public_key
    return parsed


async def httpx_fetcher(url: str, timeout_seconds: float) -> Any:
    """Default fetcher: GET ``url`` with a hard total timeout."""
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.get(url)
    except httpx.TimeoutException as exc:
        raise RefreshError(f"请求 JWKS 超时（{timeout_seconds:g} 秒）") from exc
    except httpx.HTTPError as exc:
        raise RefreshError(f"请求 JWKS 失败：{exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise RefreshError(f"JWKS 源返回 HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise JwksInvalid("JWKS 响应不是合法 JSON") from exc


@dataclass
class CacheSnapshot:
    """Diagnostic view of the cache state (rendered on the web page)."""

    has_cache: bool
    fresh: bool
    kids: list[str]
    cached_at: float | None
    expires_at: float | None
    age: float | None
    last_refresh_error: str | None
    last_attempt_at: float | None
    fetch_count: int
    suppressed_refreshes: int
    now: float = field(default_factory=time.monotonic)


class JwksCache:
    """Whole-document JWKS cache with single flight and global throttling."""

    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: float = 60.0,
        min_interval: float = 5.0,
        timeout_seconds: float = 2.0,
        fetcher: Fetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self.ttl_seconds = ttl_seconds
        self.min_interval = min_interval
        self.timeout_seconds = timeout_seconds
        self._clock = clock
        self._fetcher: Fetcher = fetcher or (
            lambda u: httpx_fetcher(u, timeout_seconds)
        )
        # Cache state.
        self._keys: dict[str, RSAPublicKey] = {}
        self._cached_at: float | None = None
        # Refresh coordination.
        self._lock = asyncio.Lock()
        self._inflight: asyncio.Future[dict[str, RSAPublicKey]] | None = None
        self._last_attempt: float | None = None
        self._last_error: str | None = None
        self._fetch_count = 0
        self._suppressed = 0

    # ------------------------------------------------------------------ state

    def _is_fresh(self, now: float) -> bool:
        return self._cached_at is not None and now - self._cached_at < self.ttl_seconds

    def snapshot(self) -> CacheSnapshot:
        now = self._clock()
        fresh = self._is_fresh(now)
        age = None if self._cached_at is None else now - self._cached_at
        return CacheSnapshot(
            has_cache=self._cached_at is not None,
            fresh=fresh,
            kids=sorted(self._keys),
            cached_at=self._cached_at,
            expires_at=(
                None if self._cached_at is None else self._cached_at + self.ttl_seconds
            ),
            age=age,
            last_refresh_error=self._last_error,
            last_attempt_at=self._last_attempt,
            fetch_count=self._fetch_count,
            suppressed_refreshes=self._suppressed,
            now=now,
        )

    # ------------------------------------------------------------------ fetch

    async def _do_refresh(self) -> dict[str, RSAPublicKey]:
        """One throttled fetch attempt.

        Throttling lives *inside* the single-flight task, so concurrent callers
        share both the request and its "skipped because rate limited" outcome.
        """
        now = self._clock()
        if self._last_attempt is not None:
            wait = self.min_interval - (now - self._last_attempt)
            if wait > 0:
                self._suppressed += 1
                raise RefreshError(
                    f"刷新被节流：距上次请求不足 {self.min_interval:g} 秒"
                    f"（还需等待 {wait:.1f} 秒）"
                )
        self._last_attempt = now
        self._fetch_count += 1
        try:
            payload = await self._fetcher(self.url)
            new_keys = parse_jwks_document(payload)
        except JwksInvalid as exc:
            self._last_error = f"JWKS 内容非法，保留旧缓存：{exc}"
            raise RefreshError(self._last_error) from exc
        except RefreshError as exc:
            self._last_error = str(exc)
            raise
        # Whole document is valid: atomic replace, TTL restarts from success.
        self._keys = new_keys
        self._cached_at = self._clock()
        self._last_error = None
        return new_keys

    async def _begin_refresh(
        self,
    ) -> asyncio.Future[dict[str, RSAPublicKey]]:
        """Join the in-flight refresh or start a new one (serialised)."""
        async with self._lock:
            if self._inflight is not None and not self._inflight.done():
                return self._inflight
            future: asyncio.Future[dict[str, RSAPublicKey]] = asyncio.get_event_loop().create_future()
            self._inflight = future
            task = asyncio.create_task(self._do_refresh())

            def _resolve(done: asyncio.Task[dict[str, RSAPublicKey]]) -> None:
                if not future.done():
                    if done.exception() is not None:
                        future.set_exception(done.exception())
                    else:
                        future.set_result(done.result())

            task.add_done_callback(_resolve)

            def _clear(done: asyncio.Task[dict[str, RSAPublicKey]]) -> None:
                # Drop the reference once settled so a later refresh starts clean.
                if self._inflight is future:
                    self._inflight = None

            task.add_done_callback(_clear)
            return future

    async def get_key(self, kid: str) -> RSAPublicKey:
        """Return the public key for ``kid``, refreshing only when required.

        Raises :class:`RefreshError` when no usable key can be sourced.
        """
        if not isinstance(kid, str) or not kid:
            raise RefreshError("缺少 kid，无法定位 JWKS 公钥")
        now = self._clock()
        # Fast path: a valid cache answers immediately, never waiting on I/O.
        if self._is_fresh(now) and kid in self._keys:
            return self._keys[kid]

        future = await self._begin_refresh()
        try:
            await future
        except RefreshError:
            # A failed refresh must not let an expired cache authenticate:
            # fall back to the stored key only while the cache is still fresh.
            if self._is_fresh(self._clock()) and kid in self._keys:
                return self._keys[kid]
            raise

        # Re-check the shared cache: a single-flight refresh joined here may
        # have populated the requested kid while we were waiting.
        if kid in self._keys:
            return self._keys[kid]
        raise RefreshError(
            f"刷新后的 JWKS 仍不含 kid={kid}（令牌 kid 与密钥源不匹配）"
        )

    async def force_refresh(self) -> dict[str, RSAPublicKey]:
        """Administrative refresh used by tests/diagnostics."""
        future = await self._begin_refresh()
        return await future


__all__ = [
    "JwksCache",
    "CacheSnapshot",
    "JwksError",
    "RefreshError",
    "JwksInvalid",
    "Fetcher",
    "parse_jwks_document",
    "parse_rsa_jwk",
    "public_key_to_rsa_jwk",
    "httpx_fetcher",
]
