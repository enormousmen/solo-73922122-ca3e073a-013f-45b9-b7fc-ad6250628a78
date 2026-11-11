"""Tests for the whole-document JWKS cache: TTL, single flight, throttling."""

from __future__ import annotations

import asyncio

import pytest

from app.jwks import (
    JwksCache,
    JwksInvalid,
    RefreshError,
    parse_jwks_document,
    public_key_to_rsa_jwk,
)
from cryptography.hazmat.primitives.asymmetric import rsa


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()


def _doc(*kids: str) -> dict:
    return {"keys": [public_key_to_rsa_jwk(_key(), kid) for kid in kids]}


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class ScriptedFetcher:
    """Fetch script: each entry is either a payload dict or an Exception."""

    def __init__(self, script: list, clock: FakeClock) -> None:
        self.script = list(script)
        self.clock = clock
        self.calls: list[float] = []
        self.gate: asyncio.Event | None = None

    async def __call__(self, url: str):
        self.calls.append(self.clock())
        if self.gate is not None:
            await self.gate.wait()
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_cache(script, clock, **kw):
    fetcher = ScriptedFetcher(script, clock)
    cache = JwksCache(
        "http://source/jwks.json",
        ttl_seconds=kw.get("ttl", 60.0),
        min_interval=kw.get("min_interval", 5.0),
        timeout_seconds=2.0,
        fetcher=fetcher,
        clock=clock,
    )
    return cache, fetcher


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------- parsing

def test_valid_document_parses_all_rsa_keys():
    doc = _doc("k1", "k2")
    parsed = parse_jwks_document(doc)
    assert set(parsed) == {"k1", "k2"}


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"keys": []},
        {"keys": "nope"},
        {"keys": [{"kty": "RSA"}]},  # no kid
        {"keys": [{"kty": "RSA", "kid": " "}]},  # blank kid
        {"keys": [{"kty": "EC", "kid": "x"}]},  # non-RSA
        {"keys": [{"kty": "RSA", "kid": "x", "alg": "ES256"}]},
        {"keys": [{"kty": "RSA", "kid": "x", "n": "aa", "e": "AQAB", "d": "xx"}]},
        "not-an-object",
    ],
)
def test_invalid_documents_rejected(doc):
    with pytest.raises(JwksInvalid):
        parse_jwks_document(doc)


def test_duplicate_kid_rejects_whole_document():
    doc = _doc("same", "same")
    with pytest.raises(JwksInvalid, match="kid 重复"):
        parse_jwks_document(doc)


# --------------------------------------------------------------------- caching

def test_first_fetch_populates_cache():
    clock = FakeClock()
    cache, fetcher = make_cache([_doc("k1")], clock)
    key = run(cache.get_key("k1"))
    assert key is not None
    snap = cache.snapshot()
    assert snap.fresh and snap.kids == ["k1"] and snap.fetch_count == 1


def test_valid_cache_hit_does_not_fetch():
    clock = FakeClock()
    cache, fetcher = make_cache([_doc("k1", "k2")], clock)
    run(cache.get_key("k1"))
    for _ in range(5):
        clock.advance(1)
        run(cache.get_key("k2"))  # same document, other kid -> still cached
    assert fetcher.calls == [1000.0]
    assert cache.snapshot().fetch_count == 1


def test_expired_cache_triggers_refresh():
    clock = FakeClock()
    cache, fetcher = make_cache([_doc("k1"), _doc("k1")], clock, ttl=60)
    run(cache.get_key("k1"))
    clock.advance(61)
    run(cache.get_key("k1"))
    assert len(fetcher.calls) == 2


def test_unknown_kid_triggers_immediate_refresh_even_within_ttl():
    clock = FakeClock()
    cache, fetcher = make_cache([_doc("k1"), _doc("k1", "k2")], clock)
    run(cache.get_key("k1"))
    clock.advance(6)  # outside the throttle window, still inside the 60s TTL
    key = run(cache.get_key("k2"))
    assert key is not None
    assert len(fetcher.calls) == 2


def test_unknown_kid_absent_after_refresh_is_refresh_error():
    clock = FakeClock()
    cache, _ = make_cache([_doc("k1"), _doc("k1")], clock)
    run(cache.get_key("k1"))
    clock.advance(10)  # beyond throttle window
    with pytest.raises(RefreshError, match="仍不含"):
        run(cache.get_key("ghost"))


def test_refresh_failure_keeps_old_cache_and_does_not_extend_ttl():
    clock = FakeClock()
    cache, fetcher = make_cache(
        [_doc("k1"), RefreshError("boom"), RefreshError("still down"), _doc("k1")],
        clock,
        ttl=60,
    )
    run(cache.get_key("k1"))
    cached_at = cache.snapshot().cached_at

    clock.advance(30)
    with pytest.raises(RefreshError):
        run(cache.get_key("new-kid"))
    snap = cache.snapshot()
    # Old cache retained, timestamp untouched (no TTL extension).
    assert snap.kids == ["k1"]
    assert snap.cached_at == cached_at
    assert snap.last_refresh_error is not None

    # An immediate retry is throttled without any new HTTP request; since the
    # cache is still fresh, its old key keeps serving until expiry.
    before = len(fetcher.calls)
    with pytest.raises(RefreshError):
        run(cache.get_key("new-kid"))
    assert len(fetcher.calls) == before

    clock.advance(32)  # now 62s old -> expired and beyond the 5s throttle window
    assert cache.snapshot().fresh is False
    # Expired old key must not authenticate even though it is still stored:
    # this fetch runs (throttle window elapsed) and the source is still down.
    with pytest.raises(RefreshError):
        run(cache.get_key("k1"))
    assert cache.snapshot().fresh is False
    # After the source recovers, verification works again.
    clock.advance(6)
    ok = run(cache.get_key("k1"))
    assert ok is not None
    assert cache.snapshot().fresh is True


def test_invalid_new_document_does_not_replace_cache():
    clock = FakeClock()
    cache, _ = make_cache(
        [_doc("k1"), {"keys": []}, _doc("k1", "k2")], clock
    )
    run(cache.get_key("k1"))
    clock.advance(10)
    with pytest.raises(RefreshError):
        run(cache.get_key("k2"))
    assert cache.snapshot().kids == ["k1"]
    clock.advance(10)
    assert run(cache.get_key("k2")) is not None
    assert set(cache.snapshot().kids) == {"k1", "k2"}


# ----------------------------------------------------------------- throttling

def test_global_throttle_allows_one_fetch_per_window():
    clock = FakeClock()
    cache, fetcher = make_cache(
        [RefreshError("down"), RefreshError("down")], clock, min_interval=5
    )
    with pytest.raises(RefreshError):
        run(cache.get_key("k1"))
    # Immediate retry: no HTTP request is made, a throttle error is raised.
    clock.advance(1)
    with pytest.raises(RefreshError, match="节流"):
        run(cache.get_key("k1"))
    assert len(fetcher.calls) == 1
    assert cache.snapshot().suppressed_refreshes == 1

    clock.advance(4.1)  # 5.1s after the attempt -> window elapsed
    with pytest.raises(RefreshError):
        run(cache.get_key("k1"))
    assert len(fetcher.calls) == 2


def test_successful_refresh_resets_ttl_but_keeps_throttle_window():
    clock = FakeClock()
    cache, fetcher = make_cache([_doc("k1"), _doc("k1")], clock)
    run(cache.get_key("k1"))
    # A successful fetch still counts toward the 5s global rate limit.
    clock.advance(2)
    with pytest.raises(RefreshError, match="节流"):
        run(cache.force_refresh())
    clock.advance(3.1)
    run(cache.force_refresh())
    assert len(fetcher.calls) == 2


# ------------------------------------------------------------- single flight

def test_concurrent_refresh_collapses_into_one_request():
    clock = FakeClock()
    fetcher = ScriptedFetcher([_doc("k1")], clock)
    gate = asyncio.Event()
    fetcher.gate = gate
    cache = JwksCache(
        "http://source/jwks.json",
        ttl_seconds=60,
        min_interval=5.0,
        fetcher=fetcher,
        clock=clock,
    )

    async def scenario():
        tasks = [asyncio.create_task(cache.get_key("k1")) for _ in range(10)]
        await asyncio.sleep(0)  # let every task reach the single-flight join
        gate.set()
        results = await asyncio.gather(*tasks)
        return results

    results = asyncio.run(scenario())
    assert len(results) == 10
    assert all(k is results[0] for k in results)
    assert fetcher.calls == [1000.0]  # exactly one HTTP request


def test_concurrent_waiters_share_throttle_outcome():
    clock = FakeClock()
    # First call fails; 10 concurrent callers within the window must all get
    # the shared throttle result without issuing further HTTP requests.
    fetcher = ScriptedFetcher([RefreshError("down")], clock)
    cache = JwksCache(
        "http://source/jwks.json",
        ttl_seconds=60,
        min_interval=5.0,
        fetcher=fetcher,
        clock=clock,
    )

    async def scenario():
        with pytest.raises(RefreshError):
            await cache.get_key("k1")
        clock.advance(0.5)
        tasks = [asyncio.create_task(cache.get_key("k1")) for _ in range(10)]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        return outcomes

    outcomes = asyncio.run(scenario())
    assert len(outcomes) == 10
    assert all(isinstance(o, RefreshError) for o in outcomes)
    assert len(fetcher.calls) == 1


def test_cache_hit_never_waits_on_refresh():
    clock = FakeClock()
    good = _doc("k1")
    fetcher = ScriptedFetcher([good, _doc("k1")], clock)
    slow_gate = asyncio.Event()
    cache = JwksCache(
        "http://source/jwks.json",
        ttl_seconds=60,
        min_interval=5.0,
        fetcher=fetcher,
        clock=clock,
    )

    async def scenario():
        await cache.get_key("k1")  # prime the cache
        # An unrelated unknown-kid refresh hangs behind a gate...
        async def hanging():
            fetcher.gate = slow_gate
            try:
                await cache.get_key("ghost")
            except RefreshError:
                pass

        task = asyncio.create_task(hanging())
        await asyncio.sleep(0.05)
        # ...meanwhile a fresh-cache hit for k1 resolves immediately.
        key = await asyncio.wait_for(cache.get_key("k1"), timeout=0.2)
        assert key is not None
        slow_gate.set()
        await task

    asyncio.run(scenario())
