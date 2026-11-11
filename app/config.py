"""Process start-up configuration for the JWT verifier.

Everything that pins trust lives here and is read once from environment
variables — the token itself can never override issuer, audience or the JWKS
endpoint.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Defaults point at the companion mock JWKS container on the compose network.
DEFAULT_JWKS_URL = "http://mock-jwks:8090/.well-known/jwks.json"
DEFAULT_ISSUER = "https://login.intranet.example/realms/ops"
DEFAULT_AUDIENCE = "intranet-console"
# Optional base URL of the mock source; when set, the verifier exposes proxied
# demo controls so the browser only talks to one origin.
DEFAULT_MOCK_BASE = "http://mock-jwks:8090"


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"环境变量 {name} 必须是数值，实际为 {raw!r}") from exc
    if value <= 0:
        raise RuntimeError(f"环境变量 {name} 必须为正数")
    return value


@dataclass(frozen=True)
class Settings:
    jwks_url: str
    issuer: str
    audience: str
    mock_base: str | None
    cache_ttl: float
    refresh_min_interval: float
    fetch_timeout: float

    @classmethod
    def from_env(cls) -> "Settings":
        mock_raw = os.environ.get("MOCK_JWKS_BASE", DEFAULT_MOCK_BASE).strip()
        return cls(
            jwks_url=os.environ.get("JWKS_URL", DEFAULT_JWKS_URL).strip(),
            issuer=os.environ.get("JWT_EXPECTED_ISSUER", DEFAULT_ISSUER).strip(),
            audience=os.environ.get("JWT_EXPECTED_AUDIENCE", DEFAULT_AUDIENCE).strip(),
            mock_base=mock_raw or None,
            cache_ttl=_float("JWKS_CACHE_TTL", 60.0),
            refresh_min_interval=_float("JWKS_REFRESH_MIN_INTERVAL", 5.0),
            fetch_timeout=_float("JWKS_FETCH_TIMEOUT", 2.0),
        )


settings = Settings.from_env()
