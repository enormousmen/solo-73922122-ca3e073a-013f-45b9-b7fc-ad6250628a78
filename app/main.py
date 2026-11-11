"""FastAPI web entry point: mTLS chain doctor and the JWT verifier page."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import httpx
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .diagnostics import (
    ALLOWED_SIGNATURE_LABEL,
    DiagnosticInputError,
    diagnose,
    parse_pem_bundle,
)
from .jwks import JwksCache
from .verifier import verify_token

BASE_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = BASE_DIR / "examples"

app = FastAPI(
    title="mTLS 证书链离线诊断 / JWT 签名核验",
    description="内网运维工具：证书链排障 + 固定配置的 RS256 JWT 核验",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# One process-wide JWKS cache: single flight + throttling live inside it.
jwks_cache = JwksCache(
    settings.jwks_url,
    ttl_seconds=settings.cache_ttl,
    min_interval=settings.refresh_min_interval,
    timeout_seconds=settings.fetch_timeout,
)


def _read_upload(f: UploadFile | None) -> bytes:
    if f is None:
        return b""
    return f.file.read()


def _run_diagnosis(
    leaf_bytes: bytes,
    intermediates_bytes: bytes,
    root_bytes: bytes,
    when: dt.datetime,
):
    leaf_certs = parse_pem_bundle(leaf_bytes)
    root_certs = parse_pem_bundle(root_bytes)
    intermediates = (
        parse_pem_bundle(intermediates_bytes) if intermediates_bytes.strip() else []
    )
    return diagnose(leaf_certs, intermediates, root_certs, when)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    examples = sorted(
        p.name
        for p in EXAMPLES_DIR.iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "examples": examples,
            "default_time": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "sig_policy": ALLOWED_SIGNATURE_LABEL,
        },
    )


def _parse_when(raw: str) -> dt.datetime:
    text = raw.strip()
    if not text:
        return dt.datetime.now(dt.timezone.utc)
    when = dt.datetime.fromisoformat(text)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.astimezone(dt.timezone.utc)


@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose_html(
    request: Request,
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        when = _parse_when(validation_time)
        result = _run_diagnosis(
            _read_upload(leaf),
            _read_upload(intermediates),
            _read_upload(root),
            when,
        )
    except (DiagnosticInputError, ValueError) as exc:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "error": str(exc),
                "examples": sorted(
                    p.name
                    for p in EXAMPLES_DIR.iterdir()
                    if p.is_dir() and (p / "manifest.json").exists()
                ),
                "default_time": validation_time,
                "sig_policy": ALLOWED_SIGNATURE_LABEL,
            },
            status_code=400,
        )
    return templates.TemplateResponse(
        request,
        "result.html",
        {"r": result, "r_dict": result.to_dict()},
    )


@app.post("/api/diagnose")
async def diagnose_api(
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        when = _parse_when(validation_time)
        result = _run_diagnosis(
            _read_upload(leaf),
            _read_upload(intermediates),
            _read_upload(root),
            when,
        )
    except (DiagnosticInputError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(result.to_dict())


@app.get("/examples/{name}")
def load_example(name: str):
    """Redirect the browser to a prefilled upload form for a built-in demo."""
    safe = Path(name).name  # strip any path components
    manifest = EXAMPLES_DIR / safe / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    return RedirectResponse(url=f"/?example={safe}", status_code=303)


@app.get("/api/examples/{name}")
def example_payload(name: str):
    safe = Path(name).name
    directory = EXAMPLES_DIR / safe
    manifest = directory / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    payload = {"manifest": manifest.read_text(encoding="utf-8"), "files": {}}
    for pem in sorted(directory.glob("*.pem")):
        payload["files"][pem.name] = pem.read_text(encoding="utf-8")
    return JSONResponse(payload)


# ---------------------------------------------------------------------------
# JWT verification (fixed issuer / audience / JWKS URL from start-up config)
# ---------------------------------------------------------------------------

_STATUS_LABELS = {
    "valid": "核验通过",
    "invalid": "令牌无效",
    "unknown": "暂时无法核验",
}


def _verify_page_context(result=None, token: str = "") -> dict:
    snap = jwks_cache.snapshot()
    return {
        "settings": settings,
        "snap": snap,
        "result": result,
        "status_label": _STATUS_LABELS.get(result.status) if result else None,
        "token_text": token,
        "has_mock": settings.mock_base is not None,
    }


@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "verify.html", _verify_page_context()
    )


@app.post("/verify", response_class=HTMLResponse)
async def verify_html(request: Request, token: str = Form(default="")):
    result = await verify_token(
        token, jwks_cache, settings.issuer, settings.audience
    )
    status_code = 200 if result.status == "valid" else (
        400 if result.status == "invalid" else 503
    )
    return templates.TemplateResponse(
        request,
        "verify.html",
        _verify_page_context(result, token),
        status_code=status_code,
    )


@app.post("/api/verify")
async def verify_api(request: Request):
    # Accept any body gracefully: malformed/non-JSON input is a token-side
    # rejection (400 invalid), never a framework-level 422.
    try:
        payload = await request.json()
    except ValueError:
        payload = None
    token = ""
    if isinstance(payload, dict):
        raw = payload.get("token", "")
        if isinstance(raw, str):
            token = raw
    result = await verify_token(
        token, jwks_cache, settings.issuer, settings.audience
    )
    status_code = 200 if result.status == "valid" else (
        400 if result.status == "invalid" else 503
    )
    return JSONResponse(result.to_dict(), status_code=status_code)


@app.get("/api/jwks/cache")
def jwks_cache_state():
    """Read-only diagnostic view of cache freshness and throttling."""
    snap = jwks_cache.snapshot()
    return {
        "jwks_url": settings.jwks_url,
        "has_cache": snap.has_cache,
        "fresh": snap.fresh,
        "cached_kids": snap.kids,
        "age_seconds": None if snap.age is None else round(snap.age, 2),
        "ttl_seconds": settings.cache_ttl,
        "expires_in": (
            None
            if snap.expires_at is None
            else round(max(0.0, snap.expires_at - snap.now), 2)
        ),
        "fetch_count": snap.fetch_count,
        "suppressed_refreshes": snap.suppressed_refreshes,
        "last_refresh_error": snap.last_refresh_error,
        "min_interval_seconds": settings.refresh_min_interval,
        "timeout_seconds": settings.fetch_timeout,
    }


# ----- demo JWKS source proxy (browser only talks to this origin) ----------

async def _proxy(method: str, suffix: str, **kwargs):
    if settings.mock_base is None:
        return JSONResponse({"error": "未配置本地 JWKS 演示源"}, status_code=404)
    url = settings.mock_base.rstrip("/") + suffix
    try:
        async with httpx.AsyncClient(timeout=settings.fetch_timeout + 1) as client:
            resp = await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        return JSONResponse(
            {"error": f"演示源不可达：{exc.__class__.__name__}"}, status_code=502
        )
    return JSONResponse(resp.json(), status_code=resp.status_code)


@app.get("/demo/state")
async def demo_state():
    return await _proxy("GET", "/__admin/state")


@app.post("/demo/keyset/{name}")
async def demo_keyset(name: str):
    return await _proxy("POST", f"/__admin/keyset/{name}")


@app.post("/demo/mode/{mode}")
async def demo_mode(mode: str):
    return await _proxy("POST", f"/__admin/mode?mode={mode}")


@app.post("/demo/reset")
async def demo_reset():
    return await _proxy("POST", "/__admin/reset")


@app.get("/demo/tokens")
async def demo_token_list():
    return await _proxy("GET", "/tokens")


@app.get("/demo/tokens/{scenario}")
async def demo_token(scenario: str):
    return await _proxy("GET", f"/tokens/{scenario}")
