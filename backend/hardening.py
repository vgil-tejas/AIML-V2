"""
CyberSentinel — production hardening layer.

Additive, non-breaking wiring for the FastAPI app: typed settings with fail-fast,
request-id + structured access logs, security headers, an env-driven CORS
allowlist, a body-size cap, a clean error envelope for unhandled errors (stack
traces never reach the client), and the three-depth health surface.

Everything here is opt-in via env and defaults to the current permissive dev
behaviour, so turning it on cannot break the running dashboard. Lock it down on
prod by setting the env vars documented in .env.example.
"""
from __future__ import annotations

import os
import time
import uuid
import logging
import contextvars
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("cybersentinel.backend")

# request-id is stashed here so any log line in the request's call stack can pick
# it up without threading it through every function signature.
request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


# ── Typed settings: one source of truth, fail-fast, redacted boot log ─────────

def _redact(v: str) -> str:
    if not v:
        return "(unset)"
    return v[:2] + "***" if len(v) > 4 else "***"


@dataclass
class Settings:
    """Every env knob the backend reads, typed and defaulted in one place.
    Call validate() at startup to fail fast on anything required-but-missing."""
    clickhouse_host: str = field(default_factory=lambda: os.getenv("CLICKHOUSE_HOST", "clickhouse"))
    clickhouse_pass: str = field(default_factory=lambda: os.getenv("CLICKHOUSE_PASS", ""))
    clickhouse_enabled: bool = field(default_factory=lambda: os.getenv(
        "CLICKHOUSE_ENABLED", os.getenv("OPENSEARCH_ENABLED", "false")).lower() in ("true", "1", "yes"))

    # read-path safety
    read_max_seconds: int = field(default_factory=lambda: int(os.getenv("READ_MAX_SECONDS", "30")))
    logs_max_window_min: int = field(default_factory=lambda: int(os.getenv("LOGS_MAX_WINDOW_MINUTES", "43200")))  # 30d
    read_concurrency: int = field(default_factory=lambda: int(os.getenv("READ_CONCURRENCY", "8")))

    # security / hardening
    cors_origins: str = field(default_factory=lambda: os.getenv("CS_CORS_ORIGINS", "*"))
    max_body_mb: int = field(default_factory=lambda: int(os.getenv("CS_MAX_BODY_MB", "550")))
    admin_token: str = field(default_factory=lambda: os.getenv("CS_ADMIN_TOKEN", ""))
    demo_mode: bool = field(default_factory=lambda: os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes"))

    # ops
    run_migrations_on_start: bool = field(default_factory=lambda: os.getenv(
        "RUN_MIGRATIONS_ON_START", "true").lower() in ("true", "1", "yes"))

    def validate(self) -> list:
        """Return a list of fatal problems (empty = ok)."""
        problems = []
        if self.clickhouse_enabled and not self.clickhouse_pass:
            problems.append("CLICKHOUSE_ENABLED is on but CLICKHOUSE_PASS is empty")
        if self.read_max_seconds < 1:
            problems.append("READ_MAX_SECONDS must be >= 1")
        if self.logs_max_window_min < 60:
            problems.append("LOGS_MAX_WINDOW_MINUTES must be >= 60")
        return problems

    def log_effective(self):
        logger.info(
            "effective config: ch_host=%s ch_pass=%s ch_enabled=%s read_max_s=%s "
            "logs_max_window_min=%s read_concurrency=%s cors=%s max_body_mb=%s "
            "admin_token=%s demo_mode=%s migrations_on_start=%s",
            self.clickhouse_host, _redact(self.clickhouse_pass), self.clickhouse_enabled,
            self.read_max_seconds, self.logs_max_window_min, self.read_concurrency,
            self.cors_origins, self.max_body_mb, _redact(self.admin_token),
            self.demo_mode, self.run_migrations_on_start,
        )


settings = Settings()


# ── Middleware ────────────────────────────────────────────────────────────────

class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request-id, times the request, emits one structured access line,
    and returns the id in X-Request-ID so a bug report maps to logs instantly."""
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        token = request_id_ctx.set(rid)
        request.state.request_id = rid
        t0 = time.perf_counter()
        status = 500
        try:
            resp = await call_next(request)
            status = resp.status_code
            return resp
        finally:
            dur_ms = round((time.perf_counter() - t0) * 1000, 1)
            # one line per request — JSON-ish, greppable, no secrets
            logger.info(
                'access rid=%s method=%s path=%s status=%s dur_ms=%s',
                rid, request.method, request.url.path, status, dur_ms,
            )
            try:
                resp.headers["X-Request-ID"] = rid  # type: ignore
            except Exception:
                pass
            request_id_ctx.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers a vendor review checks for."""
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-XSS-Protection", "0")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies early (Content-Length based). Default cap
    sits above the legitimate CSV/topology upload limit so uploads still work."""
    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse(status_code=413, content={
                "error": "request body too large",
                "code": "body_too_large",
                "request_id": getattr(request.state, "request_id", "-"),
            })
        return await call_next(request)


def cors_origins_list(raw: str) -> list:
    if raw.strip() == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


# ── Global exception handler ──────────────────────────────────────────────────

async def unhandled_exception_handler(request: Request, exc: Exception):
    """Any *unhandled* error becomes a clean JSON envelope. The full traceback
    goes to logs only — never to the client. (FastAPI's HTTPException keeps its
    own shape so existing clients that read `detail` are unaffected.)"""
    rid = getattr(request.state, "request_id", "-")
    logger.exception("unhandled error rid=%s path=%s", rid, request.url.path)
    return JSONResponse(status_code=500, content={
        "error": "internal error", "code": "internal_error", "request_id": rid,
    })


def install(app, *, osc=None, migrations_current=None):
    """Wire all hardening into the app. Safe to call once at import/startup.

    osc: the clickhouse client module (for readiness checks).
    migrations_current: optional callable -> bool for /health/ready.
    """
    problems = settings.validate()
    if problems:
        for p in problems:
            logger.error("CONFIG ERROR: %s", p)
        raise RuntimeError("invalid configuration: " + "; ".join(problems))
    settings.log_effective()

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_mb * 1024 * 1024)
    app.add_middleware(RequestContextMiddleware)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # ── Health, three depths ──────────────────────────────────────────────────
    @app.get("/health/ready", tags=["health"])
    async def health_ready():
        """Readiness: store reachable AND (if provided) migrations current."""
        store_ok = False
        if osc is not None:
            try:
                store_ok = bool(osc.get_client())
            except Exception:
                store_ok = False
        mig_ok = True
        if migrations_current is not None:
            try:
                mig_ok = bool(migrations_current())
            except Exception:
                mig_ok = False
        ready = store_ok and mig_ok
        return JSONResponse(status_code=200 if ready else 503, content={
            "ready": ready, "store": store_ok, "migrations_current": mig_ok,
        })

    @app.get("/health/detail", tags=["health"])
    async def health_detail(request: Request):
        """Deep health for the on-call engineer / pipeline strip. Auth-gated by
        CS_ADMIN_TOKEN when set (Bearer or ?token=); open in dev when unset."""
        if settings.admin_token:
            supplied = (request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                        or request.query_params.get("token", ""))
            if supplied != settings.admin_token:
                return JSONResponse(status_code=401, content={
                    "error": "admin token required", "code": "unauthorized",
                    "request_id": getattr(request.state, "request_id", "-")})
        detail = {"config": {
            "read_max_seconds": settings.read_max_seconds,
            "logs_max_window_min": settings.logs_max_window_min,
            "read_concurrency": settings.read_concurrency,
            "demo_mode": settings.demo_mode,
        }}
        # ingestion lag + newest event (partition-pruned, cheap)
        if osc is not None:
            try:
                rows = osc._q(f"SELECT max(ts) AS newest, count() AS n FROM {osc.LOGS_TABLE} "
                              "WHERE ts >= now() - INTERVAL 2 DAY")
                detail["recent_2d_events"] = int(rows[0]["n"]) if rows else 0
                detail["newest_event"] = str(rows[0]["newest"]) if rows and rows[0]["newest"] else None
            except Exception as e:
                detail["store_error"] = str(e)[:120]
        return detail

    logger.info("hardening installed: request-id, security headers, body cap %sMB, "
                "CORS=%s, error envelope, health depths",
                settings.max_body_mb, settings.cors_origins)
