"""
CyberSentinel — single-operator login gate (additive, stdlib-only).

A deliberately small authentication layer for a single-server install: ONE
operator account, a signed session cookie, and three endpoints. No database,
no extra dependency — the credential lives in the environment and the session
is a self-verifying HMAC token, so nothing needs to be stored server-side.

    AUTH_USER        the one allowed username        (default "Tejas")
    AUTH_PASS        the one allowed password         (default "tejas@123")
    AUTH_SECRET      HMAC signing key for the cookie  (default derived from
                     AUTH_PASS — set a real random value in .env for prod)
    AUTH_TTL_HOURS   how long a login stays valid     (default 12)
    AUTH_ENABLED     "false" turns the gate off        (default "true")

Endpoints (all under /api/auth so nginx can leave them open):
    POST /api/auth/login    {username,password} -> sets cookie, 200 / 401
    POST /api/auth/logout   clears the cookie
    GET  /api/auth/verify   200 if the cookie is valid, else 401
                            (this is what nginx auth_request calls)
    GET  /api/auth/me       {"user": "..."} if logged in, else 401

The real enforcement is done at nginx via auth_request -> /api/auth/verify,
so a browser with no valid cookie is bounced to the login page before it can
load the dashboard, and every /api/* data call returns 401. This module only
needs to mint and check the cookie.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time

from fastapi import Request, Response
from fastapi.responses import JSONResponse

log = logging.getLogger("cybersentinel.auth")

COOKIE_NAME = "cs_auth"


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _cfg():
    """Read config fresh each call so a container restart picks up new .env."""
    user = os.getenv("AUTH_USER", "Tejas")
    pw = os.getenv("AUTH_PASS", "tejas@123")
    # If no explicit secret is set, derive a stable one from the password so the
    # signature is still non-trivial. A real deployment should set AUTH_SECRET.
    secret = os.getenv("AUTH_SECRET") or ("cs::" + pw + "::static-fallback")
    ttl_h = float(os.getenv("AUTH_TTL_HOURS", "12") or "12")
    enabled = _env_bool("AUTH_ENABLED", "true")
    return user, pw, secret.encode("utf-8"), int(ttl_h * 3600), enabled


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def _sign(payload_b64: str, secret: bytes) -> str:
    return _b64e(hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest())


def _mint(user: str, secret: bytes, ttl_s: int) -> str:
    payload = {"u": user, "exp": int(time.time()) + ttl_s}
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return payload_b64 + "." + _sign(payload_b64, secret)


def _valid(token: str, secret: bytes) -> str | None:
    """Return the username if the token is authentic and unexpired, else None."""
    if not token or "." not in token:
        return None
    payload_b64, sig = token.rsplit(".", 1)
    expected = _sign(payload_b64, secret)
    # constant-time comparison — never leak signature match timing
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64d(payload_b64))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload.get("u")


def _current_user(request: Request) -> str | None:
    _u, _p, secret, _ttl, enabled = _cfg()
    if not enabled:
        return "anonymous"  # gate disabled -> everyone is "in"
    return _valid(request.cookies.get(COOKIE_NAME, ""), secret)


def install_auth(app) -> None:
    """Attach the four /api/auth/* endpoints to the FastAPI app."""

    @app.post("/api/auth/login", tags=["auth"])
    async def login(request: Request):
        user, pw, secret, ttl_s, enabled = _cfg()
        # Accept JSON or form-encoded bodies (login page uses JSON).
        u = p = ""
        try:
            body = await request.json()
            u = str(body.get("username", "")); p = str(body.get("password", ""))
        except Exception:
            try:
                form = await request.form()
                u = str(form.get("username", "")); p = str(form.get("password", ""))
            except Exception:
                pass
        # constant-time compare on BOTH fields so timing reveals nothing
        ok_u = hmac.compare_digest(u, user)
        ok_p = hmac.compare_digest(p, pw)
        if not (ok_u and ok_p):
            log.warning("failed login attempt for user=%r", u[:40])
            return JSONResponse({"ok": False, "error": "Invalid username or password"}, status_code=401)
        token = _mint(user, secret, ttl_s)
        resp = JSONResponse({"ok": True, "user": user})
        _set_cookie(resp, token, ttl_s)
        log.info("login ok user=%r", user)
        return resp

    @app.post("/api/auth/logout", tags=["auth"])
    async def logout():
        resp = JSONResponse({"ok": True})
        # expire the cookie immediately
        resp.set_cookie(COOKIE_NAME, "", max_age=0, httponly=True, samesite="lax", path="/")
        return resp

    @app.get("/api/auth/verify", tags=["auth"])
    async def verify(request: Request):
        # This is the endpoint nginx auth_request hits on every gated request.
        # 200 = allow, 401 = bounce to login. Keep the body tiny.
        if _current_user(request):
            return Response(status_code=200)
        return Response(status_code=401)

    @app.get("/api/auth/me", tags=["auth"])
    async def me(request: Request):
        u = _current_user(request)
        if not u:
            return JSONResponse({"authenticated": False}, status_code=401)
        return {"authenticated": True, "user": u}

    _u, _p, _s, _ttl, enabled = _cfg()
    log.info("auth gate installed (enabled=%s, user=%r, ttl=%ss)", enabled, _u, _ttl)


def _set_cookie(resp: Response, token: str, ttl_s: int) -> None:
    # HttpOnly so page scripts can't read it; SameSite=Lax to survive top-level
    # navigation while blocking cross-site sends. `secure` is opt-in via
    # AUTH_COOKIE_SECURE=true (only set it once the server is behind HTTPS,
    # otherwise the browser drops the cookie on a plain-HTTP LAN box).
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=ttl_s, httponly=True, samesite="lax", path="/",
        secure=_env_bool("AUTH_COOKIE_SECURE", "false"),
    )
