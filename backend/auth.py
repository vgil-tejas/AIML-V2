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
from fastapi.responses import JSONResponse, RedirectResponse

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


# ── SIEM SSO (single sign-on from the SIEM) ─────────────────────────────────
# The SIEM authenticates the operator, then redirects the browser to
#   /api/auth/sso?token=<signed JWT>
# We verify that short-lived token and, on success, mint the SAME cs_auth
# cookie a normal login would — so nginx's auth_request lets them straight in,
# no login page. A bad / absent / expired token just bounces to /login.html,
# so direct visitors still get the password prompt. SSO stays inert until
# SSO_SECRET is set, so this endpoint is safe to ship dark.
#
# Bring-up signs HS256 with a secret shared with the SIEM. The RS256/JWKS
# upgrade is a later coordinated flip (see the SSO onboarding punch-list).

_SSO_LEEWAY_S = 60                     # clock-skew grace for exp/nbf (SIEM back-dates nbf 60s)
_seen_nonces: dict[str, float] = {}    # nonce -> unix-expiry; single-use replay guard


def _sso_cfg():
    """SSO config read fresh so a restart picks up new .env values."""
    secret = os.getenv("SSO_SECRET", "").strip()
    iss    = os.getenv("SSO_ISS", "cybersentinel-siem").strip()
    aud    = os.getenv("SSO_AUD", "cybersentinel-sentinelai").strip()
    return secret, iss, aud


def _map_sso_role(role: str, access: str) -> str:
    """SIEM (role, access) -> our tier. The read-only cutoff keys on access,
    never on seniority: a senior analyst can be read-only, a junior read-write."""
    role   = (role or "").strip()
    access = (access or "").strip().lower()
    if role == "administrator":
        return "admin"
    if access == "read-only":
        return "viewer"
    return "user"


def _prune_nonces(now: float) -> None:
    for n, exp in list(_seen_nonces.items()):
        if exp < now:
            _seen_nonces.pop(n, None)


def _verify_sso_token(token: str, secret: str) -> tuple[dict | None, str]:
    """Verify a SIEM exchange token (HS256, stdlib-only). Returns (claims, "")
    on success or (None, reason) on failure. Enforces alg=HS256, signature,
    iss, aud, purpose, exp/nbf (with leeway) and single-use nonce."""
    if not token or token.count(".") != 2:
        return None, "malformed token"
    header_b64, payload_b64, sig_b64 = token.split(".")
    # 1) signature — pin the algorithm first to defeat alg-confusion / 'none'
    try:
        header = json.loads(_b64d(header_b64))
    except Exception:
        return None, "bad header"
    if header.get("alg") != "HS256":
        return None, f"unexpected alg {header.get('alg')!r}"
    expected = hmac.new(
        secret.encode("utf-8"),
        (header_b64 + "." + payload_b64).encode("ascii"),
        hashlib.sha256,
    ).digest()
    try:
        got = _b64d(sig_b64)
    except Exception:
        return None, "bad signature encoding"
    if not hmac.compare_digest(expected, got):
        return None, "signature mismatch"
    # 2) claims
    try:
        claims = json.loads(_b64d(payload_b64))
    except Exception:
        return None, "bad payload"
    _secret, want_iss, want_aud = _sso_cfg()
    if want_iss and claims.get("iss") != want_iss:
        return None, "issuer mismatch"
    aud = claims.get("aud")
    aud_ok = (aud == want_aud) or (isinstance(aud, list) and want_aud in aud)
    if want_aud and not aud_ok:
        return None, "audience mismatch"
    if claims.get("purpose") not in (None, "sso-exchange"):
        return None, "wrong purpose"
    now = time.time()
    if "exp" in claims and now > float(claims["exp"]) + _SSO_LEEWAY_S:
        return None, "token expired"
    if "nbf" in claims and now < float(claims["nbf"]) - _SSO_LEEWAY_S:
        return None, "token not yet valid"
    # 3) single-use nonce (replay guard)
    nonce = claims.get("nonce")
    if nonce:
        _prune_nonces(now)
        if nonce in _seen_nonces:
            return None, "nonce replay"
        _seen_nonces[nonce] = float(claims.get("exp", now + 120)) + _SSO_LEEWAY_S
    return claims, ""


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

    @app.get("/api/auth/sso", tags=["auth"])
    async def sso(request: Request):
        # SIEM redirects the browser here with ?token=<signed JWT>. A good token
        # mints the cs_auth cookie and sends them to the dashboard; anything else
        # falls through to the normal login page (so direct visitors still get
        # the password prompt). Inert until SSO_SECRET is configured.
        secret, _iss, _aud = _sso_cfg()
        if not secret:
            return RedirectResponse("/login.html?sso=disabled", status_code=302)
        token = request.query_params.get("token", "")
        claims, reason = _verify_sso_token(token, secret)
        if not claims:
            log.warning("SSO rejected: %s", reason)
            return RedirectResponse("/login.html?sso=failed", status_code=302)
        # Identity: prefer the human username for display; sub is the stable id.
        username = str(claims.get("username") or claims.get("sub") or "").strip()
        if not username:
            return RedirectResponse("/login.html?sso=failed", status_code=302)
        _u, _p, cookie_secret, ttl_s, _enabled = _cfg()
        role = _map_sso_role(claims.get("role", ""), claims.get("access", ""))
        session_token = _mint(username, cookie_secret, ttl_s)
        resp = RedirectResponse("/", status_code=302)
        _set_cookie(resp, session_token, ttl_s)
        log.info("SSO login ok user=%r role=%s sub=%r", username, role, claims.get("sub"))
        return resp

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
