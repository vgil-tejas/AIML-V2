"""
Optional shared cache (Redis) — a thin, fail-safe L2 on top of the in-process
caches. Purpose: when the backend runs more than one worker (or is restarted),
the expensive read payloads (overview-summary, entity-risk) are shared across
workers and survive a reload, instead of each worker recomputing.

Fail-safe by construction:
  * Disabled unless REDIS_URL is set.
  * Every call is wrapped in try/except with a short timeout, so a slow or dead
    Redis NEVER blocks or breaks a request — it just falls through to the
    in-process cache / a fresh compute.
  * Connection is retried every 15s if it isn't up yet (so starting the backend
    before Redis is ready still picks Redis up shortly after).
"""
from __future__ import annotations
import os
import json
import time
import logging

log = logging.getLogger("cache")

_client = None
_next_try = 0.0


def _conn():
    """Return a live Redis client, or None. Cheap and non-blocking."""
    global _client, _next_try
    if _client is not None:
        return _client
    if time.time() < _next_try:
        return None
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        _next_try = time.time() + 3600   # not configured — stop checking
        return None
    try:
        import redis  # imported lazily so a missing lib never breaks the app
        c = redis.Redis.from_url(url, socket_timeout=0.3, socket_connect_timeout=0.3,
                                 health_check_interval=30)
        c.ping()
        _client = c
        log.info("Redis shared cache enabled (%s)", url)
    except Exception as e:
        _next_try = time.time() + 15      # retry soon (Redis may still be starting)
        if int(_next_try) % 60 < 15:
            log.warning("Redis unavailable (%s) — in-process cache only", e)
        return None
    return _client


def enabled() -> bool:
    return _conn() is not None


def get(key: str):
    c = _conn()
    if not c:
        return None
    try:
        v = c.get(key)
        return json.loads(v) if v else None
    except Exception:
        return None


def set(key: str, value, ttl: int = 60):
    c = _conn()
    if not c:
        return
    try:
        c.set(key, json.dumps(value, default=str), ex=max(1, int(ttl)))
    except Exception:
        pass
