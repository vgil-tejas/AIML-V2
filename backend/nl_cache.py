"""
Lexical semantic cache for SOC Query — on-prem, no embeddings, no network.

A near-duplicate question returns the previous answer with ZERO Groq/Tavily call,
which directly relieves the provider rate limit on repeated / reworded questions.
"Semantic" here is lexical: token-set Jaccard over normalised words — the
privacy-safe, dependency-free stand-in for vector similarity (an external embedding
API would breach the no-egress rule; a local embedding model is too heavy for the
shared box). Everything stays in-process on the box.

Only cacheable answers are stored: conversational / product / web-reference answers
with no result rows. Never live-data (SQL) answers, never blocked answers, never a
question carrying an IP. Entries expire on a TTL. The caller additionally skips the
cache for follow-ups (conversation context) and obvious data questions.
"""
import os
import re
import threading
import time

_TOKEN = re.compile(r"[a-z0-9]+")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_STOP = frozenset((
    "the a an and or of to in on for is are be it its this that these those with as at by "
    "from into do does did what which who how i me my you your we our can could should would "
    "will please tell show give me about your the".split()))


def _enabled() -> bool:
    return os.getenv("NL_CACHE", "1").strip().lower() not in ("0", "false", "no", "off", "")


def _ttl() -> int:
    return int(os.getenv("NL_CACHE_TTL", "3600"))


def _max() -> int:
    return int(os.getenv("NL_CACHE_MAX", "500"))


def _sim() -> float:
    # 0.8 is deliberately strict: it catches exact repeats and trivial variants
    # (case, punctuation, stopwords, word order all score 1.0 on token sets) while
    # avoiding a false hit where ONE meaningful word differs (SSH vs RDP, admin vs
    # user) — serving the wrong security answer is worse than a cache miss. Lexical,
    # not embedding-semantic, so a heavily reworded question may still cost a call.
    return float(os.getenv("NL_CACHE_SIM", "0.8"))


def _toks(q: str) -> frozenset:
    return frozenset(t for t in _TOKEN.findall((q or "").lower())
                     if len(t) >= 2 and t not in _STOP)


class _E:
    __slots__ = ("toks", "q", "ans", "ts")

    def __init__(self, toks, q, ans, ts):
        self.toks = toks
        self.q = q
        self.ans = ans
        self.ts = ts


_store: list = []
_lock = threading.Lock()
_hits = 0
_misses = 0


def get(question: str):
    """Return a cached answer dict (with cached=True, cache_sim) for a near-duplicate
    question, or None. Jaccard over content tokens; needs >=2 content tokens."""
    global _hits, _misses
    if not _enabled():
        return None
    qt = _toks(question)
    if len(qt) < 2:
        _misses += 1
        return None
    now = time.time()
    ttl = _ttl()
    best, best_s = None, 0.0
    with _lock:
        live = [e for e in _store if now - e.ts < ttl]
        if len(live) != len(_store):
            _store[:] = live
        for e in _store:
            union = len(qt | e.toks)
            if not union:
                continue
            s = len(qt & e.toks) / union
            if s > best_s:
                best_s, best = s, e
    if best and best_s >= _sim():
        _hits += 1
        return {**best.ans, "cached": True, "cache_sim": round(best_s, 3)}
    _misses += 1
    return None


def put(question: str, answer: dict) -> None:
    """Store a cacheable answer. Skips live-data answers, blocked answers, and any
    question carrying an IP (an entity answer must never be served for another)."""
    if not _enabled() or not isinstance(answer, dict):
        return
    if answer.get("rows") or answer.get("row_count") or answer.get("blocked"):
        return
    if _IPV4.search(question or ""):
        return
    qt = _toks(question)
    if len(qt) < 2:
        return
    a = dict(answer)
    a.pop("cached", None)
    a.pop("cache_sim", None)
    with _lock:
        _store.append(_E(qt, (question or "")[:200], a, time.time()))
        if len(_store) > _max():
            del _store[:len(_store) - _max()]


def stats() -> dict:
    with _lock:
        n = len(_store)
    return {"enabled": _enabled(), "entries": n, "hits": _hits, "misses": _misses,
            "ttl": _ttl(), "sim": _sim(), "max": _max()}
