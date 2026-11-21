"""
Tavily web-search connector — the out-of-scope / mitigation-techniques fallback
for SOC Query.

Privacy: this is the ONLY path that may send a question to the open web, so it is
tightly scoped. The CALLER sanitises the question via ai_safety first; this module
ADDS a hard guard that refuses anything still carrying an IPv4 (defence in depth),
caps the query length, and never forwards log rows, usernames or internal ids.
Ships dark until TAVILY_API_KEY is set, and fails soft (returns None) on any error.
"""
import logging
import os
import re

import httpx

log = logging.getLogger("web_search")

TAVILY_URL = "https://api.tavily.com/search"

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _key() -> str:
    # Read fresh so a restart (or a .env edit + restart) picks up the key.
    return os.getenv("TAVILY_API_KEY", "").strip()


def enabled() -> bool:
    return bool(_key())


async def search(query: str, max_results: int | None = None) -> dict | None:
    """Return {answer, results:[{title,url,content}]} or None when disabled, on any
    failure, or when the query still carries an IP (which must never leave the box)."""
    key = _key()
    q = (query or "").strip()
    if not key or not q:
        return None
    if _IPV4.search(q):
        log.warning("web search refused: query carries an IP address")
        return None
    k = int(max_results or int(os.getenv("TAVILY_MAX_RESULTS", "5")))
    timeout = float(os.getenv("TAVILY_TIMEOUT", "8"))
    payload = {
        "api_key": key,                 # classic auth (body)
        "query": q[:400],
        "search_depth": "basic",
        "include_answer": True,
        "max_results": k,
    }
    headers = {"Authorization": f"Bearer {key}",   # current auth (header)
               "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(TAVILY_URL, json=payload, headers=headers)
        if r.status_code != 200:
            log.warning("tavily http %s: %s", r.status_code, r.text[:160])
            return None
        data = r.json()
    except Exception as e:
        log.warning("tavily call failed: %s", e)
        return None
    results = []
    for item in (data.get("results") or [])[:k]:
        url = (item.get("url") or "").strip()
        if not url:
            continue
        results.append({"title": (item.get("title") or url)[:120],
                        "url": url, "content": (item.get("content") or "")[:500]})
    answer = (data.get("answer") or "").strip()
    if not answer and not results:
        return None
    return {"answer": answer, "results": results}
