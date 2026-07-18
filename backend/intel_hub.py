"""
CyberSentinel — pluggable threat-intel connector hub.

Design contract (one file per provider is the goal; today they're small enough
to live together — split any of them out without touching callers):

    async def lookup(ip) -> {"score": 0-100 | None, "verdict": str,
                             "evidence": str, "link": str}

Rules every connector obeys:
  * outbound-only, keyed via env, 6s hard timeout
  * NEVER raises — an intel outage must never block triage (fail-soft)
  * results cached in ClickHouse with a TTL, so rate limits are respected
  * "no key configured" is a first-class answer, shown honestly in the UI

Add a provider: write one async lookup fn + register it in CONNECTORS.
"""
import os
import json
import time
import asyncio
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("cybersentinel.intel_hub")

CACHE_TTL_HOURS = int(os.getenv("INTEL_CACHE_TTL_HOURS", "24"))

_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_KEY", ""),
    "virustotal": os.getenv("VT_KEY", os.getenv("VIRUSTOTAL_KEY", "")),
    "greynoise": os.getenv("GREYNOISE_KEY", ""),
    "otx": os.getenv("OTX_KEY", ""),
    "shodan": os.getenv("SHODAN_KEY", ""),
}


def _has_key(name: str) -> bool:
    k = _KEYS.get(name, "")
    return bool(k) and k not in ("demo", "changeme")


async def _get(url: str, headers: dict = None, params: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=6) as hc:
        r = await hc.get(url, headers=headers or {}, params=params or {})
        if r.status_code == 429:
            return {"_rate_limited": True}
        r.raise_for_status()
        return r.json()


# ── Connectors ──────────────────────────────────────────────────────────────

async def _abuseipdb(ip: str) -> dict:
    d = (await _get("https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": _KEYS["abuseipdb"], "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90})).get("data", {})
    conf = int(d.get("abuseConfidenceScore") or 0)
    return {
        "score": conf,
        "verdict": "malicious" if conf >= 75 else "suspicious" if conf >= 25 else "clean",
        "evidence": f"{d.get('totalReports', 0)} abuse reports in 90 days · "
                    f"confidence {conf}% · ISP {d.get('isp', '?')}",
        "link": f"https://www.abuseipdb.com/check/{ip}",
    }


async def _virustotal(ip: str) -> dict:
    d = (await _get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": _KEYS["virustotal"]})).get("data", {})
    st = d.get("attributes", {}).get("last_analysis_stats", {})
    mal, tot = int(st.get("malicious") or 0), sum(int(v or 0) for v in st.values()) or 1
    return {
        "score": min(100, round(mal / tot * 100 * 4)),   # 1/4 of engines = 100
        "verdict": "malicious" if mal >= 5 else "suspicious" if mal >= 1 else "clean",
        "evidence": f"{mal} of {tot} AV engines flag this address",
        "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


async def _greynoise(ip: str) -> dict:
    # GreyNoise's superpower is the opposite of the others: proving an IP is a
    # KNOWN benign internet-wide scanner, so it can be suppressed as noise.
    d = await _get(f"https://api.greynoise.io/v3/community/{ip}",
                   headers={"key": _KEYS["greynoise"]})
    noise, riot = bool(d.get("noise")), bool(d.get("riot"))
    cls = d.get("classification", "unknown")
    return {
        "score": 0 if (riot or cls == "benign") else 60 if cls == "malicious" else None,
        "verdict": "benign-scanner" if (noise and cls == "benign") or riot
                   else cls,
        "evidence": (f"{d.get('name', 'unknown actor')} — " if d.get("name") else "")
                    + ("known internet-wide scanner; safe to deprioritise"
                       if noise and cls == "benign"
                       else "business-legitimate service (RIOT)" if riot
                       else f"classification: {cls}"),
        "link": f"https://viz.greynoise.io/ip/{ip}",
    }


async def _otx(ip: str) -> dict:
    d = await _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                   headers={"X-OTX-API-KEY": _KEYS["otx"]})
    pulses = int(d.get("pulse_info", {}).get("count") or 0)
    return {
        "score": min(100, pulses * 10),
        "verdict": "malicious" if pulses >= 5 else "suspicious" if pulses >= 1 else "clean",
        "evidence": f"appears in {pulses} community threat pulses",
        "link": f"https://otx.alienvault.com/indicator/ip/{ip}",
    }


async def _shodan(ip: str) -> dict:
    d = await _get(f"https://api.shodan.io/shodan/host/{ip}",
                   params={"key": _KEYS["shodan"]})
    ports = d.get("ports") or []
    vulns = list(d.get("vulns") or [])
    return {
        "score": min(100, len(vulns) * 25 + (10 if len(ports) > 10 else 0)),
        "verdict": "exposed-vulnerable" if vulns else "exposed" if ports else "quiet",
        "evidence": f"{len(ports)} open ports"
                    + (f" · {len(vulns)} known CVEs ({', '.join(vulns[:3])}…)" if vulns else "")
                    + (f" · org {d.get('org')}" if d.get("org") else ""),
        "link": f"https://www.shodan.io/host/{ip}",
    }


async def _misp(ip: str) -> dict:
    # Roadmap stub — a real MISP connector needs the bank's MISP instance URL.
    return {"score": None, "verdict": "not-configured",
            "evidence": "MISP connector is a roadmap stub — point MISP_URL at "
                        "the bank's instance to activate", "link": ""}


CONNECTORS = {
    "abuseipdb": {"label": "AbuseIPDB", "fn": _abuseipdb, "needs_key": True},
    "virustotal": {"label": "VirusTotal", "fn": _virustotal, "needs_key": True},
    "greynoise": {"label": "GreyNoise", "fn": _greynoise, "needs_key": True},
    "otx": {"label": "AlienVault OTX", "fn": _otx, "needs_key": True},
    "shodan": {"label": "Shodan", "fn": _shodan, "needs_key": True},
    "misp": {"label": "MISP (stub)", "fn": _misp, "needs_key": False},
}


# ── ClickHouse cache ────────────────────────────────────────────────────────

def _ensure_cache(osc):
    osc._exec(f"""CREATE TABLE IF NOT EXISTS {osc.CLICKHOUSE_DB}.intel_cache (
        ip String, source LowCardinality(String), result String,
        fetched_at DateTime64(3) DEFAULT now64(3)
    ) ENGINE = ReplacingMergeTree(fetched_at) ORDER BY (ip, source)""")


def _cache_get(osc, ip: str) -> dict:
    rows = osc._q(f"""SELECT source, result FROM {osc.CLICKHOUSE_DB}.intel_cache FINAL
        WHERE ip = {{ip:String}} AND fetched_at >= now() - INTERVAL {CACHE_TTL_HOURS} HOUR""",
        {"ip": ip})
    out = {}
    for r in rows:
        try:
            out[r["source"]] = json.loads(r["result"])
        except Exception:
            pass
    return out


def _cache_put(osc, ip: str, source: str, result: dict):
    try:
        osc._insert_row(f"{osc.CLICKHOUSE_DB}.intel_cache",
                        {"ip": ip, "source": source, "result": json.dumps(result)})
    except Exception as e:
        logger.warning(f"intel cache write failed: {e}")


# ── Hub entrypoint ──────────────────────────────────────────────────────────

async def lookup_all(ip: str, osc=None, to_thread=None) -> dict:
    """Query every connector (cache-first, parallel, fail-soft)."""
    cached = {}
    if osc is not None and to_thread is not None:
        try:
            await to_thread(lambda: _ensure_cache(osc))
            cached = await to_thread(lambda: _cache_get(osc, ip))
        except Exception:
            cached = {}

    async def one(name: str, spec: dict) -> tuple:
        if name in cached:
            return name, {**cached[name], "cached": True}
        if spec["needs_key"] and not _has_key(name):
            return name, {"score": None, "verdict": "no-key",
                          "evidence": f"add {name.upper()}_KEY in .env to activate",
                          "link": "", "cached": False}
        try:
            res = await spec["fn"](ip)
            if res.get("_rate_limited"):
                return name, {"score": None, "verdict": "rate-limited",
                              "evidence": "provider rate limit hit — cached results only",
                              "link": "", "cached": False}
            res["cached"] = False
            if osc is not None and to_thread is not None:
                await to_thread(lambda: _cache_put(osc, ip, name, res))
            return name, res
        except Exception as e:
            logger.warning(f"intel connector {name} failed for {ip}: {e}")
            return name, {"score": None, "verdict": "unreachable",
                          "evidence": f"lookup failed: {type(e).__name__}",
                          "link": "", "cached": False}

    pairs = await asyncio.gather(*(one(n, s) for n, s in CONNECTORS.items()))
    results = {n: r for n, r in pairs}

    scores = [r["score"] for r in results.values() if r.get("score") is not None]
    benign_scanner = results.get("greynoise", {}).get("verdict") == "benign-scanner"
    fused = 0 if benign_scanner else (max(scores) if scores else None)
    return {
        "ip": ip,
        "sources": {n: {**r, "label": CONNECTORS[n]["label"]} for n, r in results.items()},
        "fused_score": fused,
        "benign_scanner": benign_scanner,
        "note": ("GreyNoise identifies this as a known benign scanner — intel "
                 "score suppressed to 0 to cut noise" if benign_scanner else ""),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def key_status() -> dict:
    """For the Settings page: which providers are armed (never the keys themselves)."""
    return {n: {"label": s["label"],
                "configured": (not s["needs_key"]) or _has_key(n)}
            for n, s in CONNECTORS.items()}
