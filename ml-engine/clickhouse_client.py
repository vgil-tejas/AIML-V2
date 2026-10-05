"""
CyberSentinel — ClickHouse store client.

Drop-in replacement for opensearch_client.py: exposes the SAME function names
and return shapes, so backend / ml-engine / ml-intern only change one import
(`import clickhouse_client as osc`).

ClickHouse is the high-volume log store (crores of rows). All log-derived
dashboard reads (stats, hot-ips, trail, per-IP counts, ML features) come from
here via SQL aggregations and the materialized-view rollups.

Synchronous helpers (safe to call from any context), matching the old client.
"""
import os
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cybersentinel.ch_client")

# ── config ─────────────────────────────────────────────────────────────────
# Accept CLICKHOUSE_ENABLED, and fall back to the legacy OPENSEARCH_ENABLED flag
# so existing compose/.env that gate "external store on" keep working.
CLICKHOUSE_ENABLED = os.getenv(
    "CLICKHOUSE_ENABLED",
    os.getenv("OPENSEARCH_ENABLED", "false"),
).lower() in ("true", "1", "yes")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))   # HTTP interface
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASS = os.getenv("CLICKHOUSE_PASS", "")
CLICKHOUSE_DB   = os.getenv("CLICKHOUSE_DB", "cybersentinel")

# Compatibility alias — some callers check OPENSEARCH_ENABLED on the module.
OPENSEARCH_ENABLED = CLICKHOUSE_ENABLED

LOGS_TABLE = f"{CLICKHOUSE_DB}.logs"
AGG_TABLE  = f"{CLICKHOUSE_DB}.agg_ip_daily"

_thread_local = threading.local()


def get_client():
    """Per-thread ClickHouse client. Each thread gets its own connection."""
    if not CLICKHOUSE_ENABLED:
        return None
    client = getattr(_thread_local, "client", None)
    if client is not None:
        return client
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASS,
            database=CLICKHOUSE_DB,
            connect_timeout=10,
            send_receive_timeout=300,
            settings={"async_insert": 1, "wait_for_async_insert": 0},
        )
        _thread_local.client = client
        return client
    except Exception as e:
        logger.warning(f"ClickHouse unavailable: {e} — running without persistent store")
        _thread_local.client = None
        return None


def _q(sql: str, params: Optional[dict] = None):
    """Run a query, return list-of-dicts (column_name -> value). [] on failure."""
    client = get_client()
    if not client:
        return []
    try:
        res = client.query(sql, parameters=params or {})
        cols = res.column_names
        return [dict(zip(cols, row)) for row in res.result_rows]
    except Exception as e:
        logger.error(f"ClickHouse query failed: {e} :: {sql[:160]}")
        _thread_local.client = None
        return []


def _iso(dt) -> str:
    """Normalise a value to an ISO-8601 string."""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt) if dt is not None else ""


def _ts_float(dt) -> float:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return 0.0


# Columns returned to callers — same shape OpenSearch _source produced.
_EVENT_COLS = (
    "ts AS `@timestamp`, src_ip, dst_ip, dst_port, threat_type, severity, "
    "rule, rule_id, rule_level, action, country, agent, mitre, username, "
    "useragent, signature, "
    "mitre_tactic, mitre_technique, rule_groups, proc_image, proc_parent, "
    "proc_cmdline, target_user, logon_type, geo_lat, geo_lon"
)


def _shape_events(rows: list[dict]) -> list[dict]:
    """Attach _ts float (baseline compat) and ensure @timestamp is a string."""
    out = []
    for src in rows:
        raw_ts = src.get("@timestamp")
        src["_ts"] = _ts_float(raw_ts)
        src["@timestamp"] = _iso(raw_ts)
        out.append(src)
    return out


# ── IP event queries ───────────────────────────────────────────────────────

def get_ip_events(ip: str, limit: int = 500, days: int = 0) -> list[dict]:
    """Events for an IP, oldest-first (for baselines / ML features)."""
    where = "src_ip = {ip:String}"
    if days > 0:
        where += " AND ts >= now() - INTERVAL {days:UInt32} DAY"
    sql = (f"SELECT {_EVENT_COLS} FROM {LOGS_TABLE} WHERE {where} "
           f"ORDER BY ts ASC LIMIT {int(min(limit, 100000))}")
    return _shape_events(_q(sql, {"ip": ip, "days": days}))


def get_ip_events_desc(ip: str, limit: int = 100, days: int = 0) -> list[dict]:
    """Events for an IP, newest-first (for trail display)."""
    where = "src_ip = {ip:String}"
    if days > 0:
        where += " AND ts >= now() - INTERVAL {days:UInt32} DAY"
    sql = (f"SELECT {_EVENT_COLS} FROM {LOGS_TABLE} WHERE {where} "
           f"ORDER BY ts DESC LIMIT {int(min(limit, 100000))}")
    return _shape_events(_q(sql, {"ip": ip, "days": days}))


def get_ip_total_count(ip: str) -> int:
    rows = _q(f"SELECT count() AS c FROM {LOGS_TABLE} WHERE src_ip = {{ip:String}}",
              {"ip": ip})
    return int(rows[0]["c"]) if rows else 0


def get_ip_first_last_seen(ip: str) -> tuple[Optional[str], Optional[str]]:
    rows = _q(f"SELECT min(ts) AS first, max(ts) AS last FROM {LOGS_TABLE} "
              f"WHERE src_ip = {{ip:String}}", {"ip": ip})
    if not rows or not rows[0].get("first"):
        return None, None
    return _iso(rows[0]["first"]), _iso(rows[0]["last"])


def get_ip_threat_counts(ip: str) -> dict:
    rows = _q(f"SELECT threat_type, count() AS c FROM {LOGS_TABLE} "
              f"WHERE src_ip = {{ip:String}} GROUP BY threat_type "
              f"ORDER BY c DESC LIMIT 50", {"ip": ip})
    return {r["threat_type"]: int(r["c"]) for r in rows}


def get_ip_severity_counts(ip: str) -> dict:
    rows = _q(f"SELECT severity, count() AS c FROM {LOGS_TABLE} "
              f"WHERE src_ip = {{ip:String}} GROUP BY severity", {"ip": ip})
    return {r["severity"]: int(r["c"]) for r in rows}


# ── all-IP queries (served from the rollup table when possible) ────────────

def get_all_unique_ips(size: int = 10000) -> list[str]:
    rows = _q(f"SELECT src_ip, sum(events) AS c FROM {AGG_TABLE} "
              f"GROUP BY src_ip ORDER BY c DESC LIMIT {int(size)}")
    return [r["src_ip"] for r in rows]


def get_unique_ip_count() -> int:
    rows = _q(f"SELECT uniqExact(src_ip) AS c FROM {AGG_TABLE}")
    return int(rows[0]["c"]) if rows else 0


def get_hot_ips_from_os(size: int = 100) -> list[str]:
    """IPs with any critical/high severity events (for hot-ip lists)."""
    rows = _q(f"SELECT src_ip, sum(events) AS c FROM {AGG_TABLE} "
              f"WHERE severity IN ('critical','high') "
              f"GROUP BY src_ip ORDER BY c DESC LIMIT {int(size)}")
    return [r["src_ip"] for r in rows]


def get_global_threat_counts() -> dict:
    rows = _q(f"SELECT threat_type, sum(events) AS c FROM {AGG_TABLE} "
              f"GROUP BY threat_type ORDER BY c DESC LIMIT 50")
    return {r["threat_type"]: int(r["c"]) for r in rows}


def get_global_severity_counts() -> dict:
    rows = _q(f"SELECT severity, sum(events) AS c FROM {AGG_TABLE} GROUP BY severity")
    return {r["severity"]: int(r["c"]) for r in rows}


def get_total_doc_count() -> int:
    """Fast row count via system.parts metadata — no full table scan."""
    rows = _q(
        "SELECT sum(rows) AS c FROM system.parts "
        "WHERE database = {db:String} AND table = 'logs' AND active",
        {"db": CLICKHOUSE_DB},
    )
    return int(rows[0]["c"]) if rows else 0


def search_ips_by_prefix(prefix: str, limit: int = 20) -> list[str]:
    rows = _q(f"SELECT src_ip, sum(events) AS c FROM {AGG_TABLE} "
              f"WHERE startsWith(src_ip, {{p:String}}) "
              f"GROUP BY src_ip ORDER BY c DESC LIMIT {int(limit)}", {"p": prefix})
    return [r["src_ip"] for r in rows]


def get_index_stats() -> dict:
    """Row counts + on-disk size for the logs table (mirrors osc.get_index_stats)."""
    client = get_client()
    if not client:
        return {"status": "disabled"}
    try:
        rows = _q(
            "SELECT count() AS docs, "
            "formatReadableSize(sum(bytes_on_disk)) AS size, "
            "count(DISTINCT partition) AS parts "
            "FROM system.parts "
            "WHERE database = {db:String} AND table = 'logs' AND active",
            {"db": CLICKHOUSE_DB},
        )
        info = rows[0] if rows else {"docs": 0, "size": "0", "parts": 0}
        return {
            "status":     "connected",
            "total_docs": int(info.get("docs", 0) or 0),
            "indices": [{
                "index":  LOGS_TABLE,
                "docs":   int(info.get("docs", 0) or 0),
                "size":   info.get("size", "?"),
                "health": "green",
                "status": "open",
            }],
            "write_alias":   LOGS_TABLE,
            "alias_targets": [LOGS_TABLE],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def get_recent_logs(minutes: int = 0, start: str = "", end: str = "",
                    severities=None, min_level: int = 0, limit: int = 500) -> list[dict]:
    """Recent raw logs with optional time-range / severity / level filters.
    minutes>0 -> last N minutes; or start/end are datetime strings (UI datetime-local)."""
    where = []
    params: dict = {}
    if minutes and minutes > 0:
        where.append("ts >= now() - INTERVAL {mins:UInt32} MINUTE")
        params["mins"] = int(minutes)
    if start:
        where.append("ts >= parseDateTimeBestEffortOrNull({start:String})")
        params["start"] = start
    if end:
        where.append("ts <= parseDateTimeBestEffortOrNull({end:String})")
        params["end"] = end
    if severities:
        where.append("severity IN {sevs:Array(String)}")
        params["sevs"] = list(severities)
    if min_level and min_level > 0:
        where.append("rule_level >= {lvl:UInt16}")
        params["lvl"] = int(min_level)
    wc = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (f"SELECT {_EVENT_COLS} FROM {LOGS_TABLE}{wc} "
           f"ORDER BY ts DESC LIMIT {int(min(limit, 5000))}")
    return _shape_events(_q(sql, params))


# ── ingestion (used by backend CSV/manual ingest; watcher inserts directly) ─

INSERT_COLS = [
    "ts", "ingested_at", "src_ip", "dst_ip", "dst_port", "threat_type",
    "severity", "rule", "rule_id", "rule_level", "action", "country",
    "agent", "mitre", "username", "useragent", "signature",
    # ── Phase 1: richer Wazuh signal ──
    "mitre_tactic", "mitre_technique", "rule_groups", "rule_firedtimes",
    "pci_dss", "gdpr", "hipaa", "nist",
    "proc_image", "proc_parent", "proc_cmdline", "logon_type", "target_user",
    "sc_path", "sc_event", "sc_sha256", "geo_lat", "geo_lon",
    "decoder", "location", "full_log", "raw",
]


def insert_logs(rows: list[list]) -> int:
    """Bulk insert pre-ordered rows (matching INSERT_COLS). Returns count, 0 on fail."""
    client = get_client()
    if not client or not rows:
        return 0
    try:
        client.insert(LOGS_TABLE, rows, column_names=INSERT_COLS)
        return len(rows)
    except Exception as e:
        logger.error(f"ClickHouse insert failed ({len(rows)} rows): {e}")
        return 0


# ── STATE STORE (replaces Redis): baselines / deviations / blocklist ───────

BASELINES_TABLE  = f"{CLICKHOUSE_DB}.baselines"
DEVIATIONS_TABLE = f"{CLICKHOUSE_DB}.deviations"
BLOCKLIST_TABLE  = f"{CLICKHOUSE_DB}.blocklist"
ML_SCORES_TABLE  = f"{CLICKHOUSE_DB}.ml_scores"

_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


def save_baseline(ip: str, data: dict) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(BASELINES_TABLE, [[ip, _now(), json.dumps(data)]],
                      column_names=["ip", "built_at", "data"])
        return True
    except Exception as e:
        logger.error(f"save_baseline({ip}) failed: {e}")
        return False


def get_baseline(ip: str) -> Optional[dict]:
    rows = _q(f"SELECT data FROM {BASELINES_TABLE} WHERE ip = {{ip:String}} "
              f"ORDER BY built_at DESC LIMIT 1", {"ip": ip})
    if not rows:
        return None
    try:
        return json.loads(rows[0]["data"])
    except Exception:
        return None


def get_all_baseline_ips() -> list[str]:
    rows = _q(f"SELECT DISTINCT ip FROM {BASELINES_TABLE}")
    return [r["ip"] for r in rows]


def count_baselines() -> int:
    rows = _q(f"SELECT uniqExact(ip) AS c FROM {BASELINES_TABLE}")
    return int(rows[0]["c"]) if rows else 0


def save_deviations(ip: str, alerts: list[dict]) -> bool:
    """alerts: list of {type, severity, message, details}."""
    client = get_client()
    if not client or not alerts:
        return False
    try:
        ts = _now()
        rows = [[ip, a.get("type", "unknown"), a.get("severity", "low"),
                 str(a.get("message", ""))[:1000], json.dumps(a.get("details", {})), ts]
                for a in alerts]
        client.insert(DEVIATIONS_TABLE, rows,
                      column_names=["ip", "type", "severity", "message", "details", "ts"])
        return True
    except Exception as e:
        logger.error(f"save_deviations({ip}) failed: {e}")
        return False


def get_deviations(severity: Optional[str] = None, limit: int = 500) -> list[dict]:
    where = "WHERE severity = {sev:String}" if severity else ""
    rows = _q(f"SELECT ip, type, severity, message, details, ts FROM {DEVIATIONS_TABLE} FINAL "
              f"{where} ORDER BY ts DESC LIMIT {int(min(limit, 5000))}",
              {"sev": severity} if severity else {})
    out = []
    for r in rows:
        try:
            r["details"] = json.loads(r.get("details") or "{}")
        except Exception:
            r["details"] = {}
        r["ts"] = _iso(r.get("ts"))
        out.append(r)
    return out


def get_deviation_total() -> int:
    rows = _q(f"SELECT count() AS c FROM {DEVIATIONS_TABLE} FINAL")
    return int(rows[0]["c"]) if rows else 0


def get_alert_counts(ip: str) -> tuple[int, int]:
    """(baseline_alerts, critical_alerts) for an IP — used by ml feature vectors."""
    rows = _q(f"SELECT count() AS total, countIf(severity = 'critical') AS crit "
              f"FROM {DEVIATIONS_TABLE} FINAL WHERE ip = {{ip:String}}", {"ip": ip})
    if not rows:
        return 0, 0
    return int(rows[0]["total"]), int(rows[0]["crit"])


def get_critical_ips() -> list[str]:
    rows = _q(f"SELECT DISTINCT ip FROM {DEVIATIONS_TABLE} FINAL WHERE severity = 'critical'")
    return [r["ip"] for r in rows]


def get_alert_type_counts() -> dict:
    rows = _q(f"SELECT type, count() AS c FROM {DEVIATIONS_TABLE} FINAL GROUP BY type")
    return {r["type"]: int(r["c"]) for r in rows}


def block_ip(ip: str, kind: str = "manual") -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(BLOCKLIST_TABLE, [[ip, kind, 1, _now()]],
                      column_names=["ip", "kind", "active", "added_at"])
        return True
    except Exception as e:
        logger.error(f"block_ip({ip}) failed: {e}")
        return False


def unblock_ip(ip: str) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(BLOCKLIST_TABLE, [[ip, "manual", 0, _now()]],
                      column_names=["ip", "kind", "active", "added_at"])
        return True
    except Exception:
        return False


def get_blocklist() -> dict:
    """Return {'auto': [...], 'manual': [...]} of currently-active blocks."""
    rows = _q(f"SELECT ip, argMax(kind, added_at) AS kind, argMax(active, added_at) AS active "
              f"FROM {BLOCKLIST_TABLE} GROUP BY ip HAVING active = 1")
    out = {"auto": [], "manual": []}
    for r in rows:
        out.get(r.get("kind"), out["manual"]).append(r["ip"])
    return out


def is_blocked(ip: str) -> bool:
    rows = _q(f"SELECT argMax(active, added_at) AS active FROM {BLOCKLIST_TABLE} "
              f"WHERE ip = {{ip:String}} GROUP BY ip", {"ip": ip})
    return bool(rows and int(rows[0]["active"]) == 1)


# ── ML score store (replaces Redis ml:score:* keys) ────────────────────────

def save_ml_score(ip: str, risk_score: int, anomaly_score: float,
                  is_anomaly: bool, components: Optional[dict] = None) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(
            ML_SCORES_TABLE,
            [[ip, int(risk_score), float(anomaly_score), 1 if is_anomaly else 0,
              json.dumps(components or {}), _now()]],
            column_names=["ip", "risk_score", "anomaly_score", "is_anomaly", "components", "scored_at"],
        )
        return True
    except Exception as e:
        logger.error(f"save_ml_score({ip}) failed: {e}")
        return False


def _shape_ml_row(r: dict) -> dict:
    try:
        comp = json.loads(r.get("components") or "{}")
    except Exception:
        comp = {}
    return {
        "ip":            r["ip"],
        "risk_score":    int(r.get("risk_score", 0)),
        "anomaly_score": float(r.get("anomaly_score", 0.0)),
        "is_anomaly":    bool(int(r.get("is_anomaly", 0))),
        "components":    comp,
        "scored_at":     _iso(r.get("scored_at")),
    }


def get_ml_score(ip: str) -> Optional[dict]:
    rows = _q(f"SELECT ip, risk_score, anomaly_score, is_anomaly, components, scored_at "
              f"FROM {ML_SCORES_TABLE} FINAL WHERE ip = {{ip:String}} LIMIT 1", {"ip": ip})
    return _shape_ml_row(rows[0]) if rows else None


def get_all_ml_scores(limit: int = 10000) -> list[dict]:
    rows = _q(f"SELECT ip, risk_score, anomaly_score, is_anomaly, components, scored_at "
              f"FROM {ML_SCORES_TABLE} FINAL ORDER BY risk_score DESC LIMIT {int(limit)}")
    return [_shape_ml_row(r) for r in rows]


def get_ml_anomalies(limit: int = 500) -> list[dict]:
    rows = _q(f"SELECT ip, risk_score, anomaly_score, is_anomaly, components, scored_at "
              f"FROM {ML_SCORES_TABLE} FINAL WHERE is_anomaly = 1 "
              f"ORDER BY risk_score DESC LIMIT {int(limit)}")
    return [_shape_ml_row(r) for r in rows]


def count_ml_scores() -> int:
    rows = _q(f"SELECT count() AS c FROM {ML_SCORES_TABLE} FINAL")
    return int(rows[0]["c"]) if rows else 0


def count_ml_anomalies() -> int:
    """Real number of flagged anomalies (is_anomaly=1) — the honest total behind
    the capped anomalies list, so the UI shows the true count, not the 500 cap."""
    rows = _q(f"SELECT count() AS c FROM {ML_SCORES_TABLE} FINAL WHERE is_anomaly = 1")
    return int(rows[0]["c"]) if rows else 0


# ── ML feature extraction (identical logic to the OpenSearch client) ───────

FEATURE_COLS = [
    "n_events", "event_rate_pm", "avg_interval_s", "min_interval_s",
    "std_interval_s", "unique_dst_ips", "unique_dst_ports", "unique_countries",
    "pct_critical", "pct_high", "brute_force_cnt", "ssh_bf_cnt",
    "rdp_cnt", "db_scan_cnt", "known_bad_cnt", "priv_esc_cnt",
    "vpn_bf_cnt", "baseline_alerts", "critical_alerts",
]


def extract_features_from_events(ip: str, events: list[dict]) -> dict:
    if not events:
        return {}
    import numpy as np

    timestamps = sorted(e.get("_ts", 0.0) for e in events)
    n = len(events)
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    threat_counts: dict = {}
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    dst_ips: set = set()
    dst_ports: set = set()
    countries: set = set()

    for e in events:
        tt = e.get("threat_type", "unknown")
        threat_counts[tt] = threat_counts.get(tt, 0) + 1
        sev = e.get("severity", "low")
        if sev in severities:
            severities[sev] += 1
        dip = str(e.get("dst_ip", "")).strip()
        if dip and dip not in ("", "None", "nan"):
            dst_ips.add(dip)
        dp = str(e.get("dst_port", "")).strip()
        if dp and dp not in ("", "None", "nan"):
            dst_ports.add(dp)
        c = str(e.get("country", "")).strip()
        if c and c not in ("", "None", "nan"):
            countries.add(c)

    window_seconds = (max(timestamps) - min(timestamps)) + 1
    event_rate = n / window_seconds * 60

    return {
        "ip":               ip,
        "n_events":         n,
        "event_rate_pm":    round(event_rate, 3),
        "avg_interval_s":   round(float(np.mean(intervals)), 3) if intervals else 0,
        "min_interval_s":   round(float(np.min(intervals)), 3)  if intervals else 0,
        "std_interval_s":   round(float(np.std(intervals)), 3)  if intervals else 0,
        "unique_dst_ips":   len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "unique_countries": len(countries),
        "pct_critical":     round(severities["critical"] / n, 3),
        "pct_high":         round(severities["high"] / n, 3),
        "brute_force_cnt":  threat_counts.get("brute_force", 0),
        "ssh_bf_cnt":       threat_counts.get("ssh_bruteforce", 0),
        "rdp_cnt":          threat_counts.get("rdp_relay", 0),
        "db_scan_cnt":      threat_counts.get("db_scan", 0),
        "known_bad_cnt":    threat_counts.get("known_malicious", 0),
        "priv_esc_cnt":     threat_counts.get("privilege_escalation", 0),
        "vpn_bf_cnt":       threat_counts.get("vpn_bruteforce", 0),
        "baseline_alerts":  0,
        "critical_alerts":  0,
    }


def get_ip_features(ip: str, baseline_alerts: int = 0, critical_alerts: int = 0) -> dict:
    events = get_ip_events(ip, limit=2000)
    if not events:
        return {}
    f = extract_features_from_events(ip, events)
    f["baseline_alerts"] = baseline_alerts
    f["critical_alerts"]  = critical_alerts
    return f


def get_all_ip_features(alert_counts: Optional[dict] = None) -> list[dict]:
    ips = get_all_unique_ips()
    features = []
    for ip in ips:
        events = get_ip_events(ip, limit=2000)
        if not events:
            continue
        f = extract_features_from_events(ip, events)
        if not f:
            continue
        ac = (alert_counts or {}).get(ip, {})
        f["baseline_alerts"] = ac.get("baseline_alerts", 0)
        f["critical_alerts"]  = ac.get("critical_alerts", 0)
        features.append(f)
    return features


def get_all_alert_counts_batch() -> dict:
    """One query: {ip: {"baseline_alerts": N, "critical_alerts": N}} for all IPs."""
    rows = _q(
        f"SELECT ip, count() AS total, countIf(sev='critical') AS crit FROM ("
        f"  SELECT ip, argMax(severity, ts) AS sev "
        f"  FROM {DEVIATIONS_TABLE} GROUP BY ip, type"
        f") GROUP BY ip"
    )
    return {
        r["ip"]: {"baseline_alerts": int(r["total"]), "critical_alerts": int(r["crit"])}
        for r in rows
    }


def get_all_ip_features_batch(alert_counts: Optional[dict] = None) -> list[dict]:
    """All IP feature vectors in ONE aggregation query — replaces N per-IP event fetches."""
    client = get_client()
    if not client:
        return []
    try:
        sql = f"""
        SELECT
            src_ip                                                              AS ip,
            toUInt64(count())                                                   AS n_events,
            toFloat64(count()) / greatest(1.0, toFloat64(dateDiff('minute', min(ts), now()))) AS event_rate_pm,
            toFloat64(dateDiff('second', min(ts), max(ts))) / greatest(1, toInt64(count()) - 1) AS avg_interval_s,
            0.0                                                                 AS min_interval_s,
            0.0                                                                 AS std_interval_s,
            toUInt64(uniqExact(if(dst_ip='',NULL,dst_ip)))                     AS unique_dst_ips,
            toUInt64(uniqExact(if(dst_port='',NULL,dst_port)))                 AS unique_dst_ports,
            toUInt64(uniqExact(if(country='',NULL,country)))                   AS unique_countries,
            toFloat64(countIf(severity='critical')) / count()                  AS pct_critical,
            toFloat64(countIf(severity='high'))     / count()                  AS pct_high,
            toUInt64(countIf(threat_type IN ('brute_force','ssh_bruteforce','vpn_bruteforce','rdp_relay'))) AS brute_force_cnt,
            toUInt64(countIf(threat_type='ssh_bruteforce'))                    AS ssh_bf_cnt,
            toUInt64(countIf(threat_type='rdp_relay'))                         AS rdp_cnt,
            toUInt64(countIf(threat_type='db_scan'))                           AS db_scan_cnt,
            toUInt64(countIf(threat_type='known_malicious'))                   AS known_bad_cnt,
            toUInt64(countIf(threat_type='privilege_escalation'))              AS priv_esc_cnt,
            toUInt64(countIf(threat_type='vpn_bruteforce'))                    AS vpn_bf_cnt
        FROM {LOGS_TABLE}
        WHERE ts >= now() - INTERVAL 7 DAY
        GROUP BY src_ip
        HAVING n_events >= 3
        ORDER BY n_events DESC
        LIMIT 10000
        """
        res = client.query(sql)
        cols = res.column_names
        features = []
        for row in res.result_rows:
            f = dict(zip(cols, row))
            ip_val = f.get("ip", "")
            ac = (alert_counts or {}).get(ip_val, {})
            f["baseline_alerts"] = int(ac.get("baseline_alerts", 0))
            f["critical_alerts"]  = int(ac.get("critical_alerts", 0))
            for key in FEATURE_COLS:
                if key in f:
                    try:
                        f[key] = float(f[key])
                    except (TypeError, ValueError):
                        f[key] = 0.0
            features.append(f)
        return features
    except Exception as e:
        logger.error(f"get_all_ip_features_batch failed ({e}) — falling back to per-IP mode")
        return get_all_ip_features(alert_counts)
