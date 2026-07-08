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
import re
import json
import hashlib
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

# Thread-local storage: each thread gets its own ClickHouse connection.
# asyncio.to_thread() spawns one thread per parallel query, so without this
# all 7 concurrent queries share one session → "concurrent queries in same session" error.
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
        _thread_local.client = None   # force reconnect on next call from this thread
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

# The blocked/contacted destination NAME (URL / domain / DNS query), so the trail
# can say "blocked facebook.com" instead of just "blocked to 31.13.93.1:443".
# New ingests fill the `url` column directly; for rows ingested before the column
# existed, we recover it from the full alert JSON we always keep in `raw`
# (data.url -> data.hostname -> data.dstname -> Sysmon DNS queryName). This whole
# expression only ever runs on the bounded, user-facing trail/logs paths — never
# on the big ML/baseline scans, which keep using the lean _EVENT_COLS above.
_URL_FALLBACK = (
    "multiIf("
    "url != '', url, "
    "JSONExtractString(raw, 'data', 'url') != '', JSONExtractString(raw, 'data', 'url'), "
    "JSONExtractString(raw, 'data', 'hostname') != '', JSONExtractString(raw, 'data', 'hostname'), "
    "JSONExtractString(raw, 'data', 'dstname') != '', JSONExtractString(raw, 'data', 'dstname'), "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'queryName') != '', "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'queryName'), "
    "'') AS url"
)
# Exact values taken verbatim from the alert.json document we keep in `raw`, so an
# analyst can tie a trail row 1:1 to their source file:
#   • alert_id = Wazuh's own document id (the alert's "id" field). Distinct from our
#     EVT-... id, which is a deterministic content hash, NOT the Wazuh id.
#   • ts_raw   = the ORIGINAL timestamp string WITH its timezone offset. We store the
#     `ts` column as UTC (the source offset is lost there); ts_raw preserves it.
# Only ever read on the bounded trail/logs/search paths (never the big ML scans).
# Cheap, universally useful: the source id + original-offset timestamp. Two JSON
# parses per row, safe to read on the logs LIST (which shows correct time + can
# tie a row to its alert.json).
_RAW_TIME = (
    "JSONExtractString(raw, 'id') AS alert_id, "
    "JSONExtractString(raw, 'timestamp') AS ts_raw"
)
# HEAVY: Sysmon process telemetry + firewall policy id (incl. a regex over
# full_log). ~13 JSON parses + a regex PER ROW. These fields are only ever
# rendered in the single-entity TRAIL event card — NEVER in the logs list — so
# this set must stay off the logs-explorer query (it was making it 30s+ slow).
_RAW_PROCESS = (
    # Sysmon / Windows process telemetry — "what the endpoint actually ran".
    # Pulled from raw so it works on every row regardless of column population.
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'image') AS proc_image_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'commandLine') AS proc_cmdline_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'parentImage') AS proc_parent_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'parentCommandLine') AS proc_parent_cmdline_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'user') AS proc_user_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'parentUser') AS proc_parent_user_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'integrityLevel') AS proc_integrity_r, "
    "JSONExtractString(raw, 'data', 'win', 'eventdata', 'hashes') AS proc_hashes_r, "
    # Firewall (Fortigate etc.) POLICY id — which policy allowed/blocked the
    # traffic. Distinct from the Wazuh rule id. Prefer the decoded data.policyid,
    # fall back to parsing `policyid=NN` out of the raw full_log. Also grab the
    # policy UUID and sub/dst category when present.
    "multiIf(JSONExtractString(raw, 'data', 'policyid') != '', JSONExtractString(raw, 'data', 'policyid'), "
    "extract(JSONExtractString(raw, 'full_log'), 'policyid=\"?([0-9]+)') != '', "
    "extract(JSONExtractString(raw, 'full_log'), 'policyid=\"?([0-9]+)'), '') AS policy_id_r, "
    "JSONExtractString(raw, 'data', 'poluuid') AS policy_uuid_r, "
    "if(JSONExtractString(raw, 'data', 'policytype') != '', JSONExtractString(raw, 'data', 'policytype'), "
    "JSONExtractString(raw, 'data', 'subtype')) AS policy_type_r"
)
# Logs-LIST column set: lean columns + resolved destination name + cheap id/time.
# No heavy process/policy extraction (the list never renders those) — keeps the
# logs explorer fast even on large real-Wazuh raw blobs.
_EVENT_COLS_LIST = _EVENT_COLS + ", " + _URL_FALLBACK + ", " + _RAW_TIME
# TRAIL column set = the list set PLUS the heavy per-event process/policy fields
# that only the single-entity trail card shows.
_EVENT_COLS_UI = _EVENT_COLS_LIST + ", " + _RAW_PROCESS


# ── Serve-layer enrichment (works on existing rows; no re-ingest needed) ──────

def _derive_log_source(ev: dict) -> str:
    """Best-effort platform/source for an event from the signals we DO have
    (rule description 100%, rule_groups, agent, action). Never returns 'unknown'."""
    hay = (str(ev.get("rule_groups", "")) + " " + str(ev.get("rule", "")) + " "
           + str(ev.get("agent", "")) + " " + str(ev.get("mitre", ""))).lower()
    if any(k in hay for k in ("firewall", "iptables", "fortigate", "palo", "asa", "ufw", "pfsense")):
        return "firewall"
    if any(k in hay for k in ("windows", "win_", "sysmon", "powershell", "eventlog", "rdp", "ntlm", "kerberos")):
        return "windows"
    if any(k in hay for k in ("macos", "osx", "darwin")):
        return "macos"
    if any(k in hay for k in ("sshd", "ssh ", "sudo", "pam", "auth.log", "syslog", "systemd", "linux", "unix", "cron")):
        return "linux"
    if any(k in hay for k in ("apache", "nginx", "http", "iis", "web", "sql_injection", "xss", "url")):
        return "web"
    if any(k in hay for k in ("vpn", "openvpn", "ipsec", "suricata", "snort", "ids", "netflow", "scan", "nmap", "recon")):
        return "network"
    # Has an allow/deny verdict but no host signal -> treat as firewall/network gear
    if str(ev.get("action", "")).strip():
        return "firewall"
    return "endpoint"


# threat_type keyword -> human label (used when threat_type is missing/'unknown')
_THREAT_LABELS = [
    ("Brute Force",            ("brute", "auth", "failed login", "invalid", "password")),
    ("Privilege Escalation",   ("privilege", "sudo", "root", "escalat")),
    ("Lateral Movement",       ("rdp", "lateral", "smb", "psexec", "remote desktop")),
    ("Web Attack",             ("web", "sql", "xss", "injection", "http")),
    ("Reconnaissance",         ("scan", "nmap", "recon", "portscan", "probe")),
    ("Malware / IOC",          ("malware", "virus", "trojan", "ransom", "ioc", "blacklist", "known_bad")),
    ("Database Activity",      ("mysql", "postgres", "mongo", "database", "mssql")),
    ("VPN Activity",           ("vpn", "openvpn", "ipsec")),
    ("Successful Login",       ("login_success", "session opened", "accepted password")),
]


def _better_threat(ev: dict) -> str:
    """A readable threat label, never a bare 'unknown'. Uses threat_type when it
    is meaningful, else derives from the rule description."""
    tt = str(ev.get("threat_type", "")).strip()
    if tt and tt.lower() != "unknown":
        return tt.replace("_", " ").title()
    hay = (str(ev.get("rule", "")) + " " + str(ev.get("rule_groups", ""))).lower()
    for label, keys in _THREAT_LABELS:
        if any(k in hay for k in keys):
            return label
    rule = str(ev.get("rule", "")).strip()
    return ("Uncategorized: " + rule[:48]) if rule else "Other Activity"


_SYNTH_AGENT = re.compile(r"^agent-\d+$", re.I)


def _is_machine_account(user: str, agent: str = "") -> bool:
    """Is this 'user' actually a machine/computer name, not a person?
    Windows/AD computer accounts end in '$' (e.g. DESKTOP-AB12$), and some
    sources leak the endpoint's own hostname into the user field. We never want
    a laptop name shown as an identity — those resolve to the Wazuh agent.name
    (the installed sensor) instead."""
    u = str(user).strip()
    if not u:
        return False
    if u.endswith("$"):                                   # AD computer account
        return True
    if agent and u.lower() == str(agent).strip().lower():  # hostname leaked as user
        return True
    return False


def _resolve_entity(ev: dict) -> dict:
    """Stable identity for an event. Priority: real user (username OR target_user)
    -> host/sensor (Wazuh agent) -> IP. IP is a LOCATION, not identity (DHCP
    reassigns it). 'agent-N' is a synthetic Wazuh agent ID — a reporting SENSOR,
    NOT a person — so it is labelled honestly and flagged has_user=False.
    Machine/computer accounts (laptop names) are NOT people: they resolve to the
    Wazuh agent.name, never shown as a user identity."""
    host = str(ev.get("agent", "")).strip()
    user = ""
    for cand in (ev.get("username"), ev.get("target_user")):
        c = str(cand or "").strip()
        if c and not _is_machine_account(c, host):
            user = c
            break
    if user:
        return {"id": f"user:{user}", "type": "user", "label": user,
                "stable": True, "has_user": True}
    if host:
        synth = bool(_SYNTH_AGENT.match(host))
        return {"id": f"host:{host}", "type": "sensor" if synth else "host",
                "label": host, "stable": True, "has_user": False,
                "note": ("Reporting Wazuh agent (endpoint sensor) - no user identity "
                         "on this event") if synth
                        else "Resolved to host; no user identity on this event"}
    ip = str(ev.get("src_ip", "")).strip()
    return {"id": f"ip:{ip}", "type": "ip", "label": ip, "stable": False,
            "has_user": False,
            "note": "IP-only identity - unreliable on DHCP ranges (lease may reassign)"}


def _event_id(ev: dict) -> str:
    """Stable, citable per-event ID so an analyst can reference an exact log.
    Derived deterministically from the event's content (the demo rows carry no
    source _id), so the same log always yields the same id across reloads."""
    basis = "|".join(str(ev.get(k, "")) for k in
                     ("@timestamp", "src_ip", "dst_ip", "dst_port", "rule_id",
                      "rule_level", "threat_type", "agent", "username", "rule"))
    return "EVT-" + hashlib.blake2b(basis.encode("utf-8", "ignore"), digest_size=6).hexdigest().upper()


def _shape_events(rows: list[dict]) -> list[dict]:
    """Attach _ts float (baseline compat), normalise @timestamp, and enrich each
    event with resolved entity, log source, a readable threat label and a stable
    citable event id."""
    out = []
    for src in rows:
        raw_ts = src.get("@timestamp")
        src["_ts"] = _ts_float(raw_ts)
        src["@timestamp"] = _iso(raw_ts)
        src["log_source"] = _derive_log_source(src)
        src["threat_label"] = _better_threat(src)
        src["entity"] = _resolve_entity(src)
        # User shown in the trail: blank out machine/computer accounts so a laptop
        # name never appears as a "User" — the resolved identity carries agent.name.
        src["user_display"] = ("" if _is_machine_account(src.get("username", ""), src.get("agent", ""))
                               else str(src.get("username", "") or ""))
        src["event_id"] = _event_id(src)
        # Process telemetry: prefer the raw-extracted value (always accurate),
        # fall back to the stored column. Only present on UI/trail queries.
        def _pick(*keys):
            for k in keys:
                v = str(src.get(k, "") or "").strip()
                if v:
                    return v
            return ""
        src["proc_image"] = _pick("proc_image_r", "proc_image")
        src["proc_cmdline"] = _pick("proc_cmdline_r", "proc_cmdline")
        src["proc_parent"] = _pick("proc_parent_r", "proc_parent")
        src["proc_parent_cmdline"] = _pick("proc_parent_cmdline_r")
        src["proc_user"] = _pick("proc_user_r")
        src["proc_parent_user"] = _pick("proc_parent_user_r")
        src["proc_integrity"] = _pick("proc_integrity_r")
        src["proc_hashes"] = _pick("proc_hashes_r")
        # Firewall policy (Fortigate etc.)
        src["policy_id"] = _pick("policy_id_r")
        src["policy_uuid"] = _pick("policy_uuid_r")
        src["policy_type"] = _pick("policy_type_r")
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
    sql = (f"SELECT {_EVENT_COLS_UI} FROM {LOGS_TABLE} WHERE {where} "
           f"ORDER BY ts DESC LIMIT {int(min(limit, 100000))}")
    return _shape_events(_q(sql, {"ip": ip, "days": days}))


# Trail by a stable identity, not just IP. username/host are far more defensible
# than src_ip (which is a DHCP location). Whitelisted columns only (no injection).
_TRAIL_COLS = {"ip": "src_ip", "username": "username", "host": "agent"}


def get_entity_events_desc(field: str, value: str, limit: int = 200) -> list[dict]:
    """Events for an entity (ip | username | host), newest-first, for the trail."""
    col = _TRAIL_COLS.get(field, "src_ip")
    sql = (f"SELECT {_EVENT_COLS_UI} FROM {LOGS_TABLE} WHERE {col} = {{v:String}} "
           f"ORDER BY ts DESC LIMIT {int(min(limit, 100000))}")
    return _shape_events(_q(sql, {"v": value}))


def get_ueba_user_profiles(days: int = 30, limit: int = 300) -> list[dict]:
    """Per-user behavioural profile: 30-day baseline vs last-24h, in ONE
    aggregation pass (bounded arrays, no raw column). This is the feeder for
    the UEBA risk engine — scoring happens in Python where it's testable."""
    sql = f"""
        SELECT username,
               countIf(ts <  now() - INTERVAL 1 DAY)                        AS ev_base,
               countIf(ts >= now() - INTERVAL 1 DAY)                        AS ev_24,
               groupUniqArrayIf(20)(agent,   ts <  now() - INTERVAL 1 DAY AND agent != '')   AS hosts_base,
               groupUniqArrayIf(20)(agent,   ts >= now() - INTERVAL 1 DAY AND agent != '')   AS hosts_24,
               groupUniqArrayIf(15)(country, ts <  now() - INTERVAL 1 DAY AND country != '') AS countries_base,
               groupUniqArrayIf(15)(country, ts >= now() - INTERVAL 1 DAY AND country != '') AS countries_24,
               groupUniqArrayIf(25)(dst_port, ts <  now() - INTERVAL 1 DAY AND dst_port != '') AS ports_base,
               groupUniqArrayIf(25)(dst_port, ts >= now() - INTERVAL 1 DAY AND dst_port != '') AS ports_24,
               groupUniqArrayIf(15)(src_ip,  ts >= now() - INTERVAL 1 DAY AND src_ip != '')  AS srcs_24,
               sumMapIf([toHour(ts)], [toUInt64(1)], ts <  now() - INTERVAL 1 DAY)           AS hours_base,
               sumMapIf([toHour(ts)], [toUInt64(1)], ts >= now() - INTERVAL 1 DAY)           AS hours_24,
               sumMapIf([toDate(ts)], [toUInt64(1)], ts >= now() - INTERVAL 7 DAY)           AS days_7,
               countIf(threat_type IN ('brute_force','ssh_bruteforce','vpn_bruteforce','rdp_relay')
                       AND ts >= now() - INTERVAL 1 DAY)                    AS fails_24,
               countIf(threat_type = 'login_success'
                       AND ts >= now() - INTERVAL 1 DAY)                    AS success_24,
               countIf(severity IN ('high','critical')
                       AND ts >= now() - INTERVAL 1 DAY)                    AS crit_24,
               max(ts)                                                      AS last_ts
        FROM {LOGS_TABLE}
        WHERE ts >= now() - INTERVAL {{days:UInt32}} DAY
          AND username != ''
          AND NOT endsWith(username, '$')
          AND lower(username) != lower(agent)
        GROUP BY username
        HAVING ev_base + ev_24 >= 5
        ORDER BY ev_24 DESC, ev_base DESC
        LIMIT {int(min(limit, 2000))}
    """
    rows = _q(sql, {"days": int(days)})
    for r in rows:
        r["last_ts"] = _iso(r.get("last_ts"))
    return rows


def get_hourly_trend(hours: int = 24) -> list[dict]:
    """Events per hour (total + blocked-severity split) from the SummingMergeTree
    rollup — a few hundred rows, never touches the raw logs table."""
    rows = _q(
        f"""
        SELECT hour,
               sum(events) AS total,
               sumIf(events, severity IN ('high','critical')) AS hot
        FROM {CLICKHOUSE_DB}.agg_threat_hourly
        WHERE hour >= now() - INTERVAL {{h:UInt32}} HOUR
        GROUP BY hour ORDER BY hour ASC
        """, {"h": int(hours)})
    return [{"hour": _iso(r["hour"]), "total": int(r["total"]), "hot": int(r["hot"])}
            for r in rows]


def get_entity_summary(field: str, value: str) -> dict:
    """count + first/last + threat/severity/log-source/IP breakdown for an entity."""
    col = _TRAIL_COLS.get(field, "src_ip")
    base = f"FROM {LOGS_TABLE} WHERE {col} = {{v:String}}"
    p = {"v": value}
    total = _q(f"SELECT count() c {base}", p)
    if not total or not int(total[0]["c"]):
        return {"found": False}
    fl = _q(f"SELECT min(ts) f, max(ts) l {base}", p)
    threats = _q(f"SELECT threat_type t, count() c {base} GROUP BY t ORDER BY c DESC LIMIT 50", p)
    sevs = _q(f"SELECT severity s, count() c {base} GROUP BY s", p)
    # distinct source IPs the identity used (the whole point of identity-based trailing)
    ips = _q(f"SELECT src_ip i, count() c {base} AND src_ip != '' GROUP BY i ORDER BY c DESC LIMIT 50", p)
    users = _q(f"SELECT username u, count() c {base} AND username != '' GROUP BY u ORDER BY c DESC LIMIT 50", p)
    return {
        "found": True,
        "total": int(total[0]["c"]),
        "first_seen": _iso(fl[0]["f"]) if fl else None,
        "last_seen": _iso(fl[0]["l"]) if fl else None,
        "threat_types": {r["t"]: int(r["c"]) for r in threats},
        "severities": {r["s"]: int(r["c"]) for r in sevs},
        "src_ips": [{"ip": r["i"], "events": int(r["c"])} for r in ips],
        "users": [{"name": r["u"], "events": int(r["c"])} for r in users],
    }


# ── Playbook recommender: feature matrix + per-log-type recurrence ──────────

def get_entity_features(entities: Optional[list] = None, limit: int = 500) -> list[dict]:
    """Per-source-IP behavioural feature row used by the feedback-trained TP
    classifier. If `entities` is given, returns features for exactly those IPs
    (training set); otherwise the busiest `limit` IPs (scoring set). One scan."""
    if entities:
        safe = ",".join("'" + str(e).replace("'", "") + "'" for e in entities if e)
        if not safe:
            return []
        where = f"WHERE src_ip IN ({safe})"
        tail = "GROUP BY entity"
    else:
        where = "WHERE src_ip != ''"
        tail = f"GROUP BY entity ORDER BY events DESC LIMIT {int(min(limit, 5000))}"
    sql = (
        f"SELECT src_ip AS entity, count() AS events, max(rule_level) AS max_lvl, "
        f"avg(rule_level) AS avg_lvl, "
        f"countIf(severity = 'critical') AS crit, countIf(severity = 'high') AS high, "
        f"uniqExact(dst_ip) AS uniq_dst, uniqExactIf(dst_port, dst_port != '') AS uniq_ports, "
        f"uniqExactIf(username, username != '') AS uniq_users, "
        f"uniqExact(country) AS uniq_countries, "
        f"arrayElement(topK(1)(threat_type), 1) AS top_threat, max(ts) AS last_seen "
        f"FROM {LOGS_TABLE} {where} {tail}"
    )
    rows = _q(sql)
    return [{
        "entity": r["entity"], "events": int(r["events"]),
        "max_lvl": int(r.get("max_lvl") or 0), "avg_lvl": float(r.get("avg_lvl") or 0),
        "crit": int(r["crit"]), "high": int(r["high"]),
        "uniq_dst": int(r["uniq_dst"]), "uniq_ports": int(r["uniq_ports"]),
        "uniq_users": int(r["uniq_users"]), "uniq_countries": int(r["uniq_countries"]),
        "top_threat": r.get("top_threat") or "unknown", "last_seen": _iso(r.get("last_seen")),
    } for r in rows]


def get_label_queue_examples(labelled_entities: Optional[list] = None,
                             window_days: int = 30, max_types: int = 40) -> dict:
    """One representative (busiest) UNLABELLED source IP per threat_type, so the
    fast-labelling queue always has an example for every recurring pattern —
    not just whichever types happen to dominate the top-N busiest IPs overall.
    Uses a window function to pick top-1-by-volume per threat_type in one scan."""
    excl = ""
    if labelled_entities:
        safe = ",".join("'" + str(e).replace("'", "") + "'" for e in labelled_entities if e)
        if safe:
            excl = f"AND src_ip NOT IN ({safe})"
    sql = (
        "SELECT threat_type, entity, events, max_lvl, crit, uniq_dst FROM ("
        "  SELECT threat_type, src_ip AS entity, count() AS events, "
        "         max(rule_level) AS max_lvl, countIf(severity = 'critical') AS crit, "
        "         uniqExact(dst_ip) AS uniq_dst, "
        "         row_number() OVER (PARTITION BY threat_type ORDER BY count() DESC) AS rn "
        f"  FROM {LOGS_TABLE} "
        f"  WHERE threat_type != '' AND src_ip != '' {excl} "
        f"  AND ts >= now() - INTERVAL {int(window_days)} DAY "
        "   GROUP BY threat_type, src_ip"
        f") WHERE rn = 1 LIMIT {int(min(max_types, 200))}"
    )
    rows = _q(sql)
    return {r["threat_type"]: {
        "entity": r["entity"], "events": int(r["events"]), "max_lvl": int(r.get("max_lvl") or 0),
        "crit": int(r["crit"]), "uniq_dst": int(r["uniq_dst"]),
    } for r in rows}


def get_threat_type_recurrence(window_days: int = 30) -> list[dict]:
    """Per log type (threat_type): how much it recurs and how severe — the raw
    recurrence signal the recommender ranks. One scan over recent logs."""
    sql = (
        f"SELECT threat_type, count() AS events, uniqExact(src_ip) AS ips, "
        f"max(rule_level) AS max_lvl, "
        f"countIf(severity IN ('high','critical')) AS hi, "
        f"countIf(severity = 'critical') AS crit, "
        f"toUInt32(dateDiff('day', min(ts), max(ts)) + 1) AS span_days, "
        f"min(ts) AS first_seen, max(ts) AS last_seen "
        f"FROM {LOGS_TABLE} WHERE ts >= now() - INTERVAL {int(window_days)} DAY "
        f"AND threat_type != '' GROUP BY threat_type ORDER BY events DESC"
    )
    rows = _q(sql)
    return [{
        "threat_type": r["threat_type"], "events": int(r["events"]),
        "ips": int(r["ips"]), "max_lvl": int(r.get("max_lvl") or 0),
        "hi": int(r["hi"]), "crit": int(r["crit"]),
        "span_days": int(r.get("span_days") or 1),
        "first_seen": _iso(r.get("first_seen")), "last_seen": _iso(r.get("last_seen")),
    } for r in rows]


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


def get_ip_reputation_features(ip: str) -> dict:
    """One-scan behavioural feature vector for an IP, computed entirely from our
    own ClickHouse history. No external API — works fully air-gapped. Feeds the
    deterministic in-house reputation score (see main._score_ip_reputation)."""
    rows = _q(
        f"SELECT "
        f"  count() AS total, "
        f"  countIf(severity = 'critical') AS crit, "
        f"  countIf(severity = 'high')     AS high, "
        f"  countIf(severity = 'medium')   AS med, "
        f"  countIf(severity = 'low')      AS low, "
        f"  max(rule_level)                AS max_level, "
        f"  uniqExact(dst_port)            AS uniq_ports, "
        f"  uniqExact(dst_ip)              AS uniq_dsts, "
        f"  uniqExact(country)             AS uniq_countries, "
        f"  uniqExactIf(username, username != '') AS uniq_users, "
        f"  min(ts) AS first_seen, max(ts) AS last_seen "
        f"FROM {LOGS_TABLE} WHERE src_ip = {{ip:String}}",
        {"ip": ip},
    )
    if not rows or int(rows[0].get("total") or 0) == 0:
        return {"total": 0}
    r = rows[0]
    # Top threat types for the human-readable factor list.
    tt = _q(f"SELECT threat_type, count() AS c FROM {LOGS_TABLE} "
            f"WHERE src_ip = {{ip:String}} AND threat_type != '' "
            f"GROUP BY threat_type ORDER BY c DESC LIMIT 5", {"ip": ip})
    return {
        "total":          int(r.get("total") or 0),
        "crit":           int(r.get("crit") or 0),
        "high":           int(r.get("high") or 0),
        "med":            int(r.get("med") or 0),
        "low":            int(r.get("low") or 0),
        "max_level":      int(r.get("max_level") or 0),
        "uniq_ports":     int(r.get("uniq_ports") or 0),
        "uniq_dsts":      int(r.get("uniq_dsts") or 0),
        "uniq_countries": int(r.get("uniq_countries") or 0),
        "uniq_users":     int(r.get("uniq_users") or 0),
        "first_seen":     _iso(r.get("first_seen")),
        "last_seen":      _iso(r.get("last_seen")),
        "top_threats":    [{"type": t["threat_type"], "count": int(t["c"])} for t in tt],
    }


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


def get_hot_ip_summaries(size: int = 30) -> list[dict]:
    """Get hot IPs + their threat/severity breakdown in ONE query.
    Replaces N×4 per-IP ClickHouse queries with a single aggregated scan.
    Uses agg_ip_daily (materialized view) — tiny row count, very fast."""
    # Step 1: identify hot IPs by critical/high event count
    hot_rows = _q(
        f"SELECT src_ip, sum(events) AS total FROM {AGG_TABLE} "
        f"WHERE severity IN ('critical','high') "
        f"GROUP BY src_ip ORDER BY total DESC LIMIT {int(size)}"
    )
    if not hot_rows:
        return []
    hot_ips = [r["src_ip"] for r in hot_rows]
    ip_totals = {r["src_ip"]: int(r["total"]) for r in hot_rows}

    # Step 2: one batch query for all stats — threat/severity breakdown + first/last seen
    placeholders = ",".join(f"'{ip}'" for ip in hot_ips)
    detail_rows = _q(
        f"SELECT src_ip, threat_type, severity, sum(events) AS cnt "
        f"FROM {AGG_TABLE} WHERE src_ip IN ({placeholders}) "
        f"GROUP BY src_ip, threat_type, severity"
    )
    # Also get first/last seen in one query from the raw logs (partitioned, fast with src_ip filter)
    time_rows = _q(
        f"SELECT src_ip, min(ts) AS first_seen, max(ts) AS last_seen "
        f"FROM cybersentinel.logs WHERE src_ip IN ({placeholders}) "
        f"GROUP BY src_ip"
    )
    time_map = {r["src_ip"]: (_iso(r["first_seen"]), _iso(r["last_seen"])) for r in time_rows}

    # Identities behind each hot IP (users + hosts). IP is a LOCATION, not identity
    # (DHCP reassigns it) -- so an analyst must see WHO/WHAT was on that IP.
    # Fast: src_ip is the table's leading ORDER BY key.
    # Pull username AND target_user as real users; agent is the reporting host/sensor.
    ident_map: dict[str, dict] = {}
    try:
        ident_rows = _q(
            f"SELECT src_ip, username, target_user, agent, count() AS cnt "
            f"FROM cybersentinel.logs WHERE src_ip IN ({placeholders}) "
            f"AND (username != '' OR target_user != '' OR agent != '') "
            f"GROUP BY src_ip, username, target_user, agent ORDER BY cnt DESC"
        )
        for r in ident_rows:
            m = ident_map.setdefault(r["src_ip"], {"users": {}, "hosts": {}})
            h, c = (r.get("agent") or "").strip(), int(r["cnt"])
            u = ""
            for cand in (r.get("username"), r.get("target_user")):
                cc = (cand or "").strip()
                if cc and not _is_machine_account(cc, h):
                    u = cc
                    break
            if u:
                m["users"][u] = m["users"].get(u, 0) + c
            if h:
                m["hosts"][h] = m["hosts"].get(h, 0) + c
    except Exception:
        pass

    # Aggregate in Python
    by_ip: dict[str, dict] = {}
    for r in detail_rows:
        ip = r["src_ip"]
        if ip not in by_ip:
            by_ip[ip] = {"ip": ip, "found": True, "total": ip_totals.get(ip, 0),
                         "threat_types": {}, "severities": {}, "source": "clickhouse"}
        by_ip[ip]["threat_types"][r["threat_type"]] = by_ip[ip]["threat_types"].get(r["threat_type"], 0) + int(r["cnt"])
        by_ip[ip]["severities"][r["severity"]] = by_ip[ip]["severities"].get(r["severity"], 0) + int(r["cnt"])

    results = []
    for ip in hot_ips:
        s = by_ip.get(ip, {"ip": ip, "found": True, "total": ip_totals.get(ip, 0),
                           "threat_types": {}, "severities": {}, "source": "clickhouse"})
        first, last = time_map.get(ip, (None, None))
        s["first_seen"] = first
        s["last_seen"] = last
        s["is_hot"] = True

        # Attach the identities (users/hosts) seen on this IP, ranked by activity.
        ident = ident_map.get(ip, {"users": {}, "hosts": {}})
        users = sorted(ident["users"].items(), key=lambda kv: kv[1], reverse=True)
        hosts = sorted(ident["hosts"].items(), key=lambda kv: kv[1], reverse=True)
        s["users"] = [{"name": u, "events": c} for u, c in users[:8]]
        s["hosts"] = [{"name": h, "events": c} for h, c in hosts[:8]]
        s["user_count"] = len(users)
        s["host_count"] = len(hosts)
        # Resolve the most likely identity: real user > host/sensor > IP. Honest
        # labels: a synthetic 'agent-N' is a reporting SENSOR (not a person), and
        # has_user=False tells the UI to show "no user on these events".
        if users:
            s["identity"] = {"label": users[0][0], "kind": "user",
                             "stable": True, "has_user": True}
        elif hosts:
            top_host = hosts[0][0]
            synth = bool(_SYNTH_AGENT.match(top_host))
            s["identity"] = {"label": top_host, "kind": "sensor" if synth else "host",
                             "stable": True, "has_user": False,
                             "note": ("Wazuh agent (endpoint sensor) - no user identity "
                                      "captured on these events") if synth
                                     else "Resolved to host; no user on these events"}
        else:
            s["identity"] = {"label": ip, "kind": "ip", "stable": False, "has_user": False,
                             "note": "no user/host on these events - IP is a location, not an identity (DHCP)"}
        results.append(s)
    return results


def get_global_threat_counts(include_unknown: bool = False) -> dict:
    # Exclude the 'unknown' bucket so "top threat" is always a real category an
    # analyst can act on (flaw #4). Pass include_unknown=True for raw totals.
    where = "" if include_unknown else "WHERE threat_type NOT IN ('unknown','')"
    rows = _q(f"SELECT threat_type, sum(events) AS c FROM {AGG_TABLE} "
              f"{where} GROUP BY threat_type ORDER BY c DESC LIMIT 50")
    return {r["threat_type"]: int(r["c"]) for r in rows}


def get_global_severity_counts() -> dict:
    rows = _q(f"SELECT severity, sum(events) AS c FROM {AGG_TABLE} GROUP BY severity")
    return {r["severity"]: int(r["c"]) for r in rows}


def get_global_mitre_counts(days: int = 90) -> dict:
    """Event counts per raw ATT&CK technique id present in the logs (the `mitre`
    field). Sparse vs threat_type, but authoritative when present."""
    rows = _q(f"SELECT mitre, count() AS c FROM {LOGS_TABLE} "
              f"WHERE mitre != '' AND ts >= now() - INTERVAL {int(days)} DAY "
              f"GROUP BY mitre ORDER BY c DESC LIMIT 200")
    out: dict = {}
    for r in rows:
        # mitre can be a comma/space list (e.g. "T1110, T1078").
        for tid in str(r["mitre"]).replace(",", " ").split():
            tid = tid.strip().upper()
            if tid:
                out[tid] = out.get(tid, 0) + int(r["c"])
    return out


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
                    severities=None, min_level: int = 0, limit: int = 500,
                    q: str = "") -> list[dict]:
    """Recent raw logs with optional time-range / severity / level / search filters.
    minutes>0 -> last N minutes; or start/end are datetime strings (UI datetime-local).
    q -> free-text search across country, src_ip, rule, threat, username, host."""
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
    q = (q or "").strip()
    if q:
        # case-insensitive substring across the fields an analyst searches by.
        where.append("(positionCaseInsensitive(country, {q:String}) > 0 "
                     "OR positionCaseInsensitive(src_ip, {q:String}) > 0 "
                     "OR positionCaseInsensitive(dst_ip, {q:String}) > 0 "
                     "OR positionCaseInsensitive(rule, {q:String}) > 0 "
                     "OR positionCaseInsensitive(threat_type, {q:String}) > 0 "
                     "OR positionCaseInsensitive(username, {q:String}) > 0 "
                     "OR positionCaseInsensitive(agent, {q:String}) > 0)")
        params["q"] = q
    wc = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (f"SELECT {_EVENT_COLS_LIST} FROM {LOGS_TABLE}{wc} "
           f"ORDER BY ts DESC LIMIT {int(min(limit, 5000))}")
    return _shape_events(_q(sql, params))


# ── entity queries (UEBA: user / host as first-class entities) ─────────────

# Whitelist of columns an entity can key on (prevents SQL injection on the col).
_ENTITY_FIELDS = {"username": "username", "agent": "agent", "target_user": "target_user"}


def get_entity_events(field: str, value: str, limit: int = 2000, days: int = 0) -> list[dict]:
    """Events for a user/host entity, oldest-first (for UEBA timelines)."""
    col = _ENTITY_FIELDS.get(field)
    if not col:
        return []
    where = f"{col} = {{v:String}}"
    if days > 0:
        where += " AND ts >= now() - INTERVAL {days:UInt32} DAY"
    sql = (f"SELECT {_EVENT_COLS} FROM {LOGS_TABLE} WHERE {where} "
           f"ORDER BY ts ASC LIMIT {int(min(limit, 100000))}")
    return _shape_events(_q(sql, {"v": value, "days": days}))


def get_top_users(limit: int = 200) -> list[str]:
    rows = _q(f"SELECT username, count() AS c FROM {LOGS_TABLE} "
              f"WHERE username != '' GROUP BY username ORDER BY c DESC LIMIT {int(limit)}")
    return [r["username"] for r in rows]


def get_top_hosts(limit: int = 200) -> list[str]:
    rows = _q(f"SELECT agent, count() AS c FROM {LOGS_TABLE} "
              f"WHERE agent != '' GROUP BY agent ORDER BY c DESC LIMIT {int(limit)}")
    return [r["agent"] for r in rows]


def get_user_countries(user: str) -> list[str]:
    rows = _q(f"SELECT DISTINCT country FROM {LOGS_TABLE} "
              f"WHERE username = {{v:String}} AND country != ''", {"v": user})
    return [r["country"] for r in rows]


def get_entity_aggregates(field: str = "username", limit: int = 500) -> list[dict]:
    """Per-entity aggregate feature rows for peer-group anomaly scoring."""
    col = _ENTITY_FIELDS.get(field, "username")
    rows = _q(
        f"SELECT {col} AS entity, count() AS events, "
        f"countIf(severity = 'critical') AS crit, "
        f"uniqExact(dst_ip) AS dsts, uniqExact(dst_port) AS ports, "
        f"uniqExact(country) AS countries, uniqExact(src_ip) AS srcs "
        f"FROM {LOGS_TABLE} WHERE {col} != '' "
        f"GROUP BY entity ORDER BY events DESC LIMIT {int(limit)}"
    )
    for r in rows:
        for k in ("events", "crit", "dsts", "ports", "countries", "srcs"):
            r[k] = int(r.get(k, 0) or 0)
    return rows


def get_recent_login_events(limit: int = 5000, days: int = 0) -> list[dict]:
    """Recent auth-related events (success + brute force) for ATO sweeps."""
    where = ("threat_type IN ('login_success','brute_force','ssh_bruteforce',"
             "'vpn_bruteforce','rdp_relay') AND username != ''")
    if days > 0:
        where += " AND ts >= now() - INTERVAL {days:UInt32} DAY"
    sql = (f"SELECT {_EVENT_COLS} FROM {LOGS_TABLE} WHERE {where} "
           f"ORDER BY ts ASC LIMIT {int(min(limit, 200000))}")
    return _shape_events(_q(sql, {"days": days}))


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


def _deviations_base_sql() -> str:
    """argMax deduplication — avoids FINAL table scan on ReplacingMergeTree."""
    return (f"SELECT ip, type, "
            f"argMax(severity, ts) AS severity, "
            f"argMax(message, ts) AS message, "
            f"argMax(details, ts) AS details, "
            f"max(ts) AS ts "
            f"FROM {DEVIATIONS_TABLE} GROUP BY ip, type")


def get_deviations(severity: Optional[str] = None, limit: int = 500,
                   ip: Optional[str] = None) -> list[dict]:
    where_parts = []
    params: dict = {}
    if ip:
        where_parts.append("ip = {ip:String}")
        params["ip"] = ip
    if severity:
        where_parts.append("severity = {sev:String}")
        params["sev"] = severity
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    # alias max_ts (not ts) to avoid ClickHouse resolving ts-alias inside argMax args
    sql = (f"SELECT ip, type, "
           f"argMax(severity, ts) AS severity, "
           f"argMax(message, ts) AS message, "
           f"argMax(details, ts) AS details, "
           f"max(ts) AS max_ts "
           f"FROM {DEVIATIONS_TABLE} {where} "
           f"GROUP BY ip, type ORDER BY max_ts DESC LIMIT {int(min(limit, 5000))}")
    rows = _q(sql, params)
    out = []
    for r in rows:
        try:
            r["details"] = json.loads(r.get("details") or "{}")
        except Exception:
            r["details"] = {}
        r["ts"] = _iso(r.pop("max_ts", None) or r.get("ts"))
        out.append(r)
    return out


def get_deviation_total() -> int:
    rows = _q(f"SELECT count() AS c FROM "
              f"(SELECT ip, type FROM {DEVIATIONS_TABLE} GROUP BY ip, type)")
    return int(rows[0]["c"]) if rows else 0


def get_alert_counts(ip: str) -> tuple[int, int]:
    """(baseline_alerts, critical_alerts) for an IP — used by ml feature vectors."""
    rows = _q(
        f"SELECT count() AS total, countIf(sev = 'critical') AS crit FROM ("
        f"SELECT argMax(severity, ts) AS sev FROM {DEVIATIONS_TABLE} "
        f"WHERE ip = {{ip:String}} GROUP BY ip, type)",
        {"ip": ip}
    )
    if not rows:
        return 0, 0
    return int(rows[0]["total"]), int(rows[0]["crit"])


def get_critical_ips() -> list[str]:
    rows = _q(
        f"SELECT ip FROM ("
        f"SELECT ip, argMax(severity, ts) AS sev FROM {DEVIATIONS_TABLE} GROUP BY ip, type"
        f") WHERE sev = 'critical' GROUP BY ip"
    )
    return [r["ip"] for r in rows]


def get_alert_type_counts() -> dict:
    rows = _q(
        f"SELECT type, count() AS c FROM ("
        f"SELECT type FROM {DEVIATIONS_TABLE} GROUP BY ip, type"
        f") GROUP BY type"
    )
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


# ── SOAR: playbook ledger / cases / tags (the "ops tool" layer) ────────────
# These tables are created on a fresh volume by 01-schema.sql, and on EXISTING
# volumes by ensure_runtime_tables() (called at backend startup) — the init SQL
# only runs once on first container init.

PLAYBOOK_RUNS_TABLE = f"{CLICKHOUSE_DB}.playbook_runs"
CASES_TABLE         = f"{CLICKHOUSE_DB}.cases"
ENTITY_TAGS_TABLE   = f"{CLICKHOUSE_DB}.entity_tags"
FEEDBACK_TABLE      = f"{CLICKHOUSE_DB}.alert_feedback"

_RUNTIME_DDL = [
    f"""CREATE TABLE IF NOT EXISTS {PLAYBOOK_RUNS_TABLE} (
        run_id       String,
        playbook_id  String,
        incident_id  String,
        entity       String,
        status       LowCardinality(String),      -- suggested|approved|done|failed
        approved_by  String DEFAULT '',
        steps        String,                       -- JSON array of step results (the ledger)
        blast_radius String DEFAULT '',            -- JSON
        created_at   DateTime64(3) DEFAULT now64(3),
        updated_at   DateTime64(3) DEFAULT now64(3)
    ) ENGINE = ReplacingMergeTree(updated_at) ORDER BY run_id""",
    f"""CREATE TABLE IF NOT EXISTS {CASES_TABLE} (
        case_id     String,
        title       String,
        incident_id String DEFAULT '',
        entity      String DEFAULT '',
        severity    LowCardinality(String) DEFAULT 'medium',
        status      LowCardinality(String) DEFAULT 'open',   -- open|investigating|closed
        assignee    String DEFAULT '',
        disposition String DEFAULT '',                        -- '' until closed: tp|fp|benign
        notes       String DEFAULT '',
        created_by  String DEFAULT '',
        created_at  DateTime64(3) DEFAULT now64(3),
        updated_at  DateTime64(3) DEFAULT now64(3)
    ) ENGINE = ReplacingMergeTree(updated_at) ORDER BY case_id""",
    f"""CREATE TABLE IF NOT EXISTS {ENTITY_TAGS_TABLE} (
        entity     String,
        tag        LowCardinality(String),
        source     String DEFAULT 'playbook',
        active     UInt8 DEFAULT 1,
        added_at   DateTime64(3) DEFAULT now64(3)
    ) ENGINE = ReplacingMergeTree(added_at) ORDER BY (entity, tag)""",
    f"""CREATE TABLE IF NOT EXISTS {FEEDBACK_TABLE} (
        entity      String DEFAULT '',
        signature   String DEFAULT '',                 -- threat_type:rule_id (kind of alert)
        disposition LowCardinality(String),             -- true_positive|false_positive|benign|escalate
        note        String DEFAULT '',
        analyst     String DEFAULT '',
        ts          DateTime64(3) DEFAULT now64(3)
    ) ENGINE = ReplacingMergeTree(ts) ORDER BY (entity, signature)""",
    # Destination NAME (blocked/contacted URL / domain / DNS query) so the trail
    # can name the target, not just its IP. Cheap metadata-only ALTER; the serve
    # layer back-fills old rows from `raw` on the fly (see _URL_FALLBACK).
    f"ALTER TABLE {LOGS_TABLE} ADD COLUMN IF NOT EXISTS url String DEFAULT ''",
]


def ensure_runtime_tables() -> bool:
    """Create SOAR/case/tag tables on existing volumes (idempotent)."""
    client = get_client()
    if not client:
        return False
    ok = True
    for ddl in _RUNTIME_DDL:
        try:
            client.command(ddl)
        except Exception as e:
            logger.error(f"ensure_runtime_tables failed: {e}")
            ok = False
    return ok


def get_blast_radius(ips: list[str]) -> dict:
    """What an action against these source IPs would touch — the entity's full
    retained footprint (hosts, users, destinations) plus a 24h recency figure.
    Shown to the analyst BEFORE they approve a containment step."""
    if not ips:
        return {"ips": 0, "hosts": 0, "users": 0, "dst_ips": 0,
                "events": 0, "events_24h": 0}
    placeholders = ",".join(f"'{ip}'" for ip in ips)
    rows = _q(
        f"SELECT uniqExact(agent) AS hosts, uniqExactIf(username, username != '') AS users, "
        f"uniqExact(dst_ip) AS dst_ips, count() AS events, "
        f"countIf(ts >= now() - INTERVAL 24 HOUR) AS events_24h "
        f"FROM {LOGS_TABLE} WHERE src_ip IN ({placeholders})"
    )
    r = rows[0] if rows else {}
    return {
        "ips":        len(ips),
        "hosts":      int(r.get("hosts") or 0),
        "users":      int(r.get("users") or 0),
        "dst_ips":    int(r.get("dst_ips") or 0),
        "events":     int(r.get("events") or 0),
        "events_24h": int(r.get("events_24h") or 0),
    }


def insert_playbook_run(run: dict) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(
            PLAYBOOK_RUNS_TABLE,
            [[run["run_id"], run["playbook_id"], run.get("incident_id", ""),
              run.get("entity", ""), run.get("status", "suggested"),
              run.get("approved_by", ""), json.dumps(run.get("steps", [])),
              json.dumps(run.get("blast_radius", {})), _now(), _now()]],
            column_names=["run_id", "playbook_id", "incident_id", "entity", "status",
                          "approved_by", "steps", "blast_radius", "created_at", "updated_at"],
        )
        return True
    except Exception as e:
        logger.error(f"insert_playbook_run failed: {e}")
        return False


def _shape_run(r: dict) -> dict:
    try:
        steps = json.loads(r.get("steps") or "[]")
    except Exception:
        steps = []
    try:
        blast = json.loads(r.get("blast_radius") or "{}")
    except Exception:
        blast = {}
    return {
        "run_id": r["run_id"], "playbook_id": r["playbook_id"],
        "incident_id": r.get("incident_id", ""), "entity": r.get("entity", ""),
        "status": r.get("status", ""), "approved_by": r.get("approved_by", ""),
        "steps": steps, "blast_radius": blast,
        "created_at": _iso(r.get("created_at")), "updated_at": _iso(r.get("updated_at")),
    }


def get_playbook_runs(incident_id: str = "", limit: int = 50) -> list[dict]:
    where = "WHERE incident_id = {iid:String} " if incident_id else ""
    rows = _q(f"SELECT * FROM {PLAYBOOK_RUNS_TABLE} FINAL {where}"
              f"ORDER BY updated_at DESC LIMIT {int(limit)}",
              {"iid": incident_id} if incident_id else None)
    return [_shape_run(r) for r in rows]


def insert_case(case: dict) -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(
            CASES_TABLE,
            [[case["case_id"], case.get("title", ""), case.get("incident_id", ""),
              case.get("entity", ""), case.get("severity", "medium"),
              case.get("status", "open"), case.get("assignee", ""),
              case.get("disposition", ""), case.get("notes", ""),
              case.get("created_by", ""), _now(), _now()]],
            column_names=["case_id", "title", "incident_id", "entity", "severity",
                          "status", "assignee", "disposition", "notes", "created_by",
                          "created_at", "updated_at"],
        )
        return True
    except Exception as e:
        logger.error(f"insert_case failed: {e}")
        return False


def tag_entity(entity: str, tag: str, source: str = "playbook") -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(ENTITY_TAGS_TABLE, [[entity, tag, source, 1, _now()]],
                      column_names=["entity", "tag", "source", "active", "added_at"])
        return True
    except Exception as e:
        logger.error(f"tag_entity failed: {e}")
        return False


def get_entity_tags(entity: str) -> list[str]:
    rows = _q(f"SELECT tag, argMax(active, added_at) AS a FROM {ENTITY_TAGS_TABLE} "
              f"WHERE entity = {{e:String}} GROUP BY tag HAVING a = 1", {"e": entity})
    return [r["tag"] for r in rows]


# ── Analyst feedback loop (TP/FP) → re-disposition ─────────────────────────
# An analyst's verdict on an entity (or a kind of alert) is remembered and
# re-applied: a future appearance of the same entity/signature inherits the
# disposition, so a confirmed false-positive never costs triage time twice.

def insert_feedback(entity: str, signature: str, disposition: str,
                    note: str = "", analyst: str = "") -> bool:
    client = get_client()
    if not client:
        return False
    try:
        client.insert(FEEDBACK_TABLE,
                      [[entity or "", signature or "", disposition, note or "", analyst or "", _now()]],
                      column_names=["entity", "signature", "disposition", "note", "analyst", "ts"])
        return True
    except Exception as e:
        logger.error(f"insert_feedback failed: {e}")
        return False


def get_entity_disposition(entity: str) -> Optional[dict]:
    """Latest analyst verdict for a specific entity, if any."""
    rows = _q(f"SELECT disposition, note, analyst, ts FROM {FEEDBACK_TABLE} FINAL "
              f"WHERE entity = {{e:String}} AND entity != '' ORDER BY ts DESC LIMIT 1", {"e": entity})
    if not rows:
        return None
    r = rows[0]
    return {"disposition": r["disposition"], "note": r.get("note", ""),
            "analyst": r.get("analyst", ""), "ts": _iso(r.get("ts"))}


def get_dispositions_map(entities: list[str]) -> dict:
    """{entity: disposition} for a batch — used to annotate the risk watch-list."""
    ents = [e for e in entities if e]
    if not ents:
        return {}
    placeholders = ",".join(f"'{e}'" for e in ents)
    rows = _q(f"SELECT entity, argMax(disposition, ts) AS disposition FROM {FEEDBACK_TABLE} "
              f"WHERE entity IN ({placeholders}) GROUP BY entity")
    return {r["entity"]: r["disposition"] for r in rows}


def get_all_feedback(limit: int = 200) -> list[dict]:
    rows = _q(f"SELECT entity, signature, disposition, note, analyst, ts FROM {FEEDBACK_TABLE} FINAL "
              f"ORDER BY ts DESC LIMIT {int(limit)}")
    return [{"entity": r["entity"], "signature": r["signature"],
             "disposition": r["disposition"], "note": r.get("note", ""),
             "analyst": r.get("analyst", ""), "ts": _iso(r.get("ts"))} for r in rows]


# ── Risk-Based Alerting (RBA): per-entity time-decayed risk ────────────────
# Every event adds severity-weighted points to its entity (IP or user); points
# decay exponentially with age (half-life), so stale risk fades and only
# entities with sustained/recent bad behaviour float to the top. This turns a
# flood of alerts into a short ranked watch-list — the alert-fatigue killer.

def get_entity_risk_ranking(dimension: str = "ip", half_life_hours: int = 72,
                            window_days: int = 30, limit: int = 50) -> list[dict]:
    col = {"ip": "src_ip", "user": "username", "host": "agent"}.get(dimension, "src_ip")
    where_ident = f"AND {col} != ''" if dimension in ("user", "host") else ""
    hl = max(1, int(half_life_hours))
    rows = _q(
        f"SELECT {col} AS entity, "
        f"  count() AS events, "
        f"  round(sum( "
        f"    multiIf(severity='critical',10, severity='high',6.5, "
        f"            severity='medium',3.5, severity='low',1, 0.5) "
        f"    * exp(-0.6931471805 * dateDiff('hour', ts, now()) / {hl}) "
        f"  ), 2) AS risk_points, "
        f"  max(rule_level) AS max_level, "
        f"  countIf(severity = 'critical') AS crit, "
        f"  uniqExact(dst_ip) AS uniq_dsts, "
        f"  max(ts) AS last_seen "
        f"FROM {LOGS_TABLE} "
        f"WHERE ts >= now() - INTERVAL {int(window_days)} DAY {where_ident} "
        f"GROUP BY {col} "
        f"ORDER BY risk_points DESC LIMIT {int(limit)}"
    )
    if not rows:
        return []
    top = max((float(r.get("risk_points") or 0) for r in rows), default=0) or 1.0
    out = []
    for r in rows:
        pts = float(r.get("risk_points") or 0)
        score = int(max(0, min(100, round(pts / top * 100))))   # relative to hottest entity
        band = ("critical" if score >= 80 else "high" if score >= 55
                else "medium" if score >= 30 else "low")
        out.append({
            "entity":      r["entity"],
            "dimension":   dimension,
            "events":      int(r.get("events") or 0),
            "risk_points": round(pts, 1),
            "score":       score,            # 0-100 relative ranking, for bars/triage
            "band":        band,
            "max_level":   int(r.get("max_level") or 0),
            "critical":    int(r.get("crit") or 0),
            "uniq_dsts":   int(r.get("uniq_dsts") or 0),
            "last_seen":   _iso(r.get("last_seen")),
        })
    return out


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
    """One query: returns {ip: {"baseline_alerts": N, "critical_alerts": N}} for all IPs."""
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
    """All IP feature vectors in ONE aggregation query — replaces N per-IP event fetches.
    Falls back to per-IP mode if the aggregation fails."""
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
