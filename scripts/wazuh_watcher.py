#!/usr/bin/env python3
"""
CyberSentinel — Wazuh alerts.json Streamer v3 (ClickHouse sink)

Tails Wazuh's alerts.json locally with byte-offset tracking and writes the
filtered alerts STRAIGHT INTO ClickHouse (no backend round-trip).

Reads alerts.json as a read-only mount — NOTHING is modified on the Wazuh side.

Production properties:
  - Batched inserts (BATCH_SIZE rows) → ClickHouse never sees tiny inserts.
  - Disk spool: if ClickHouse is down, the batch is written to a spool file and
    replayed on recovery → zero log loss across restarts/outages.
  - Offset only advances once a batch is durably stored (inserted OR spooled).

Smart filtering for high-volume logs (lakhs/hour):
  - Level 0-3:  DROP   (noise)
  - Level 4-6:  SAMPLE 1 in N
  - Level 7+:   KEEP ALL (attacks, brute force, exploits)
"""
import json
import os
import random
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── config ────────────────────────────────────────────────────────────────────

# Mount the DIRECTORY (not the file) so rotation is transparent to the container
ALERTS_DIR  = Path(os.getenv("WAZUH_ALERTS_DIR", "/wazuh/alerts"))
ALERTS_PATH = ALERTS_DIR / os.getenv("WAZUH_ALERTS_FILENAME", "alerts.json")
API_BASE = os.getenv("WAZUH_API_URL", "http://backend:8000").rstrip("/")
ML_API_BASE = os.getenv("WAZUH_ML_API_URL", "http://ml-engine:8001").rstrip("/")
OFFSET_FILE = Path(os.getenv("WAZUH_OFFSET_FILE", "/app/data/wazuh_offset.json"))
SPOOL_DIR = Path(os.getenv("WAZUH_SPOOL_DIR", "/app/data/spool"))
INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "5"))
BATCH_SIZE = int(os.getenv("WAZUH_BATCH_SIZE", "5000"))
TRAIN_THRESHOLD = int(os.getenv("WAZUH_TRAIN_THRESHOLD", "20000"))
ARCHIVE_THRESHOLD = int(os.getenv("WAZUH_ARCHIVE_THRESHOLD", "100000"))
# Minimum seconds between heavy retrain/baseline/deviation runs. On a high-volume
# feed the event threshold is crossed constantly; this cooldown stops the
# baseline-rebuild storm from pinning ClickHouse. Override via WAZUH_TRAIN_COOLDOWN.
TRAIN_COOLDOWN = int(os.getenv("WAZUH_TRAIN_COOLDOWN", "900"))

# ClickHouse
CH_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse")
CH_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CH_USER = os.getenv("CLICKHOUSE_USER", "default")
CH_PASS = os.getenv("CLICKHOUSE_PASS", "")
CH_DB   = os.getenv("CLICKHOUSE_DB", "cybersentinel")
CH_TABLE = f"{CH_DB}.logs"

# Smart filtering
MIN_LEVEL = int(os.getenv("WAZUH_MIN_LEVEL", "4"))
SAMPLE_BELOW = int(os.getenv("WAZUH_SAMPLE_BELOW", "7"))
SAMPLE_RATE = int(os.getenv("WAZUH_SAMPLE_RATE", "10"))
MAX_PER_MINUTE = int(os.getenv("WAZUH_MAX_PER_MINUTE", "0"))   # 0 = unlimited
STALE_SECONDS = int(os.getenv("WAZUH_STALE_SECONDS", "600"))
CHUNK_LINES = int(os.getenv("WAZUH_CHUNK_LINES", "50000"))

INSERT_COLS = [
    "ts", "ingested_at", "src_ip", "dst_ip", "dst_port", "threat_type",
    "severity", "rule", "rule_id", "rule_level", "action", "country",
    "agent", "mitre", "username", "useragent", "signature", "url",
    # ── Phase 1: richer Wazuh signal ──
    "mitre_tactic", "mitre_technique", "rule_groups", "rule_firedtimes",
    "pci_dss", "gdpr", "hipaa", "nist",
    "proc_image", "proc_parent", "proc_cmdline", "logon_type", "target_user",
    "sc_path", "sc_event", "sc_sha256", "geo_lat", "geo_lon",
    "decoder", "location", "full_log", "raw",
    "policy_id",   # firewall policy that matched (Fortigate data.policyid)
]

filter_stats = defaultdict(int)
minute_counter = {"count": 0, "minute": 0}


# ── ClickHouse client ──────────────────────────────────────────────────────────

_ch_client = None


def get_ch():
    """Lazy ClickHouse client. Returns None if unreachable (caller spools)."""
    global _ch_client
    if _ch_client is not None:
        return _ch_client
    try:
        import clickhouse_connect
        _ch_client = clickhouse_connect.get_client(
            host=CH_HOST, port=CH_PORT, username=CH_USER, password=CH_PASS,
            database=CH_DB, connect_timeout=10, send_receive_timeout=120,
            # Server-side batching, but WAIT for the ack so a successful insert
            # is durable — that's what lets us safely advance the read offset.
            settings={"async_insert": 1, "wait_for_async_insert": 1},
        )
        _ch_client.command("SELECT 1")
        # Idempotent migration: the watcher may start before the backend, and
        # its INSERT names policy_id explicitly - make sure the column exists.
        try:
            _ch_client.command(
                f"ALTER TABLE {CH_TABLE} ADD COLUMN IF NOT EXISTS "
                f"policy_id LowCardinality(String) DEFAULT ''")
        except Exception as mig_e:
            print(f"  ! policy_id migration skipped: {mig_e}")
        print(f"[Watcher] ClickHouse connected at {CH_HOST}:{CH_PORT}")
        return _ch_client
    except Exception as e:
        print(f"  ✗ ClickHouse connect failed: {e}")
        _ch_client = None
        return None


def ch_insert(rows: list) -> bool:
    """Insert a list of column-ordered rows. Returns True on success."""
    if not rows:
        return True
    client = get_ch()
    if not client:
        return False
    try:
        client.insert(CH_TABLE, rows, column_names=INSERT_COLS)
        return True
    except Exception as e:
        print(f"  ✗ ClickHouse insert failed ({len(rows)} rows): {e}")
        # Drop the client so the next call reconnects
        global _ch_client
        _ch_client = None
        return False


# ── disk spool (durability when ClickHouse is down) ────────────────────────────

def spool_batch(rows: list) -> bool:
    """Persist a failed batch to disk for later replay. Returns True if saved."""
    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        fname = SPOOL_DIR / f"batch_{int(time.time()*1000)}_{random.randint(1000,9999)}.json"
        # rows contain datetimes → serialise ts/ingested_at as ISO strings
        serialisable = [[_iso(c) if isinstance(c, datetime) else c for c in row] for row in rows]
        with open(fname, "w") as f:
            json.dump(serialisable, f)
        print(f"  💾 Spooled {len(rows)} rows → {fname.name} (ClickHouse unreachable)")
        return True
    except Exception as e:
        print(f"  ✗ SPOOL FAILED: {e}")
        return False


def replay_spool() -> int:
    """Try to flush spooled batches into ClickHouse. Returns rows replayed."""
    if not SPOOL_DIR.exists():
        return 0
    files = sorted(SPOOL_DIR.glob("batch_*.json"))
    if not files:
        return 0
    replayed = 0
    for fpath in files:
        try:
            with open(fpath) as f:
                rows = json.load(f)
        except Exception:
            fpath.unlink(missing_ok=True)
            continue
        # revive ts / ingested_at (cols 0,1) back into datetimes
        for row in rows:
            row[0] = _parse_ts(row[0])
            row[1] = _parse_ts(row[1])
        if ch_insert(rows):
            replayed += len(rows)
            fpath.unlink(missing_ok=True)
        else:
            break  # ClickHouse still down — stop, retry next cycle
    if replayed:
        print(f"  ♻ Replayed {replayed:,} spooled rows into ClickHouse")
    return replayed


def store_batch(rows: list) -> bool:
    """Durably store a batch: insert, else spool. True = safe to advance offset."""
    if ch_insert(rows):
        return True
    return spool_batch(rows)


# ── filtering ──────────────────────────────────────────────────────────────────

def get_rule_level(raw_alert: dict) -> int:
    rule = raw_alert.get("rule", {})
    level = rule.get("level", 0) if isinstance(rule, dict) else 0
    try:
        return int(level)
    except (ValueError, TypeError):
        return 0


def should_ingest(raw_alert: dict) -> str:
    level = get_rule_level(raw_alert)
    if level < MIN_LEVEL:
        return "drop"
    if level < SAMPLE_BELOW:
        return "sample" if random.randint(1, SAMPLE_RATE) == 1 else "drop"
    return "keep"


def check_rate_limit() -> bool:
    if MAX_PER_MINUTE <= 0:
        return True
    current_minute = int(time.time() / 60)
    if minute_counter["minute"] != current_minute:
        minute_counter["minute"] = current_minute
        minute_counter["count"] = 0
    if minute_counter["count"] >= MAX_PER_MINUTE:
        return False
    minute_counter["count"] += 1
    return True


# ── offset tracking ────────────────────────────────────────────────────────────

def load_offset() -> dict:
    if OFFSET_FILE.exists():
        try:
            with open(OFFSET_FILE) as f:
                data = json.load(f)
                print(f"[Offset] Loaded: byte_offset={data.get('byte_offset', 0):,}, "
                      f"total_ingested={data.get('total_ingested', 0):,}")
                return data
        except Exception as e:
            print(f"[Offset] Failed to load: {e}")
    return {"byte_offset": 0, "lines_read": 0, "last_run": None, "total_ingested": 0}


def save_offset(state: dict):
    try:
        OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        with open(OFFSET_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"  ✗ OFFSET SAVE FAILED: {e}")


# ── Wazuh alert → ClickHouse row mapping ───────────────────────────────────────

def flatten_wazuh(alert: dict, prefix: str = "") -> dict:
    """Flatten nested Wazuh JSON into dot-notation keys."""
    flat = {}
    for key, value in alert.items():
        full_key = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        if isinstance(value, dict):
            flat.update(flatten_wazuh(value, full_key))
        elif isinstance(value, list):
            flat[full_key] = ", ".join(str(v) for v in value) if value else ""
        else:
            flat[full_key] = value
    return flat


def _first(flat: dict, *keys) -> str:
    for k in keys:
        v = flat.get(k)
        if v not in (None, "", "None"):
            return str(v)
    return ""


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_ts(value) -> datetime:
    """Parse a Wazuh/ISO timestamp string to a naive-UTC datetime for ClickHouse."""
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        dt = None
        if s:
            txt = s.replace("Z", "+00:00")
            # Wazuh uses +0000 (no colon) — normalise to +00:00
            if len(txt) >= 5 and (txt[-5] in "+-") and txt[-3] != ":":
                txt = txt[:-2] + ":" + txt[-2:]
            try:
                dt = datetime.fromisoformat(txt)
            except Exception:
                for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        dt = datetime.strptime(s, fmt)
                        break
                    except Exception:
                        continue
        if dt is None:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


# keyword → threat_type, checked against rule.groups + description
_THREAT_RULES = [
    ("ssh_bruteforce",        ("ssh", "sshd")),
    ("vpn_bruteforce",        ("vpn", "openvpn", "ipsec")),
    ("rdp_relay",             ("rdp", "remote desktop", "terminal")),
    ("brute_force",           ("brute", "authentication_failed", "auth_failed",
                               "multiple_auth", "invalid_login", "login_denied")),
    ("privilege_escalation",  ("privilege", "sudo", "rootkit", "escalation")),
    ("db_scan",               ("mysql", "postgres", "mongodb", "database", "sql")),
    ("malware",               ("malware", "virus", "trojan", "ransom")),
    ("web_attack",            ("web", "sql_injection", "xss", "attack")),
    ("recon_scan",            ("scan", "nmap", "recon", "portscan")),
    ("known_malicious",       ("blacklist", "known_bad", "threat_intel", "ioc")),
    ("login_success",         ("authentication_success", "login_success", "session_opened",
                               "logged in successfully", "logged into firewall interface",
                               "admin login successful")),
    # Benign admin session churn (e.g. a FortiGate GUI left open re-authing every few
    # seconds). Labelling it keeps it OUT of the "unknown" bucket so the auth-volume
    # detector can see it, without treating it as a threat.
    ("admin_logout",          ("logout successful", "admin logout successful", "user logout successful")),
]


def _to_float(value) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def _to_int(value) -> int:
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


def _threat_from_alert(flat: dict) -> str:
    haystack = (_first(flat, "rule.groups") + " " +
                _first(flat, "rule.description") + " " +
                _first(flat, "rule.pci_dss")).lower()
    for ttype, keywords in _THREAT_RULES:
        if any(k in haystack for k in keywords):
            return ttype
    return "unknown"


def map_to_row(raw_alert: dict):
    """Map a raw Wazuh alert to a ClickHouse row (column order = INSERT_COLS)."""
    flat = flatten_wazuh(raw_alert)
    level = get_rule_level(raw_alert)

    src_ip = _first(flat, "data.srcip", "data.src_ip", "srcip",
                    "data.win.eventdata.ipAddress", "agent.ip")
    if not src_ip:
        return None

    ts = _parse_ts(_first(flat, "@timestamp", "timestamp") or datetime.now(timezone.utc))
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    return [
        ts,                                                          # ts
        now,                                                         # ingested_at
        src_ip,                                                      # src_ip
        _first(flat, "data.dstip", "data.dest_ip", "data.win.eventdata.destinationIp"),
        _first(flat, "data.dstport", "data.dest_port", "data.win.eventdata.destinationPort"),
        _threat_from_alert(flat),                                    # threat_type
        _severity_from_level(level),                                 # severity
        _first(flat, "rule.description")[:200],                      # rule
        _first(flat, "rule.id"),                                     # rule_id
        max(0, min(level, 255)),                                     # rule_level (UInt8)
        _first(flat, "data.action"),                                 # action
        _first(flat, "data.srccountry", "GeoLocation.country_name"), # country
        _first(flat, "agent.name"),                                  # agent
        _first(flat, "rule.mitre.id"),                               # mitre
        _first(flat, "data.user", "data.win.eventdata.user", "data.win.eventdata.targetUserName",
               "data.win.eventdata.subjectUserName", "data.dstuser", "data.srcuser",
               "data.audit.auid", "data.aws.userIdentity.userName", "data.gcp.protoPayload.authenticationInfo.principalEmail",
               "data.office365.UserId", "syscheck.uname_after"),  # username (many Wazuh sources)
        _first(flat, "data.http.http_user_agent"),                   # useragent
        _first(flat, "data.alert.signature")[:200],                  # signature
        # destination NAME the alert is about — blocked/contacted URL, domain or
        # DNS query. Covers Fortigate/proxy URL blocks, web alerts and Sysmon DNS.
        _first(flat, "data.url", "data.hostname", "data.dstname", "data.uri",
               "data.win.eventdata.queryName", "data.dns.question.name")[:512],  # url
        # ── Phase 1: richer Wazuh signal ──
        _first(flat, "rule.mitre.tactic"),                           # mitre_tactic
        _first(flat, "rule.mitre.technique"),                        # mitre_technique
        _first(flat, "rule.groups"),                                 # rule_groups
        _to_int(_first(flat, "rule.firedtimes")),                    # rule_firedtimes
        _first(flat, "rule.pci_dss"),                                # pci_dss
        _first(flat, "rule.gdpr"),                                   # gdpr
        _first(flat, "rule.hipaa"),                                  # hipaa
        _first(flat, "rule.nist_800_53"),                            # nist
        _first(flat, "data.win.eventdata.image", "data.process.name", "data.command")[:300],
        _first(flat, "data.win.eventdata.parentImage", "data.parent.name")[:300],
        _first(flat, "data.win.eventdata.commandLine", "data.win.eventdata.parentCommandLine")[:500],
        _first(flat, "data.win.eventdata.logonType"),               # logon_type
        _first(flat, "data.win.eventdata.targetUserName", "data.dstuser"),
        _first(flat, "syscheck.path"),                               # sc_path
        _first(flat, "syscheck.event"),                              # sc_event
        _first(flat, "syscheck.sha256_after", "syscheck.sha256_before"),
        _to_float(_first(flat, "GeoLocation.location.lat", "data.gps_location.lat")),
        _to_float(_first(flat, "GeoLocation.location.lon", "data.gps_location.lon")),
        _first(flat, "decoder.name"),                                # decoder
        _first(flat, "location")[:300],                              # location
        _first(flat, "full_log")[:2000],                             # full_log
        json.dumps(raw_alert),                                       # raw (no truncation)
        _first(flat, "data.policyid", "data.policy_id"),             # policy_id
    ]


# ── backend triggers (non-blocking — run in daemon threads) ──────────────────

_trigger_lock = threading.Lock()
_active_triggers: set = set()


def _run_in_bg(name: str, fn):
    """Fire-and-forget: run fn() in a daemon thread. Skip if already running."""
    with _trigger_lock:
        if name in _active_triggers:
            print(f"  ⏭ {name} already running — skipping")
            return
        _active_triggers.add(name)

    def _wrap():
        try:
            fn()
        finally:
            with _trigger_lock:
                _active_triggers.discard(name)

    t = threading.Thread(target=_wrap, name=name, daemon=True)
    t.start()


def trigger_ml_train():
    def _do():
        try:
            resp = requests.post(f"{ML_API_BASE}/api/ml/train", timeout=180)
            data = resp.json()
            print(f"  🧠 ML train: {data.get('status')} — {data.get('ip_count','?')} IPs, "
                  f"{data.get('anomalies','?')} anomalies")
        except Exception as e:
            print(f"  ⚠ ML train failed: {e}")
    _run_in_bg("ml-train", _do)


def trigger_archive():
    def _do():
        try:
            resp = requests.post(f"{API_BASE}/api/archive/run", timeout=120)
            print(f"  📦 Archive: {resp.json().get('archived','?')} events archived")
        except Exception as e:
            print(f"  ⚠ Archive failed: {e}")
    _run_in_bg("archive", _do)


def trigger_baseline_build():
    def _do():
        try:
            resp = requests.post(f"{API_BASE}/api/baseline/build-all", timeout=300)
            print(f"  📊 Baselines: {resp.json().get('baselines_built','?')} built")
        except Exception as e:
            print(f"  ⚠ Baseline build failed: {e}")
    _run_in_bg("baseline-build", _do)


def trigger_deviation_scan():
    def _do():
        try:
            resp = requests.post(f"{API_BASE}/api/baseline/scan-deviations", timeout=300)
            d = resp.json()
            print(f"  🚨 Deviations: {d.get('deviations_written','?')} across "
                  f"{d.get('ips_with_deviations','?')} IPs")
        except Exception as e:
            print(f"  ⚠ Deviation scan failed: {e}")
    _run_in_bg("deviation-scan", _do)


def wait_for_clickhouse(max_wait: int = 120):
    print(f"[Watcher] Waiting for ClickHouse at {CH_HOST}:{CH_PORT} ...")
    start = time.time()
    while time.time() - start < max_wait:
        if get_ch():
            return
        time.sleep(3)
    print(f"[Watcher] ClickHouse not reachable after {max_wait}s — starting anyway (will spool)")


# ── main loop ──────────────────────────────────────────────────────────────────

def tail_alerts():
    state = load_offset()
    is_first_run = state["byte_offset"] == 0

    if is_first_run:
        print("[Watcher] FIRST RUN — ingesting entire alerts.json history (no rate limit)")
    else:
        print(f"[Watcher] Resuming from offset {state['byte_offset']:,} "
              f"({state['total_ingested']:,} ingested)")

    if not ALERTS_PATH.exists():
        print(f"[Watcher] Waiting for {ALERTS_PATH} ...")
        while not ALERTS_PATH.exists():
            time.sleep(INTERVAL)
        print("[Watcher] File found ✓")

    session_ingested = 0
    since_last_train = 0
    since_last_archive = 0
    last_progress_ts = time.time()
    last_train_ts = 0.0   # epoch of last heavy retrain (for TRAIN_COOLDOWN gating)

    while True:
        # Always try to drain the spool first (ClickHouse may have recovered)
        replay_spool()

        try:
            st = ALERTS_PATH.stat()
            file_size  = st.st_size
            file_inode = st.st_ino
        except Exception:
            time.sleep(INTERVAL)
            continue

        # Detect rotation: inode changed (Wazuh replaced the file) OR file shrank
        saved_inode = state.get("file_inode")
        if (saved_inode and saved_inode != file_inode) or file_size < state["byte_offset"]:
            reason = "inode changed" if (saved_inode and saved_inode != file_inode) else "file shrank"
            print(f"[Watcher] File rotated ({reason}) — resetting offset to 0")
            state["byte_offset"] = 0
            state["file_inode"]  = file_inode
            save_offset(state)
            last_progress_ts = time.time()
        else:
            state["file_inode"] = file_inode

        if file_size > state["byte_offset"] and time.time() - last_progress_ts > STALE_SECONDS:
            print(f"[Watcher] Stale {STALE_SECONDS}s with unread data — exiting for Docker restart")
            sys.exit(2)

        if file_size == state["byte_offset"]:
            if is_first_run and session_ingested > 0:
                print(f"\n[Watcher] ═══ FIRST RUN COMPLETE — {session_ingested:,} alerts ═══")
                trigger_baseline_build()
                trigger_ml_train()
                trigger_archive()
                is_first_run = False
                since_last_train = 0
                since_last_archive = 0
                print(f"[Watcher] Now watching for new alerts every {INTERVAL}s\n")
            time.sleep(INTERVAL)
            continue

        chunk_kept = chunk_dropped = chunk_rate_limited = chunk_lines = 0
        batch = []
        last_good_offset = state["byte_offset"]

        def flush(rows, advance_to) -> bool:
            """Store rows; on success advance offset + counters. Returns ok."""
            nonlocal session_ingested, since_last_train, since_last_archive
            if not rows:
                return True
            if store_batch(rows):
                state["byte_offset"] = advance_to
                state["lines_read"] += len(rows)
                state["total_ingested"] += len(rows)
                session_ingested += len(rows)
                since_last_train += len(rows)
                since_last_archive += len(rows)
                save_offset(state)
                return True
            return False

        try:
            with open(ALERTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                f.seek(state["byte_offset"])
                for _ in range(CHUNK_LINES):
                    line = f.readline()
                    if not line or not line.endswith("\n"):
                        break  # EOF or incomplete line
                    last_good_offset = f.tell()
                    chunk_lines += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_alert = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    decision = should_ingest(raw_alert)
                    if decision == "drop":
                        chunk_dropped += 1
                        continue
                    if not is_first_run and not check_rate_limit():
                        chunk_rate_limited += 1
                        continue

                    row = map_to_row(raw_alert)
                    if row is None:
                        chunk_dropped += 1
                        continue
                    filter_stats["sampled" if decision == "sample" else "kept"] += 1
                    batch.append(row)
                    chunk_kept += 1

                    if len(batch) >= BATCH_SIZE:
                        if flush(batch, last_good_offset):
                            last_progress_ts = time.time()
                            batch = []
                        else:
                            print("  ✗ Could not store/spool batch — waiting 15s")
                            time.sleep(15)
                            batch = []
                            break
        except Exception as e:
            print(f"  ✗ Read error: {e}")
            time.sleep(INTERVAL)
            continue

        if batch:
            if flush(batch, last_good_offset):
                last_progress_ts = time.time()
        elif chunk_lines > 0:
            # everything filtered out — still advance past the read lines
            state["byte_offset"] = last_good_offset
            save_offset(state)
            last_progress_ts = time.time()

        if chunk_lines > 0:
            ts = datetime.now().strftime("%H:%M:%S")
            pct = f" | {state['byte_offset']/file_size*100:.1f}% of file" if file_size else ""
            rl = f", {chunk_rate_limited} rate-limited" if chunk_rate_limited else ""
            print(f"  [{ts}] {chunk_lines:,} lines → {chunk_kept} kept, "
                  f"{chunk_dropped:,} dropped{rl} "
                  f"(total: {state['total_ingested']:,}{pct})")

        if since_last_train >= TRAIN_THRESHOLD and (time.time() - last_train_ts) >= TRAIN_COOLDOWN:
            print(f"[Watcher] Triggering ML train ({since_last_train:,} new)...")
            trigger_deviation_scan()    # detect novelty vs the PRIOR baseline first
            trigger_baseline_build()    # then refresh baselines to absorb new data
            trigger_ml_train()
            since_last_train = 0
            last_train_ts = time.time()

        if since_last_archive >= ARCHIVE_THRESHOLD:
            print(f"[Watcher] Triggering archive ({since_last_archive:,} new)...")
            trigger_archive()
            since_last_archive = 0

        time.sleep(0.1 if is_first_run else INTERVAL)


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   CyberSentinel — Wazuh alerts.json Streamer v3        ║")
    print("║   Sink: ClickHouse (direct, batched, spooled)         ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  File       : {ALERTS_PATH} (dir-mounted, rotation-safe)")
    print(f"  ClickHouse : {CH_HOST}:{CH_PORT} → {CH_TABLE}")
    print(f"  Backend    : {API_BASE} (triggers only)")
    print(f"  Batch      : {BATCH_SIZE} | Chunk: {CHUNK_LINES:,} lines | Spool: {SPOOL_DIR}")
    print(f"  Filter     : drop <{MIN_LEVEL}, sample {MIN_LEVEL}-{SAMPLE_BELOW-1} (1/{SAMPLE_RATE}), keep {SAMPLE_BELOW}+")
    print()
    wait_for_clickhouse()
    tail_alerts()
