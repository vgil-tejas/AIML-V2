# CyberSentinel — Production Scale & Safe-Deploy Runbook

> **Read this first, in full, before touching the `.23` server.**
> The production box holds **~26 million real bank logs**. This document is the
> complete, in-depth process for two things the team asked for:
>
> 1. **Keep the 26M safe** across every deploy, and make sure the local ~10k
>    demo/test logs **never** land on production.
> 2. **Fix the "dashboard takes a lot of load to load"** problem with a proper
>    queuing / read-throttling / query-bounding system.
>
> It is written so a fresh Claude session (or any engineer) on the server can
> execute it without re-deriving context. Every command is specific to this
> project (container names `aiml_*`, dashboard port `19888`, DB `cybersentinel`).

---

## 0. The single most important idea

**Code and data live in two completely separate places.**

| Thing | Where it lives | Travels on `git pull`? | Wiped by a rebuild? |
|---|---|---|---|
| App code (backend, frontend, compose) | the git repo | **Yes** | n/a |
| The 26M logs, baselines, cases, feedback | the **`clickhouse_data` Docker volume** | **No** | **No** |

A deploy = *new code, same data*. Pulling code and rebuilding containers
**cannot** touch the 26M rows, because ClickHouse data is a **named Docker
volume** that is never part of the repo and is never recreated by
`docker compose up -d --build`.

That is why the local 10k (including the demo attack rows) "stays away" from
prod automatically: it only exists in the **local** machine's `clickhouse_data`
volume. Git never carries it.

**There are exactly four ways to destroy the 26M. Memorise them as the things you never do on prod:**

1. `docker compose down -v`  ← the `-v` deletes volumes. **Never use `-v` on prod.**
2. `docker volume rm ...clickhouse_data`
3. `TRUNCATE TABLE` / `DROP TABLE` / `ALTER TABLE ... DELETE` run by hand
4. Running **demo mode** on prod (writes synthetic rows *into* the 26M) —
   now hard-gated, see §4.3.

Everything else in this runbook is safe by construction.

---

## 1. Current state — measured facts (so nobody guesses)

**Store table** `cybersentinel.logs`:

```
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)                 -- one partition per calendar day (good)
ORDER BY (src_ip, ts)                        -- sort key LEADS with src_ip  ← the perf trap
TTL  low/medium/unknown  -> 90 days
     everything else     -> 180 days         -- retention already automatic
```

**Ingestion — the CyberSentinel Collector** (`scripts/wazuh_watcher.py`) is already production-grade:

- Batches inserts at `WAZUH_BATCH_SIZE=5000` — ClickHouse never sees tiny inserts.
- Disk-spools a batch if ClickHouse is down, replays it later.
- Advances its file offset **only after** a batch is durably stored.
- Uses `async_insert=1, wait_for_async_insert=1` (acknowledged writes).

➡️ **The write path does not need a new queue — it already has one.** The load
problem is on the **read** path.

**Backend read path** (`backend/main.py`) already has:

- `ThreadPoolExecutor(max_workers=20)` + `_ch_sem = asyncio.Semaphore(8)` (concurrency cap).
- Per-endpoint TTL caches: stats 60s, hot-ips 60s, incidents 60s, resilience 120s, kill-chain 60s.

**The actual bottleneck:** two call sites force a **full 26M-row scan**:

1. **Overview boot** — `frontend/overview-neural.html` fetches
   `GET /api/logs?minutes=99999999&limit=60` just to show the 60 newest events.
2. **Logs Explorer → "All time"** — sends the same `minutes=99999999`.

Because the sort key is `(src_ip, ts)` — **not** `ts` first — "give me the newest
60 by time" cannot seek; it reads every partition. At 10k rows that's 48 ms; at
26M it's the multi-second stall the team is seeing.

`GET /api/logs` **already defaults to a 7-day, partition-pruned window** when no
range is given — so the fix is to stop *asking* for all-time on pages that only
need "recent".

---

## 2. The plan at a glance (do it in this order)

| # | Change | Risk | Where it runs | Effort |
|---|---|---|---|---|
| A | Safe-deploy runbook (preserve 26M, drop 10k) | none | server | procedure |
| B1 | Gate demo mode behind `DEMO_MODE` | none | **already done in code** | done |
| B2 | Stop the Overview / "All time" full scans | low | code + rebuild | small |
| B3 | Read-admission queue: bounded + **serve-stale on timeout** | low | code + rebuild | small |
| B4 | Serve dashboard aggregates from materialized views | med | code | medium |
| C | (Optional) `ts` skip-index or `ORDER BY (ts, src_ip)` rebuild | med→high | server, staged | large |

Ship **A + B2 + B3** first — they remove the stall with near-zero risk. Do **B4**
and **C** only if load is still high after measuring.

---

## 3. PART A — Safe deploy (preserve 26M, keep the 10k off prod)

### 3.1 One-time, before your first deploy of this branch — snapshot the 26M

```bash
# On the .23 server. A physical backup you can restore from if anything ever goes wrong.
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" \
  --query "SELECT count() FROM cybersentinel.logs"          # note this number

# Freeze = hard-link snapshot of all parts (cheap, instant, no downtime)
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" \
  --query "ALTER TABLE cybersentinel.logs FREEZE"
# Snapshot lands in the volume under shadow/. Copy it off-box if you want true DR:
docker cp aiml_clickhouse:/var/lib/clickhouse/shadow ./ch-shadow-$(date +%F)
```

### 3.2 The deploy itself (this is the whole routine)

```bash
# 1. Pull the new code
cd /path/to/cybersentinel
git fetch origin main
git log --oneline -3 origin/main        # sanity: is this the commit you expect?
git pull origin main

# 2. Confirm prod .env does NOT enable demo mode (must be absent or false)
grep -i '^DEMO_MODE' .env || echo "DEMO_MODE not set -> demo disabled (correct)"

# 3. Rebuild ONLY the app containers. NO -v. NEVER -v.
docker compose up -d --build backend frontend nginx
#   clickhouse is NOT listed -> its container and volume are untouched.
#   The backend auto-runs pending ADDITIVE migrations at boot (idempotent;
#   RUN_MIGRATIONS_ON_START=true). To run/inspect them manually instead:
#     docker exec aiml_backend python migrate.py --status   # show applied/pending
#     docker exec aiml_backend python migrate.py            # apply pending
#   The runner REFUSES any DROP/DELETE/TRUNCATE/ALTER…DELETE unless
#   ALLOW_DESTRUCTIVE=true (never set on prod).

# 4. Verify data survived (must equal the number from 3.1, plus new ingest)
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" \
  --query "SELECT count() FROM cybersentinel.logs"

# 5. Smoke test — liveness, readiness (store+migrations), and a bounded read
curl -s localhost:19110/health           # {"status":"ok","store":"connected",...}
curl -s localhost:19110/health/ready     # {"ready":true,"store":true,"migrations_current":true}
curl -s "localhost:19888/api/logs/latest?limit=5" | head -c 120
# Confirm the full-scan hole is closed at the API layer:
curl -s "localhost:19888/api/logs?minutes=99999999&limit=1" \
  | python -c "import json,sys;print('clamped:',json.load(sys.stdin)['window_clamped'])"  # -> True

# 6. (one-time, optional) backfill the idx_ts skip-index over existing 26M parts.
#    ADD INDEX (migration 001) only covers NEW parts; this rewrites old ones.
#    Heavy — run in a maintenance window:
#   docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" \
#     --query "ALTER TABLE cybersentinel.logs MATERIALIZE INDEX idx_ts"
```

> **Why the 26M is safe:** step 3 rebuilds `backend/frontend/nginx` images and
> recreates *those* containers. The `clickhouse` service isn't rebuilt, and even
> if it were, its data is in the `clickhouse_data` **named volume**, which
> `up -d --build` preserves. The only command that deletes it is `down -v`.

### 3.3 "The 10k should go away, the 26M should stay" — what this actually means

The 10k local logs are **not in git** and are **not on the server** — they only
exist in your laptop's `clickhouse_data` volume. So after a normal deploy the
server simply keeps its 26M and never gains your 10k. Nothing to do.

**Only** run the following if you previously ran demo mode or hand-loaded test
data **on the server** and want it gone. It is a **targeted** delete keyed to the
synthetic demo identifiers — it never touches real traffic:

```sql
-- Run inside: docker exec -it aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS"
-- Preview first — see exactly what would be removed:
SELECT count(), min(ts), max(ts)
FROM cybersentinel.logs
WHERE src_ip IN ('198.51.100.66','10.0.10.5','10.0.10.21','10.0.10.33','10.0.20.7','10.0.20.11')
   OR dst_ip = '198.51.100.66';

-- If (and only if) the preview is all synthetic, delete it:
ALTER TABLE cybersentinel.logs
DELETE WHERE src_ip IN ('198.51.100.66','10.0.10.5','10.0.10.21','10.0.10.33','10.0.20.7','10.0.20.11')
          OR dst_ip = '198.51.100.66';
-- (mutation runs in background; check: SELECT * FROM system.mutations WHERE is_done = 0)
```

`198.51.100.66` is TEST-NET-2 and `10.0.10.x` are the scripted demo targets — they
are never real bank hosts, so this is safe. **Do not** broaden the filter.

---

## 4. PART B1 — Demo-mode gate (DONE in code, verify on deploy)

Demo mode writes synthetic attack rows **into the live store**. It is now
**hard-disabled unless `DEMO_MODE=true`**:

- `backend/main.py`: `POST /api/demo/run` returns **403** unless the flag is set.
- `docker-compose.yml`: `DEMO_MODE=${DEMO_MODE:-false}` — **defaults off**.
- Local dev box `.env` sets `DEMO_MODE=true` (keep it there, never on prod).
- The Settings "Run demo attack" card **hides itself** when the backend reports
  `enabled:false`.

**Verify after deploy (prod must refuse):**

```bash
curl -s localhost:19888/api/demo/status      # expect  "enabled":false  on prod
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:19888/api/demo/run   # expect 403
```

---

## 5. PART B2 — Stop the full-table scans (small, low-risk)

The Overview and "All time" ask for `minutes=99999999`. On a **live** prod feed
the newest events are seconds old, so a bounded window returns them instantly via
partition pruning. The only reason `99999999` existed is the **dev box has stale
data** (newest event is days old), so a short window looked empty there.

**Fix — make "recent" mean recent, with a stale-data fallback.**

### 5.1 Backend: a dedicated bounded "latest" path

Add to `backend/main.py` (near `get_logs`):

```python
@app.get("/api/logs/latest")
async def get_logs_latest(limit: int = 60):
    """The newest N events, partition-pruned. Walks back day-by-day so it is
    fast on a live feed AND still returns rows on a stale dev store."""
    if not (STORE_ENABLED and osc):
        return {"logs": [], "count": 0, "source": "disabled"}
    for minutes in (1440, 10080, 43200, 525600):     # 1d -> 7d -> 30d -> 1y
        logs = await _to_thread(osc.get_recent_logs,
                                minutes, "", "", None, 0, min(limit, 200), "")
        if logs:
            return {"logs": logs, "count": len(logs), "window_minutes": minutes,
                    "source": "event-store"}
    return {"logs": [], "count": 0, "source": "event-store"}
```

Each probe is partition-pruned, so on prod the first (1-day) probe returns and
never scans older partitions.

### 5.2 Frontend: point the Overview at it

In `frontend/overview-neural.html`, change the boot fetch:

```diff
- j(`${API}/logs?minutes=99999999&limit=60`),
+ j(`${API}/logs/latest?limit=60`),
```

### 5.3 Logs Explorer "All time" — make it explicit and bounded

In `frontend/index.html` `loadLogs()`, cap the implicit all-time scan. Keep an
explicit "All time (slow)" only behind the search box (a `q` search is the one
case a full range is justified):

```diff
- if (!logsRange.from && !logsRange.to) q += `&minutes=${logsRange.mins || 99999999}`;
+ // default browse is bounded; only a text search may span everything
+ if (!logsRange.from && !logsRange.to) q += `&minutes=${logsRange.mins || 10080}`; // 7d
```

**Local test (dev box, DEMO_MODE=true so there is fresh data):**

```bash
curl -s localhost:19888/api/logs/latest?limit=60 | python -c "import json,sys;d=json.load(sys.stdin);print(d['count'],'in',d.get('window_minutes'),'min')"
```

---

## 6. PART B3 — Read-admission queue (bounded + serve-stale)

Goal: heavy dashboard queries **queue** instead of piling onto ClickHouse, and if
the queue is saturated the UI gets **slightly stale cache instantly** rather than
hanging. This is the "queuing system" in the request the team made.

Add to `backend/main.py` (once, near the top helpers):

```python
# ── Read-admission control ────────────────────────────────────────────────────
# Heavy aggregate endpoints acquire a slot; if none frees within the deadline we
# serve the last cached value (stale-but-instant) instead of adding to the pileup.
_read_gate = asyncio.Semaphore(int(os.getenv("READ_CONCURRENCY", "6")))
_ADMIT_WAIT = float(os.getenv("READ_ADMIT_WAIT", "2.0"))   # seconds

async def admit(coro_factory, *, stale):
    """Run coro_factory() under the gate. On saturation/timeout return `stale`."""
    try:
        await asyncio.wait_for(_read_gate.acquire(), timeout=_ADMIT_WAIT)
    except asyncio.TimeoutError:
        return stale                       # dashboard shows last-known value
    try:
        return await coro_factory()
    finally:
        _read_gate.release()
```

Wrap the expensive endpoints (`/api/overview`, `/api/entity-risk`,
`/api/ml/anomalies`, `/api/incidents`) so each passes its own last cache as the
stale fallback, e.g.:

```python
return await admit(lambda: _build_overview(), stale={"stats": _stats_cache or {},
                    "hot_ips": _hot_ips_cache or [], "ml_health": {}})
```

Tune with env (no rebuild of logic needed): `READ_CONCURRENCY`, `READ_ADMIT_WAIT`.
Start at `6 / 2.0s`; if ClickHouse CPU still spikes under a crowd, drop
`READ_CONCURRENCY` to 4.

**Why this helps:** 30 analysts hitting the Overview at 9am no longer launch 30
concurrent 26M scans — at most `READ_CONCURRENCY` run, the rest get the 60-second
cache instantly. Combined with B2 (no full scans) the stall disappears.

---

## 7. PART B4 — Aggregates from materialized views (medium)

The store already has rollup MVs (confirm with `SHOW TABLES FROM cybersentinel`):
`mv_threat_hourly → agg_threat_hourly`, `mv_ip_daily → agg_ip_daily`, `first_seen`,
`mv_fs_*`. Any dashboard number that is a **count/trend over time** should read the
`agg_*` table, not `logs`.

Audit each read in `clickhouse_client.py` used by `/api/stats`, `/api/overview`,
`/api/trend/*`:

- **Trend/severity-over-time** → already MV-backed (`/api/trend/hourly`). Keep.
- **Global counts** (`get_total_doc_count`, `get_global_severity_counts`) → these
  scan `logs`. At 26M, back them with a small always-current rollup or accept the
  60s cache (they are already cached). Prefer: a `agg_daily_totals` MV so the count
  is a sum over ~180 tiny rows, not 26M.
- **Entity risk** (`get_entity_risk_ranking`) → bound its window to
  `window_days` (already a param) and ensure it filters `ts >=` first so partition
  pruning applies.

This is medium effort because it means adding one or two MVs and repointing a few
queries. Do it **only if** §5+§6 didn't get load low enough — measure first (§9).

---

## 8. PART C — Table/index change for 26M (optional, staged, last resort)

The root cause of slow *time-ordered* reads is `ORDER BY (src_ip, ts)`. Two options,
cheapest first:

### 8.1 Cheap & online — add a `ts` data-skipping index (try this first)

```sql
ALTER TABLE cybersentinel.logs
  ADD INDEX idx_ts ts TYPE minmax GRANULARITY 4;
ALTER TABLE cybersentinel.logs MATERIALIZE INDEX idx_ts;   -- backfills in background
```

`minmax` on `ts` lets ClickHouse skip granules outside a time range even though
`ts` isn't the primary key. No rewrite, no downtime, reversible (`DROP INDEX`).

### 8.2 Heavy & last-resort — rebuild with `ORDER BY (ts, src_ip)`

Only if 8.1 is not enough. This rewrites 26M rows — do it in a maintenance window.

```sql
-- 1. New table, time-leading sort, same partitions/TTL/columns
CREATE TABLE cybersentinel.logs_v2 AS cybersentinel.logs
  ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (ts, src_ip);
-- (copy the TTL clause from SHOW CREATE TABLE logs)

-- 2. Backfill oldest→newest (chunk by month to keep memory sane)
INSERT INTO cybersentinel.logs_v2 SELECT * FROM cybersentinel.logs;

-- 3. Verify counts match, THEN swap atomically
--    (point the watcher at logs_v2 first, or briefly pause it)
RENAME TABLE cybersentinel.logs TO cybersentinel.logs_old,
             cybersentinel.logs_v2 TO cybersentinel.logs;

-- 4. Keep logs_old for a day as insurance, then DROP it.
```

Trade-off: `(ts, src_ip)` makes time queries fast but per-IP Trail lookups a touch
slower (still fine — Trail also filters by a recent window). Most of the dashboard
is time-ordered, so this is usually the right sort — but it's invasive, so it's
**last**.

---

## 9. Measure before & after (don't optimise blind)

```bash
# Slowest queries in the last hour (run on the server)
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" --query "
SELECT round(query_duration_ms) ms, read_rows, substring(query,1,80) q
FROM system.query_log
WHERE type='QueryFinish' AND event_time > now()-3600 AND query LIKE '%logs%'
ORDER BY query_duration_ms DESC LIMIT 15 FORMAT PrettyCompact"

# Active parts per table (merge pressure — high = ingestion tuning needed)
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" --query "
SELECT table, count() parts, sum(rows) rows FROM system.parts
WHERE active AND database='cybersentinel' GROUP BY table ORDER BY parts DESC FORMAT PrettyCompact"

# End-to-end page latency the analyst actually feels
for u in /api/overview /api/logs/latest?limit=60 /api/entity-risk /api/stats; do
  printf '%-32s %s\n' "$u" "$(curl -s -o /dev/null -w '%{time_total}s' localhost:19888$u)"
done
```

**Target:** every Overview boot endpoint < 1.5s at 26M. If `read_rows` on a
dashboard query is ~26M, that query is still full-scanning — fix its window/index.

---

## 10. Rollback

- **Code**: `git log --oneline`, then `git checkout <good-sha> -- .` (or
  `git revert <sha>`), then `docker compose up -d --build backend frontend`.
  Data is untouched.
- **Index (8.1)**: `ALTER TABLE cybersentinel.logs DROP INDEX idx_ts;`
- **Table rebuild (8.2)**: you kept `logs_old` — `RENAME` it back.
- **Read gate / windows (§5,§6)**: env-tunable; set `READ_CONCURRENCY` high and
  `READ_ADMIT_WAIT` large to effectively disable admission control without a
  redeploy.

---

## 11. Hand-off note — for the next Claude session on the server

When you pick this up, in order:

1. Run §9 to get the current baseline (slowest queries, page latencies, part counts).
2. Do **§3 (safe deploy)** — this is a procedure, not a code change; it's how every
   deploy must go. Confirm the 26M count is unchanged after.
3. Confirm **§4** (demo gate) returns 403 on prod.
4. Apply **§5 (B2)** and **§6 (B3)** — small code diffs, rebuild `backend frontend`,
   re-measure §9. This alone should kill the load stall.
5. Only if still slow: **§7 (B4)**, then **§8.1** (cheap index), then **§8.2**
   (rebuild) as the last resort.

**Never** on prod: `docker compose down -v`, `DEMO_MODE=true`, `DROP`/`TRUNCATE`
on `logs`, or broadening the §3.3 delete filter. When unsure whether a command
touches the 26M, stop and check `SELECT count() FROM cybersentinel.logs` before
and after.

---

*Facts in §1 were measured on 2026-07-18 against the live containers. Ingestion
(watcher batching + spool) and backend caches/semaphore already exist; the demo
gate is already in code. The remaining items (B2–C) are staged, reversible, and
must be validated against real 26M load on the server — they cannot be perf-tested
on the ~10k dev store.*
