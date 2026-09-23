# CyberSentinel — ClickHouse Pipeline Runbook

Production log pipeline. Read this when something looks wrong — most issues map
to one command below.

```
alerts.json ──► CyberSentinel Collector ──► Event Store (cybersentinel.logs)
                  │  (batch + disk spool)        │
                  │                               ├─ mv_ip_daily   → agg_ip_daily
                  └─ triggers baseline/ML/archive └─ mv_threat_hourly → agg_threat_hourly
                                                  │
                                                  ▼
                                         backend (SQL) ──► UI
                                         Redis = small state only (no logs)
```

## Start / stop

```bash
# Core stack (no log ingestion)
docker compose up -d --build

# With the CyberSentinel Collector (the log ingester)
docker compose --profile wazuh up -d --build

# Logs
docker compose logs -f wazuh-watcher
docker compose logs -f backend
docker compose logs -f clickhouse
```

The watcher needs the host path to alerts.json. Set it before starting:
```bash
export WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json   # the real path
```

## First-time / fresh index

The schema in `clickhouse/init/01-schema.sql` auto-applies **only on a fresh
ClickHouse data volume**. To (re)apply on an existing volume:

```bash
docker exec -i cs_clickhouse clickhouse-client --multiquery < clickhouse/init/01-schema.sql
```

Quick sanity queries:
```bash
docker exec -it cs_clickhouse clickhouse-client -q "SELECT count() FROM cybersentinel.logs"
docker exec -it cs_clickhouse clickhouse-client -q \
  "SELECT src_ip, sum(events) e FROM cybersentinel.agg_ip_daily GROUP BY src_ip ORDER BY e DESC LIMIT 10"
```

## Health checks (do these first)

| Check | Command | Healthy result |
|---|---|---|
| Backend ↔ ClickHouse | `curl -s localhost:18110/api/health` | `"clickhouse":"connected"` + a doc count |
| Rows landing | `clickhouse-client -q "SELECT count() FROM cybersentinel.logs"` (run twice) | number increasing |
| Watcher progress | `docker compose logs --tail=20 wazuh-watcher` | `N kept … total: …` lines |
| Spool backlog | `docker exec cs_wazuh_watcher ls /app/data/spool` | empty (or draining) |

## Failure → fix

**`Too many parts` (ClickHouse insert errors)**
Inserts arriving too small/fast. We already batch (`WAZUH_BATCH_SIZE`, default
5000) and use `async_insert`. If it still happens, raise the batch size and
check parts:
```bash
docker exec -it cs_clickhouse clickhouse-client -q \
  "SELECT table, count() FROM system.parts WHERE active GROUP BY table"
# then: export WAZUH_BATCH_SIZE=10000 && docker compose up -d wazuh-watcher
```

**Ingestion stalled (row count not moving)**
1. `docker compose logs --tail=50 wazuh-watcher` — look for connect/insert errors.
2. Is ClickHouse up? `docker compose ps clickhouse` / `curl -s localhost:18123/ping`.
3. Spool filling? `docker exec cs_wazuh_watcher ls -la /app/data/spool` — if files
   exist, ClickHouse was down; they replay automatically once it's back.
4. Offset: `docker exec cs_wazuh_watcher cat /app/data/wazuh_offset.json`.

**ClickHouse won't start / out of memory**
```bash
docker compose logs --tail=80 clickhouse
docker stats cs_clickhouse --no-stream
```
Lower memory: add `--ulimit` is already set; to cap RAM, set a container
`mem_limit` in compose and/or `max_server_memory_usage` via a config.d file.

**Disk filling up**
Raw logs auto-expire via TTL (90 days). Inspect / drop early:
```bash
docker exec -it cs_clickhouse clickhouse-client -q \
  "SELECT partition, formatReadableSize(sum(bytes_on_disk)) FROM system.parts
   WHERE table='logs' AND active GROUP BY partition ORDER BY partition"
# manual drop of an old day:
docker exec -it cs_clickhouse clickhouse-client -q \
  "ALTER TABLE cybersentinel.logs DROP PARTITION 20250101"
```
Change retention: edit the `TTL` lines in `clickhouse/init/01-schema.sql` then
`ALTER TABLE cybersentinel.logs MODIFY TTL toDateTime(ts) + INTERVAL <N> DAY`.

**Dashboard empty but rows exist**
The materialized views only roll up rows inserted **after** they were created.
If you backfilled raw rows before the MV existed, rebuild the rollup:
```bash
docker exec -it cs_clickhouse clickhouse-client -q \
  "INSERT INTO cybersentinel.agg_ip_daily
   SELECT toDate(ts), src_ip, threat_type, severity, count()
   FROM cybersentinel.logs GROUP BY toDate(ts), src_ip, threat_type, severity"
```

## Backup

```bash
# Snapshot the named volume (stop CH first for a consistent copy)
docker run --rm -v cybersentinel_clickhouse_data:/data -v "$PWD":/backup \
  alpine tar czf /backup/clickhouse_backup_$(date +%F).tgz /data
```

## Tunables (env)

| Var | Default | Meaning |
|---|---|---|
| `WAZUH_BATCH_SIZE` | 5000 | rows per ClickHouse insert |
| `WAZUH_MIN_LEVEL` | 4 | drop alerts below this rule level |
| `WAZUH_SAMPLE_BELOW` / `WAZUH_SAMPLE_RATE` | 7 / 10 | sample 1/N for levels 4–6 |
| `WAZUH_MAX_PER_MINUTE` | 0 (unlimited) | post-first-run rate cap |
| `WATCHER_SINK` | clickhouse | ingestion sink |
| `CLICKHOUSE_*` | see `.env` | store connection |
