# CyberSentinel — Architecture (at a glance)

> Full documentation lives in **[`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md)** —
> this file is the one-page summary. AI-native SIEM/SOC platform: high-volume
> security telemetry is collected, normalised, stored, scored by ML + behavioural
> models, mapped to the ATT&CK kill chain, and served to a SOC dashboard.

## Data flow

```
  Alert feed                              CyberSentinel platform
 ┌──────────────┐   read-only
 │ alerts.json  │──────────────►  CyberSentinel Collector
 │ 100k–M/day   │                  • byte-offset tail
 └──────────────┘                  • smart filter (drop/sample/keep)
                                    • batch + DISK SPOOL (zero loss)
                                          │
                                          ▼
                                  CyberSentinel Normaliser   (flatten + classify + map)
                                    • threat_type + severity
                                    • ATT&CK / geo / process / FIM
                                          │ bulk insert
                                          ▼
                               ┌──────────────────────────────┐
                               │          Event Store         │  ClickHouse
                               │  logs (MergeTree, day-part,   │
                               │        ZSTD, 90/180d TTL)     │
                               │   ├─ mv_ip_daily   → agg_ip_daily
                               │   └─ mv_threat_hourly→ agg_threat_hourly
                               └───┬───────────────────┬───────┘
                            read SQL                read SQL
                                  ▼                   ▼
                           Risk Engine            Backend  (FastAPI)
                           (ML anomaly,           • UEBA • ATT&CK
                            Isolation Forest)     • incidents • detections
                                                  │ /api/*
                                                  ▼
                                            Gateway (nginx + login gate, :19888)
                                                  ▼
                                            Dashboard (SOC UI)
```

## Components

| Component | Container | Role |
|-----------|-----------|------|
| **CyberSentinel Collector** | *(ingestion service)* | Tail the alert feed, filter, batch-insert with disk spool. Managed via `aiml start`. |
| **CyberSentinel Normaliser** | *(in the Collector)* | Flatten, classify `threat_type`/`severity`, extract ATT&CK/geo/process/FIM, map to the 39-column schema. |
| **Event Store** | `aiml_clickhouse` | Columnar log store + rollups (ClickHouse). Source of truth: `cybersentinel.logs`. |
| **Risk Engine** | `aiml_ml` | Isolation-Forest anomaly + deviation + intel → 0–100 risk. Auto-retrains. |
| **Backend** | `aiml_backend` | FastAPI: UEBA, ATT&CK, incidents, detections, telemetry intel, NL query, playbooks; serves `/api/*`. |
| **Gateway** | `aiml_nginx` | Reverse proxy + single login gate. Only external port (`19888`). |
| **Dashboard** | `aiml_frontend` | SOC UI (static HTML/JS). |

Sidecar ports bind to `127.0.0.1`; the Gateway is the single external door.

## Run

```bash
aiml start      # bring the whole stack up (Collector included)
aiml update     # pull latest + rebuild
```

See **[`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md)** for the full explanation of
every engine, the data model, security, deployment and scale tuning, and
`RUNBOOK.md` for health checks and failure→fix steps.
