# CyberSentinel — Threat Intelligence SIEM Platform

A full-stack, Dockerised threat intelligence dashboard for SOC teams.
Built for **Virtual Galaxy Infotech Ltd** · Bank client log analysis.

---

## What's inside

```
cybersentinel/
├── docker-compose.yml          ← Run everything with one command
├── .env.example                ← Copy to .env and fill in keys
│
├── frontend/                   ← Single-page dashboard (nginx)
│   ├── index.html              ← Full threat intel UI
│   ├── nginx.conf
│   └── Dockerfile
│
├── backend/                    ← FastAPI REST API
│   ├── main.py                 ← Log ingestion, IP trail, blocklist, intel
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml-engine/                  ← ML anomaly detection (FastAPI)
│   ├── main.py                 ← Isolation Forest, subnet clustering, risk scoring
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml-intern/                  ← Hybrid retraining governance service (FastAPI)
│   ├── main.py                 ← Time + data + drift retraining checks
│   ├── requirements.txt
│   └── Dockerfile
│
├── redis-config/               ← Redis with persistence
│   ├── redis.conf
│   └── Dockerfile
│
├── nginx/                      ← Reverse proxy (routes /api/ml → ml-engine, /api → backend)
│   ├── nginx.conf
│   └── Dockerfile
│
├── scripts/
│   ├── watch_and_ingest.py     ← Continuous folder watcher for live log ingestion
│   └── fortigate_autoblock.py  ← Push blocklist to Fortigate via REST API
│
└── sample-data/
    ├── generate_sample_data.py ← Generates realistic test logs
    └── sample_logs.csv         ← Ready-to-use sample (1,390 events)
```

---

## Quick start

### 1. Prerequisites
- Docker + Docker Compose installed
- Ports 80, 8000, 8001, 6379 free

### 2. Clone / unzip and start
```bash
cd cybersentinel
cp .env.example .env           # optionally add ABUSEIPDB_KEY
docker compose up --build -d
```

### 3. Open dashboard
```
http://localhost
```

> If port `80` is already in use, open the dashboard at `http://localhost:8888` after adjusting `nginx` service ports in `docker-compose.yml`.

### 4. Load sample data
- Go to **Ingest Logs** in the sidebar
- Upload `sample-data/sample_logs.csv`
- Wait ~5 seconds, click **Refresh**
- Go to **Overview** — metrics and charts populate automatically

### 5. Train ML model
- Go to **ML Anomaly**
- Click **Train ML model**
- Click **Load anomalies** — see which IPs Isolation Forest flagged

---

## Features

### Dashboard pages

| Page | What it does |
|------|-------------|
| Overview | Metric cards, threat distribution chart, hot IP table |
| IP Trail | Full chronological event history for any IP |
| Live Alerts | All events from hot IPs, real-time |
| ML Anomaly | Train Isolation Forest, score IPs, list anomalies |
| Subnet Clusters | NetworkX graph clustering — finds coordinated attack groups |
| Blocklist | View, add, remove blocked IPs |
| Ingest Logs | Upload CSV or paste single JSON log event |

### Backend API endpoints

```
POST /api/ingest/csv              Upload a CSV log file
POST /api/ingest/log              Ingest a single JSON log
GET  /api/trail/{ip}              Full event trail for an IP
GET  /api/trail/{ip}/summary      Summary (first/last seen, threat types)
GET  /api/stats                   Global metrics
GET  /api/hot-ips                 All high/critical severity IPs
GET  /api/intel/{ip}              Threat intel (local + AbuseIPDB)
GET  /api/blocklist               View blocklist
POST /api/blocklist/add           Block an IP
DEL  /api/blocklist/{ip}          Unblock an IP
GET  /api/search?q=               Search IPs by prefix
GET  /api/reports/generate        Generate deterministic weekly/monthly SOC report
                                  ?timeframe=weekly|monthly&format=json|md|html|pdf
```

### ML Engine endpoints

```
POST /api/ml/train                Train Isolation Forest on all ingested IPs
GET  /api/ml/score/{ip}           Score a specific IP (anomaly + risk 0-100)
GET  /api/ml/anomalies            List all detected anomalies
GET  /api/ml/clusters             Subnet clustering (coordinated attack groups)
GET  /api/ml/health               Health + model status
```

### ML Intern endpoints

ML Intern is a separate service for model governance. It watches Redis, checks
hybrid retraining conditions, creates candidate model versions, and waits for
manual approval before a candidate becomes active.

```
GET  /api/ml-intern/health              Service health
GET  /api/ml-intern/status              Scheduler, trigger, and active model state
POST /api/ml-intern/retrain             Manual retraining trigger
GET  /api/ml-intern/models              All model versions and statuses
POST /api/ml-intern/approve-model/{id}  Promote candidate model to active
POST /api/ml-intern/rollback            Revert to previous approved model
GET  /api/ml-intern/reports/latest      Latest training report
```

Hybrid retraining checks run every few minutes. Retraining starts if **any**
condition is true:

- 24 hours passed since the last training
- new logs exceed the configured threshold
- feature distribution drift exceeds the configured drift threshold

---

## For live/continuous ingestion

### Option A — CyberSentinel Collector (alerts.json streamer, RECOMMENDED)
Directly tails the alert feed's `alerts.json` with smart offset tracking:
- **First run:** ingests entire alert history
- **After that:** only new alerts are ingested (no duplicates)
- **Auto-triggers:** ML training + archive after threshold

**As a Docker service:**
```bash
# 1. Set the path to your alerts.json in .env
WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json

# 2. Start the CyberSentinel Collector (wazuh profile)
docker compose --profile wazuh up -d
```

**Standalone:**
```bash
python scripts/wazuh_watcher.py \
  --alerts /var/ossec/logs/alerts/alerts.json \
  --api http://localhost:8000 \
  --interval 5
```

### Option B — Folder watcher
Point your SIEM to export logs to a folder, then run:
```bash
python scripts/watch_and_ingest.py \
  --folder /var/log/siem-exports \
  --api http://localhost:8000 \
  --interval 10
```

### Option C — Direct API push
From your agent / Fortigate log shipper, POST each event:
```bash
curl -X POST http://localhost:8000/api/ingest/log \
  -H "Content-Type: application/json" \
  -d '{"@timestamp":"2026-04-22T09:30:00Z","rule.description":"Login failed","data.ui":"85.11.187.36"}'
```

### Option D — Fortigate auto-block integration
```bash
python scripts/fortigate_autoblock.py \
  --cs-api http://localhost:8000 \
  --fg-host 192.168.1.1 \
  --fg-token YOUR_TOKEN \
  --dry-run     # remove --dry-run when ready for real blocks
```

---

## Hot/Cold Storage (Smart Memory Management)

Redis stays lean while no logs are ever lost:

| Layer | What | Retention |
|-------|------|-----------|
| **Redis (Hot)** | Last 200 events/IP + baselines + stats + ML scores | Always in memory |
| **Disk (Cold)** | ALL older events compressed as `.jsonl.gz` | Preserved forever |

### API endpoints
```
POST /api/archive/run                    Archive & trim ALL IP trails
POST /api/archive/ip/{ip}               Archive & trim single IP
GET  /api/archive/list                   List archive files with sizes
GET  /api/archive/search/{ip}?date=...  Search cold archive for old events
GET  /api/storage/stats                  Redis + disk usage summary
```

### Configure
```env
TRAIL_RETAIN=200          # events to keep in Redis per IP
WAZUH_ARCHIVE_THRESHOLD=5000  # auto-archive after N new alerts
```

---

## ML explanation

### Isolation Forest (anomaly detection)
- **What it does:** Trains on all IPs in Redis, learns what "normal" looks like
- **Features used:** event rate per minute, inter-event interval, unique dst IPs, unique dst ports, % critical/high severity, brute_force count, ssh_bf count, rdp count, db_scan count
- **Output:** anomaly score (negative = more anomalous) + risk score 0–100
- **Retrain:** POST /api/ml/train — do this after every major log ingestion

### ML Intern (hybrid retraining governance)
- **What it does:** monitors Redis and decides whether a new model should be trained
- **Hybrid triggers:** time elapsed, new log volume, or data drift
- **Output:** candidate model, metadata, anomaly rate, drift score, report summary
- **Approval:** candidate models are not auto-deployed; approve one with `/api/ml-intern/approve-model/{model_id}`
- **Rollback:** `/api/ml-intern/rollback` restores the previous approved model

### Subnet clustering (NetworkX)
- **What it does:** Builds a graph where IPs in the same /24 subnet are connected
- **Output:** connected components = coordinated attack groups
- **Why it matters:** The 85.11.x.x subnet (21 IPs, 1,769 events) is one cluster = one actor

---

## Adding AbuseIPDB live intel

1. Register free at https://www.abuseipdb.com/register
2. Copy your API key
3. Add to `.env`: `ABUSEIPDB_KEY=your_key`
4. `docker compose restart backend`
5. Now IP Trail → **+ Intel** shows live reputation scores

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| ABUSEIPDB_KEY | demo | AbuseIPDB API key for live threat intel |
| REDIS_HOST | redis | Redis hostname |
| REDIS_PORT | 6379 | Redis port |
| LOG_LEVEL | INFO | Backend log level |
| MODEL_RETRAIN_HOURS | 24 | ML auto-retrain interval (future) |
| ML_INTERN_CHECK_MINUTES | 5 | How often ML Intern checks retraining conditions |
| ML_INTERN_TIME_HOURS | 24 | Time-based retraining threshold |
| ML_INTERN_NEW_LOG_THRESHOLD | 10000 | Data-volume retraining threshold |
| ML_INTERN_DRIFT_THRESHOLD | 0.35 | Distribution drift threshold |
| ML_INTERN_MIN_TRAINING_IPS | 5 | Minimum IP feature rows needed to train |
| TRAIL_RETAIN | 200 | Events to keep in Redis per IP (rest archived to disk) |
| WAZUH_ALERTS_PATH | ./sample-data/alerts.json | Host path to the Collector's alerts.json feed |
| WAZUH_POLL_INTERVAL | 5 | Seconds between tail checks |
| WAZUH_BATCH_SIZE | 200 | Alerts per batch to backend |
| WAZUH_TRAIN_THRESHOLD | 500 | Trigger ML train after N new alerts |
| WAZUH_ARCHIVE_THRESHOLD | 5000 | Trigger archive/trim after N new alerts |

---

## Architecture

```
Browser
  ↓ :80
Nginx (reverse proxy)
  ↓ /api/ml/*        ↓ /api/ml-intern/*     ↓ /api/*         ↓ /
ML Engine :8001    ML Intern :8002       Backend :8000    Frontend :80
  ↓                   ↓                    ↓
  └────────────────── Redis :6379 ─────────┘
             (IP trails, stats,
              blocklist, ML scores,
              model metadata)
```

---

## Extending this

| What to add | How |
|-------------|-----|
| Real-time WebSocket push | Add FastAPI WebSocket endpoint, use `redis.pubsub()` |
| Email alerts for P1 | Add `smtplib` call in backend when severity=critical |
| Grafana dashboards | Redis → Prometheus exporter → Grafana |
| MISP integration | POST IOCs to MISP API from backend on each new hot IP |
| Elasticsearch backend | Replace Redis trail store with ES for full-text search |
| Agent log-shipper integration | Use your agent/SIEM Logstash output → POST to `/api/ingest/log` |
