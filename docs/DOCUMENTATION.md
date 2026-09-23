# CyberSentinel — Product & Architecture Documentation

> **CyberSentinel** is an AI-native SIEM / SOC analytics platform. It ingests
> high-volume security telemetry, normalises it into a single schema, scores it
> with machine-learning and behavioural models, maps it to the MITRE ATT&CK
> kill chain, and presents a SOC analyst with a small number of prioritised
> decisions instead of a flood of raw alerts.
>
> This document explains **what each part is and how it works**, end to end.

---

## Table of contents

1. [What CyberSentinel is](#1-what-cybersentinel-is)
2. [Architecture at a glance](#2-architecture-at-a-glance)
3. [The data pipeline, stage by stage](#3-the-data-pipeline-stage-by-stage)
   - 3.1 [CyberSentinel Collector](#31-cybersentinel-collector-ingestion)
   - 3.2 [CyberSentinel Normaliser](#32-cybersentinel-normaliser)
   - 3.3 [The Event Store](#33-the-event-store)
4. [The analytics engines](#4-the-analytics-engines)
   - 4.1 [Risk Engine (ML anomaly)](#41-risk-engine--ml-anomaly)
   - 4.2 [UEBA — user & entity behaviour](#42-ueba--user--entity-behaviour)
   - 4.3 [ATT&CK & kill-chain engine](#43-attck--kill-chain-engine)
   - 4.4 [Incident correlation](#44-incident-correlation)
   - 4.5 [Detection catalog & threat forecast](#45-detection-catalog--threat-forecast)
   - 4.6 [Telemetry intelligence](#46-telemetry-intelligence)
   - 4.7 [AI investigator & natural-language query](#47-ai-investigator--natural-language-query)
   - 4.8 [Response playbooks & case workbench](#48-response-playbooks--case-workbench)
5. [The dashboard](#5-the-dashboard)
6. [Security & access control](#6-security--access-control)
7. [Deployment & operations](#7-deployment--operations)
8. [Performance at scale](#8-performance-at-scale)
9. [Configuration reference](#9-configuration-reference)
10. [Glossary](#10-glossary)

---

## 1. What CyberSentinel is

A bank or enterprise SOC drowns in alerts: hundreds of thousands to millions of
security events per day, most of them noise. CyberSentinel sits on top of that
firehose and answers three questions a SOC lead actually cares about:

- **Who should I look at first?** — a ranked, risk-scored watch-list of entities.
- **Why?** — a plain-English narrative fusing every engine's signal, mapped to
  the ATT&CK kill chain.
- **What could happen next?** — a forward-looking threat forecast projecting
  live detections to their likely next stage.

It does this with **in-built AI/ML models** (unsupervised anomaly detection plus
per-user behavioural baselining) rather than static rules alone, so it catches
novel and low-and-slow attacks a signature would miss.

**Deployed at:** Buldhana Urban Co-op Bank, Aurangabad — with further bank
rollouts planned.

---

## 2. Architecture at a glance

CyberSentinel is a set of containers that form one pipeline: **collect →
normalise → store → analyse → serve.**

```
  Security telemetry feed                    CyberSentinel platform
  (agent / EDR / HIDS alerts,
   JSON alert stream)
 ┌───────────────────────┐
 │  alerts feed          │   read-only
 │  (100k–millions/day)  │─────────────►  ┌──────────────────────────┐
 └───────────────────────┘                │  CyberSentinel Collector │  tail + filter + spool
                                          │  CyberSentinel Normaliser│  flatten + classify + map
                                          └────────────┬─────────────┘
                                                       │ bulk insert
                                                       ▼
                                          ┌──────────────────────────┐
                                          │       Event Store        │  columnar, day-partitioned
                                          │  logs + rollup views     │  (ClickHouse)
                                          └───┬───────────┬──────────┘
                                    read SQL  │           │  read SQL
                                              ▼           ▼
                                   ┌──────────────┐  ┌──────────────┐
                                   │  Risk Engine │  │   Backend    │  analytics + API (FastAPI)
                                   │  (ML anomaly)│  │  • UEBA      │
                                   └──────────────┘  │  • ATT&CK    │
                                                     │  • incidents │
                                                     │  • detections│
                                                     └──────┬───────┘
                                                            │ /api/*
                                                            ▼
                                                     ┌──────────────┐
                                                     │   Gateway    │  reverse proxy + login gate (nginx)
                                                     └──────┬───────┘
                                                            ▼
                                                     ┌──────────────┐
                                                     │  Dashboard   │  SOC UI (static HTML/JS)
                                                     └──────────────┘
```

### Components

| Component | Container | Role |
|-----------|-----------|------|
| **CyberSentinel Collector** | `aiml_wazuh_watcher` | Tails the alert feed, applies a smart filter, batches, disk-spools for zero loss, and bulk-inserts into the Event Store. Started with the `wazuh` compose profile. |
| **CyberSentinel Normaliser** | *(runs inside the Collector)* | Flattens nested alert JSON, classifies `threat_type` + `severity`, extracts ATT&CK tactic/technique, geo, process and file-integrity fields, and maps everything to the 39-column event schema. |
| **Event Store** | `aiml_clickhouse` | Columnar log store (ClickHouse). Day-partitioned, ZSTD-compressed, with materialised rollup views for millisecond dashboards. Holds the source-of-truth `logs` table. |
| **Risk Engine** | `aiml_ml` | Unsupervised anomaly scoring (Isolation Forest) fused with baseline-deviation and threat-intel signals into a 0–100 per-entity risk score. Auto-retrains. |
| **Backend** | `aiml_backend` | FastAPI application. Runs UEBA, ATT&CK mapping, incident correlation, the detection catalog, telemetry intelligence, NL query and playbooks; serves all `/api/*` endpoints. |
| **Gateway** | `aiml_nginx` | Reverse proxy and single login gate. `/`→Dashboard, `/api/`→Backend, `/api/ml/`→Risk Engine. Enforces the session cookie on every request. |
| **Dashboard** | `aiml_frontend` | The SOC analyst UI — static HTML/JS served behind the gateway. |

All sidecar service ports bind to `127.0.0.1` only; the **Gateway is the single
external door** (default host port `19888`).

---

## 3. The data pipeline, stage by stage

### 3.1 CyberSentinel Collector (ingestion)

**Source:** `scripts/wazuh_watcher.py` · **Container:** `aiml_wazuh_watcher`

The Collector is a lightweight, fully decoupled ingestor. It reads the alert
feed read-only and never modifies the source.

- **Byte-offset tail** — it reads the alert file (default source path
  `/var/ossec/logs/alerts/alerts.json`) and tracks a byte offset on disk, so on
  restart it resumes exactly where it stopped. Log rotation at midnight is
  handled by mounting the *directory*, not the file.
- **Smart filter** — tames hundreds of thousands of events per hour. By policy
  it keeps every event at rule level ≥ 1 (no dropping) in production, but the
  filter is fully tunable: drop below a floor, sample the mid band 1-in-N, keep
  all high-severity.
- **Batch + disk spool (zero loss)** — events accumulate into batches (default
  5000) and are inserted durably. If the Event Store is briefly unreachable, the
  batch is written to a disk spool and replayed on recovery. **The read offset
  only advances once a batch is durably stored** — so no event is ever lost
  across a store restart or outage.
- **Triggers** — after batches it nudges the Backend to refresh behavioural
  baselines and the Risk Engine to retrain, and periodically archives.

Because the Collector is decoupled, **if ingestion stops the rest of the
platform keeps serving stored data with no impact.**

> **Manual / API ingestion** — CSV and JSON can also be pushed directly via
> `POST /api/ingest/csv | bulk | log`; the Backend builds the same normalised
> row shape, so every path lands in one consistent schema.

### 3.2 CyberSentinel Normaliser

**Source:** the `flatten_wazuh` → `map_to_row` logic inside the Collector.

Raw security alerts arrive as deeply-nested, inconsistent JSON. The Normaliser
turns each one into a single flat, analysis-ready row:

- **Flatten** — recursively flattens nested alert JSON into dotted keys
  (`rule.groups`, `data.srcip`, `data.win.eventdata.…`).
- **Classify severity** — from the rule level: 12+ → `critical`, 8+ → `high`,
  4+ → `medium`, else `low`.
- **Classify `threat_type`** — keyword-matches the rule groups + description +
  compliance tags to a canonical type: `ssh_bruteforce`, `vpn_bruteforce`,
  `rdp_relay`, `brute_force`, `privilege_escalation`, `db_scan`, `malware`,
  `web_attack`, `recon_scan`, `known_malicious`, `login_success` (else
  `unknown`).
- **Extract rich signal** — pulls the fields the analytics need: ATT&CK
  tactic/technique, source geo (lat/lon + country), process image / parent /
  command line, Windows logon type, target user, file-integrity (FIM) path /
  event / hash, firewall policy id, and compliance tags (PCI-DSS, GDPR, HIPAA,
  NIST).
- **Map to schema** — writes all of it into the 39-column event row (see below),
  preserving the full raw alert JSON in a `raw` column so no data is ever lost.

This normalisation is what lets every downstream engine speak one language,
regardless of which product emitted the original alert.

### 3.3 The Event Store

**Source:** `clickhouse/init/01-schema.sql` · **Container:** `aiml_clickhouse`

A columnar store (ClickHouse) tuned for security telemetry at scale.

**`cybersentinel.logs`** — the source of truth. One row per event, 39 columns.

- **Engine:** `MergeTree`, `PARTITION BY toYYYYMMDD(ts)` (per-day partitions →
  instant, cheap retention drops), `ORDER BY (src_ip, ts)` (per-IP trails are
  the hot path).
- **Compression:** `LowCardinality` + `ZSTD` keeps hundreds of millions of rows
  small on disk.
- **Retention (TTL):** low/medium events drop after 90 days, everything after
  180 days.

Selected columns: `ts`, `src_ip`, `dst_ip`, `dst_port`, `threat_type`,
`severity`, `rule`, `rule_id`, `rule_level`, `action`, `country`, `agent`,
`username`, `target_user`, `logon_type`, `mitre_tactic`, `mitre_technique`,
`proc_image`, `proc_parent`, `proc_cmdline`, `sc_path/sc_event/sc_sha256` (FIM),
`geo_lat/geo_lon`, `url`, `policy_id`, plus compliance tags and the full `raw`
alert.

**Rollup views** — materialised views aggregate at insert time so dashboards
never scan raw rows:

- `agg_ip_daily` (via `mv_ip_daily`) — per day/IP/threat/severity counts. Powers
  top-IPs, threat counts, unique-IP counts, per-IP summaries in milliseconds.
- `agg_threat_hourly` (via `mv_threat_hourly`) — the hourly threat trend chart.

**State tables** (no logs, small): `baselines`, `deviations`, `blocklist`,
`ml_scores`, SOAR `playbook_runs` / `cases` / `entity_tags`, `alert_feedback`,
and auth `cs_users` / `cs_auth_audit`.

---

## 4. The analytics engines

Everything below reads the Event Store and turns raw events into decisions.

### 4.1 Risk Engine — ML anomaly

**Source:** `ml-engine/main.py` · **Container:** `aiml_ml`

A single fused **0–100 risk score per source IP**, combining three signals:

1. **Anomaly** — an **Isolation Forest** (unsupervised ML) over a 19-feature
   behavioural vector per IP: event counts and rates, inter-arrival intervals,
   unique destination IPs/ports/countries, %-critical/high, and per-threat-type
   counts (brute force, SSH/VPN brute, RDP, DB scan, privilege escalation,
   known-bad).
2. **Deviation** — baseline-deviation alerts already raised for that entity.
3. **Threat-intel** — membership in known-bad subnets.

The model **auto-retrains** every 24 hours (or after 10k new events), caches the
model in memory, and persists scores to `ml_scores`. It also does **subnet
clustering** to surface coordinated/botnet campaigns. Everything runs on a
thread pool with a bounded connection semaphore so scoring never blocks the API.

### 4.2 UEBA — user & entity behaviour

**Source:** `backend/ueba.py`

Treats **users and hosts as first-class entities** and scores each against
**their own 30-day baseline** (the Exabeam/Securonix model): *what did this
identity do in the last 24h that it has never done before?* Additive,
plain-English risk drivers, capped at 100:

- **New host** — accessed a machine never seen in the baseline (lateral-movement
  tell).
- **New country** — activity from a country never seen for this account.
- **Off-hours** — active outside the account's usual working window (IST).
- **Volume spike** — 24h event count far above the account's daily average.
- **Takeover pattern** — many failed logins followed by a success.
- **Critical hits**, **impossible travel** (geo-velocity faster than any
  flight), and **peer-group outlier** (z-score vs the user population).

Standalone detectors back these: `detect_account_takeover` (failure burst →
success, or new-country login) and `detect_impossible_travel` (same identity in
two far-apart places too fast, including simultaneous multi-country presence).

### 4.3 ATT&CK & kill-chain engine

**Source:** `backend/threat_intel.py`

A curated, offline **MITRE ATT&CK knowledge base** focused on the techniques a
banking SIEM actually sees (brute force T1110, valid accounts T1078, remote
services T1021, privilege escalation T1068, discovery T1046, exploit-public-app
T1190, ransomware T1486, malware T1204, C2 T1071, …). For each technique it
holds a summary, banking context, detection guidance, real-world mitigations and
"how the world responds."

It maps each event's `threat_type` → ATT&CK technique → tactic, lays the tactics
along the **14-stage ATT&CK order** and overlays them on the classic **7-stage
Lockheed Cyber Kill Chain**. This same layer **grounds the AI** narratives (a
retrieval step, so the model cites real technique docs rather than hallucinating).

### 4.4 Incident correlation

**Source:** `backend/incidents.py`

Turns hundreds of per-entity signals into a handful of **correlated incidents**:

- A single risky IP with a multi-stage kill chain → a **host** incident.
- Multiple IPs in the same /24 active in an overlapping window → a **campaign**
  incident (coordinated/botnet).
- UEBA identity findings (takeover, impossible travel) attach to the incident
  they share, or stand alone as **identity** incidents.

Each incident gets a **0–100 priority** (fusing risk, kill-chain depth, campaign
breadth, whether it reached lateral movement, and identity impact) and a
**plain-English narrative**. This is the layer that converts alert-fatigue into
a short triage queue.

### 4.5 Detection catalog & threat forecast

**Source:** `backend/detections.py` · **API:** `/api/detections`

A catalog of **17 named detection use-cases** — each mapped to a concrete
in-built detector, its ATT&CK technique, and a "what this attack leads to"
narrative. Every use-case reports a live status: **active** (firing now, with the
offending entities) or **monitoring** (armed, zero current hits).

| Code | Use-case | Engine |
|------|----------|--------|
| UC-A | Password spraying / user enumeration / brute force | Auth-abuse analytic + UEBA |
| UC-B | Account takeover or credentialed access | UEBA takeover model |
| UC-C | Unauthorised activity during non-business hours | UEBA baseline |
| UC-D | Lateral movement with a compromised account | Remote-service analytic |
| UC-E | Unusual / rare username in auth logs | Rare-entity baseline |
| UC-F | Suspicious login activity | Composite login-risk |
| UC-G | Rare and unusual errors | Rare-signature frequency |
| UC-H | Anomalous network activity | Isolation Forest anomaly model |
| UC-I | C2 / persistence / data exfiltration | IOC + ATT&CK tactic |
| UC-J / UC-M | Unauthorised software / malware / persistence | Malware + file-integrity |
| UC-K | Unusual network destination (C2) | Known-bad egress |
| UC-L | Denial-of-service / traffic floods | Rate-spike analytic |
| UC-N | Rare user: credentialed access / lateral movement | Rare-entity + auth join |
| UC-O | Credential harvesting via cloud metadata service | Metadata-access analytic |
| UC-P | Unusual user context switches (privilege escalation) | Context-switch analytic |
| UC-Q | Unusual RDP user logins | RDP logon analytic |

On the **Overview dashboard**, this powers the **Threat Forecast** panel: for
every use-case firing now, it shows the detection and projects it forward —
*"Detected now → ⚠ Could lead to …"* — so an analyst sees not just what is
happening but what it will become if unchecked. The endpoint is cached,
single-flighted and background-warmed so it never slows the dashboard.

### 4.6 Telemetry intelligence

**Source:** `backend/telemetry_intel.py` · **API:** `/api/telemetry/*`

Value from the **95% of logs that never fire an alert**: silent/degraded agents,
first-seen ledgers (new users, hosts, destinations), and other passive signals
that update in real time on every insert.

### 4.7 AI investigator & natural-language query

**Source:** backend NL/investigator endpoints.

- **AI Investigator** — writes the incident narrative from real fused scores
  (grounded by the ATT&CK layer, never a static string).
- **SOC Query (NL → SQL)** — an analyst asks in plain English; the model writes a
  **SELECT-only, validated** query against the Event Store, runs it, and returns
  a grounded answer with the SQL shown. Hardened so it cannot mutate data or
  hallucinate numbers.

### 4.8 Response playbooks & case workbench

**Source:** `backend/playbooks.py`, `playbook_recommender.py`

- **Playbooks** — customer-editable YAML response playbooks matched to incidents;
  every run is logged to a replayable ledger with a blast-radius estimate.
- **Case workbench** — turns incidents into trackable cases (New → Investigating
  → Contained → Closed). Every action is audit-logged; closing requires a
  disposition, and that verdict trains the feedback loop that suppresses noisy
  alert types over time.

---

## 5. The dashboard

**Source:** `frontend/` (served at the Gateway, default `:19888`).

A single-page SOC console with a "Neural Spine" sidebar. Main sections:

- **Overview** — the AI verdict, the risk-ranked "start here" queue, the
  **Threat Forecast**, kill-chain progression and live wire.
- **Incidents** — the correlated triage queue, ATT&CK coverage, risk watch-list,
  and the case workbench.
- **Deviations / UEBA / Anomalies** — baseline deviations, per-user risk and
  identity findings, and the ML anomaly list.
- **IP Trail / Logs Explorer** — per-entity history and a fast raw-log explorer.
- **Intelligence / Kill Chain / Responder / Reports** — telemetry intelligence,
  ATT&CK view, playbooks, and exportable reports.

The Overview is a self-contained deck; the rest are lazy-loaded and
background-prefetched so tab switches are instant.

---

## 6. Security & access control

- **Single login gate** — the Gateway runs an `auth_request` subrequest against
  the Backend's `/api/auth/verify` on every call. No cookie → pages bounce to
  `/login.html`, API calls get a plain 401. The dashboard cannot be reached
  without a valid session. Sidecar ports are localhost-bound so the Gateway is
  the only door.
- **Session cookie** — a signed, HttpOnly, `SameSite=Lax` cookie minted by
  `backend/auth.py`; `Secure` follows the scheme (off on plain-HTTP LAN).
- **SIEM SSO (optional)** — a fragment-based single-sign-on: the upstream SIEM
  mints a short-lived signed JWT and redirects the browser to
  `/auth/sso#token=<JWT>`; the landing page reads the token from the URL
  fragment (never sent to a server) and POSTs it to `/api/auth/sso/validate`,
  which verifies claims (issuer, audience, single-use nonce, expiry) and mints a
  session + JIT-provisions the user. HS256 shared-secret today; RS256/JWKS is the
  planned Phase 2.
- **No production log store is ever touched** — the platform reads only its own
  Event Store; upstream production log systems are strictly off-limits.

---

## 7. Deployment & operations

**Topology** — one Docker Compose stack, all services building from source
images. The **Gateway** publishes the only external port (`19888` by default);
every other service binds to `127.0.0.1`.

**Workflow** — develop → push to GitHub → `git pull` on the server → rebuild.
Because every service uses baked images, config/file changes require `--build`.

```bash
# On the server (install dir, e.g. /tejas/aiml):
git pull
docker compose up -d --build            # core stack
docker compose --profile wazuh up -d    # add the Collector (ingestion)
```

**Ports** (host side, `19xxx` family): Gateway `19888`, Backend `19110`
(localhost), Risk Engine `19111` (localhost), Event Store `19123/19000`
(localhost), Dashboard `19180` (localhost).

**Health & resilience** — every service has a healthcheck and
`restart: unless-stopped`. The Collector is decoupled (ingestion can stop with
no impact on serving); disk-spool + acked inserts mean no log loss across
restarts; the Backend degrades gracefully (returns empty, never crashes) if the
Event Store is briefly unreachable.

**Isolated demo stack** — a completely separate `aimldemo` stack (project name
`aimldemo`, its own empty volume and network, URL `:29888`) exists for buyer
demos so demo activity can never touch the production store. Start with
`docker compose -f docker-compose.demo.yml up -d --build`.

**Scoped uninstall** — `scripts/uninstall.sh` removes only the CyberSentinel
containers, volumes and images, never co-tenant services on a shared host.

---

## 8. Performance at scale

CyberSentinel runs at **100M+ events** on a host it may share with other teams'
services. Several deliberate choices keep the dashboard fast:

- **Rollup-backed reads** — dashboard KPIs read the materialised rollup tables,
  not the raw `logs` table.
- **Cache + single-flight + background warm** — hot endpoints (`/api/stats`,
  `/api/overview`, incidents, detections) are cached, collapse concurrent
  recomputes into one, serve a stale copy while refreshing, and are warmed by a
  background loop — so a cache miss never storms the store and the boot path is
  never blocked.
- **Bounded read budget** — every query runs under a time / row / thread budget;
  a runaway query is killed rather than allowed to starve the store.
- **Tunable parallelism** — `READ_MAX_THREADS` sets how many cores a heavy query
  may use. Default is conservative (4); on a large host raise it (e.g. 16 on an
  80-core box) so 100M-row scans finish fast.
- **CPU scheduling priority** — on a shared host the Event Store and Backend are
  given a higher `cpu_shares` weight so co-tenant services can't starve them
  under contention.
- **Latest-not-scan for logs** — the Logs Explorer default uses a day-walk
  "latest" query (1d→7d→30d→1y, returns as soon as it finds rows) instead of an
  all-time scan.

---

## 9. Configuration reference

Configuration is via `.env` (never committed — it holds secrets). Key knobs:

| Variable | Purpose |
|----------|---------|
| `CLICKHOUSE_PASS` | Event Store password (also used by Backend / Risk Engine / Collector). |
| `CLICKHOUSE_MEM_LIMIT` | Event Store memory limit (recommend ≥ 24G at 100M+). |
| `READ_MAX_THREADS` | Cores per heavy query (raise on a big host). |
| `READ_MAX_SECONDS` | Per-query kill budget. |
| `CLICKHOUSE_CPU_SHARES` / `BACKEND_CPU_SHARES` | CPU scheduling weight on a shared host. |
| `AUTH_USER` / `AUTH_PASS` / `AUTH_SECRET` | Login gate credentials + cookie signing key. |
| `SSO_SECRET` / `SSO_ISS` / `SSO_AUD` | SIEM SSO shared secret and issuer/audience (empty → SSO off). |
| `AI_API_KEY` / `AI_MODEL` / `AI_BASE_URL` | LLM provider for narratives / NL query (external egress, on-demand only). |
| `WAZUH_ALERTS_DIR` / `WAZUH_ALERTS_FILENAME` | Collector source path for the alert feed. |
| `WAZUH_BATCH_SIZE` / `WAZUH_MIN_LEVEL` / `WAZUH_SAMPLE_*` | Collector batching and smart-filter policy. |

> The `WAZUH_*` variables are the Collector's internal configuration keys (kept
> for deployment compatibility); the component is branded **CyberSentinel
> Collector** in all product and analyst-facing surfaces.

---

## 10. Glossary

| Term | Meaning |
|------|---------|
| **CyberSentinel Collector** | The ingestion component — tails the alert feed, filters, spools, and inserts into the Event Store. |
| **CyberSentinel Normaliser** | The normalisation stage — flattens, classifies and maps raw alerts into the unified 39-column schema. |
| **Event Store** | The columnar log store (ClickHouse) holding the `logs` table and rollups. |
| **Risk Engine** | The ML anomaly-scoring service (Isolation Forest + fusion). |
| **UEBA** | User & Entity Behaviour Analytics — per-user 30-day baseline scoring. |
| **Kill chain** | The ATT&CK / Lockheed stage progression an intrusion moves through. |
| **Incident** | A correlated group of signals (host / campaign / identity) with a priority and narrative. |
| **Detection catalog** | The 17 named detection use-cases and their live status. |
| **Threat forecast** | The Overview panel projecting live detections to their likely next attack stage. |
| **Gateway** | The nginx reverse proxy + single login gate. |

---

*This document reflects the current architecture. For failure→fix runbook steps
see `RUNBOOK.md`; for scale/deploy detail see `docs/PROD_SCALE_AND_DEPLOY.md`.*
