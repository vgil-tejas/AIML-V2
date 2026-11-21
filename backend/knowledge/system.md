# CyberSentinel AI/ML — System Knowledge Base

This file is the single source of truth the SOC Query assistant reads to understand
our own product. It is indexed by a vectorless (BM25, word-by-word) retriever at
`backend/kb.py` and re-indexed automatically whenever this file changes — so to teach
the assistant something new, edit THIS file (no code change, no rebuild when mounted).

Each `##` / `###` section below is one retrievable chunk. A `page_id:` line under a
heading tells the assistant which console page to deep-link for that topic.

---

## What CyberSentinel AI/ML is

CyberSentinel AI/ML is an AI-native analytics layer that sits on top of a bank's SIEM.
It reads already-collected security events from the log store and adds machine-learning
risk scoring, behavioural baselines, user/identity analytics (UEBA), incident correlation,
MITRE ATT&CK kill-chain mapping, external threat-intel enrichment, and a natural-language
SOC Query console. It does not replace the SIEM and never changes how the SIEM collects
events — it is an intelligence layer over the same data. It is deployed at bank sites
(e.g. Buldhana and Aurangabad) and integrates with the enterprise SIEM over SSO and a
read-only alert feed.

## Architecture and data flow
page_id: overview

Logs flow: Collector → Normaliser → ClickHouse (the on-prem event store) → Risk Engine
+ Backend → dashboard. The Collector gathers events from Wazuh; the Normaliser maps them
to our canonical schema; ClickHouse stores them; the Risk Engine (ML) scores entities; the
Backend (FastAPI) serves the APIs; the dashboard (single-page app) renders everything.
The AI/ML layer only reads that store and adds analytics — it never alters ingestion.

### Services and containers

- `aiml_clickhouse` — ClickHouse 24.3, the log/event store (tables: logs, deviations,
  baselines, ml_scores, blocklist, incidents, cases/tags).
- `aiml_backend` — FastAPI backend: ingestion-read, IP trail, stats, baselines, ATT&CK,
  UEBA, incidents, SOC Query, intel, SIEM feed. Baked into its image (rebuild to apply
  code changes).
- `aiml_ml` — the Risk Engine (Isolation Forest) and auto-MLOps.
- `aiml_nginx` — the only externally exposed door; enforces the login gate via
  auth_request and proxies to the other services.
- `aiml_frontend` — the dashboard single-page app.
- `aiml_redis` — optional shared cache (fail-safe; the system runs without it).

The external port is nginx on 19888; the other services are localhost-bound sidecars so
nginx is the only entry point.

## Pages in the console

These are the places in the dashboard and what each one is for. Each maps to a deep-link
target (page_id).

### Overview
page_id: overview
The single-verdict command overview and attention list. One clear verdict plus the
entities that most need a human right now, and a continuously-running "threat forecast"
of the named detection use-cases. Start here.

### IP Trail
page_id: trail
The full event trail for a single IP — every event for that address on one timeline. This
is the real evidence behind a verdict. Open it on a specific IP to see what actually happened.

### Logs Explorer
page_id: logs
Raw, searchable log events — the ground-truth records, held on-prem. Use it to browse or
search the underlying events directly.

### Anomalies · ML
page_id: ml
The ML risk/anomaly score for an IP and the ranked anomaly list from the Risk Engine.
Shows which entities the Isolation Forest finds most anomalous.

### Deviations
page_id: deviations
Entities that broke their own learned baseline and were escalated for a human. This is the
attention queue of "something changed."

### Baseline Explorer
page_id: bslexplorer
The learned "normal" baseline per entity — event rates, usual ports, protocols and timing.

### UEBA · Identity
page_id: ueba
User and identity behaviour analytics — account takeover, impossible travel, and
peer-group outliers, with identity (not just IP) as a first-class entity.

### Incidents
page_id: incidents
Correlated incidents — scattered alerts stitched into one attack story, mapped onto the
MITRE ATT&CK kill chain and ranked by priority.

### Kill Chain
page_id: killchain
The MITRE ATT&CK kill-chain view for an attack — the tactics and techniques an attacker
moved through, for a given IP.

### Telemetry Intelligence
page_id: intelligence
The telemetry intelligence / novelty view — value drawn from the ~95% of logs that never
raise an alert (first-seen, novelty, rare combinations).

### SOC Query
page_id: nlquery
This natural-language query console. Ask in plain English; it answers product questions
from this knowledge base and data questions by running a validated read-only SQL query.

### AI Investigator
page_id: aiinvestigate
The AI investigator that writes up an entity for you — an auto-generated investigation
narrative for an IP, user or host.

### Responder · Playbooks
page_id: playbooks
Response playbooks and recommended remediation actions — the next steps to take on a
confirmed threat, including approval-gated actions and ATT&CK mitigations.

### Reports
page_id: reports
Exportable reports for management and handover (PDF / management summary).

## How the risk score works
page_id: ml

CyberSentinel's entity-risk is an absolute 0–100 score (roughly 60×points/(points+140)).
It is severity-weighted and time-decayed (72-hour half-life), plus concentration, recency
and spread, with a bump when external intel flags the entity. So a host with a few recent
critical events outranks a noisy host with only low-severity volume. The score is absolute,
not relative — it does not merely rank entities against each other.

## How the anomaly / ML engine works
page_id: ml

The Risk Engine is an unsupervised Isolation Forest (150 trees) over a 19-feature
behavioural vector. It fuses an anomaly score with baseline-deviation and threat-intel into
the 0–100 risk, flags behaviour that has no written rule, and auto-retrains on a rolling
window — that is how it catches novel and zero-day attacks without signatures. It is
unsupervised machine learning: no labelled training data and no hand-written rules are
required. When asked "which algorithm / model is running," the answer is the Isolation
Forest described here.

## How UEBA (user & identity behaviour) works
page_id: ueba

UEBA learns each identity's normal and flags: account-takeover (repeated failures then a
success, or a login from a new country), impossible travel (two logins too far apart in
space and time to be real), and peer-group outliers (a user behaving far from its peers,
z-score based). Identity — user or host — is treated as a first-class entity, not just an IP.

## How correlation and incidents work
page_id: incidents

Correlation is non-rule and statistical: related events are clustered into one incident
(including by network /24), mapped onto the MITRE ATT&CK kill chain, and ranked by a
priority score — so dozens of scattered alerts become one attack story. This is heuristic,
statistical and behavioural correlation, not signature correlation.

## How baselines and deviations work
page_id: bslexplorer

A baseline is the learned "normal" for an entity (event rates, ports, protocols, timing).
A deviation is when an entity breaks its own baseline; deviations are escalated for a human
on the Deviations view. Baselines need roughly 2–4 weeks of history to become statistically
meaningful.

## How threat-intel enrichment works
page_id: intelligence

Enrichment checks an IP against external sources (AbuseIPDB, VirusTotal, GreyNoise, OTX,
Shodan) for reputation — cache-first, orchestrated on-prem, fail-soft, and only on an
explicit lookup. It enriches the picture; it does not itself block anything. External keys
live in the server .env and a source with no key is simply skipped.

## Detection use-cases (threat forecast)
page_id: overview

17+ named detection use-cases run continuously as a "threat forecast" on the Overview —
out of the box, with no rule authoring required. They cover heuristic, statistical and
behavioural threat categories.

## How SOC Query answers questions
page_id: nlquery

SOC Query first decides whether a message is a product/help question or a data question.
Product questions are answered from this knowledge base (retrieved word-by-word, not
guessed). Data questions are turned into a validated, read-only SQL query, run on-premise,
and answered strictly from the returned rows — it will not invent facts — with the evidence
one click away. A conversational LLM front-brain understands free phrasing but is given only
sanitised text and this product knowledge; it never sees event data.

## Privacy and data protection
page_id: nlquery

Before anything is sent to the external LLM, real IPs, emails, usernames (and hosts and ID
numbers) are swapped for harmless decoys locally and restored on return — pseudonymisation,
not hashing. By default log rows are not sent at all; the answer is written on-premise.
Queries, scoring, evidence retrieval and verdicts stay on the box. Raw bank logs, internal
IPs, usernames, customer data, credentials and SQL results are never sent to the external
model. The system supports local-only operation.

## SIEM integration — single sign-on (SSO)
page_id: overview

Analysts can single-sign-on from the enterprise SIEM: the SIEM authenticates the operator
and redirects the browser to `/auth/sso#token=<JWT>`; the landing page reads the token from
the URL fragment and posts it to the backend, which verifies the signature, issuer,
audience, purpose, expiry and a single-use nonce, maps the SIEM role to ours, creates the
user on first login, and mints the session cookie — no second password prompt. SSO is inert
until its signing secret/key is configured, so it ships safely dark.

## SIEM integration — read-only alert feed
page_id: overview

Our alerts are exposed to the SIEM over a read-only API (`/api/siem/alerts`) that the SIEM
polls every few minutes and lists in its Attention queue. It is authenticated with a
dedicated read-only token — never the operator login cookie — and supports an incremental
"only new since <id or time>" cursor. Each alert carries id, time, entity, score, severity,
verdict, use-case and a deep link back into our console. The feed is inert until its token
is configured.

## SIEM integration — log-source silence watchdog (SR 64)
page_id: deviations

A watchdog alerts when a watch-listed server that must always send logs goes silent for
more than five minutes. It is a watch-list (not every host), so laptops powering off never
raise an alarm. When a watch-listed server stops sending, it raises a high-severity
"log source silence" alert; when it resumes, it clears with an informational alert. These
alerts flow to the SIEM through the read-only alert feed.

## How to extend this knowledge base

To teach the assistant about a new feature or concept, add a new `##` or `###` section to
this file with a clear heading, a one-line `page_id:` pointing at the right console page,
and a few plain sentences. The retriever re-indexes automatically on the next query. Keep
each section self-contained (it is retrieved on its own) and written the way an analyst
would ask about it.
