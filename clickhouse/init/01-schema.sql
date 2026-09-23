-- ============================================================================
-- CyberSentinel — ClickHouse schema (auto-applied on first container init)
-- Runs from /docker-entrypoint-initdb.d on a FRESH data volume only.
-- To re-apply after changes on an existing volume, run manually:
--   docker exec -i aiml_clickhouse clickhouse-client --multiquery < clickhouse/init/01-schema.sql
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cybersentinel;

-- ── Source of truth: every ingested alert ──────────────────────────────────
-- Partitioned by day so retention drops are instant (drop a partition).
-- ORDER BY (src_ip, ts) makes per-IP trail/queries — the hot path — very fast.
-- LowCardinality + ZSTD keeps crores of rows small on disk.
CREATE TABLE IF NOT EXISTS cybersentinel.logs
(
    ts           DateTime64(3)            DEFAULT now64(3),
    ingested_at  DateTime64(3)            DEFAULT now64(3),
    src_ip       String,
    dst_ip       String                   DEFAULT '',
    dst_port     String                   DEFAULT '',
    threat_type  LowCardinality(String)   DEFAULT 'unknown',
    severity     LowCardinality(String)   DEFAULT 'low',
    rule         String                   DEFAULT '',
    rule_id      String                   DEFAULT '',
    rule_level   UInt8                    DEFAULT 0,
    action       String                   DEFAULT '',
    country      LowCardinality(String)   DEFAULT '',
    agent        LowCardinality(String)   DEFAULT '',
    mitre        String                   DEFAULT '',
    username     String                   DEFAULT '',
    useragent    String                   DEFAULT '',
    signature    String                   DEFAULT '',
    url          String                   DEFAULT '',   -- blocked/contacted URL, domain or DNS query (the destination NAME)
    -- ── Phase 1: richer Wazuh signal (previously discarded) ──────────────
    mitre_tactic    String                 DEFAULT '',   -- ATT&CK tactic name(s)
    mitre_technique String                 DEFAULT '',   -- ATT&CK technique name(s)
    rule_groups     String                 DEFAULT '',   -- Wazuh rule.groups
    rule_firedtimes UInt32                 DEFAULT 0,    -- how often this rule fired
    pci_dss         String                 DEFAULT '',   -- compliance tags
    gdpr            String                 DEFAULT '',
    hipaa           String                 DEFAULT '',
    nist            String                 DEFAULT '',
    proc_image      String                 DEFAULT '',   -- process / image
    proc_parent     String                 DEFAULT '',   -- parent process
    proc_cmdline    String                 DEFAULT '',   -- command line
    logon_type      LowCardinality(String) DEFAULT '',   -- Windows logon type
    target_user     String                 DEFAULT '',   -- targeted account
    sc_path         String                 DEFAULT '',   -- syscheck (FIM) path
    sc_event        LowCardinality(String) DEFAULT '',   -- added | modified | deleted
    sc_sha256       String                 DEFAULT '',   -- file hash after change
    geo_lat         Float64                DEFAULT 0,    -- geo of src_ip
    geo_lon         Float64                DEFAULT 0,
    decoder         LowCardinality(String) DEFAULT '',   -- Wazuh decoder name
    location        String                 DEFAULT '',   -- log source path
    full_log        String                 DEFAULT '',   -- raw log line (for embeddings)
    raw             String                 DEFAULT '',   -- full alert JSON (never-lose-data)
    policy_id       LowCardinality(String) DEFAULT ''    -- firewall policy that matched (data.policyid)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src_ip, ts)
TTL
    toDateTime(ts) + INTERVAL 90 DAY  DELETE WHERE severity IN ('low', 'medium', 'unknown', ''),
    toDateTime(ts) + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

-- ── Rollup: per-IP / per-day / per-threat / per-severity counts ────────────
-- Powers the dashboard (top IPs, threat counts, unique IPs, per-IP summaries)
-- by scanning a few thousand rollup rows instead of crores of raw rows.
CREATE TABLE IF NOT EXISTS cybersentinel.agg_ip_daily
(
    day          Date,
    src_ip       String,
    threat_type  LowCardinality(String),
    severity     LowCardinality(String),
    events       UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, src_ip, threat_type, severity)
TTL day + INTERVAL 730 DAY;                   -- keep rollups 2 years

CREATE MATERIALIZED VIEW IF NOT EXISTS cybersentinel.mv_ip_daily
TO cybersentinel.agg_ip_daily AS
SELECT
    toDate(ts)  AS day,
    src_ip,
    threat_type,
    severity,
    count()     AS events
FROM cybersentinel.logs
GROUP BY day, src_ip, threat_type, severity;

-- ── Rollup: hourly threat trend (for time-series charts) ───────────────────
CREATE TABLE IF NOT EXISTS cybersentinel.agg_threat_hourly
(
    hour         DateTime,
    threat_type  LowCardinality(String),
    severity     LowCardinality(String),
    events       UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, threat_type, severity)
TTL hour + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS cybersentinel.mv_threat_hourly
TO cybersentinel.agg_threat_hourly AS
SELECT
    toStartOfHour(ts) AS hour,
    threat_type,
    severity,
    count()           AS events
FROM cybersentinel.logs
GROUP BY hour, threat_type, severity;

-- ── State tables (replace Redis) ───────────────────────────────────────────
-- Behavioural baseline per IP. ReplacingMergeTree keeps the newest by built_at.
CREATE TABLE IF NOT EXISTS cybersentinel.baselines
(
    ip        String,
    built_at  DateTime64(3) DEFAULT now64(3),
    data      String                              -- JSON baseline blob
)
ENGINE = ReplacingMergeTree(built_at)
ORDER BY ip;

-- Deviation alerts. One row per (ip,type), newest wins (matches old alert:ip:type key).
CREATE TABLE IF NOT EXISTS cybersentinel.deviations
(
    ip        String,
    type      LowCardinality(String),
    severity  LowCardinality(String),
    message   String,
    details   String,                             -- JSON
    ts        DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (ip, type)
TTL toDateTime(ts) + INTERVAL 180 DAY;

-- Blocklist. active=1 blocked, active=0 unblocked; newest added_at wins.
CREATE TABLE IF NOT EXISTS cybersentinel.blocklist
(
    ip        String,
    kind      LowCardinality(String),             -- auto | manual
    active    UInt8 DEFAULT 1,
    added_at  DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(added_at)
ORDER BY ip;

-- Unified per-IP risk scores (Risk Engine output; replaces Redis ml:score:*).
-- ReplacingMergeTree keeps the newest score per IP.
CREATE TABLE IF NOT EXISTS cybersentinel.ml_scores
(
    ip            String,
    risk_score    UInt8,                           -- 0-100 fused risk
    anomaly_score Float64,                          -- Isolation Forest decision fn
    is_anomaly    UInt8,
    components    String,                           -- JSON breakdown of risk drivers
    scored_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(scored_at)
ORDER BY ip;

-- ── SOAR: playbook ledger / cases / entity tags ────────────────────────────
-- The "ops tool" layer: every response playbook run is logged here (replayable
-- ledger), cases turn incidents into trackable work, tags annotate entities.
CREATE TABLE IF NOT EXISTS cybersentinel.playbook_runs
(
    run_id       String,
    playbook_id  String,
    incident_id  String,
    entity       String,
    status       LowCardinality(String),
    approved_by  String DEFAULT '',
    steps        String,
    blast_radius String DEFAULT '',
    created_at   DateTime64(3) DEFAULT now64(3),
    updated_at   DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY run_id;

CREATE TABLE IF NOT EXISTS cybersentinel.cases
(
    case_id     String,
    title       String,
    incident_id String DEFAULT '',
    entity      String DEFAULT '',
    severity    LowCardinality(String) DEFAULT 'medium',
    status      LowCardinality(String) DEFAULT 'open',
    assignee    String DEFAULT '',
    disposition String DEFAULT '',
    notes       String DEFAULT '',
    created_by  String DEFAULT '',
    created_at  DateTime64(3) DEFAULT now64(3),
    updated_at  DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY case_id;

CREATE TABLE IF NOT EXISTS cybersentinel.entity_tags
(
    entity     String,
    tag        LowCardinality(String),
    source     String DEFAULT 'playbook',
    active     UInt8 DEFAULT 1,
    added_at   DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(added_at)
ORDER BY (entity, tag);

-- Analyst feedback (TP/FP/benign/escalate) remembered per entity / alert-kind.
CREATE TABLE IF NOT EXISTS cybersentinel.alert_feedback
(
    entity      String DEFAULT '',
    signature   String DEFAULT '',
    disposition LowCardinality(String),
    note        String DEFAULT '',
    analyst     String DEFAULT '',
    ts          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (entity, signature);

-- ── Auth: users + audit log ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cybersentinel.cs_users
(
    id            String        DEFAULT toString(generateUUIDv4()),
    username      String,
    password_hash String,
    role          String        DEFAULT 'user',
    created_at    DateTime64(3) DEFAULT now64(3),
    created_by    String        DEFAULT '',
    is_active     UInt8         DEFAULT 1
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY username;

CREATE TABLE IF NOT EXISTS cybersentinel.cs_auth_audit
(
    id         String        DEFAULT toString(generateUUIDv4()),
    username   String,
    action     String,
    client_ip  String        DEFAULT '',
    session_id String        DEFAULT '',
    ts         DateTime64(3) DEFAULT now64(3),
    extra      String        DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (username, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY;
