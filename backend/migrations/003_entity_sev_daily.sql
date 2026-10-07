-- 003: per-entity (source IP) daily severity rollup, so /api/entity-risk can
-- rank from ~(IPs x days) small rows instead of a 30-day GROUP BY over the raw
-- 190M logs table on every open. SummingMergeTree: every non-key column is an
-- additive count, summed on merge.
--
-- The MV captures rows inserted AFTER creation (going-forward). Backfill of
-- existing history is a ONE-TIME manual step (keeps this migration cheap and
-- non-scanning). Run it once on the server, off-peak:
--
--   INSERT INTO cybersentinel.agg_entity_sev_daily
--   SELECT src_ip, toDate(ts) AS day, count() AS events,
--          countIf(severity='critical') AS n_critical,
--          countIf(severity='high')     AS n_high,
--          countIf(severity='medium')   AS n_medium,
--          countIf(severity='low')      AS n_low,
--          countIf(severity NOT IN ('critical','high','medium','low')) AS n_other,
--          countIf(action ILIKE '%deni%' OR action ILIKE '%fail%' OR action ILIKE '%block%'
--                  OR rule ILIKE '%fail%' OR rule ILIKE '%invalid%' OR rule ILIKE '%brute%') AS n_failed
--   FROM cybersentinel.logs
--   WHERE src_ip != '' AND ts < today()
--   GROUP BY src_ip, day;
--
-- (ts < today() so it doesn't overlap today's rows, which the MV captures from
-- creation forward.) Then enable the read path with ENTITY_RISK_ROLLUP=1 and
-- compare /api/entity-risk against the raw path before trusting it.
-- Additive and reversible: DROP the MV then the table. Raw logs untouched.

CREATE TABLE IF NOT EXISTS cybersentinel.agg_entity_sev_daily
(
    src_ip     String,
    day        Date,
    events     UInt64,
    n_critical UInt64,
    n_high     UInt64,
    n_medium   UInt64,
    n_low      UInt64,
    n_other    UInt64,
    n_failed   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (src_ip, day);

CREATE MATERIALIZED VIEW IF NOT EXISTS cybersentinel.mv_entity_sev_daily
TO cybersentinel.agg_entity_sev_daily AS
SELECT
    src_ip,
    toDate(ts) AS day,
    count()                         AS events,
    countIf(severity = 'critical')  AS n_critical,
    countIf(severity = 'high')      AS n_high,
    countIf(severity = 'medium')    AS n_medium,
    countIf(severity = 'low')       AS n_low,
    countIf(severity NOT IN ('critical','high','medium','low')) AS n_other,
    countIf(action ILIKE '%deni%' OR action ILIKE '%fail%' OR action ILIKE '%block%'
            OR rule ILIKE '%fail%' OR rule ILIKE '%invalid%' OR rule ILIKE '%brute%') AS n_failed
FROM cybersentinel.logs
WHERE src_ip != ''
GROUP BY src_ip, day;
