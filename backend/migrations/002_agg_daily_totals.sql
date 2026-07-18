-- 002: daily totals rollup so global counts sum ~180 tiny rows, not 26M.
-- Target table + materialized view. The MV captures rows inserted AFTER
-- creation (going-forward). Backfill of existing history is a one-time manual
-- step (documented) so this migration stays cheap and non-scanning:
--   INSERT INTO cybersentinel.agg_daily_totals
--   SELECT toDate(ts), severity, count() FROM cybersentinel.logs
--   WHERE ts < today() GROUP BY toDate(ts), severity;
-- Additive and reversible (DROP the MV then the table). Idempotent.
CREATE TABLE IF NOT EXISTS cybersentinel.agg_daily_totals
(
    day    Date,
    severity LowCardinality(String),
    events AggregateFunction(count)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, severity);

CREATE MATERIALIZED VIEW IF NOT EXISTS cybersentinel.mv_daily_totals
TO cybersentinel.agg_daily_totals AS
SELECT toDate(ts) AS day, severity, countState() AS events
FROM cybersentinel.logs
GROUP BY day, severity;
