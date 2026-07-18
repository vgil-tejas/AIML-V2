-- 001: time skip-index on logs.
-- The sort key is (src_ip, ts), so time-range queries can't seek. A minmax
-- index on ts lets ClickHouse skip granules outside a window. ADD INDEX is
-- instant and affects NEW parts only; backfilling existing 26M parts is done
-- separately and manually (heavy) per PROD_SCALE_AND_DEPLOY.md §8.1:
--   ALTER TABLE cybersentinel.logs MATERIALIZE INDEX idx_ts;
-- Additive and reversible (DROP INDEX idx_ts). Idempotent via IF NOT EXISTS.
ALTER TABLE cybersentinel.logs ADD INDEX IF NOT EXISTS idx_ts ts TYPE minmax GRANULARITY 4;
