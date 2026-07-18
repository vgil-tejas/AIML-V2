# CyberSentinel — Deploy & Rollback (the `.23` server)

This is the quick card. The full reasoning lives in
`docs/PROD_SCALE_AND_DEPLOY.md` — read it once before your first deploy.

## Layout of versions on GitHub (repo: `Tejasvgipl/AIML-V2`)

| Ref | What it is |
|---|---|
| `main` | the **old** version currently running on `.23` — left untouched as the safety anchor |
| tag `v1-last-good` | immutable pointer to that old version → the rollback target |
| branch `release/v2` | the **new** version (this whole revamp) |
| tag `v2.0.0` | immutable pointer to the new version → the deploy target |

Your data (the ~26M logs) lives in the `clickhouse_data` Docker volume, **not**
in git — none of this moves it.

## Deploy the new version

On the server, from the repo root:

```bash
git fetch origin --tags
./scripts/deploy.sh v2.0.0
```

`deploy.sh` will:
1. Record the currently-running commit (rollback point) + snapshot the row count.
2. Check out `v2.0.0`.
3. Rebuild **only** `backend frontend nginx` (ClickHouse + its volume untouched, never `-v`).
4. Run additive DB migrations at backend boot (idempotent; refuses destructive DDL).
5. Health-check `/api/health`. **If it fails, it automatically rolls back** to the
   version that was running, rebuilds it, and exits non-zero.

## Roll back manually (any time)

```bash
./scripts/rollback.sh              # back to the version deploy.sh replaced
./scripts/rollback.sh v1-last-good # back to the original old version explicitly
```

## Verify after either

```bash
curl -s localhost:19888/api/health                 # {"status":"ok","store":"connected",...}
curl -s localhost:19110/health/ready               # {"ready":true,...}
docker exec aiml_clickhouse clickhouse-client --password "$CLICKHOUSE_PASS" \
  --query 'SELECT count() FROM cybersentinel.logs'  # must match pre-deploy count + new ingest
```

## Hard rules on `.23` (never break these)

- **Never** `docker compose down -v` — the `-v` deletes the 26M volume.
- **Never** set `DEMO_MODE=true` or `ALLOW_DESTRUCTIVE=true` on prod.
- If a deploy misbehaves, roll back first, investigate second:
  `docker logs aiml_backend --tail 120`.
