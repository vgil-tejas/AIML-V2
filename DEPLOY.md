# CyberSentinel — Deploy & Rollback (the `.23` server)

This is the quick card. The full reasoning lives in
`docs/PROD_SCALE_AND_DEPLOY.md` — read it once before your first deploy.

## Layout of versions on GitHub (repo: `cybersentinel-06/CyberSentinel-AIML`)

| Ref | What it is |
|---|---|
| `main` | the **current** version — what installs and servers track |
| tag `v2.0.0` | immutable pointer to the current release → the deploy target |

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

## Live demo for buyers (isolated stack — safe on the same server)

Demo mode is **off** on production so it can never write synthetic attack rows
into the real 27M store. To show buyers the live demo film, run the **separate
demo stack** — its own containers, ports, network, and an **empty** ClickHouse
volume, so `DEMO_MODE=true` there can never touch prod:

```bash
docker compose -f docker-compose.demo.yml up -d --build   # start it
# open http://<server>:29888  → Settings → Demo mode → pick a scenario
docker compose -f docker-compose.demo.yml down            # stop it (keeps demo data)
docker compose -f docker-compose.demo.yml down -v         # stop + wipe demo store
```

| | Prod | Demo |
|---|---|---|
| URL | `:19888` | `:29888` |
| Project | `aiml` | `aimldemo` |
| ClickHouse volume | `clickhouse_data` (27M) | `aimldemo_clickhouse_demo` (empty) |
| `DEMO_MODE` | `false` | `true` |

Both stacks share the same code/images and read the same `.env` (password, AI
key), but **different data volumes** — the `down -v` above only ever removes the
demo's own volumes. Never run `down -v` against the prod `docker-compose.yml`.

## Hard rules on `.23` (never break these)

- **Never** `docker compose down -v` — the `-v` deletes the 26M volume.
- **Never** set `DEMO_MODE=true` or `ALLOW_DESTRUCTIVE=true` on prod.
- If a deploy misbehaves, roll back first, investigate second:
  `docker logs aiml_backend --tail 120`.
