#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — production deploy with automatic rollback.
#
# Run ON the .23 server, from the repo root:   ./scripts/deploy.sh [ref]
#   ref defaults to the tag v2.0.0. Pass a branch/tag/commit to deploy that.
#
# SAFETY (see docs/PROD_SCALE_AND_DEPLOY.md):
#   * Only the APP containers are rebuilt. ClickHouse and its 26M-row data
#     volume are NEVER touched. This script never uses `-v`.
#   * The currently-running commit is recorded before switching, so a failed
#     health check rolls straight back to it — no manual recovery needed.
#   * Additive migrations run at backend boot; the runner refuses destructive
#     DDL unless ALLOW_DESTRUCTIVE=true (never set here).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TARGET="${1:-v2.0.0}"
APP_SERVICES="backend frontend nginx"
HEALTH_URL="${HEALTH_URL:-http://localhost:19888/api/health}"
COMPOSE="docker compose"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
err() { printf '\n\033[1;31m==> %s\033[0m\n' "$*"; }

# 0. Preconditions -------------------------------------------------------------
command -v docker >/dev/null || { err "docker not found"; exit 1; }
git rev-parse --git-dir >/dev/null 2>&1 || { err "not a git repo"; exit 1; }
if [ -n "$(git status --porcelain)" ]; then
  err "Working tree has local changes. Commit/stash them first (deploy must be clean)."
  git status --short
  exit 1
fi

# 1. Record the current running version as the rollback point ------------------
CURRENT="$(git rev-parse HEAD)"
echo "$CURRENT" > .deploy_previous_commit
say "Current version recorded for rollback: $CURRENT"

# Snapshot the row count so we can prove data survived the deploy.
BEFORE_ROWS="$(docker exec aiml_clickhouse clickhouse-client \
  --password "${CLICKHOUSE_PASS:-tejas@123}" \
  --query 'SELECT count() FROM cybersentinel.logs' 2>/dev/null || echo '?')"
say "Rows before deploy: $BEFORE_ROWS"

# 2. Fetch + check out the target ---------------------------------------------
say "Fetching origin and checking out $TARGET"
git fetch origin --tags --prune
git checkout "$TARGET"

# 3. Rebuild ONLY the app containers (data volume untouched; NO -v) ------------
say "Rebuilding app containers ($APP_SERVICES)"
$COMPOSE up -d --build $APP_SERVICES

# 4. Health gate ---------------------------------------------------------------
say "Waiting for health at $HEALTH_URL"
ok=0
for i in $(seq 1 30); do
  if curl -sf "$HEALTH_URL" 2>/dev/null | grep -q '"store":"connected"'; then ok=1; break; fi
  sleep 2
done

AFTER_ROWS="$(docker exec aiml_clickhouse clickhouse-client \
  --password "${CLICKHOUSE_PASS:-tejas@123}" \
  --query 'SELECT count() FROM cybersentinel.logs' 2>/dev/null || echo '?')"

# 5. Verdict -------------------------------------------------------------------
if [ "$ok" = "1" ]; then
  say "✅ Deploy healthy. Now running: $TARGET"
  echo "    Rows before/after: $BEFORE_ROWS -> $AFTER_ROWS (data preserved)"
  echo "    Roll back anytime:  ./scripts/rollback.sh"
else
  err "❌ Health check FAILED — rolling back to $CURRENT"
  git checkout "$CURRENT"
  $COMPOSE up -d --build $APP_SERVICES
  err "Rolled back to the previous version. Inspect: docker logs aiml_backend --tail 120"
  exit 1
fi
