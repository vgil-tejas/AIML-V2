#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — roll back to the previous version.
#
# Run ON the .23 server, from the repo root:   ./scripts/rollback.sh [ref]
#   With no argument, rolls back to whatever deploy.sh recorded as the previous
#   running version (.deploy_previous_commit), falling back to the tag
#   v1-last-good.  Pass a branch/tag/commit to roll back to that instead.
#
# The 26M-row data volume is NEVER touched — only app containers are rebuilt.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_SERVICES="backend frontend nginx"
COMPOSE="docker compose"

TARGET="${1:-}"
if [ -z "$TARGET" ] && [ -f .deploy_previous_commit ]; then
  TARGET="$(cat .deploy_previous_commit)"
fi
TARGET="${TARGET:-v1-last-good}"

printf '\n\033[1;33m==> Rolling back to %s\033[0m\n' "$TARGET"
git fetch origin --tags --prune
git checkout "$TARGET"
$COMPOSE up -d --build $APP_SERVICES

printf '\n\033[1;33m==> Rolled back to %s. Verify:\033[0m\n' "$TARGET"
echo "    curl -s localhost:19888/api/health"
echo "    docker exec aiml_clickhouse clickhouse-client --password \"\$CLICKHOUSE_PASS\" --query 'SELECT count() FROM cybersentinel.logs'"
