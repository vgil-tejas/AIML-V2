#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — one-command installer / repair for a fresh server.
#
#   bash scripts/install.sh
#
# This exists because three failures kept biting fresh installs. Each one is now
# detected and fixed automatically instead of being debugged by hand:
#
#   1. "store degraded" in the UI
#      The store password in .env drifted from the password the store's data
#      volume was created with, so backend / ml-engine / watcher could not
#      authenticate. -> we verify the credential end to end and say exactly
#      which side is wrong.
#
#   2. "Database cybersentinel does not exist"
#      First-boot init skipped 01-schema.sql. -> we always re-apply the schema
#      once the store is up. Every statement is CREATE ... IF NOT EXISTS, so
#      this is safe to run on a store that already holds crores of rows.
#
#   3. "failed to create endpoint ... cannot allocate memory"
#      Docker leaked veth interfaces from earlier failed attempts (it is NOT a
#      RAM shortage). -> we restart the Docker daemon once and retry.
#
# Safe to re-run at any time. It never deletes a volume and never wipes data.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose --profile wazuh"

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; exit 1; }

# ── 1. Prerequisites ─────────────────────────────────────────────────────────
say "Checking prerequisites"
command -v docker >/dev/null || die "Docker is not installed. See docs/INSTALL.html (Prerequisites)."
docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin is missing (need 'docker compose', not 'docker-compose')."
docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon. Try: sudo systemctl start docker"
ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null || echo '?') is ready"

# ── 2. Configuration ─────────────────────────────────────────────────────────
say "Configuration"
if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  ok "Created .env from the template (defaults: UI on port 19888, AI disabled)."
  echo "    Run ./scripts/setup.sh later to set an AI key or change the store password."
else
  ok ".env already present — leaving it untouched."
fi
set -a; . ./.env; set +a
CH_PASS="${CLICKHOUSE_PASS:-tejas@123}"
UI_PORT="${NGINX_HOST_PORT:-19888}"

# ── 3. Start the stack (auto-recovering from the veth leak) ──────────────────
say "Building and starting containers (first run pulls images — a few minutes)"
UP_LOG="$(mktemp)"
if ! $COMPOSE up -d --build >"$UP_LOG" 2>&1; then
  tail -20 "$UP_LOG"
  if grep -qi "cannot allocate memory\|failed to create endpoint" "$UP_LOG"; then
    warn "Docker leaked network interfaces from an earlier failed attempt — not a RAM problem."
    warn "Restarting the Docker daemon and retrying once…"
    sudo systemctl restart docker || die "Could not restart Docker. Run: sudo systemctl restart docker"
    sleep 10
    $COMPOSE up -d --build || die "Startup still failing. Send the output above."
  else
    die "Startup failed — see the output above."
  fi
fi
ok "Containers started"

# ── 4. Wait for the store, then guarantee the schema exists ─────────────────
say "Waiting for the event store"
CH_CTR=aiml_clickhouse
for i in $(seq 1 60); do
  if docker exec "$CH_CTR" clickhouse-client --password "$CH_PASS" --query 'SELECT 1' >/dev/null 2>&1; then
    ok "Store is up and the password in .env is correct"; break
  fi
  [ "$i" = 60 ] && {
    echo; docker logs --tail 30 "$CH_CTR" 2>&1 | sed 's/^/    /'
    die "Store never accepted CLICKHOUSE_PASS from .env.
    This means its data volume was created with a DIFFERENT password.
    Either put the original password back in .env, or — only if this server holds
    no data you need — reset it with:  docker compose down && docker volume rm \$(docker volume ls -q | grep clickhouse_data)"
  }
  sleep 3
done

say "Applying the schema (idempotent — existing data is untouched)"
docker exec -i "$CH_CTR" clickhouse-client --password "$CH_PASS" --multiquery < clickhouse/init/01-schema.sql
ROWS="$(docker exec "$CH_CTR" clickhouse-client --password "$CH_PASS" \
        --query 'SELECT count() FROM cybersentinel.logs' 2>/dev/null || echo 0)"
ok "Schema present — cybersentinel.logs holds $ROWS rows"

# ── 5. Verify end to end ────────────────────────────────────────────────────
say "Verifying the application"
$COMPOSE up -d backend ml-engine >/dev/null 2>&1 || true   # pick up a corrected password
HEALTH=""
for i in $(seq 1 40); do
  HEALTH="$(curl -fsS --max-time 10 "http://localhost:${UI_PORT}/api/health" 2>/dev/null || true)"
  case "$HEALTH" in *'"store"'*'"connected"'*) break ;; esac
  sleep 3
done

echo
if case "$HEALTH" in *'"store"'*'"connected"'*) true ;; *) false ;; esac; then
  ok "Health check passed"
  echo "$HEALTH" | sed 's/^/    /'
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '\n\033[1;32m  CyberSentinel is live at  http://%s:%s\033[0m\n\n' "${IP:-<server-ip>}" "$UI_PORT"
else
  warn "The store is fine but the app is not reporting healthy yet."
  echo "    Response: ${HEALTH:-<no response>}"
  echo "    Check:    docker compose logs --tail 50 backend"
  exit 1
fi
