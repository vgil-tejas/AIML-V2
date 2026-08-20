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
  # Bake in the AI key + store password from the private deploy defaults, so a
  # fresh install is fully configured with no prompts. Missing file / unset
  # values just fall through to the template defaults (AI shows "not configured").
  if [ -f scripts/deploy.defaults ]; then
    # shellcheck disable=SC1091
    . scripts/deploy.defaults
  fi
  if [ -n "${GROQ_API_KEY:-}" ] && [ "${GROQ_API_KEY:-}" != "gsk_REPLACE_WITH_YOUR_GROQ_KEY" ]; then
    sed -i "s|^GROQ_API_KEY=.*|GROQ_API_KEY=${GROQ_API_KEY}|" .env
    ok "AI key applied from scripts/deploy.defaults."
  else
    warn "No AI key in scripts/deploy.defaults — AI panels will show 'not configured'."
  fi
  sed -i "s|^CLICKHOUSE_PASS=.*|CLICKHOUSE_PASS=${CLICKHOUSE_PASS:-tejas@123}|" .env

  # ── Login gate: bake the operator credential + a per-server signing key ──
  # AUTH_USER/AUTH_PASS come from deploy.defaults (Tejas / tejas@123). AUTH_SECRET
  # is generated FRESH per server so a copied bundle can never forge a session.
  AUTH_SECRET_GEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sed -i "s|^AUTH_ENABLED=.*|AUTH_ENABLED=${AUTH_ENABLED:-true}|"        .env
  sed -i "s|^AUTH_USER=.*|AUTH_USER=${AUTH_USER:-Tejas}|"                .env
  sed -i "s|^AUTH_PASS=.*|AUTH_PASS=${AUTH_PASS:-tejas@123}|"            .env
  sed -i "s|^AUTH_SECRET=.*|AUTH_SECRET=${AUTH_SECRET_GEN}|"             .env
  sed -i "s|^AUTH_TTL_HOURS=.*|AUTH_TTL_HOURS=${AUTH_TTL_HOURS:-12}|"    .env
  ok "Login gate set (user '${AUTH_USER:-Tejas}', unique session key generated)."

  chmod 600 .env
  ok "Created .env (UI on port 19888, store password set, DEMO_MODE=false)."
else
  ok ".env already present — leaving it untouched."
fi
set -a; . ./.env; set +a
CH_PASS="${CLICKHOUSE_PASS:-tejas@123}"
UI_PORT="${NGINX_HOST_PORT:-19888}"

# ── 3. Start the stack (auto-recovering from known startup traps) ────────────
# Trap: older releases bind-mounted clickhouse/users.d/default-password.xml. That
# file is gone now, but a container CREATED before the upgrade still references
# it, and Docker silently makes an empty DIRECTORY at the missing path. The mount
# then fails with "not a directory" and the store exits 127 before it ever
# starts — while the backend stays up, so the UI just shows an empty dashboard.
if [ -d clickhouse/users.d/default-password.xml ]; then
  rmdir clickhouse/users.d/default-password.xml 2>/dev/null \
    && warn "Removed a stale mount placeholder left by an older release." \
    || warn "clickhouse/users.d/default-password.xml is a non-empty directory — remove it by hand."
fi

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
# ── Install the `aiml` operator command (start/stop/status/health) ──────────
# So ops can run `aiml start|stop|status|health` from anywhere instead of docker.
chmod +x scripts/aiml 2>/dev/null || true
if [ -w /usr/local/bin ] || sudo -n true 2>/dev/null; then
  if ln -sf "$(pwd)/scripts/aiml" /usr/local/bin/aiml 2>/dev/null \
     || sudo ln -sf "$(pwd)/scripts/aiml" /usr/local/bin/aiml 2>/dev/null; then
    ok "Installed the 'aiml' command — try:  aiml status"
  else
    warn "Could not link 'aiml' into /usr/local/bin — run it as ./scripts/aiml instead."
  fi
else
  warn "No permission for /usr/local/bin — run the command as ./scripts/aiml (or re-run with sudo)."
fi

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
