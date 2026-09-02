#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — full uninstall / clean removal.
#
#   bash scripts/uninstall.sh            # interactive: asks before deleting data
#   bash scripts/uninstall.sh --yes      # no prompt (deletes everything)
#   bash scripts/uninstall.sh --keep-data   # remove app but KEEP the data volumes
#
# Removes ONLY the CyberSentinel stack:
#   • containers  aiml_clickhouse aiml_backend aiml_ml aiml_frontend
#                 aiml_nginx aiml_wazuh_watcher
#   • the compose project's network and locally-built images
#   • the data volumes (clickhouse_data / ml_models / watcher_data / backend_data)
#   • the `aiml` command in /usr/local/bin (only if it points at this install)
#
# It is scoped by the `aiml_` container prefix and the compose project, so it will
# NEVER touch other teams' containers (siem-*, kafka, mongo, elastic, misp, vault)
# and never runs a broad `docker system prune`.
#
# WARNING: deleting the data volumes is IRREVERSIBLE — it wipes the ingested logs.
# Use --keep-data if you only want to remove the application and keep the store.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Run from the repo root (this script lives in scripts/).
cd "$(dirname "$0")/.."
INSTALL_DIR="$(pwd)"
COMPOSE="docker compose --profile wazuh"

# Our containers, by exact name. Nothing else is ever targeted.
OUR_CONTAINERS="aiml_clickhouse aiml_backend aiml_ml aiml_frontend aiml_nginx aiml_wazuh_watcher"

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; exit 1; }

KEEP_DATA=false
ASSUME_YES=false
for arg in "$@"; do
  case "$arg" in
    --keep-data) KEEP_DATA=true ;;
    --yes|-y)    ASSUME_YES=true ;;
    *) die "Unknown option: $arg (use --yes and/or --keep-data)" ;;
  esac
done

command -v docker >/dev/null || die "Docker is not installed — nothing to do."

# ── Confirmation ─────────────────────────────────────────────────────────────
say "About to remove the CyberSentinel stack from: $INSTALL_DIR"
echo "    Containers : $OUR_CONTAINERS"
if $KEEP_DATA; then
  echo "    Data       : KEPT (--keep-data) — the store volumes are preserved."
else
  echo "    Data       : DELETED — clickhouse_data / ml_models / watcher_data / backend_data"
  warn "This wipes all ingested logs on THIS server. It cannot be undone."
fi
if ! $ASSUME_YES; then
  printf '\n  Type exactly  DELETE  to proceed: '
  read -r CONFIRM
  [ "$CONFIRM" = "DELETE" ] || die "Aborted — nothing was removed."
fi

# ── 1. Compose down (scoped to THIS project only) ────────────────────────────
# `docker compose down` acts only on the project defined by this directory's
# compose file, so other teams' containers are untouched. -v removes named
# volumes; --rmi local drops images this project built; --remove-orphans clears
# a partial/half-loaded start.
say "Stopping and removing the compose project"
DOWN_FLAGS="--remove-orphans --rmi local"
$KEEP_DATA || DOWN_FLAGS="$DOWN_FLAGS -v"
if [ -f docker-compose.yml ]; then
  $COMPOSE down $DOWN_FLAGS 2>/dev/null && ok "Compose project torn down" \
    || warn "compose down reported an issue — continuing with the direct sweep below."
else
  warn "No docker-compose.yml here — skipping compose down, doing the direct sweep."
fi

# ── 2. Belt-and-suspenders sweep (by exact aiml_ names only) ─────────────────
# In case the install was partial and containers exist outside the project,
# remove ONLY our named containers. This never matches another team's names.
say "Removing any leftover aiml_ containers"
for c in $OUR_CONTAINERS; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
    docker rm -f "$c" >/dev/null 2>&1 && ok "removed container $c" || warn "could not remove $c"
  fi
done

# ── 3. Data volumes (unless --keep-data) ─────────────────────────────────────
# Compose prefixes volume names with the project name; a partial install may
# have left them behind. Match ONLY our four volume basenames, project-prefixed.
if ! $KEEP_DATA; then
  say "Removing leftover data volumes"
  for v in $(docker volume ls -q 2>/dev/null | grep -E '(_|^)(clickhouse_data|ml_models|watcher_data|backend_data)$' || true); do
    docker volume rm "$v" >/dev/null 2>&1 && ok "removed volume $v" || warn "could not remove volume $v (still in use?)"
  done
else
  warn "Kept data volumes (--keep-data)."
fi

# ── 4. Locally-built images (only ours) ──────────────────────────────────────
say "Removing locally-built CyberSentinel images"
PROJECT="$(basename "$INSTALL_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
             | grep -E "^${PROJECT}[-_](backend|frontend|nginx|ml-engine|wazuh-watcher):" || true); do
  docker rmi -f "$img" >/dev/null 2>&1 && ok "removed image $img" || warn "could not remove image $img"
done

# ── 5. The `aiml` operator command (only if it points at THIS install) ───────
say "Removing the 'aiml' command"
AIML_LINK=/usr/local/bin/aiml
if [ -L "$AIML_LINK" ]; then
  TARGET="$(readlink -f "$AIML_LINK" 2>/dev/null || true)"
  case "$TARGET" in
    "$INSTALL_DIR"/*)
      { rm -f "$AIML_LINK" || sudo rm -f "$AIML_LINK"; } 2>/dev/null \
        && ok "removed $AIML_LINK" || warn "could not remove $AIML_LINK (try: sudo rm -f $AIML_LINK)"
      ;;
    *) warn "$AIML_LINK points elsewhere ($TARGET) — left in place." ;;
  esac
else
  ok "No 'aiml' command link found."
fi

# ── 6. Done ──────────────────────────────────────────────────────────────────
say "Uninstall complete"
echo "    Verify nothing of ours remains:"
echo "      docker ps -a  | grep aiml_        # should print nothing"
echo "      docker volume ls | grep -E 'clickhouse_data|ml_models|watcher_data|backend_data'"
echo
echo "    The source folder is still at: $INSTALL_DIR"
echo "    Delete it too if you want a totally clean box:"
echo "      cd / && sudo rm -rf \"$INSTALL_DIR\""
echo
ok "CyberSentinel removed from this server."
