#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — MASTER one-command bootstrap for a brand-new server.
#
# Nothing needs to exist on the box first. Run ONE line on a fresh server — it
# fetches itself from GitHub with your token and does the rest: clone the
# product, write its config, build and start everything, apply the schema,
# verify health, and install the `aiml` operator command — end to end.
#
#   TRUE ONE-LINER (nothing pre-installed but curl + docker + git):
#
#     GH_PAT=YOUR_TOKEN bash -c "$(curl -fsSL \
#       -H "Authorization: token $GH_PAT" -H 'Accept: application/vnd.github.raw' \
#       https://api.github.com/repos/Tejasvgipl/AIML-V2/contents/scripts/bootstrap.sh?ref=release/v2)"
#
#   Or, if you already copied this file over:   GH_PAT=YOUR_TOKEN bash bootstrap.sh
#
# The GitHub token is the ONLY input. The AI key, store password and ports are
# baked in below, so the operator types nothing else.
#
# Re-runnable and safe: if the install already exists it updates in place, it
# never overwrites an existing .env, and it never deletes data.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ═══ BAKE THESE IN ONCE (edit here, commit to the private repo) ══════════════
# Each can also be overridden at run time by an env var of the same name.
GH_REPO="${GH_REPO:-github.com/Tejasvgipl/AIML-V2.git}"     # repo host/path — NO token here
GH_BRANCH="${GH_BRANCH:-release/v2}"                        # branch the server tracks
INSTALL_DIR="${INSTALL_DIR:-/tejas/aiml}"                   # where the product installs
GROQ_API_KEY="${GROQ_API_KEY:-gsk_REPLACE_WITH_YOUR_GROQ_KEY}"  # baked AI key — installs never ask
STORE_PASS="${STORE_PASS:-tejas@123}"                       # ClickHouse password for a FRESH store
# ═════════════════════════════════════════════════════════════════════════════

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; exit 1; }

# ── 1. Prerequisites ─────────────────────────────────────────────────────────
say "Checking prerequisites"
command -v git >/dev/null    || die "git is not installed.  sudo apt-get install -y git"
command -v docker >/dev/null || die "Docker is not installed. See docs/INSTALL.html (Prerequisites)."
docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin is missing (need 'docker compose')."
docker info >/dev/null 2>&1   || die "Cannot talk to the Docker daemon. Try: sudo systemctl start docker"
ok "git and Docker are ready"

[ "$GROQ_API_KEY" = "gsk_REPLACE_WITH_YOUR_GROQ_KEY" ] && \
  warn "GROQ_API_KEY is still the placeholder — AI panels will show 'not configured' until it's set."

# ── 2. GitHub token (the ONE prompt) ─────────────────────────────────────────
say "GitHub access"
PAT="${GH_PAT:-}"
if [ -z "$PAT" ]; then
  # -s hides the token; falls back gracefully if the shell has no controlling tty
  printf '  Paste your GitHub Personal Access Token (input hidden): '
  read -rs PAT || true
  echo
fi
[ -z "$PAT" ] && die "No token provided. Create one at https://github.com/settings/tokens (scope: repo)."
ok "Token received"

# ── 3. Clone (or update) the product ─────────────────────────────────────────
CLONE_URL="https://${PAT}@${GH_REPO}"
CLEAN_URL="https://${GH_REPO}"
if [ -d "$INSTALL_DIR/.git" ]; then
  say "Existing install found at $INSTALL_DIR — updating"
  git -C "$INSTALL_DIR" remote set-url origin "$CLONE_URL"
  git -C "$INSTALL_DIR" fetch --depth 1 origin "$GH_BRANCH" || die "Fetch failed — is the token valid?"
  git -C "$INSTALL_DIR" checkout -q "$GH_BRANCH" 2>/dev/null || true
  git -C "$INSTALL_DIR" reset --hard "origin/$GH_BRANCH"
else
  say "Cloning into $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --branch "$GH_BRANCH" "$CLONE_URL" "$INSTALL_DIR" \
    || die "Clone failed — check the token (needs 'repo' scope) and the repo/branch names."
fi
# Strip the token from the stored remote so it is NOT persisted in .git/config.
git -C "$INSTALL_DIR" remote set-url origin "$CLEAN_URL"
unset PAT
ok "Source is in place ($GH_BRANCH)"

cd "$INSTALL_DIR"

# ── 4. Configuration (.env) — created once, with the AI key + store password ─
say "Configuration"
if [ -f .env ]; then
  warn ".env already exists — leaving it untouched (keeping this server's settings)."
else
  cp .env.example .env
  # Inject the baked AI key and store password; leave every other default as-is.
  #  - use | as the sed delimiter because keys can contain / and +
  sed -i "s|^GROQ_API_KEY=.*|GROQ_API_KEY=${GROQ_API_KEY}|" .env
  sed -i "s|^CLICKHOUSE_PASS=.*|CLICKHOUSE_PASS=${STORE_PASS}|" .env
  chmod 600 .env
  ok "Wrote .env (AI key baked in, store password set, UI on port 19888, DEMO_MODE=false)."
fi

# ── 5. Hand off to the installer (build → schema → verify → link `aiml`) ─────
say "Running the installer"
chmod +x scripts/install.sh scripts/aiml 2>/dev/null || true
bash scripts/install.sh

echo
ok "Bootstrap complete. From now on, manage the stack with:  aiml start | stop | status | health"
