#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — MASTER one-command bootstrap for a brand-new server.
#
# This file contains NO secrets, so you host it at a PUBLIC url (a GitHub gist or
# a tiny public repo). Then a fresh server installs the whole product with one
# line — nothing needs to be on the box first:
#
#     curl -fsSL https://<your-public-url>/bootstrap.sh | bash
#
# It asks for ONE thing — your GitHub Personal Access Token — then clones the
# private repo, and hands off to install.sh which writes the config (AI key +
# store password come from the private repo, never typed), builds and starts
# everything, applies the schema, verifies health, and installs the `aiml`
# operator command. When it finishes it prints http://<server-ip>:19888.
#
# The token is prompted, never stored in this script or on the command line, and
# is stripped from the git remote after the clone. Re-runnable and safe: an
# existing install is updated in place, an existing .env is left untouched, and
# no data is ever deleted.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Which private repo to install (no secrets — safe to be public) ───────────
# Overridable at run time with an env var of the same name.
GH_REPO="${GH_REPO:-github.com/Tejasvgipl/AIML-V2.git}"   # repo host/path — NO token here
GH_BRANCH="${GH_BRANCH:-release/v2}"                      # branch the server tracks
INSTALL_DIR="${INSTALL_DIR:-/tejas/aiml}"                 # where the product installs

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

# ── 2. GitHub token (the ONE prompt) ─────────────────────────────────────────
# Prompted here, never stored in the script or on the command line. Read from
# /dev/tty (not stdin) so the prompt works even under `curl ... | bash`.
say "GitHub access"
PAT="${GH_PAT:-}"
if [ -z "$PAT" ]; then
  if [ -r /dev/tty ]; then
    printf '  Paste your GitHub Personal Access Token (input hidden): ' > /dev/tty
    read -rs PAT < /dev/tty || true
    printf '\n' > /dev/tty
  else
    die "No terminal to prompt on. Re-run as: GH_PAT=your_token bash bootstrap.sh"
  fi
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

# ── 4. Hand off to the installer ─────────────────────────────────────────────
# install.sh creates .env (baking the AI key + store password from the private
# repo's scripts/deploy.defaults), builds, applies the schema, verifies health,
# and installs the `aiml` command.
cd "$INSTALL_DIR"
say "Running the installer"
chmod +x scripts/install.sh scripts/aiml 2>/dev/null || true
bash scripts/install.sh

echo
ok "Bootstrap complete. From now on, manage the stack with:  aiml start | stop | status | health"
