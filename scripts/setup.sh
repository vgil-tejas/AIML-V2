#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — first-run / reconfigure setup for a customer (bank) install.
#
#   Run from the repo root:   ./scripts/setup.sh
#
# It writes secrets into .env ONLY (chmod 600, gitignored — never committed).
# Nothing here goes into git or over the network. Re-run it any time to rotate
# the AI key or switch the AI mode.
#
# The AI analyst is the ONE feature that can send log data to an external
# service. This script lets each bank choose:
#   1) Groq cloud   — hosted, fast (short log snippets leave the bank's network)
#   2) On-prem LLM  — your own OpenAI-compatible endpoint (nothing leaves)
#   3) Disabled     — no AI at all, zero external calls (fully air-gapped)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ENV_FILE=".env"
say()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }

[ -f docker-compose.yml ] || { echo "Run this from the repo root (docker-compose.yml not found)."; exit 1; }

# Seed .env from the template on a fresh install; back up an existing one.
if [ ! -f "$ENV_FILE" ]; then
  [ -f .env.example ] && cp .env.example "$ENV_FILE" || : > "$ENV_FILE"
  note "Created $ENV_FILE from template."
else
  cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%Y%m%d%H%M%S)"
  note "Backed up existing $ENV_FILE."
fi

# upsert KEY VALUE  — set or replace a line in .env (value written literally)
upsert() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  grep -vE "^${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

say "CyberSentinel setup"
echo "Configuring this deployment's secrets in $ENV_FILE (local only)."

# ── AI analyst mode ──────────────────────────────────────────────────────────
say "AI analyst — where should it run?"
echo "  1) Groq cloud    (hosted, fastest; log snippets leave your network)"
echo "  2) On-prem LLM   (your own OpenAI-compatible endpoint; nothing leaves)"
echo "  3) Disabled      (no AI, zero external calls — safest for an air-gapped bank)"
read -rp "Choice [1/2/3] (default 3): " AICHOICE
AICHOICE="${AICHOICE:-3}"

case "$AICHOICE" in
  1)
    read -rsp "  Groq API key: " KEY; echo
    [ -n "$KEY" ] || { echo "  No key entered — aborting (use option 3 to run without AI)."; exit 1; }
    upsert GROQ_API_KEY   "$KEY"
    upsert AI_API_KEY     "$KEY"
    upsert AI_BASE_URL    "https://api.groq.com/openai/v1/chat/completions"
    upsert AI_MODEL       "llama-3.3-70b-versatile"
    upsert AI_FAST_MODEL  "llama-3.1-8b-instant"
    note "AI mode: Groq cloud."
    ;;
  2)
    read -rp  "  OpenAI-compatible base URL (…/v1/chat/completions): " URL
    read -rsp "  API key (leave blank if the endpoint needs none): " KEY; echo
    read -rp  "  Model name to use: " MODEL
    [ -n "$URL" ] && [ -n "$MODEL" ] || { echo "  URL and model are required — aborting."; exit 1; }
    upsert GROQ_API_KEY   ""            # clear so it can't override the on-prem key
    upsert AI_API_KEY     "${KEY:-none}"
    upsert AI_BASE_URL    "$URL"
    upsert AI_MODEL       "$MODEL"
    upsert AI_FAST_MODEL  "$MODEL"
    note "AI mode: on-prem LLM at $URL."
    ;;
  3|*)
    upsert GROQ_API_KEY   ""
    upsert AI_API_KEY     ""
    note "AI mode: DISABLED. No log data will ever be sent to any external service."
    note "The AI panels degrade gracefully (SOC Query, Explain, Narratives show 'not configured')."
    ;;
esac

# ── Store password ───────────────────────────────────────────────────────────
say "Event-store password"
CURRENT="$(grep -E '^CLICKHOUSE_PASS=' "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
if [ -n "$CURRENT" ]; then
  read -rsp "  New store password [Enter to keep the existing one]: " CHP; echo
  [ -n "$CHP" ] && upsert CLICKHOUSE_PASS "$CHP" && note "Store password updated." || note "Kept existing store password."
else
  read -rsp "  Set store password (Enter to use default 'tejas@123'): " CHP; echo
  upsert CLICKHOUSE_PASS "${CHP:-tejas@123}"
fi

chmod 600 "$ENV_FILE" 2>/dev/null || true

say "Done."
echo "  Wrote $ENV_FILE (permissions 600, gitignored — never commit it)."
echo "  Apply it:  ./scripts/deploy.sh v2.0.0     (or: docker compose up -d --build)"
echo "  Verify:    curl -s localhost:19888/api/health   → \"ai\":\"configured\" or \"missing\""
