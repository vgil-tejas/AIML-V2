#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel — VENDOR packaging: build a source-free bundle for a bank.
#
#   Run from the repo root:   ./scripts/package.sh [version]   (default 2.0.0)
#
# Produces  dist/cybersentinel-<version>/  containing ONLY runtime artifacts:
#   • images.tar.gz         — the 5 pre-built images (all code lives inside)
#   • docker-compose.prod.yml, clickhouse/init schema, sample-data/ioc_store.json
#   • setup.sh, run.sh, .env.example, README.txt
# It contains NO application source (.py / build context / git history). Hand the
# bank the dist/cybersentinel-<version>/ folder (or a tar of it) and nothing else.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VER="${1:-2.0.0}"
OUT="dist/cybersentinel-${VER}"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

[ -f docker-compose.prod.yml ] || { echo "Run from the repo root."; exit 1; }

# 1. Build the 5 images (code baked in; nothing mounted from source at runtime) --
say "Building images @ ${VER}"
docker build -t "cybersentinel-backend:${VER}"  ./backend
docker build -t "cybersentinel-ml:${VER}"       ./ml-engine
docker build -t "cybersentinel-frontend:${VER}" ./frontend
docker build -t "cybersentinel-nginx:${VER}"    ./nginx
docker build -t "cybersentinel-watcher:${VER}"  ./scripts

# 2. Assemble the source-free bundle ------------------------------------------
say "Assembling bundle at ${OUT}"
rm -rf "$OUT"; mkdir -p "$OUT/clickhouse/init" "$OUT/sample-data" "$OUT/scripts"
cp docker-compose.prod.yml            "$OUT/"
cp clickhouse/init/*.sql              "$OUT/clickhouse/init/"
cp sample-data/ioc_store.json         "$OUT/sample-data/" 2>/dev/null || true
cp .env.example                       "$OUT/"
cp scripts/setup.sh                   "$OUT/scripts/"

# 3. Save the images into one tarball -----------------------------------------
say "Saving images to images.tar.gz (this is the big one)"
docker save \
  "cybersentinel-backend:${VER}" "cybersentinel-ml:${VER}" \
  "cybersentinel-frontend:${VER}" "cybersentinel-nginx:${VER}" \
  "cybersentinel-watcher:${VER}" clickhouse/clickhouse-server:24.3 \
  | gzip > "$OUT/images.tar.gz"

# 4. Bank-side run script + readme --------------------------------------------
cat > "$OUT/run.sh" <<EOF
#!/usr/bin/env bash
# CyberSentinel — load images and start the stack (run from this folder).
set -euo pipefail
export CS_VERSION="${VER}"
echo "==> Loading images (first run only)…"
gunzip -c images.tar.gz | docker load
if [ ! -f .env ]; then
  echo "==> First run: configuring secrets (AI key + store password)…"
  bash scripts/setup.sh
fi
echo "==> Starting CyberSentinel…"
docker compose -f docker-compose.prod.yml --profile wazuh up -d
echo "==> Up. Dashboard: http://<this-server>:\${NGINX_HOST_PORT:-18888}"
echo "    Health: curl -s localhost:\${NGINX_HOST_PORT:-18888}/api/health"
EOF
chmod +x "$OUT/run.sh" "$OUT/scripts/setup.sh"

cat > "$OUT/README.txt" <<EOF
CyberSentinel ${VER} — install bundle (no source code included).

Requirements: Docker + Docker Compose v2 on the target server.

Install:
  1) Copy this whole folder to the server.
  2) cd into it.
  3) ./run.sh
       - loads the images (images.tar.gz)
       - runs setup (asks for AI mode/key + store password -> .env, chmod 600)
       - starts the stack (dashboard on port \${NGINX_HOST_PORT:-18888})

Point log ingestion at your alerts.json by setting WAZUH_ALERTS_DIR in .env
(default /var/ossec/logs/alerts), then: ./run.sh  (idempotent).

Reconfigure/rotate the AI key any time:  bash scripts/setup.sh  then  ./run.sh
Stop:    docker compose -f docker-compose.prod.yml down        (data is kept)
Update:  replace images.tar.gz with a newer one, then ./run.sh

The AI analyst is the only feature that can send data outside this server, and
only when an analyst clicks an AI panel or runs a query. Run setup.sh option 2
(on-prem LLM) or 3 (disabled) to keep all data on-prem.
EOF

say "Done."
echo "  Bundle: ${OUT}/  (hand this to the bank — it has no source)"
du -sh "$OUT" 2>/dev/null || true
ls -1 "$OUT"
