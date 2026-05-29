#!/usr/bin/env bash
# cleanup.sh — remove all transient demo artefacts
#
# Removes credential files, the generated PNG, Python cache, and optionally
# stops the Vault Docker container.
#
# Usage:  bash scripts/cleanup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "🧹 Cleaning up demo artefacts..."

_rm() {
  if [[ -e "$1" ]]; then
    rm -rf "$1"
    echo "   ✅ removed $1"
  fi
}

# Transient token written by Vault Agent (deleted by run_demo.sh on success,
# but may linger if the demo crashed)
_rm .vault/token

# secret_id — remove so the next run calls seed_creds.sh for a fresh one
_rm .vault/secret_id

# Generated PNG from save_output.py
_rm vault-adp.png

# Python byte-code cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
echo "   ✅ removed __pycache__ / *.pyc"

# Optional: stop the Vault Docker container
echo ""
printf "Stop the Vault Docker container? [y/N] "
read -r reply
if [[ "$reply" =~ ^[Yy]$ ]]; then
  docker-compose -f docker/docker-compose.yml down
  echo "   ✅ Vault container stopped"
fi

echo ""
echo "✅ Cleanup complete."
echo ""
echo "  To restart from scratch:"
echo "    docker-compose -f docker/docker-compose.yml up -d"
echo "    bash scripts/setup_vault.sh"
echo "    bash scripts/seed_creds.sh"
echo "    bash run_demo.sh"
