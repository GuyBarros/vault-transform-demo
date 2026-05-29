#!/usr/bin/env bash
# run_demo.sh — authenticate via Vault Agent (AppRole auto-auth) and run demo.
#
# Flow:
#   1. vault agent authenticates as core-approle, writes token to .vault/token,
#      then exits (exit_after_auth = true)
#   2. this script reads the token, exports it as VAULT_TOKEN, removes the file
#   3. demo_all.py is exec'd with VAULT_TOKEN in the environment
#
# Usage:  bash run_demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Parse .env without eval/source (safe for values that contain special chars)
_env() { grep -m1 "^${1}=" .env 2>/dev/null | cut -d= -f2-; }

export VAULT_ADDR="${VAULT_ADDR:-$(_env VAULT_ADDR)}"
export VAULT_API_ROLE_ID="${VAULT_API_ROLE_ID:-$(_env VAULT_API_ROLE_ID)}"
export VAULT_API_SECRET_ID="${VAULT_API_SECRET_ID:-$(_env VAULT_API_SECRET_ID)}"

if [[ ! -f .vault/role_id || ! -f .vault/secret_id ]]; then
  echo "❌  .vault/role_id or .vault/secret_id not found."
  echo "    Run: bash scripts/setup_vault.sh"
  exit 1
fi

echo "🔐 Vault Agent: authenticating via AppRole (core-approle)..."
vault agent -config=vault-agent.hcl -log-level=warn

if [[ ! -f .vault/token ]]; then
  echo "❌  Authentication failed — token not written to .vault/token"
  exit 1
fi

# Load token into memory and remove from disk immediately
export VAULT_TOKEN
VAULT_TOKEN=$(cat .vault/token)
rm -f .vault/token
echo "✅ Token injected as \$VAULT_TOKEN — starting demo..."
echo ""

exec python scripts/demo_all.py
