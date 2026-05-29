#!/usr/bin/env bash
# seed_creds.sh — generate fresh AppRole credentials and write them to .vault/
#
# Fetches the stable role_id and mints a new secret_id for core-approle,
# then writes both to .vault/ so run_demo.sh and Vault Agent can use them.
#
# Usage:  bash scripts/seed_creds.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

_env() { grep -m1 "^${1}=" .env 2>/dev/null | cut -d= -f2-; }

export VAULT_ADDR="${VAULT_ADDR:-$(_env VAULT_ADDR)}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"   # dev-mode default

echo "🔐 Seeding Vault Agent credentials (core-approle)..."
echo "   Vault : $VAULT_ADDR"

# role_id is stable — only changes if the AppRole is recreated
ROLE_ID=$(vault read -field=role_id auth/approle/role/core-approle/role-id)

# secret_id — mint a fresh one each time
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/core-approle/secret-id)

mkdir -p .vault
printf '%s' "$ROLE_ID"   > .vault/role_id
printf '%s' "$SECRET_ID" > .vault/secret_id
chmod 600 .vault/role_id .vault/secret_id

echo "   ✅ .vault/role_id   = $ROLE_ID"
echo "   ✅ .vault/secret_id = $SECRET_ID"
echo ""
echo "  Run the demo:  bash run_demo.sh"
