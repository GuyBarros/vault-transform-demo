#!/usr/bin/env bash
# setup_vault.sh — Configura o Vault Transform Engine para a demo LGPD/PII
# Equivalente ao vault-init.sh mas para execução local (fora do Docker)

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

export VAULT_ADDR VAULT_TOKEN

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Vault Transform Engine — Setup LGPD/PII Demo       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Vault: $VAULT_ADDR"
echo ""

# Aguardar Vault
echo "⏳ Verificando conectividade com o Vault..."
for i in {1..15}; do
  vault status > /dev/null 2>&1 && break
  echo "  Tentativa $i/15 — aguardando 2s..."
  sleep 2
done

vault status > /dev/null 2>&1 || { echo "❌ Vault não disponível em $VAULT_ADDR"; exit 1; }
echo "✅ Vault disponível"

# ── Transform Engine ─────────────────────────────────────────────────────────
echo ""
echo "🔧 [1/5] Habilitando Transform Secret Engine..."
vault secrets enable transform 2>/dev/null && echo "  ✅ Habilitado" || echo "  ℹ️  Já habilitado"

# ── Alphabets ──────────────────────────────────────────────────────────────
echo ""
echo "📋 [2/5] Configurando Alphabets..."
vault write transform/alphabet/numeric      alphabet="0123456789"            && echo "  ✅ numeric"
vault write transform/alphabet/alphanumeric alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" && echo "  ✅ alphanumeric"

# ── FPE Templates ──────────────────────────────────────────────────────────
echo ""
echo "📐 [2b/5] Configurando FPE Templates (regex por comprimento)..."

vault write transform/template/tmpl-9digits  type=regex pattern="([0-9]{9})"  alphabet=numeric && echo "  ✅ tmpl-9digits"
vault write transform/template/tmpl-11digits type=regex pattern="([0-9]{11})" alphabet=numeric && echo "  ✅ tmpl-11digits"
vault write transform/template/tmpl-16digits type=regex pattern="([0-9]{16})" alphabet=numeric && echo "  ✅ tmpl-16digits"
vault write transform/template/tmpl-cpf      type=regex pattern='(^.{3})\.?(.{3})\.?(.{3})[-\./]?(.{2}$)' alphabet=numeric && echo "  ✅ tmpl-cpf"
vault write transform/template/tmpl-cnpj     type=regex pattern='(^.{2})\.?(.{3})\.?(.{3})[/\.-]?(.{4})[-\./]?(.{2}$)' alphabet=numeric && echo "  ✅ tmpl-cnpj"

# ── FPE Transformations ────────────────────────────────────────────────────
echo ""
echo "🔐 [3/5] Configurando FPE Transformations (FF3-1)..."

vault write transform/transformation/ff-cpf      type=fpe alphabet=numeric template=tmpl-cpf     tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-cpf"
vault write transform/transformation/ff-cnpj     type=fpe alphabet=numeric template=tmpl-cnpj    tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-cnpj"
vault write transform/transformation/ff-rg       type=fpe alphabet=numeric template=tmpl-9digits  tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-rg"
vault write transform/transformation/ff-cnh      type=fpe alphabet=numeric template=tmpl-11digits tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-cnh"
vault write transform/transformation/ff-pan      type=fpe alphabet=numeric template=tmpl-16digits tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-pan"
vault write transform/transformation/ff-telefone type=fpe alphabet=numeric template=tmpl-11digits tweak_source=internal allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ ff-telefone"

# ── Masking Templates ─────────────────────────────────────────────────────
echo ""
echo "🎭 [3b/5] Configurando Masking Templates..."

vault write transform/template/tmpl-email  type=regex pattern='(\w)([^@]*)(@)(\w)([^.]*)(\..*)'  alphabet=alphanumeric && echo "  ✅ tmpl-email"
vault write transform/template/tmpl-string type=regex pattern='(.+)'             alphabet=alphanumeric && echo "  ✅ tmpl-string"
vault write transform/template/tmpl-dob    type=regex pattern='(\d{2}/\d{2}/\d{4})' alphabet=numeric   && echo "  ✅ tmpl-dob"
vault write transform/template/tmpl-cvv    type=regex pattern='(\d{3,4})'        alphabet=numeric      && echo "  ✅ tmpl-cvv"

# ── Masking ───────────────────────────────────────────────────────────────
echo ""
echo "🎭 [3/5] Configurando Masking Transformations..."

vault write transform/transformation/mask-email type=masking template=tmpl-email  masking_character="*" allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ mask-email"
vault write transform/transformation/mask-nome  type=masking template=tmpl-string masking_character="*" allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ mask-nome"
vault write transform/transformation/mask-dob   type=masking template=tmpl-dob    masking_character="*" allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ mask-dob"
vault write transform/transformation/mask-cvv   type=masking template=tmpl-cvv    masking_character="*" allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ mask-cvv"

# ── Tokenization ──────────────────────────────────────────────────────────
echo ""
echo "🔑 [3/5] Configurando Tokenization Transformations..."

vault write transform/transformation/tok-endereco \
  type=tokenization convergent=true max_ttl=0 \
  allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ tok-endereco"

vault write transform/transformation/tok-conta \
  type=tokenization convergent=true max_ttl=0 \
  allowed_roles="api-role,core-role,db-role,pipeline-role" && echo "  ✅ tok-conta"

# ── Roles ─────────────────────────────────────────────────────────────────
echo ""
echo "👥 [4/5] Configurando Transform Roles..."

vault write transform/role/api-role \
  transformations=ff-cpf,ff-cnpj,ff-pan,ff-telefone,mask-email,mask-nome,mask-dob,mask-cvv,tok-endereco,tok-conta \
  && echo "  ✅ api-role (encode-only)"

vault write transform/role/core-role \
  transformations=ff-cpf,ff-cnpj,ff-rg,ff-cnh,ff-pan,ff-telefone,mask-email,mask-nome,mask-dob,mask-cvv,tok-endereco,tok-conta \
  && echo "  ✅ core-role (encode + decode)"

vault write transform/role/db-role \
  transformations=ff-cpf,ff-cnpj,ff-rg,ff-cnh,ff-pan,ff-telefone,tok-endereco,tok-conta \
  && echo "  ✅ db-role"

vault write transform/role/pipeline-role \
  transformations=ff-cpf,ff-cnpj,ff-pan,ff-telefone,mask-email,mask-dob,tok-endereco,tok-conta \
  && echo "  ✅ pipeline-role"

# ── AppRole ───────────────────────────────────────────────────────────────
echo ""
echo "🔐 [5/5] Configurando AppRole Auth Method..."
vault auth enable approle 2>/dev/null || echo "  ℹ️  approle já habilitado"

# Policies
vault policy write encode-only - <<'EOF'
path "transform/encode/*"    { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF
echo "  ✅ policy: encode-only"

vault policy write core-access - <<'EOF'
path "transform/encode/*"    { capabilities = ["create","update"] }
path "transform/decode/*"    { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF
echo "  ✅ policy: core-access"

vault policy write pipeline-access - <<'EOF'
path "transform/encode/*"    { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF
echo "  ✅ policy: pipeline-access"

# AppRoles — secret_id_ttl=0 so credentials persist across sessions
vault write auth/approle/role/api-approle \
  token_policies="encode-only" token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0 \
  && echo "  ✅ approle: api-approle"

vault write auth/approle/role/core-approle \
  token_policies="core-access" token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0 \
  && echo "  ✅ approle: core-approle"

vault write auth/approle/role/pipeline-approle \
  token_policies="pipeline-access" token_ttl=2h token_max_ttl=8h \
  secret_id_ttl=0 secret_id_num_uses=0 \
  && echo "  ✅ approle: pipeline-approle"

# ── Exportar credenciais ──────────────────────────────────────────────────
echo ""
echo "📄 Exportando credenciais..."

CORE_ROLE_ID=$(vault read    -field=role_id   auth/approle/role/core-approle/role-id)
CORE_SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/core-approle/secret-id)

API_ROLE_ID=$(vault read     -field=role_id   auth/approle/role/api-approle/role-id)
API_SECRET_ID=$(vault write  -f -field=secret_id auth/approle/role/api-approle/secret-id)

# core-approle → .vault/ files (read by Vault Agent; not in source control)
mkdir -p .vault
printf '%s' "$CORE_ROLE_ID"    > .vault/role_id
printf '%s' "$CORE_SECRET_ID"  > .vault/secret_id
chmod 600 .vault/role_id .vault/secret_id
echo "  ✅ .vault/role_id + .vault/secret_id  (core-approle, Vault Agent)"

# api-approle → .env (used directly by demo for RBAC section)
cat > ".env" <<ENVEOF
# ── Vault ──────────────────────────────────────────────────────────────────────
VAULT_ADDR=${VAULT_ADDR}
VAULT_NAMESPACE=
# namespace Enterprise (vazio = root)

# core-approle credentials live in .vault/ (read by Vault Agent, not stored here)
# Run the demo via:  bash run_demo.sh

# api-approle — encode only (encode-only policy); used directly by demo for RBAC
VAULT_API_ROLE_ID=${API_ROLE_ID}
VAULT_API_SECRET_ID=${API_SECRET_ID}
VAULT_TRANSFORM_MOUNT=transform

# ── Banco de Dados ─────────────────────────────────────────────────────────────
DB_URL=postgresql://vault_demo:vault_demo@localhost:5432/vault_demo

# ── API ────────────────────────────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000
API_ROLE=api-role
CORE_ROLE=core-role

# ── Pipeline ───────────────────────────────────────────────────────────────────
PIPELINE_ROLE=pipeline-role
PIPELINE_BATCH_SIZE=100
ENVEOF
echo "  ✅ .env  (api-approle credentials)"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✅ Setup concluído com sucesso!                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Próximo passo:"
echo "    bash run_demo.sh"
echo ""
