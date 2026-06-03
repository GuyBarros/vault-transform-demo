#!/usr/bin/env bash
# vault-init.sh — Inicialização do Vault Transform Engine no container Docker
# Executado automaticamente após o vault container subir

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

export VAULT_ADDR VAULT_TOKEN

echo "⏳ Aguardando Vault ficar disponível..."
until vault status > /dev/null 2>&1; do sleep 1; done
echo "✅ Vault disponível em $VAULT_ADDR"

echo ""
echo "🔧 Habilitando Transform Secret Engine..."
vault secrets enable transform || echo "  (já habilitado)"

echo ""
echo "📋 Configurando Alphabets..."
vault write transform/alphabet/numeric      alphabet="0123456789"
vault write transform/alphabet/alphanumeric alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

echo ""
echo "🔐 Configurando FPE Transformations (FF3-1)..."

# CPF — 11 dígitos
vault write transform/transformation/ff-cpf \
  type=fpe \
  alphabet=numeric \
  template="builtin/creditcardnumber" \
  tweak_source=internal \
  allowed_roles="api-role,core-role,pipeline-role,db-role"

# RG — 9 dígitos
vault write transform/transformation/ff-rg \
  type=fpe \
  alphabet=numeric \
  template="builtin/creditcardnumber" \
  tweak_source=internal \
  allowed_roles="api-role,core-role,pipeline-role,db-role"

# CNH — 11 dígitos
vault write transform/transformation/ff-cnh \
  type=fpe \
  alphabet=numeric \
  template="builtin/creditcardnumber" \
  tweak_source=internal \
  allowed_roles="core-role,db-role"

# PAN (cartão de crédito) — 16 dígitos
vault write transform/transformation/ff-pan \
  type=fpe \
  alphabet=numeric \
  template="builtin/creditcardnumber" \
  tweak_source=internal \
  allowed_roles="api-role,core-role,pipeline-role,db-role"

# Telefone BR — 11 dígitos (DDD + número)
vault write transform/transformation/ff-telefone \
  type=fpe \
  alphabet=numeric \
  template="builtin/creditcardnumber" \
  tweak_source=internal \
  allowed_roles="api-role,core-role,pipeline-role,db-role"

echo ""
echo "🎭 Configurando Masking Transformations..."

# E-mail masking
vault write transform/transformation/mask-email \
  type=masking \
  template="builtin/builtin" \
  masking_character="*" \
  allowed_roles="api-role,core-role,pipeline-role"

# Nome masking
vault write transform/transformation/mask-nome \
  type=masking \
  template="builtin/builtin" \
  masking_character="*" \
  allowed_roles="api-role,core-role,pipeline-role"

# Data de nascimento masking
vault write transform/transformation/mask-dob \
  type=masking \
  template="builtin/builtin" \
  masking_character="*" \
  allowed_roles="api-role,core-role,pipeline-role"

# CVV masking (total)
vault write transform/transformation/mask-cvv \
  type=masking \
  template="builtin/builtin" \
  masking_character="*" \
  allowed_roles="api-role,core-role"

echo ""
echo "🔑 Configurando Tokenization Transformations..."

# Endereço — token convergente
vault write transform/transformation/tok-endereco \
  type=tokenization \
  convergent=true \
  max_ttl=0 \
  allowed_roles="api-role,core-role,pipeline-role,db-role"

# Conta bancária / IBAN
vault write transform/transformation/tok-conta \
  type=tokenization \
  convergent=true \
  max_ttl=0 \
  allowed_roles="core-role,db-role,pipeline-role"

echo ""
echo "👤 Configurando Roles..."

# Role para APIs de produção (encode-only — sem decode)
vault write transform/role/api-role \
  transformations=ff-cpf,ff-pan,ff-telefone,mask-email,mask-nome,mask-dob,mask-cvv,tok-endereco

# Role para sistemas core (encode + decode completo)
vault write transform/role/core-role \
  transformations=ff-cpf,ff-rg,ff-cnh,ff-pan,ff-telefone,mask-email,mask-nome,mask-dob,mask-cvv,tok-endereco,tok-conta

# Role para banco de dados
vault write transform/role/db-role \
  transformations=ff-cpf,ff-rg,ff-cnh,ff-pan,ff-telefone,tok-endereco,tok-conta

# Role para pipelines ETL/Spark
vault write transform/role/pipeline-role \
  transformations=ff-cpf,ff-pan,ff-telefone,mask-email,mask-dob,tok-endereco,tok-conta

echo ""
echo "🔐 Configurando AppRole Auth Method..."
vault auth enable approle 2>/dev/null || echo "  (approle já habilitado)"

# Policy encode-only (APIs de produção)
vault policy write encode-only - <<'POLICY'
path "transform/encode/*" { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
POLICY

# Policy core (encode + decode)
vault policy write core-access - <<'POLICY'
path "transform/encode/*"  { capabilities = ["create","update"] }
path "transform/decode/*"  { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
POLICY

# Policy pipeline (encode + batch)
vault policy write pipeline-access - <<'POLICY'
path "transform/encode/*" { capabilities = ["create","update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
POLICY

# AppRole para API
vault write auth/approle/role/api-approle \
  token_policies="encode-only" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=120s

# AppRole para sistemas core
vault write auth/approle/role/core-approle \
  token_policies="core-access" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=120s

# AppRole para pipeline
vault write auth/approle/role/pipeline-approle \
  token_policies="pipeline-access" \
  token_ttl=2h \
  token_max_ttl=8h \
  secret_id_ttl=300s

echo ""
echo "📄 Salvando Role IDs para .env..."
API_ROLE_ID=$(vault read -field=role_id auth/approle/role/api-approle/role-id)
CORE_ROLE_ID=$(vault read -field=role_id auth/approle/role/core-approle/role-id)
PIPELINE_ROLE_ID=$(vault read -field=role_id auth/approle/role/pipeline-approle/role-id)

echo "VAULT_API_ROLE_ID=$API_ROLE_ID"
echo "VAULT_CORE_ROLE_ID=$CORE_ROLE_ID"
echo "VAULT_PIPELINE_ROLE_ID=$PIPELINE_ROLE_ID"

echo ""
echo "✅ Transform Secret Engine configurado com sucesso!"
echo ""
echo "  FPE:         ff-cpf, ff-rg, ff-cnh, ff-pan, ff-telefone"
echo "  Masking:     mask-email, mask-nome, mask-dob, mask-cvv"
echo "  Tokenização: tok-endereco, tok-conta"
echo "  Roles:       api-role, core-role, db-role, pipeline-role"
echo ""
echo "🚀 Execute: python scripts/demo_all.py"
