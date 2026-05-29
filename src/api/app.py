"""
api/app.py — FastAPI com proteção PII via Vault Transform Secret Engine.

Endpoints:
  POST /api/v1/clientes              — Cria cliente (FPE + Mask + Token antes de persistir)
  GET  /api/v1/clientes/{id}         — Retorna cliente com dados mascarados
  GET  /api/v1/clientes/{id}/reveal  — Retorna PII revelada (sistemas core apenas)
  GET  /api/v1/clientes/buscar/cpf   — Busca por CPF (encode antes do WHERE)
  POST /api/v1/transform/encode      — Encode direto (para testes)
  POST /api/v1/transform/decode      — Decode direto (role core)
  GET  /api/v1/health                — Health check
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse

from src.vault.client import VaultTransformClient, get_vault_client
from src.api.models import (
    CustomerIn, CustomerProtected, CustomerResponse,
    CustomerDecoded, SearchByCpfRequest, EncodeRequest, EncodeResponse,
)
from src.database.db import CustomerRepository

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

API_ROLE  = os.environ.get("API_ROLE", "api-role")
CORE_ROLE = os.environ.get("CORE_ROLE", "core-role")

# Transformations reversíveis (FPE + Tokenização)
REVERSIBLE = {"ff-cpf", "ff-rg", "ff-cnh", "ff-pan", "ff-telefone", "tok-endereco", "tok-conta"}


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Iniciando API — conectando ao Vault em %s", os.environ.get("VAULT_ADDR"))
    vault = get_vault_client()
    try:
        vault._get_client()
        logger.info("✅ Vault conectado e autenticado")
    except Exception as e:
        logger.warning("⚠️  Vault não disponível na inicialização: %s", e)
    yield
    logger.info("🔴 API encerrada")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Vault Transform Demo — LGPD/PII Protection",
    description=(
        "Demonstração do HashiCorp Vault Transform Secret Engine para proteção de dados PII conforme LGPD. "
        "FPE (Format Preserving Encryption), Masking e Tokenização em APIs REST."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Dependencies ──────────────────────────────────────────────────────────────

def get_repo() -> CustomerRepository:
    return CustomerRepository()


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", tags=["Health"])
def health():
    vault = get_vault_client()
    try:
        vault._get_client()
        vault_ok = True
    except Exception:
        vault_ok = False
    return {"status": "ok", "vault_connected": vault_ok}


# ── Transform direct endpoints (testes/demo) ──────────────────────────────────

@app.post("/api/v1/transform/encode", response_model=EncodeResponse, tags=["Transform"])
def encode_value(req: EncodeRequest):
    """
    Encode direto de um valor PII — FPE, Masking ou Tokenização.
    Para demonstração e testes de integração.
    """
    vault = get_vault_client()
    try:
        encoded = vault.encode(req.transformation, req.value, req.role)
        return EncodeResponse(
            transformation=req.transformation,
            original_length=len(req.value),
            encoded_value=encoded,
            reversible=req.transformation in REVERSIBLE,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/v1/transform/decode", tags=["Transform"])
def decode_value(req: EncodeRequest):
    """
    Decode de um valor protegido — apenas FPE e Tokenização.
    Requer role com permissão de decode (ex: core-role).
    Masking é irreversível — retorna erro.
    """
    if req.transformation not in REVERSIBLE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transformation '{req.transformation}' usa Masking — irreversível por design LGPD."
        )
    vault = get_vault_client()
    try:
        decoded = vault.decode(req.transformation, req.value, req.role)
        return {"transformation": req.transformation, "decoded_value": decoded}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


# ── Customers CRUD ────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/clientes",
    response_model=CustomerResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Clientes"],
)
def create_customer(
    customer: CustomerIn,
    vault: VaultTransformClient = Depends(get_vault_client),
    repo: CustomerRepository    = Depends(get_repo),
):
    """
    Cria um novo cliente.

    **Fluxo de proteção PII:**
    1. Recebe dados PII em claro no request body
    2. Aplica protect_customer() — FPE, Masking e Tokenização por campo
    3. Persiste apenas dados protegidos no BD (nunca o dado original)
    4. Retorna resposta com dados mascarados para exibição

    O dado PII em claro nunca é escrito em log, em BD ou em cache.
    """
    raw = customer.model_dump(exclude_none=True)
    logger.info("Criando cliente — protegendo PII para %d campos", len(raw))

    try:
        protected_data = vault.protect_customer(raw, role=API_ROLE)
    except Exception as e:
        logger.error("Erro ao proteger PII: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao proteger dados PII — verifique conectividade com o Vault"
        )

    # Remapear campos para o schema do BD
    row = CustomerProtected(
        nome=protected_data.get("nome", customer.nome),
        cpf_protected=protected_data["cpf"],
        email_masked=protected_data["email"],
        telefone_protected=protected_data["telefone"],
        pan_protected=protected_data.get("pan"),
        cvv_masked=protected_data.get("cvv"),
        dob_masked=protected_data.get("dob"),
        endereco_token=protected_data.get("endereco"),
        conta_token=protected_data.get("conta"),
    )

    saved = repo.insert(row)
    logger.info("Cliente criado — ID %d | CPF protegido com FPE", saved.id)
    return CustomerResponse.from_protected(saved)


@app.get("/api/v1/clientes/{customer_id}", response_model=CustomerResponse, tags=["Clientes"])
def get_customer(
    customer_id: int,
    repo: CustomerRepository = Depends(get_repo),
):
    """
    Retorna dados do cliente com PII mascarada para exibição.
    Adequado para interfaces de suporte, dashboards e logs.
    Não requer permissão de decode no Vault.
    """
    row = repo.get_by_id(customer_id)
    if not row:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    return CustomerResponse.from_protected(row)


@app.get(
    "/api/v1/clientes/{customer_id}/reveal",
    response_model=CustomerDecoded,
    tags=["Clientes — Core Only"],
)
def reveal_customer(
    customer_id: int,
    vault: VaultTransformClient = Depends(get_vault_client),
    repo: CustomerRepository    = Depends(get_repo),
):
    """
    **Endpoint restrito — sistemas core autorizados pelo DPO apenas.**

    Reverte FPE e Tokenização para exibir o dado PII original.
    Masking (email, nome, dob) permanece mascarado — irreversível por design.

    Em produção este endpoint requer:
    - Token Vault com policy core-access
    - Aprovação do DPO registrada no audit log
    - Autenticação MFA do operador
    """
    row = repo.get_by_id(customer_id)
    if not row:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")

    logger.warning(
        "⚠️  REVEAL solicitado para cliente ID %d — registrado no audit log Vault",
        customer_id,
    )

    try:
        cpf      = vault.decode("ff-cpf",       row.cpf_protected,      CORE_ROLE)
        telefone = vault.decode("ff-telefone",   row.telefone_protected, CORE_ROLE)
        pan      = vault.decode("ff-pan",        row.pan_protected,      CORE_ROLE) if row.pan_protected else None
        endereco = vault.decode("tok-endereco",  row.endereco_token,     CORE_ROLE) if row.endereco_token else None
        conta    = vault.decode("tok-conta",     row.conta_token,        CORE_ROLE) if row.conta_token else None
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sem permissão para decode — {e}"
        )

    return CustomerDecoded(
        id=row.id,
        nome=row.nome,
        cpf=VaultTransformClient.format_cpf(cpf),
        email=row.email_masked,   # masking é irreversível
        telefone=telefone,
        pan=pan,
        endereco=endereco,
        conta=conta,
    )


@app.post("/api/v1/clientes/buscar/cpf", response_model=List[CustomerResponse], tags=["Clientes"])
def search_by_cpf(
    req: SearchByCpfRequest,
    vault: VaultTransformClient = Depends(get_vault_client),
    repo: CustomerRepository    = Depends(get_repo),
):
    """
    Busca cliente por CPF.

    **Como funciona com FPE:**
    O CPF é FPE-encoded antes de consultar o BD.
    Como FPE é determinístico (mesmo input → mesmo output),
    a busca WHERE cpf_protected = :cpf_encoded funciona normalmente.
    O índice no banco de dados é preservado — não há full table scan.
    """
    normalized = VaultTransformClient.normalize_cpf(req.cpf)
    cpf_encoded = vault.encode("ff-cpf", normalized, API_ROLE)
    rows = repo.find_by_cpf(cpf_encoded)
    return [CustomerResponse.from_protected(r) for r in rows]


@app.get("/api/v1/clientes", response_model=List[CustomerResponse], tags=["Clientes"])
def list_customers(
    limit: int = 20,
    repo: CustomerRepository = Depends(get_repo),
):
    """Lista clientes com dados mascarados (sem decode)."""
    rows = repo.list_all(limit=limit)
    return [CustomerResponse.from_protected(r) for r in rows]
