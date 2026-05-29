"""
database/db.py — Repositório PostgreSQL para clientes com PII protegida.

Todos os dados chegam aqui já protegidos pelo Vault Transform — o repositório
não conhece o dado PII original e nunca o persiste.
"""

from __future__ import annotations

import os
import logging
from typing import List, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from src.api.models import CustomerProtected

load_dotenv()
logger = logging.getLogger(__name__)

DB_URL = os.environ.get("DB_URL", "postgresql://vault_demo:vault_demo@localhost:5432/vault_demo")


class CustomerRepository:
    """Repositório de clientes — opera exclusivamente com dados PII protegidos."""

    def __init__(self, db_url: Optional[str] = None):
        url = db_url or DB_URL
        self._engine = create_engine(url, pool_pre_ping=True, echo=False)

    def _session(self) -> Session:
        return Session(self._engine)

    # ── Write ──────────────────────────────────────────────────────────────────

    def insert(self, customer: CustomerProtected) -> CustomerProtected:
        """
        Insere um novo cliente com dados PII protegidos.
        O CPF, PAN, telefone chegam FPE-cifrados; e-mail mascarado; endereço tokenizado.
        """
        sql = text("""
            INSERT INTO clientes (
                nome, cpf_protected, email_masked, telefone_protected,
                pan_protected, cvv_masked, dob_masked, endereco_token, conta_token
            ) VALUES (
                :nome, :cpf_protected, :email_masked, :telefone_protected,
                :pan_protected, :cvv_masked, :dob_masked, :endereco_token, :conta_token
            )
            RETURNING id, created_at
        """)
        with self._session() as session:
            row = session.execute(sql, {
                "nome":               customer.nome,
                "cpf_protected":      customer.cpf_protected,
                "email_masked":       customer.email_masked,
                "telefone_protected": customer.telefone_protected,
                "pan_protected":      customer.pan_protected,
                "cvv_masked":         customer.cvv_masked,
                "dob_masked":         customer.dob_masked,
                "endereco_token":     customer.endereco_token,
                "conta_token":        customer.conta_token,
            }).fetchone()
            session.commit()

        customer.id         = row.id
        customer.created_at = row.created_at
        logger.info("INSERT cliente ID=%d | cpf_protected=%s", row.id, customer.cpf_protected)
        return customer

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_by_id(self, customer_id: int) -> Optional[CustomerProtected]:
        """Busca cliente por ID — retorna dados protegidos."""
        sql = text("SELECT * FROM clientes WHERE id = :id")
        with self._session() as session:
            row = session.execute(sql, {"id": customer_id}).fetchone()
        return self._row_to_model(row) if row else None

    def find_by_cpf(self, cpf_protected: str) -> List[CustomerProtected]:
        """
        Busca por CPF FPE-cifrado.

        Como FPE é determinístico, o mesmo CPF original sempre gera o mesmo
        valor cifrado → WHERE cpf_protected = :cpf_encoded funciona normalmente.
        O índice idx_clientes_cpf_protected é utilizado — sem full table scan.
        """
        sql = text("SELECT * FROM clientes WHERE cpf_protected = :cpf")
        with self._session() as session:
            rows = session.execute(sql, {"cpf": cpf_protected}).fetchall()
        logger.info(
            "SELECT por CPF FPE-cifrado — %d resultado(s) encontrado(s)", len(rows)
        )
        return [self._row_to_model(r) for r in rows]

    def list_all(self, limit: int = 20) -> List[CustomerProtected]:
        """Lista todos os clientes (dados protegidos)."""
        sql = text("SELECT * FROM clientes ORDER BY created_at DESC LIMIT :limit")
        with self._session() as session:
            rows = session.execute(sql, {"limit": limit}).fetchall()
        return [self._row_to_model(r) for r in rows]

    def list_from_support_view(self, limit: int = 20) -> list[dict]:
        """
        Lista clientes via VIEW de suporte — dados mascarados para DBA.
        Não requer policy decode no Vault.
        """
        sql = text("SELECT * FROM vw_clientes_suporte ORDER BY created_at DESC LIMIT :limit")
        with self._session() as session:
            rows = session.execute(sql, {"limit": limit}).fetchall()
        return [dict(r._mapping) for r in rows]

    # ── Helper ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_model(row) -> CustomerProtected:
        m = row._mapping
        return CustomerProtected(
            id=m["id"],
            nome=m["nome"],
            cpf_protected=m["cpf_protected"],
            email_masked=m["email_masked"],
            telefone_protected=m["telefone_protected"],
            pan_protected=m.get("pan_protected"),
            cvv_masked=m.get("cvv_masked"),
            dob_masked=m.get("dob_masked"),
            endereco_token=m.get("endereco_token"),
            conta_token=m.get("conta_token"),
            created_at=m.get("created_at"),
        )
