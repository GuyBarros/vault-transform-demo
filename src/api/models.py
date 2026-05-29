"""
api/models.py — Modelos Pydantic para a API REST de clientes.

Separação clara entre:
  - CustomerIn:        dado bruto (PII em claro) recebido na requisição
  - CustomerProtected: dado com PII protegida (armazenado no BD)
  - CustomerResponse:  resposta com campos mascarados para exibição
  - CustomerDecoded:   resposta com PII revelada (sistemas core autorizados)
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import re


# ── Input (PII em claro) ──────────────────────────────────────────────────────

class CustomerIn(BaseModel):
    """Dados brutos do cliente — PII em claro recebido na API."""

    nome:     str = Field(..., examples=["João Carlos da Silva"])
    cpf:      str = Field(..., examples=["123.456.789-09"])
    email:    str = Field(..., examples=["joao.silva@empresa.com"])
    telefone: str = Field(..., examples=["(11) 99876-5432"])
    pan:      Optional[str] = Field(None, examples=["4111 1111 1111 1111"])
    cvv:      Optional[str] = Field(None, examples=["123"])
    dob:      Optional[str] = Field(None, examples=["15/03/1985"])
    endereco: Optional[str] = Field(None, examples=["Rua das Flores, 123, São Paulo, SP"])
    conta:    Optional[str] = Field(None, examples=["BR6000360305000010009795493P1"])

    @field_validator("cpf")
    @classmethod
    def validate_cpf(cls, v: str) -> str:
        digits = re.sub(r"[.\-]", "", v)
        if len(digits) != 11 or not digits.isdigit():
            raise ValueError("CPF deve conter 11 dígitos")
        return v

    @field_validator("pan")
    @classmethod
    def validate_pan(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        digits = v.replace(" ", "").replace("-", "")
        if len(digits) not in (13, 14, 15, 16) or not digits.isdigit():
            raise ValueError("PAN inválido")
        return v


# ── Stored (PII protegida — armazenada no BD) ─────────────────────────────────

class CustomerProtected(BaseModel):
    """Dados com PII protegida — estrutura armazenada no banco de dados."""

    id:                  Optional[int] = None
    nome:                str
    cpf_protected:       str   # FPE
    email_masked:        str   # Masking (irreversível)
    telefone_protected:  str   # FPE
    pan_protected:       Optional[str] = None   # FPE
    cvv_masked:          Optional[str] = None   # Masking
    dob_masked:          Optional[str] = None   # Masking
    endereco_token:      Optional[str] = None   # Tokenização
    conta_token:         Optional[str] = None   # Tokenização
    created_at:          Optional[datetime] = None


# ── Response (para exibição — dados mascarados) ───────────────────────────────

class CustomerResponse(BaseModel):
    """
    Resposta padrão da API — campos sensíveis exibidos de forma mascarada.
    Adequado para interfaces de suporte, dashboards e listagens.
    """

    id:                  int
    nome:                str
    cpf_display:         str   # ex: ***.***.789-09
    email_masked:        str   # ex: j***@e**.com
    telefone_display:    str   # ex: (11) 9****-5432
    pan_display:         Optional[str] = None  # ex: **** **** **** 5817
    dob_masked:          Optional[str] = None
    endereco_token:      Optional[str] = None
    created_at:          Optional[datetime] = None

    @classmethod
    def from_protected(cls, row: CustomerProtected) -> "CustomerResponse":
        """Gera resposta mascarada a partir dos dados protegidos."""
        # CPF: exibe apenas últimos 6 dígitos no formato ***.***.XXX-XX
        cpf = row.cpf_protected
        cpf_display = f"***.***.{cpf[6:9]}-{cpf[9:]}" if len(cpf) == 11 else cpf

        # Telefone: exibe DDD e últimos 4 dígitos
        tel = row.telefone_protected
        tel_display = f"({tel[:2]}) *****-{tel[-4:]}" if len(tel) == 11 else tel

        # PAN: exibe apenas últimos 4
        pan_display = None
        if row.pan_protected:
            pan = row.pan_protected
            pan_display = f"**** **** **** {pan[-4:]}" if len(pan) == 16 else pan

        return cls(
            id=row.id,
            nome=row.nome,
            cpf_display=cpf_display,
            email_masked=row.email_masked,
            telefone_display=tel_display,
            pan_display=pan_display,
            dob_masked=row.dob_masked,
            endereco_token=row.endereco_token,
            created_at=row.created_at,
        )


# ── Decoded (apenas para sistemas core autorizados) ───────────────────────────

class CustomerDecoded(BaseModel):
    """
    Dados com PII revelada — uso restrito a sistemas core autorizados pelo DPO.
    Nunca retornado por endpoints públicos.
    """

    id:       int
    nome:     str
    cpf:      str
    email:    str           # Masking é irreversível — retorna valor mascarado
    telefone: str
    pan:      Optional[str] = None
    endereco: Optional[str] = None
    conta:    Optional[str] = None


# ── Request/Response auxiliares ───────────────────────────────────────────────

class SearchByCpfRequest(BaseModel):
    """Busca por CPF — a API encode o CPF antes de consultar o BD."""
    cpf: str = Field(..., examples=["123.456.789-09"])


class EncodeRequest(BaseModel):
    """Encode direto via API — para testes e integração."""
    transformation: str = Field(..., examples=["ff-cpf"])
    value: str          = Field(..., examples=["12345678909"])
    role:  str          = Field("api-role")


class EncodeResponse(BaseModel):
    transformation:  str
    original_length: int
    encoded_value:   str
    reversible:      bool
