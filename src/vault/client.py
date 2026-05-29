"""
vault/client.py — Cliente Vault para o Transform Secret Engine.

Suporta:
  - Autenticação via Token (dev) ou AppRole (produção)
  - FPE encode/decode
  - Masking encode
  - Tokenização encode/decode (detokenize)
  - Batch encode para pipelines de alta performance
"""

from __future__ import annotations

import os
import re
import logging
from functools import lru_cache
from typing import Literal, Optional

import hvac
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

TransformOp = Literal["encode", "decode"]


class VaultTransformClient:
    """
    Cliente de alto nível para o Vault Transform Secret Engine.

    Uso básico:
        client = VaultTransformClient()
        cpf_enc = client.encode("ff-cpf", "12345678909", role="api-role")
        cpf_orig = client.decode("ff-cpf", cpf_enc, role="core-role")
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        namespace: Optional[str] = None,
        mount_path: str = "transform",
    ):
        self.vault_addr  = vault_addr  or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self.mount_path  = mount_path
        self.namespace   = namespace   or os.environ.get("VAULT_NAMESPACE", "")
        self._token      = token       or os.environ.get("VAULT_TOKEN")
        self._role_id    = role_id     or os.environ.get("VAULT_ROLE_ID")
        self._secret_id  = secret_id   or os.environ.get("VAULT_SECRET_ID")

        self._client: Optional[hvac.Client] = None

    # ── Authentication ────────────────────────────────────────────────────────

    def _get_client(self) -> hvac.Client:
        """Retorna cliente autenticado, re-autenticando se necessário."""
        if self._client and self._client.is_authenticated():
            return self._client

        kwargs: dict = {"url": self.vault_addr}
        if self.namespace:
            kwargs["namespace"] = self.namespace

        client = hvac.Client(**kwargs)

        if self._token:
            client.token = self._token
        elif self._role_id and self._secret_id:
            resp = client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )
            client.token = resp["auth"]["client_token"]
            logger.info("Autenticado via AppRole — token TTL: %ss", resp["auth"]["lease_duration"])
        else:
            raise RuntimeError(
                "Configure VAULT_TOKEN ou VAULT_ROLE_ID + VAULT_SECRET_ID"
            )

        if not client.is_authenticated():
            raise RuntimeError("Falha na autenticação no Vault")

        self._client = client
        return client

    # ── Core Transform Operations ─────────────────────────────────────────────

    def encode(self, transformation: str, value: str, role: str) -> str:
        """
        Protege um valor PII — FPE, Masking ou Tokenização.

        Args:
            transformation: nome da transformation (ex: "ff-cpf", "mask-email")
            value: dado PII a proteger (apenas dígitos para FPE)
            role: Transform role configurado no Vault

        Returns:
            Valor protegido (mesmo formato para FPE, mascarado para Masking,
            token opaco para Tokenização)
        """
        client = self._get_client()
        resp = client.secrets.transform.encode(
            role_name=role,
            transformation=transformation,
            value=value,
            mount_point=self.mount_path,
        )
        return resp["data"]["encoded_value"]

    def decode(self, transformation: str, value: str, role: str) -> str:
        """
        Recupera o valor PII original.

        Funciona apenas para FPE e Tokenização — Masking é irreversível.
        Requer policy com permissão de decode (ex: core-role).

        Args:
            transformation: nome da transformation
            value: valor protegido a reverter
            role: Transform role com permissão de decode

        Returns:
            Dado PII original
        """
        client = self._get_client()
        resp = client.secrets.transform.decode(
            role_name=role,
            transformation=transformation,
            value=value,
            mount_point=self.mount_path,
        )
        return resp["data"]["decoded_value"]

    def batch_encode(
        self,
        transformation: str,
        values: list[str],
        role: str,
    ) -> list[str]:
        """
        Encode em lote — múltiplos valores em uma única chamada API.
        Ideal para pipelines ETL com alto volume de registros.

        Args:
            transformation: nome da transformation
            values: lista de valores a proteger
            role: Transform role

        Returns:
            Lista de valores protegidos (mesma ordem)
        """
        if not values:
            return []

        client = self._get_client()
        batch_input = [{"value": v, "transformation": transformation} for v in values]
        resp = client.secrets.transform.encode(
            role_name=role,
            transformation=transformation,
            batch_input=batch_input,
            mount_point=self.mount_path,
        )
        return [item["encoded_value"] for item in resp["data"]["batch_results"]]

    def batch_decode(
        self,
        transformation: str,
        values: list[str],
        role: str,
    ) -> list[str]:
        """Decode em lote para múltiplos valores (FPE e Tokenização apenas)."""
        if not values:
            return []

        client = self._get_client()
        batch_input = [{"value": v, "transformation": transformation} for v in values]
        resp = client.secrets.transform.decode(
            role_name=role,
            transformation=transformation,
            batch_input=batch_input,
            mount_point=self.mount_path,
        )
        return [item["decoded_value"] for item in resp["data"]["batch_results"]]

    # ── Helpers de Normalização ───────────────────────────────────────────────

    @staticmethod
    def normalize_cpf(cpf: str) -> str:
        """Remove formatação do CPF: '123.456.789-09' → '12345678909'"""
        return re.sub(r"[.\-/]", "", cpf)

    @staticmethod
    def normalize_cnpj(cnpj: str) -> str:
        """Remove formatação do CNPJ: '12.345.678/0001-90' → '12345678000190'"""
        return re.sub(r"[.\-/]", "", cnpj)

    @staticmethod
    def format_cnpj(digits: str) -> str:
        """Formata 14 dígitos como CNPJ: '12345678000190' → '12.345.678/0001-90'"""
        d = re.sub(r"[.\-/]", "", digits)
        return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}" if len(d) == 14 else digits

    @staticmethod
    def format_cpf(digits: str) -> str:
        """Formata 11 dígitos como CPF: '12345678909' → '123.456.789-09'"""
        d = re.sub(r"[.\-/]", "", digits)
        return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}" if len(d) == 11 else digits

    @staticmethod
    def normalize_telefone(tel: str) -> str:
        """Remove formatação: '(11) 99876-5432' → '11998765432'"""
        return re.sub(r"[^\d]", "", tel)

    @staticmethod
    def normalize_pan(pan: str) -> str:
        """Remove espaços do PAN: '4111 1111 1111 1111' → '4111111111111111'"""
        return pan.replace(" ", "")

    # ── High-level PII Protection ─────────────────────────────────────────────

    def protect_customer(self, data: dict, role: str = "api-role") -> dict:
        """
        Protege todos os campos PII de um dicionário de cliente.

        Aplica a transformation correta por tipo de campo:
          - cpf       → FPE ff-cpf
          - cnpj      → FPE ff-cnpj
          - rg        → FPE ff-rg
          - cnh       → FPE ff-cnh
          - pan       → FPE ff-pan
          - telefone  → FPE ff-telefone
          - email     → Masking mask-email
          - nome      → Masking mask-nome
          - dob       → Masking mask-dob
          - cvv       → Masking mask-cvv
          - endereco  → Tokenização tok-endereco
          - conta     → Tokenização tok-conta

        Returns:
            Dicionário com campos PII substituídos pelos valores protegidos.
            Campos desconhecidos são mantidos sem alteração.
        """
        protected = dict(data)
        field_map = {
            "cpf":      ("ff-cpf",       self.normalize_cpf),
            "cnpj":     ("ff-cnpj",      self.normalize_cnpj),
            "rg":       ("ff-rg",        lambda x: re.sub(r"[^\d]", "", x)),
            "cnh":      ("ff-cnh",       lambda x: re.sub(r"[^\d]", "", x)),
            "pan":      ("ff-pan",       self.normalize_pan),
            "telefone": ("ff-telefone",  self.normalize_telefone),
            "email":    ("mask-email",   str),
            "nome":     ("mask-nome",    str),
            "dob":      ("mask-dob",     str),
            "cvv":      ("mask-cvv",     str),
            "endereco": ("tok-endereco", str),
            "conta":    ("tok-conta",    str),
        }

        for field, (transformation, normalizer) in field_map.items():
            if field in protected and protected[field]:
                try:
                    normalized = normalizer(str(protected[field]))
                    protected[field] = self.encode(transformation, normalized, role)
                except Exception as e:
                    logger.error("Erro ao proteger campo '%s': %s", field, e)
                    raise

        return protected

    def reveal_customer_field(
        self,
        field: str,
        protected_value: str,
        role: str = "core-role",
    ) -> str:
        """
        Revela o valor original de um campo PII protegido.
        Requer role com permissão de decode (ex: core-role).

        Nota: campos mascarados (email, nome, dob, cvv) não podem ser revertidos.
        """
        reversible = {
            "cpf":      "ff-cpf",
            "cnpj":     "ff-cnpj",
            "rg":       "ff-rg",
            "cnh":      "ff-cnh",
            "pan":      "ff-pan",
            "telefone": "ff-telefone",
            "endereco": "tok-endereco",
            "conta":    "tok-conta",
        }
        if field not in reversible:
            raise ValueError(
                f"Campo '{field}' usa Masking (irreversível) — "
                "não é possível recuperar o valor original."
            )
        return self.decode(reversible[field], protected_value, role)


@lru_cache(maxsize=1)
def get_vault_client() -> VaultTransformClient:
    """Singleton do cliente Vault — reutilizado entre requests FastAPI."""
    return VaultTransformClient()
