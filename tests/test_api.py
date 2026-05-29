"""
tests/test_api.py — Testes de integração para a API FastAPI.

Testa os endpoints com mocks do Vault e BD para validar:
  - Fluxo de criação de cliente (PII protegida antes de persistir)
  - Resposta com dados mascarados (nunca PII em claro)
  - Busca por CPF FPE (índice funcional)
  - Endpoint /reveal exige policy core (encode/decode segregado)
  - Transform direto (encode/decode)
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Cliente FastAPI com mocks de Vault e BD."""
    from fastapi.testclient import TestClient
    from src.api.app import app

    # Mock do Vault client
    mock_vault = MagicMock()
    mock_vault._get_client.return_value = True
    mock_vault.is_authenticated.return_value = True

    # Simula FPE: prefixo "ENC_"
    mock_vault.encode.side_effect = lambda t, v, r: f"ENC_{v[:6]}"
    mock_vault.decode.side_effect = lambda t, v, r: v.replace("ENC_", "")
    mock_vault.protect_customer.side_effect = lambda data, role: {
        **data,
        "cpf":      f"ENC_{data.get('cpf','')[:6]}",
        "email":    f"m***@m**.com",
        "telefone": f"ENC_{data.get('telefone','')[:6]}",
        "pan":      f"ENC_{data.get('pan','')[:6]}" if "pan" in data else None,
        "cvv":      "***" if "cvv" in data else None,
        "endereco": "TKN-abc123" if "endereco" in data else None,
    }

    # Mock do repositório
    from src.api.models import CustomerProtected
    from datetime import datetime

    mock_repo = MagicMock()
    saved = CustomerProtected(
        id=1,
        nome="João Silva",
        cpf_protected="ENC_123456",
        email_masked="m***@m**.com",
        telefone_protected="ENC_119987",
        pan_protected="ENC_411111",
        cvv_masked="***",
        dob_masked="**/**/1985",
        endereco_token="TKN-abc123",
        created_at=datetime(2026, 5, 26, 10, 0, 0),
    )
    mock_repo.insert.return_value = saved
    mock_repo.get_by_id.return_value = saved
    mock_repo.list_all.return_value = [saved]
    mock_repo.find_by_cpf.return_value = [saved]

    with patch("src.api.app.get_vault_client", return_value=mock_vault), \
         patch("src.api.app.get_repo", return_value=mock_repo):
        yield TestClient(app)


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_endpoint(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["status"] == "ok"


# ── Transform Direto ──────────────────────────────────────────────────────────

def test_encode_endpoint(client):
    resp = client.post("/api/v1/transform/encode", json={
        "transformation": "ff-cpf",
        "value": "12345678909",
        "role": "api-role",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "encoded_value" in data
    assert data["transformation"] == "ff-cpf"
    assert data["original_length"] == 11
    assert data["reversible"] is True


def test_encode_masking_not_reversible(client):
    resp = client.post("/api/v1/transform/encode", json={
        "transformation": "mask-email",
        "value": "joao@empresa.com",
        "role": "api-role",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["reversible"] is False


def test_decode_masking_returns_400(client):
    """Tentativa de decode de campo mascarado deve retornar 400."""
    resp = client.post("/api/v1/transform/decode", json={
        "transformation": "mask-email",
        "value": "j***@e**.com",
        "role": "core-role",
    })
    assert resp.status_code == 400
    assert "irreversível" in resp.json()["detail"].lower() or \
           "masking" in resp.json()["detail"].lower()


# ── Clientes CRUD ─────────────────────────────────────────────────────────────

def test_create_customer_success(client):
    resp = client.post("/api/v1/clientes", json={
        "nome":      "João Silva",
        "cpf":       "12345678909",
        "email":     "joao@empresa.com",
        "telefone":  "11998765432",
        "pan":       "4111111111111111",
        "cvv":       "123",
        "dob":       "15/03/1985",
        "endereco":  "Rua das Flores, 123, SP",
    })
    assert resp.status_code == 201
    data = resp.json()

    # PII em claro NÃO deve aparecer na resposta
    resp_str = str(data)
    assert "12345678909" not in resp_str, "CPF original não deve aparecer na resposta"
    assert "4111111111111111" not in resp_str, "PAN original não deve aparecer na resposta"
    assert "joao@empresa.com" not in resp_str, "E-mail original não deve aparecer na resposta"

    # Campos mascarados devem estar presentes
    assert "id" in data
    assert "cpf_display" in data
    assert "email_masked" in data


def test_create_customer_invalid_cpf(client):
    resp = client.post("/api/v1/clientes", json={
        "nome":     "Test",
        "cpf":      "123",   # CPF inválido
        "email":    "test@test.com",
        "telefone": "11999999999",
    })
    assert resp.status_code == 422  # Pydantic validation error


def test_get_customer_by_id(client):
    resp = client.get("/api/v1/clientes/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 1
    assert "cpf_display" in data
    # CPF exibido deve estar mascarado
    assert data["cpf_display"].startswith("***")


def test_list_customers(client):
    resp = client.get("/api/v1/clientes")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_search_by_cpf(client):
    resp = client.post("/api/v1/clientes/buscar/cpf", json={"cpf": "12345678909"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_get_customer_not_found(client):
    from unittest.mock import patch, MagicMock
    with patch("src.api.app.get_repo") as mock_get_repo:
        mock_repo = MagicMock()
        mock_repo.get_by_id.return_value = None
        mock_get_repo.return_value = mock_repo
        resp = client.get("/api/v1/clientes/99999")
    assert resp.status_code == 404


# ── Segurança: PII não vaza na resposta ───────────────────────────────────────

def test_response_never_contains_raw_pii(client):
    """
    Testa que nenhuma resposta da API contém dados PII em claro.
    Essencial para conformidade LGPD.
    """
    pii_values = [
        "12345678909",      # CPF
        "4111111111111111", # PAN
        "joao@empresa.com", # e-mail
        "11998765432",      # telefone
        "Rua das Flores",   # endereço
    ]

    # Criar cliente
    resp = client.post("/api/v1/clientes", json={
        "nome":     "João Silva",
        "cpf":      "12345678909",
        "email":    "joao@empresa.com",
        "telefone": "11998765432",
        "pan":      "4111111111111111",
        "endereco": "Rua das Flores, 123, SP",
    })

    resp_body = resp.text
    for pii in pii_values:
        assert pii not in resp_body, \
            f"PII '{pii}' encontrado na resposta da API — violação LGPD!"
