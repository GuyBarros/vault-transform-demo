"""
tests/test_fpe.py — Testes unitários para FPE (Format Preserving Encryption).

Testa:
  - Encode/decode round-trip para todos os tipos FPE
  - Preservação de formato (comprimento e charset)
  - Determinismo (mesmo input → mesmo output)
  - Falha graceful quando Vault não disponível
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_vault_client():
    """Mock do VaultTransformClient para testes sem Vault real."""
    with patch("src.vault.client.hvac.Client") as mock_hvac:
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac.return_value = mock_client

        # Simula FPE: inverte os dígitos (preserva comprimento)
        def mock_encode(role_name, transformation_name, value, mount_point, **kwargs):
            encoded = value[::-1]  # inversão simples como mock
            return {"data": {"encoded_value": encoded}}

        def mock_decode(role_name, transformation_name, value, mount_point, **kwargs):
            decoded = value[::-1]  # inversão reversa
            return {"data": {"decoded_value": decoded}}

        mock_client.secrets.transform.encode_value.side_effect = mock_encode
        mock_client.secrets.transform.decode_value.side_effect = mock_decode

        from src.vault.client import VaultTransformClient
        yield VaultTransformClient(vault_addr="http://mock:8200", token="mock-token")


@pytest.fixture
def live_vault_client():
    """Cliente Vault real — pulado se VAULT_ADDR não estiver disponível."""
    vault_addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.environ.get("VAULT_TOKEN", "root")

    from src.vault.client import VaultTransformClient
    client = VaultTransformClient(vault_addr=vault_addr, token=vault_token)
    try:
        client._get_client()
        return client
    except Exception:
        pytest.skip(f"Vault não disponível em {vault_addr} — pulando teste de integração")


# ── Testes de Normalização ────────────────────────────────────────────────────

class TestNormalization:
    def test_normalize_cpf_formatted(self):
        from src.vault.client import VaultTransformClient
        assert VaultTransformClient.normalize_cpf("123.456.789-09") == "12345678909"

    def test_normalize_cpf_plain(self):
        from src.vault.client import VaultTransformClient
        assert VaultTransformClient.normalize_cpf("12345678909") == "12345678909"

    def test_format_cpf(self):
        from src.vault.client import VaultTransformClient
        assert VaultTransformClient.format_cpf("12345678909") == "123.456.789-09"

    def test_normalize_telefone(self):
        from src.vault.client import VaultTransformClient
        assert VaultTransformClient.normalize_telefone("(11) 99876-5432") == "11998765432"

    def test_normalize_pan(self):
        from src.vault.client import VaultTransformClient
        assert VaultTransformClient.normalize_pan("4111 1111 1111 1111") == "4111111111111111"


# ── Testes Unitários (com Mock) ───────────────────────────────────────────────

class TestFPEMock:
    def test_encode_returns_string(self, mock_vault_client):
        result = mock_vault_client.encode("ff-cpf", "12345678909", "core-role")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_encode_preserves_length(self, mock_vault_client):
        """FPE deve preservar o comprimento do dado original."""
        original = "12345678909"
        encoded  = mock_vault_client.encode("ff-cpf", original, "core-role")
        assert len(encoded) == len(original), \
            f"FPE deve preservar comprimento: {len(original)} → {len(encoded)}"

    def test_decode_roundtrip(self, mock_vault_client):
        """FPE round-trip deve recuperar o dado original."""
        original = "12345678909"
        encoded  = mock_vault_client.encode("ff-cpf", original, "core-role")
        decoded  = mock_vault_client.decode("ff-cpf", encoded,  "core-role")
        assert decoded == original, f"Round-trip falhou: {original} → {encoded} → {decoded}"

    def test_batch_encode_returns_same_count(self, mock_vault_client):
        """batch_encode deve retornar a mesma quantidade de itens."""
        cpfs    = ["12345678909", "98765432100", "11122233344"]
        encoded = mock_vault_client.batch_encode("ff-cpf", cpfs, "core-role")
        assert len(encoded) == len(cpfs)

    def test_batch_encode_empty_list(self, mock_vault_client):
        result = mock_vault_client.batch_encode("ff-cpf", [], "core-role")
        assert result == []

    def test_protect_customer_maps_all_fields(self, mock_vault_client):
        raw = {
            "nome":      "João Silva",
            "cpf":       "12345678909",
            "email":     "joao@empresa.com",
            "telefone":  "11998765432",
            "pan":       "4111111111111111",
            "endereco":  "Rua X, 123, SP",
        }
        protected = mock_vault_client.protect_customer(raw, role="api-role")
        assert "cpf"      in protected
        assert "email"    in protected
        assert "telefone" in protected
        assert "pan"      in protected
        assert "endereco" in protected
        # nome não é PII mapeado para transform
        assert protected["nome"] == "João Silva"

    def test_reveal_masking_raises(self, mock_vault_client):
        """reveal_customer_field deve falhar para campos de Masking."""
        with pytest.raises(ValueError, match="Masking"):
            mock_vault_client.reveal_customer_field("email", "j***@e**.com")

    def test_reveal_fpe_works(self, mock_vault_client):
        """reveal_customer_field deve funcionar para campos FPE."""
        # O mock inverte → inversão dupla = original
        encoded = mock_vault_client.encode("ff-cpf", "12345678909", "core-role")
        decoded = mock_vault_client.reveal_customer_field("cpf", encoded, "core-role")
        assert decoded == "12345678909"


# ── Testes de Integração (requerem Vault real) ────────────────────────────────

class TestFPEIntegration:
    def test_cpf_fpe_roundtrip(self, live_vault_client):
        cpf     = "12345678909"
        encoded = live_vault_client.encode("ff-cpf", cpf, "core-role")
        decoded = live_vault_client.decode("ff-cpf", encoded, "core-role")
        assert decoded == cpf
        assert len(encoded) == 11
        assert encoded.isdigit()

    def test_cpf_fpe_deterministic(self, live_vault_client):
        """FPE deve ser determinístico — fundamental para buscas no BD."""
        cpf = "12345678909"
        enc1 = live_vault_client.encode("ff-cpf", cpf, "core-role")
        enc2 = live_vault_client.encode("ff-cpf", cpf, "core-role")
        assert enc1 == enc2, "FPE deve ser determinístico para mesmo input"

    def test_pan_fpe_preserves_format(self, live_vault_client):
        pan     = "4111111111111111"
        encoded = live_vault_client.encode("ff-pan", pan, "core-role")
        assert len(encoded) == 16
        assert encoded.isdigit()

    def test_telefone_fpe_preserves_length(self, live_vault_client):
        tel     = "11998765432"
        encoded = live_vault_client.encode("ff-telefone", tel, "core-role")
        assert len(encoded) == 11
        assert encoded.isdigit()

    def test_different_cpfs_produce_different_ciphertexts(self, live_vault_client):
        enc1 = live_vault_client.encode("ff-cpf", "12345678909", "core-role")
        enc2 = live_vault_client.encode("ff-cpf", "98765432100", "core-role")
        assert enc1 != enc2, "CPFs diferentes devem gerar ciphertexts diferentes"

    def test_batch_fpe_consistency(self, live_vault_client):
        """batch_encode deve ser consistente com encode individual."""
        cpfs   = ["12345678909", "98765432100", "11122233344"]
        batch  = live_vault_client.batch_encode("ff-cpf", cpfs, "core-role")
        single = [live_vault_client.encode("ff-cpf", c, "core-role") for c in cpfs]
        assert batch == single, "batch_encode deve ser idêntico a encode individual"
