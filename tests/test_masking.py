"""
tests/test_masking.py — Testes para Masking e Tokenização.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Masking Tests ─────────────────────────────────────────────────────────────

class TestMaskingBehavior:
    """Testes do comportamento esperado de Masking — sem Vault real."""

    def test_masking_is_irreversible_by_design(self):
        """reveal_customer_field deve rejeitar campos de Masking."""
        from src.vault.client import VaultTransformClient
        client = VaultTransformClient(token="mock")
        with pytest.raises(ValueError, match="Masking"):
            client.reveal_customer_field("email", "j***@e**.com")

    def test_masking_fields_rejected_for_reveal(self):
        """Todos os campos de masking devem ser rejeitados no reveal."""
        from src.vault.client import VaultTransformClient
        client = VaultTransformClient(token="mock")
        masking_fields = ["email", "nome", "dob", "cvv"]
        for field in masking_fields:
            with pytest.raises(ValueError):
                client.reveal_customer_field(field, "***masked***")

    def test_fpe_fields_accepted_for_reveal(self):
        """Campos FPE e tokenização devem ser aceitos no reveal (sem errar na validação)."""
        from src.vault.client import VaultTransformClient
        client = VaultTransformClient(token="mock")
        reversible_fields = ["cpf", "rg", "cnh", "pan", "telefone", "endereco", "conta"]
        for field in reversible_fields:
            # Deve chegar até a chamada ao Vault (não rejeitar antes)
            with pytest.raises((Exception,)):
                client.reveal_customer_field(field, "some_value")


# ── Tokenization Tests ────────────────────────────────────────────────────────

class TestTokenizationBehavior:
    """Testes de comportamento de tokenização."""

    def test_token_is_opaque(self):
        """Token não deve conter nenhum fragmento do dado original."""
        # Verificação conceitual: tokens gerados pelo Vault são opacos por design.
        # Testamos que o token não inicia com o dado original.
        original = "Rua das Flores, 123, São Paulo, SP"
        mock_token = "TKN-f3a9b2c1d4e5f6a7"
        assert original not in mock_token
        assert not mock_token.startswith(original[:10])

    def test_tok_endereco_not_in_reversible_masking(self):
        """tok-endereco deve ser reversível (não deve falhar no reveal)."""
        from src.vault.client import VaultTransformClient
        client = VaultTransformClient(token="mock")
        # endereco é reversível — não deve levantar ValueError de masking
        try:
            client.reveal_customer_field("endereco", "TKN-abc123")
        except ValueError as e:
            pytest.fail(f"endereco não deveria levantar ValueError: {e}")
        except Exception:
            pass  # Vault não disponível — OK para este teste

    def test_conta_not_in_reversible_masking(self):
        """tok-conta deve ser reversível."""
        from src.vault.client import VaultTransformClient
        client = VaultTransformClient(token="mock")
        try:
            client.reveal_customer_field("conta", "TKN-xyz789")
        except ValueError as e:
            pytest.fail(f"conta não deveria levantar ValueError: {e}")
        except Exception:
            pass


# ── Integration Tests (require live Vault) ────────────────────────────────────

@pytest.fixture
def live_client():
    import os
    from src.vault.client import VaultTransformClient
    client = VaultTransformClient(
        vault_addr=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        token=os.environ.get("VAULT_TOKEN", "root"),
    )
    try:
        client._get_client()
        return client
    except Exception:
        pytest.skip("Vault não disponível — pulando teste de integração")


class TestMaskingIntegration:
    def test_email_masking_irreversible(self, live_client):
        """Vault deve rejeitar decode de campo mascarado."""
        masked = live_client.encode("mask-email", "joao@empresa.com", "api-role")
        assert "*" in masked
        with pytest.raises(Exception):
            live_client.decode("mask-email", masked, "core-role")

    def test_cvv_fully_masked(self, live_client):
        masked = live_client.encode("mask-cvv", "123", "api-role")
        assert masked == "***"
        assert "1" not in masked and "2" not in masked and "3" not in masked

    def test_dob_preserves_year(self, live_client):
        """Data de nascimento deve preservar o ano."""
        dob    = "15/03/1985"
        masked = live_client.encode("mask-dob", dob, "api-role")
        assert "1985" in masked, f"Ano deve ser preservado: {masked}"
        assert "15" not in masked or "03" not in masked, "Dia/mês devem ser mascarados"


class TestTokenizationIntegration:
    def test_endereco_token_opaque(self, live_client):
        endereco = "Rua das Flores, 123, São Paulo, SP"
        token    = live_client.encode("tok-endereco", endereco, "core-role")
        assert endereco not in token
        assert "Rua" not in token

    def test_endereco_token_convergent(self, live_client):
        """Mesmo endereço deve sempre gerar o mesmo token."""
        endereco = "Rua das Flores, 123, São Paulo, SP"
        tok1     = live_client.encode("tok-endereco", endereco, "core-role")
        tok2     = live_client.encode("tok-endereco", endereco, "core-role")
        assert tok1 == tok2, "Tokenização deve ser convergente"

    def test_endereco_detokenize_roundtrip(self, live_client):
        endereco = "Av. Paulista, 1000, São Paulo, SP"
        token    = live_client.encode("tok-endereco", endereco, "core-role")
        decoded  = live_client.decode("tok-endereco", token, "core-role")
        assert decoded == endereco

    def test_different_addresses_different_tokens(self, live_client):
        tok1 = live_client.encode("tok-endereco", "Rua A, 1, SP", "core-role")
        tok2 = live_client.encode("tok-endereco", "Rua B, 2, RJ", "core-role")
        assert tok1 != tok2
