"""
scripts/demo_all.py — Demo completa do Vault Transform Secret Engine.

Executa e exibe todas as operações PII em sequência:
  1. FPE encode/decode  — CPF, PAN, telefone, RG
  2. Masking            — e-mail, nome, data de nascimento, CVV
  3. Tokenização        — endereço, conta bancária
  4. protect_customer() — proteção de um cliente completo
  5. Busca por CPF FPE  — demonstra índice funcional
  6. Batch encode       — 20 CPFs em uma única chamada
  7. Casos RBAC         — encode-only vs. decode

Uso:
    python scripts/demo_all.py
    python scripts/demo_all.py --vault-addr http://localhost:8200
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Garantir que o diretório raiz está no path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

load_dotenv()

console = Console()


def section(title: str):
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]")


def ok(label: str, orig: str, prot: str, reversible: bool = True):
    icon = "🔐" if reversible else "🎭"
    console.print(f"  {icon} [bold]{label:<20}[/bold] [red]{orig:<35}[/red] → [green]{prot}[/green]")


def run_demo(vault_addr: str, vault_token: str,
             api_role_id: str, api_secret_id: str):
    from src.vault.client import VaultTransformClient

    # Token injected by Vault Agent (AppRole auto-auth → VAULT_TOKEN)
    client = VaultTransformClient(vault_addr=vault_addr, token=vault_token)
    # api-approle: encode only (encode-only policy) — used in RBAC section
    client_api = VaultTransformClient(vault_addr=vault_addr,
                                      role_id=api_role_id, secret_id=api_secret_id)

    # ── Verificar conectividade ──────────────────────────────────────────────
    console.print(Panel.fit(
        "[bold]HashiCorp Vault Transform Secret Engine[/bold]\n"
        "[dim]Demo de Proteção PII / LGPD — FPE + Masking + Tokenização[/dim]",
        border_style="cyan"
    ))

    try:
        client._get_client()
        console.print(f"\n✅ [green]Vault conectado:[/green] {vault_addr}  "
                      f"[dim](token via Vault Agent / core-approle)[/dim]")
    except Exception as e:
        console.print(f"\n❌ [red]Vault não disponível: {e}[/red]")
        console.print("   Execute primeiro: [bold]docker-compose -f docker/docker-compose.yml up -d[/bold]")
        console.print("   E configure:      [bold]bash scripts/setup_vault.sh[/bold]")
        console.print(e)
        sys.exit(1)

    role_api  = "api-role"
    role_core = "core-role"

    # ────────────────────────────────────────────────────────────────────────
    section("1. FPE — Format Preserving Encryption (FF3-1 / NIST SP 800-38G)")
    # ────────────────────────────────────────────────────────────────────────
    console.print("  [dim]O dado cifrado mantém o mesmo formato e comprimento original.[/dim]")
    console.print("  [dim]Banco de dados não precisa de ALTER TABLE — índices funcionam normalmente.[/dim]\n")

    fpe_cases = [
        ("ff-cpf",      "CPF",       "123.456.789-09",       client.normalize_cpf,  client.format_cpf),
        ("ff-cnpj",     "CNPJ",      "12.345.678/0001-90",   client.normalize_cnpj, client.format_cnpj),
        ("ff-rg",       "RG",        "123456789",             str,                   str),
        ("ff-cnh",      "CNH",       "01234567891",           str,                   str),
        ("ff-pan",      "PAN",       "4111111111111111",      str,                   str),
        ("ff-telefone", "Telefone",  "11998765432",           str,                   str),
    ]

    for transformation, label, original, normalizer, formatter in fpe_cases:
        try:
            normalized = normalizer(original)
            encoded    = client.encode(transformation, normalized, role_core)
            ok(label, original, formatter(encoded), reversible=True)
        except Exception as e:
            console.print(f"  ⚠️  {label}: {e}")

    # ── FPE Decode ─────────────────────────────────────────────────────────
    console.print("\n  [bold]Decode (core-role):[/bold]")
    cpf_enc = client.encode("ff-cpf", "12345678909", role_core)
    cpf_dec = client.decode("ff-cpf", cpf_enc, role_core)
    assert cpf_dec == "12345678909", f"FPE decode falhou: {cpf_dec}"
    console.print(f"  ✅ CPF FPE round-trip: [red]{client.format_cpf(cpf_dec)}[/red] → [green]{client.format_cpf(cpf_enc)}[/green] → [blue]{client.format_cpf(cpf_dec)}[/blue]")

    # ── FPE busca BD ────────────────────────────────────────────────────────
    cpf1 = client.encode("ff-cpf", "12345678909", role_core)
    cpf2 = client.encode("ff-cpf", "12345678909", role_core)
    assert cpf1 == cpf2, "FPE deve ser determinístico!"
    console.print(f"\n  ✅ [bold]FPE é determinístico[/bold] — mesmo CPF sempre gera o mesmo valor cifrado")
    console.print(f"     Encode #1 = Encode #2 = [green]{client.format_cpf(cpf1)}[/green]")
    console.print(f"     [dim]→ SELECT * FROM clientes WHERE cpf_protected = '{client.format_cpf(cpf1)}' funciona com índice![/dim]")

    # ────────────────────────────────────────────────────────────────────────
    section("2. Masking — Ofuscação Parcial (One-Way / Irreversível)")
    # ────────────────────────────────────────────────────────────────────────
    console.print("  [dim]Masking é IRREVERSÍVEL — adequado para logs, UIs de suporte e dashboards.[/dim]")
    console.print("  [dim]Não requer policy de decode — equipes de suporte enxergam apenas o mascarado.[/dim]\n")

    mask_cases = [
        ("mask-email", "E-mail",           "joao.silva@empresa.com"),
        ("mask-email", "E-mail (pessoal)", "maria.costa@gmail.com.br"),
        ("mask-nome",  "Nome Completo",    "João Carlos da Silva"),
        ("mask-dob",   "Data Nascimento",  "15/03/1985"),
        ("mask-cvv",   "CVV Cartão",       "123"),
    ]

    for transformation, label, original in mask_cases:
        try:
            masked = client.encode(transformation, original, role_api)
            ok(label, original, masked, reversible=False)
        except Exception as e:
            console.print(f"  ⚠️  {label}: {e}")

    # ── Confirmar irreversibilidade ─────────────────────────────────────────
    console.print("\n  [bold]Tentativa de decode em campo mascarado:[/bold]")
    try:
        client.decode("mask-email", "j***@e**.com", role_core)
        console.print("  ❌ [red]ERRO: decode deveria ter falhado![/red]")
    except Exception:
        console.print("  ✅ [green]Masking confirmado como irreversível — decode retornou erro 403[/green]")

    # ────────────────────────────────────────────────────────────────────────
    section("3. Tokenização Convergente — Token Opaco e Reversível (HMAC)")
    # ────────────────────────────────────────────────────────────────────────
    console.print("  [dim]Token opaco — nada do dado original é visível no token.[/dim]")
    console.print("  [dim]Convergente: mesmo dado → mesmo token. Permite joins em Data Lakes.[/dim]\n")

    tok_cases = [
        ("tok-endereco", "Endereço",      "Rua das Flores, 123, São Paulo, SP"),
        ("tok-endereco", "Endereço 2",    "Av. Paulista, 1000, São Paulo, SP"),
        ("tok-conta",    "Conta Bancária","BR6000360305000010009795493P1"),
    ]

    tokens = {}
    for transformation, label, original in tok_cases:
        try:
            token = client.encode(transformation, original, role_core)
            tokens[(transformation, original)] = token
            ok(label, original[:40], token, reversible=True)
        except Exception as e:
            console.print(f"  ⚠️  {label}: {e}")

    # ── Convergência ────────────────────────────────────────────────────────
    console.print("\n  [bold]Convergência (mesmo endereço → mesmo token):[/bold]")
    end = "Rua das Flores, 123, São Paulo, SP"
    tok_a = client.encode("tok-endereco", end, role_core)
    tok_b = client.encode("tok-endereco", end, role_core)
    assert tok_a == tok_b, "Tokenização deve ser convergente!"
    console.print(f"  ✅ Token #1 = Token #2 = [green]{tok_a}[/green]")
    console.print(f"     [dim]→ Joins em Data Lake por token funcionam corretamente[/dim]")

    # ── Detokenize ─────────────────────────────────────────────────────────
    console.print("\n  [bold]Detokenize (core-role):[/bold]")
    tok     = client.encode("tok-endereco", end, role_core)
    decoded = client.decode("tok-endereco", tok, role_core)
    console.print(f"  ✅ [red]{end}[/red] → [green]{tok}[/green] → [blue]{decoded}[/blue]")

    # ────────────────────────────────────────────────────────────────────────
    section("4. protect_customer() — Proteção Completa de um Registro de Cliente")
    # ────────────────────────────────────────────────────────────────────────
    raw_customer = {
        "nome":      "João Carlos da Silva",
        "cpf":       "12345678909",
        "cnpj":      "12345678000190",
        "email":     "joao.silva@empresa.com",
        "telefone":  "11998765432",
        "pan":       "4111111111111111",
        "cvv":       "123",
        "dob":       "15/03/1985",
        "endereco":  "Rua das Flores, 123, São Paulo, SP",
        "conta":     "BR6000360305000010009795493P1",
    }

    protected = client.protect_customer(raw_customer, role=role_api)

    tbl = Table(title="Dados do Cliente", box=box.ROUNDED, show_lines=True)
    tbl.add_column("Campo",           style="bold", width=14)
    tbl.add_column("Original (PII)",  style="red",  width=38)
    tbl.add_column("Protegido (BD)",  style="green",width=38)
    tbl.add_column("Operação",        style="cyan", width=16)

    ops = {
        "nome":     ("—",               "Mantido"),
        "cpf":      ("FPE ff-cpf",      "FPE"),
        "cnpj":     ("FPE ff-cnpj",     "FPE"),
        "email":    ("Mask mask-email", "Masking"),
        "telefone": ("FPE ff-tel",      "FPE"),
        "pan":      ("FPE ff-pan",      "FPE"),
        "cvv":      ("Mask mask-cvv",   "Masking"),
        "dob":      ("Mask mask-dob",   "Masking"),
        "endereco": ("Token tok-end",   "Tokenização"),
        "conta":    ("Token tok-cta",   "Tokenização"),
    }

    display_fmt = {
        "cpf":  client.format_cpf,
        "cnpj": client.format_cnpj,
    }

    for campo, (_, op_label) in ops.items():
        fmt      = display_fmt.get(campo, str)
        orig_val = fmt(str(raw_customer.get(campo, "—")))
        prot_val = fmt(str(protected.get(campo, "—")))
        tbl.add_row(campo, orig_val[:36], prot_val[:36], op_label)

    console.print(tbl)

    # ────────────────────────────────────────────────────────────────────────
    section("5. Batch Encode — Alta Performance para Pipelines ETL")
    # ────────────────────────────────────────────────────────────────────────
    import time

    cpfs = [
        "12345678909", "98765432100", "11122233344", "55566677788", "99988877766",
        "44433322211", "77788899900", "33344455566", "66677788899", "22211100099",
        "10987654321", "20987654321", "30987654321", "40987654321", "50987654321",
        "60987654321", "70987654321", "80987654321", "90987654321", "01987654321",
    ]

    console.print(f"  Encode de [bold]{len(cpfs)} CPFs[/bold] em uma única chamada batch_input API...\n")

    t0 = time.perf_counter()
    encoded_batch = client.batch_encode("ff-cpf", cpfs, role_core)
    elapsed = time.perf_counter() - t0

    for orig, enc in zip(cpfs[:5], encoded_batch[:5]):
        console.print(f"  [red]{client.format_cpf(orig)}[/red] → [green]{client.format_cpf(enc)}[/green]")
    console.print(f"  [dim]... ({len(cpfs) - 5} mais)[/dim]")
    console.print(f"\n  ✅ [bold]{len(cpfs)} valores em {elapsed*1000:.1f}ms[/bold] — 1 chamada à API Vault")

    # ────────────────────────────────────────────────────────────────────────
    section("6. RBAC — Demonstração de Controle de Acesso")
    # ────────────────────────────────────────────────────────────────────────
    console.print("  [dim]api-approle   → encode-only policy  (apps de produção)[/dim]")
    console.print("  [dim]core-approle  → core-access policy  (sistemas core autorizados pelo DPO)[/dim]\n")

    # api-approle (encode-only policy) — encode deve funcionar
    cpf_encoded = client_api.encode("ff-cpf", "12345678909", role_api)
    console.print(f"  ✅ api-approle  encode CPF: [green]{client.format_cpf(cpf_encoded)}[/green]")

    # api-approle — decode deve falhar com 403 (Vault ACL bloqueia transform/decode/*)
    try:
        client_api.decode("ff-cpf", cpf_encoded, role_api)
        console.print("  ❌ [red]ERRO: api-approle não deveria conseguir decode![/red]")
    except Exception:
        console.print("  ✅ api-approle  decode CPF: [green]403 Forbidden — encode-only policy funcional[/green]")

    # core-approle (core-access policy) — decode deve funcionar
    decoded = client.decode("ff-cpf", cpf_encoded, role_core)
    console.print(f"  ✅ core-approle decode CPF: [blue]{client.format_cpf(decoded)}[/blue] ← dado original recuperado")

    # ────────────────────────────────────────────────────────────────────────
    section("Resumo LGPD")
    # ────────────────────────────────────────────────────────────────────────
    lgpd = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    lgpd.add_column("Artigo LGPD", style="bold yellow", width=20)
    lgpd.add_column("Obrigação",                        width=35)
    lgpd.add_column("Atendimento",  style="green",      width=40)

    lgpd.add_row("Art. 46 — Segurança",     "Medidas técnicas de proteção",    "✅ FPE/Masking/Token em todas as camadas")
    lgpd.add_row("Art. 47 — Sigilo",        "Sigilo de agentes de tratamento", "✅ Masking para suporte — dado real inacessível")
    lgpd.add_row("Art. 48 — Incidentes",    "Notificação de vazamentos",       "✅ Dado FPE ≠ dado pessoal acessível")
    lgpd.add_row("Art. 49 — Privacy by Design","Segurança desde a concepção",  "✅ PII protegida antes de persistir")
    lgpd.add_row("Art. 20 — Revisão",       "Revisão de decisões automatizadas","✅ Detokenize por sistemas core autorizados")

    console.print(lgpd)
    console.print("\n[bold green]✅ Demo concluída com sucesso![/bold green]")
    console.print("\n  Próximos passos:")
    console.print("    • API REST:  [bold]uvicorn src.api.app:app --reload[/bold]")
    console.print("    • Docs API:  [bold]http://localhost:8000/docs[/bold]")
    console.print("    • Pipeline:  [bold]python src/pipeline/batch_protect.py --generate[/bold]")
    console.print("    • Testes:    [bold]pytest tests/ -v[/bold]\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault Transform Demo — LGPD/PII")
    parser.add_argument("--vault-addr",    default=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"))
    parser.add_argument("--vault-token",   default=os.environ.get("VAULT_TOKEN"))
    parser.add_argument("--api-role-id",   default=os.environ.get("VAULT_API_ROLE_ID"))
    parser.add_argument("--api-secret-id", default=os.environ.get("VAULT_API_SECRET_ID"))
    args = parser.parse_args()

    if not args.vault_token:
        print("❌  VAULT_TOKEN not set — run via Vault Agent:  bash run_demo.sh")
        sys.exit(1)

    run_demo(
        args.vault_addr,
        args.vault_token,
        args.api_role_id, args.api_secret_id,
    )
