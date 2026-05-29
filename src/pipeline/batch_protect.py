"""
pipeline/batch_protect.py — Proteção PII em lote para arquivos CSV.

Usa a batch_input API do Vault Transform para processar múltiplos valores
em uma única chamada — ideal para pipelines ETL com alto volume.

Uso:
    python src/pipeline/batch_protect.py \\
        --input  data/clientes_raw.csv \\
        --output data/clientes_protected.csv \\
        --batch-size 100

Mapeamento de campos (hardcoded — customize via config):
    cpf       → ff-cpf       (FPE)
    pan       → ff-pan       (FPE)
    telefone  → ff-telefone  (FPE)
    email     → mask-email   (Masking)
    dob       → mask-dob     (Masking)
    endereco  → tok-endereco (Tokenização)
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import sys
import time
from pathlib import Path
from typing import Iterator

import pandas as pd
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from src.vault.client import VaultTransformClient

load_dotenv()
logger  = logging.getLogger(__name__)
console = Console()

# Mapeamento campo CSV → transformation Vault + normalização
FIELD_TRANSFORM_MAP = {
    "cpf":      ("ff-cpf",       lambda v: v.replace(".", "").replace("-", "")),
    "pan":      ("ff-pan",       lambda v: v.replace(" ", "").replace("-", "")),
    "telefone": ("ff-telefone",  lambda v: v.replace("(","").replace(")","").replace(" ","").replace("-","")),
    "email":    ("mask-email",   str),
    "nome":     ("mask-nome",    str),
    "dob":      ("mask-dob",     str),
    "endereco": ("tok-endereco", str),
    "conta":    ("tok-conta",    str),
}


def chunked(lst: list, size: int) -> Iterator[list]:
    """Divide lista em chunks de `size` elementos."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def protect_dataframe(
    df: pd.DataFrame,
    vault: VaultTransformClient,
    role: str = "pipeline-role",
    batch_size: int = 100,
) -> tuple[pd.DataFrame, dict]:
    """
    Protege todas as colunas PII de um DataFrame usando batch_input API.

    Args:
        df:         DataFrame com dados raw (PII em claro)
        vault:      cliente Vault autenticado
        role:       Transform role (ex: pipeline-role)
        batch_size: quantidade de valores por chamada batch_input

    Returns:
        (DataFrame protegido, dict com estatísticas)
    """
    df_out  = df.copy()
    stats   = {"fields_protected": 0, "records": len(df), "api_calls": 0, "errors": 0}

    pii_cols = [col for col in df.columns if col.lower() in FIELD_TRANSFORM_MAP]

    if not pii_cols:
        console.print("[yellow]⚠️  Nenhuma coluna PII mapeada encontrada no CSV.[/yellow]")
        return df_out, stats

    console.print(f"\n[bold]Colunas PII detectadas:[/bold] {', '.join(pii_cols)}")

    for col in pii_cols:
        transformation, normalizer = FIELD_TRANSFORM_MAP[col.lower()]
        console.print(f"\n  🔐 [bold]{col}[/bold] → {transformation}")

        # Coleta valores não nulos
        mask      = df_out[col].notna() & (df_out[col].astype(str).str.strip() != "")
        values    = df_out.loc[mask, col].astype(str).tolist()
        normalized = [normalizer(v) for v in values]

        protected_values: list[str] = []
        errors = 0

        # Processa em batches
        batches = list(chunked(normalized, batch_size))
        for batch in batches:
            try:
                encoded = vault.batch_encode(transformation, batch, role)
                protected_values.extend(encoded)
                stats["api_calls"] += 1
            except Exception as e:
                logger.error("Erro no batch encode (%s): %s", transformation, e)
                protected_values.extend(["ERROR"] * len(batch))
                errors += len(batch)
                stats["errors"] += len(batch)

        # Reinsere na posição correta
        idx_list = df_out.index[mask].tolist()
        for idx, prot_val in zip(idx_list, protected_values):
            df_out.at[idx, col] = prot_val

        stats["fields_protected"] += 1
        console.print(
            f"    ✅ {len(values)} valores protegidos em {len(batches)} batch(es)"
            + (f" | ⚠️  {errors} erros" if errors else "")
        )

    return df_out, stats


def run(
    input_path: str,
    output_path: str,
    role: str = "pipeline-role",
    batch_size: int = 100,
) -> dict:
    """Executa a pipeline de proteção PII no CSV especificado."""

    in_path  = Path(input_path)
    out_path = Path(output_path)

    if not in_path.exists():
        console.print(f"[red]❌ Arquivo não encontrado: {in_path}[/red]")
        sys.exit(1)

    console.rule("[bold blue]Vault Transform — Batch PII Protection Pipeline")
    console.print(f"[dim]Input:[/dim]  {in_path}")
    console.print(f"[dim]Output:[/dim] {out_path}")
    console.print(f"[dim]Role:[/dim]   {role} | [dim]Batch:[/dim] {batch_size}")

    # Autenticar no Vault
    vault = VaultTransformClient()
    try:
        vault._get_client()
        console.print("\n✅ [green]Vault autenticado[/green]")
    except Exception as e:
        console.print(f"\n[red]❌ Falha ao conectar ao Vault: {e}[/red]")
        sys.exit(1)

    # Ler CSV
    df = pd.read_csv(in_path, dtype=str)
    console.print(f"\n📊 {len(df)} registros lidos | {len(df.columns)} colunas")

    # Proteger PII
    t0 = time.perf_counter()
    df_protected, stats = protect_dataframe(df, vault, role=role, batch_size=batch_size)
    elapsed = time.perf_counter() - t0

    # Salvar
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_protected.to_csv(out_path, index=False, quoting=csv.QUOTE_NONNUMERIC)

    # Resumo
    console.rule("[bold green]Resumo")
    tbl = Table(show_header=True, header_style="bold cyan")
    tbl.add_column("Métrica",    style="bold")
    tbl.add_column("Valor",      justify="right")
    tbl.add_row("Registros processados",   str(stats["records"]))
    tbl.add_row("Campos PII protegidos",   str(stats["fields_protected"]))
    tbl.add_row("Chamadas API Vault",      str(stats["api_calls"]))
    tbl.add_row("Erros",                   str(stats["errors"]))
    tbl.add_row("Tempo total",             f"{elapsed:.2f}s")
    tbl.add_row("Throughput",              f"{stats['records'] / elapsed:.0f} registros/s")
    console.print(tbl)
    console.print(f"\n💾 [green]Arquivo protegido salvo em:[/green] {out_path}")

    return stats


def generate_sample_csv(path: str = "data/clientes_raw.csv", n: int = 200):
    """Gera arquivo CSV de teste com dados PII fictícios."""
    import random
    import string

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    def rand_cpf():
        d = [random.randint(0, 9) for _ in range(9)]
        # Calcula dígitos verificadores
        s1 = sum((10 - i) * d[i] for i in range(9)) % 11
        d.append(0 if s1 < 2 else 11 - s1)
        s2 = sum((11 - i) * d[i] for i in range(10)) % 11
        d.append(0 if s2 < 2 else 11 - s2)
        return f"{''.join(map(str, d[:3]))}.{''.join(map(str, d[3:6]))}.{''.join(map(str, d[6:9]))}-{''.join(map(str, d[9:]))}"

    def rand_pan():
        digits = [4] + [random.randint(0, 9) for _ in range(15)]
        return "".join(map(str, digits))

    nomes = ["João Silva", "Maria Santos", "Carlos Oliveira", "Ana Costa",
             "Pedro Souza", "Juliana Lima", "Roberto Ferreira", "Camila Pereira"]
    dominios = ["gmail.com", "hotmail.com", "yahoo.com.br", "empresa.com.br"]

    rows = []
    for i in range(n):
        nome = random.choice(nomes)
        first = nome.split()[0].lower()
        rows.append({
            "id":        i + 1,
            "nome":      nome,
            "cpf":       rand_cpf(),
            "email":     f"{first}.{i:03d}@{random.choice(dominios)}",
            "telefone":  f"119{''.join([str(random.randint(0,9)) for _ in range(8)])}",
            "pan":       rand_pan(),
            "dob":       f"{random.randint(1,28):02d}/{random.randint(1,12):02d}/{random.randint(1960,2000)}",
            "endereco":  f"Rua {random.choice(['das Flores','do Sol','Principal'])}, {random.randint(1,999)}, São Paulo, SP",
        })

    df = pd.DataFrame(rows)
    df.to_csv(path, index=False, quoting=csv.QUOTE_NONNUMERIC)
    console.print(f"✅ CSV de teste gerado: {path} ({n} registros)")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault Transform — Batch PII Protection")
    parser.add_argument("--input",      default="data/clientes_raw.csv")
    parser.add_argument("--output",     default="data/clientes_protected.csv")
    parser.add_argument("--role",       default="pipeline-role")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--generate",   action="store_true", help="Gera CSV de teste antes de proteger")
    args = parser.parse_args()

    if args.generate:
        generate_sample_csv(args.input)

    run(args.input, args.output, role=args.role, batch_size=args.batch_size)
