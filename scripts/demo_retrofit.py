"""
scripts/demo_retrofit.py — Demo: Retrofit PII Protection via Vault Transform

Simulates the classic scenario: an existing production database has cleartext
PII that needs to be protected in place using Vault Transform Secret Engine.

Flow:
  1. Create clientes_staging table with cleartext PII columns
  2. Seed N rows with fake cleartext data (no Vault involved)
  3. Display "BEFORE" — cleartext PII visible to anyone with DB access
  4. Protection pass — batch-encode every PII field via Vault, UPDATE in place
  5. Display "AFTER"  — same rows, PII replaced with FPE / Masked / Token values
  6. Verify round-trip for reversible fields (FPE, tokenisation)

Usage:
    python scripts/demo_retrofit.py
    python scripts/demo_retrofit.py --count 10
    python scripts/demo_retrofit.py --vault-addr http://localhost:8200 --count 5
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from sqlalchemy import create_engine, text

load_dotenv()
console = Console()

DB_URL = os.environ.get("DB_URL", "postgresql://vault_demo:vault_demo@localhost:5432/vault_demo")

# ── Fake data pools ───────────────────────────────────────────────────────────

NOMES = [
    "João Carlos da Silva", "Maria Aparecida Santos", "Carlos Eduardo Oliveira",
    "Ana Paula Costa", "Pedro Henrique Souza", "Juliana Lima", "Roberto Ferreira",
    "Camila Pereira", "Lucas Rodrigues", "Fernanda Alves",
]
DOMINIOS = ["gmail.com", "hotmail.com", "yahoo.com.br", "empresa.com.br"]
RUAS = [
    "Rua das Flores, 123, São Paulo, SP",
    "Av. Paulista, 1000, São Paulo, SP",
    "Rua do Comércio, 45, Rio de Janeiro, RJ",
    "Travessa Central, 78, Curitiba, PR",
    "Alameda Santos, 500, São Paulo, SP",
]
SAUDES = [
    "Diabetes tipo 2", "Hipertensão arterial", "Asma brônquica",
    "HIV positivo", "Transtorno depressivo maior", "Nenhuma condição conhecida",
    "Hipotireoidismo", "Doença celíaca",
]
RACAS = ["Branca", "Preta", "Parda", "Amarela", "Indígena"]
RELIGIOES = [
    "Católica", "Evangélica", "Espírita", "Sem religião",
    "Budista", "Umbandista", "Judaica", "Islâmica",
]


def format_cpf(digits: str) -> str:
    """'12345678909' → '123.456.789-09'"""
    d = digits.replace(".", "").replace("-", "")
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}" if len(d) == 11 else digits


def rand_cpf() -> str:
    d = [random.randint(0, 9) for _ in range(9)]
    s1 = sum((10 - i) * d[i] for i in range(9)) % 11
    d.append(0 if s1 < 2 else 11 - s1)
    s2 = sum((11 - i) * d[i] for i in range(10)) % 11
    d.append(0 if s2 < 2 else 11 - s2)
    return "".join(map(str, d))


def rand_pan() -> str:
    return "4" + "".join([str(random.randint(0, 9)) for _ in range(15)])


def rand_telefone() -> str:
    return "119" + "".join([str(random.randint(0, 9)) for _ in range(8)])


# ── DDL ───────────────────────────────────────────────────────────────────────

DDL_STAGING = """
CREATE TABLE IF NOT EXISTS clientes_staging (
    id                  SERIAL PRIMARY KEY,
    nome                VARCHAR(200) NOT NULL,

    -- Cleartext PII (pre-migration)
    cpf_raw             VARCHAR(20),
    email_raw           VARCHAR(200),
    telefone_raw        VARCHAR(20),
    pan_raw             VARCHAR(20),
    dob_raw             VARCHAR(20),
    endereco_raw        VARCHAR(200),
    -- Dados sensíveis LGPD Art. 11 (cleartext pre-migration)
    saude_raw           VARCHAR(200),
    raca_raw            VARCHAR(100),
    religiao_raw        VARCHAR(100),

    -- Protected values populated by the Vault protection pass
    cpf_protected       VARCHAR(11),
    email_masked        VARCHAR(200),
    telefone_protected  VARCHAR(11),
    pan_protected       VARCHAR(16),
    dob_masked          VARCHAR(20),
    endereco_token      VARCHAR(100),
    -- Dados sensíveis tokenizados
    saude_token         VARCHAR(100),
    raca_token          VARCHAR(100),
    religiao_token      VARCHAR(100),

    protected           BOOLEAN DEFAULT FALSE,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""


def setup_staging(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS clientes_staging"))
        conn.execute(text(DDL_STAGING))


# ── Seed ──────────────────────────────────────────────────────────────────────

def seed_cleartext(engine, count: int) -> None:
    rows = []
    for i in range(count):
        nome  = random.choice(NOMES)
        first = nome.split()[0].lower()
        rows.append({
            "nome":     nome,
            "cpf":      rand_cpf(),
            "email":    f"{first}.{i:03d}@{random.choice(DOMINIOS)}",
            "telefone": rand_telefone(),
            "pan":      rand_pan(),
            "dob":      f"{random.randint(1,28):02d}/{random.randint(1,12):02d}/{random.randint(1960,2005)}",
            "endereco": random.choice(RUAS),
            "saude":    random.choice(SAUDES),
            "raca":     random.choice(RACAS),
            "religiao": random.choice(RELIGIOES),
        })

    sql = text("""
        INSERT INTO clientes_staging
            (nome, cpf_raw, email_raw, telefone_raw, pan_raw, dob_raw, endereco_raw,
             saude_raw, raca_raw, religiao_raw)
        VALUES
            (:nome, :cpf, :email, :telefone, :pan, :dob, :endereco,
             :saude, :raca, :religiao)
    """)
    with engine.begin() as conn:
        conn.execute(sql, rows)


# ── Display helpers ────────────────────────────────────────────────────────────

def show_before(engine, limit: int) -> None:
    sql = text("""
        SELECT id, nome, cpf_raw, email_raw, telefone_raw, pan_raw, dob_raw,
               saude_raw, raca_raw, religiao_raw
        FROM clientes_staging
        ORDER BY id
        LIMIT :limit
    """)
    with engine.connect() as conn:
        rows = conn.execute(sql, {"limit": limit}).fetchall()

    tbl = Table(
        title="[bold red]BEFORE — Cleartext PII in Database[/bold red]",
        box=box.ROUNDED, show_lines=True,
    )
    tbl.add_column("ID",       style="dim",    width=4)
    tbl.add_column("Nome",     style="white",  width=22)
    tbl.add_column("CPF",      style="red",    width=15)
    tbl.add_column("E-mail",   style="red",    width=28)
    tbl.add_column("PAN",      style="red",    width=18)
    tbl.add_column("Saúde",    style="red",    width=26)
    tbl.add_column("Raça",     style="red",    width=12)
    tbl.add_column("Religião", style="red",    width=14)

    for r in rows:
        pan = r.pan_raw or ""
        pan_fmt = f"{pan[:4]} {pan[4:8]} {pan[8:12]} {pan[12:]}" if len(pan) == 16 else pan
        tbl.add_row(
            str(r.id), r.nome,
            format_cpf(r.cpf_raw or ""),
            r.email_raw or "",
            pan_fmt,
            r.saude_raw or "",
            r.raca_raw or "",
            r.religiao_raw or "",
        )

    console.print(tbl)
    console.print(
        "  [bold red]Any DBA or developer with SELECT on this table can read full PII "
        "— including sensitive health, race, and religion data.[/bold red]\n"
    )


def show_after(engine, limit: int) -> None:
    sql = text("""
        SELECT id, nome,
               cpf_protected, email_masked, pan_protected,
               saude_token, raca_token, religiao_token
        FROM clientes_staging
        ORDER BY id
        LIMIT :limit
    """)
    with engine.connect() as conn:
        rows = conn.execute(sql, {"limit": limit}).fetchall()

    tbl = Table(
        title="[bold green]AFTER — PII Protected by Vault Transform[/bold green]",
        box=box.ROUNDED, show_lines=True,
    )
    tbl.add_column("ID",               style="dim",    width=4)
    tbl.add_column("Nome",             style="white",  width=22)
    tbl.add_column("CPF (FPE)",        style="green",  width=15)
    tbl.add_column("E-mail (Mask)",    style="yellow", width=28)
    tbl.add_column("PAN (FPE)",        style="green",  width=18)
    tbl.add_column("Saúde (Token)",    style="cyan",   width=26)
    tbl.add_column("Raça (Token)",     style="cyan",   width=22)
    tbl.add_column("Religião (Token)", style="cyan",   width=22)

    for r in rows:
        pan = r.pan_protected or ""
        pan_fmt = f"{pan[:4]} {pan[4:8]} {pan[8:12]} {pan[12:]}" if len(pan) == 16 else pan
        tbl.add_row(
            str(r.id), r.nome,
            format_cpf(r.cpf_protected or ""),
            r.email_masked or "",
            pan_fmt,
            (r.saude_token or "")[:24],
            (r.raca_token or "")[:20],
            (r.religiao_token or "")[:20],
        )

    console.print(tbl)
    console.print(
        "  [bold green]Green = FPE (reversible)  "
        "Yellow = Masking (irreversible)  "
        "Cyan = Tokenisation (reversible by core-role)[/bold green]\n"
    )


# ── Protection pass ───────────────────────────────────────────────────────────

def protect_in_place(engine, vault, role: str) -> dict:
    """
    Reads all unprotected rows, batch-encodes every PII field via Vault,
    then UPDATEs the table in a single transaction.

    Returns timing statistics.
    """
    sql_read = text("""
        SELECT id, cpf_raw, email_raw, telefone_raw, pan_raw, dob_raw, endereco_raw,
               saude_raw, raca_raw, religiao_raw
        FROM clientes_staging
        WHERE protected = FALSE
        ORDER BY id
    """)
    with engine.connect() as conn:
        rows = conn.execute(sql_read).fetchall()

    if not rows:
        console.print("  [yellow]No unprotected rows found.[/yellow]")
        return {}

    ids       = [r.id            for r in rows]
    cpfs      = [r.cpf_raw      or "" for r in rows]
    emails    = [r.email_raw    or "" for r in rows]
    telefones = [r.telefone_raw or "" for r in rows]
    pans      = [r.pan_raw      or "" for r in rows]
    dobs      = [r.dob_raw      or "" for r in rows]
    enderecos = [r.endereco_raw or "" for r in rows]
    saudes    = [r.saude_raw    or "" for r in rows]
    racas     = [r.raca_raw     or "" for r in rows]
    religioes = [r.religiao_raw or "" for r in rows]

    console.print(f"  Encoding [bold]{len(rows)}[/bold] rows via Vault Transform batch API...\n")

    timings = {}

    t0 = time.perf_counter()
    cpf_enc  = vault.batch_encode("ff-cpf",      cpfs,      role)
    timings["ff-cpf"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    tel_enc  = vault.batch_encode("ff-telefone", telefones, role)
    timings["ff-telefone"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    pan_enc  = vault.batch_encode("ff-pan",      pans,      role)
    timings["ff-pan"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    email_enc = vault.batch_encode("mask-email",  emails,    role)
    timings["mask-email"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    dob_enc  = vault.batch_encode("mask-dob",    dobs,      role)
    timings["mask-dob"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    end_enc  = vault.batch_encode("tok-endereco", enderecos, role)
    timings["tok-endereco"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    saude_enc   = vault.batch_encode("tok-saude",   saudes,    role)
    timings["tok-saude"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    raca_enc    = vault.batch_encode("tok-raca",    racas,     role)
    timings["tok-raca"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    religiao_enc = vault.batch_encode("tok-religiao", religioes, role)
    timings["tok-religiao"] = time.perf_counter() - t0

    sql_update = text("""
        UPDATE clientes_staging SET
            cpf_protected      = :cpf_protected,
            email_masked       = :email_masked,
            telefone_protected = :telefone_protected,
            pan_protected      = :pan_protected,
            dob_masked         = :dob_masked,
            endereco_token     = :endereco_token,
            saude_token        = :saude_token,
            raca_token         = :raca_token,
            religiao_token     = :religiao_token,
            protected          = TRUE
        WHERE id = :id
    """)

    updates = [
        {
            "id":                 ids[i],
            "cpf_protected":      cpf_enc[i],
            "email_masked":       email_enc[i],
            "telefone_protected": tel_enc[i],
            "pan_protected":      pan_enc[i],
            "dob_masked":         dob_enc[i],
            "endereco_token":     end_enc[i],
            "saude_token":        saude_enc[i],
            "raca_token":         raca_enc[i],
            "religiao_token":     religiao_enc[i],
        }
        for i in range(len(ids))
    ]

    with engine.begin() as conn:
        conn.execute(sql_update, updates)

    return timings


# ── Verification ──────────────────────────────────────────────────────────────

def verify_roundtrip(engine, vault, role_decode: str) -> None:
    """Spot-check FPE round-trip on the first protected row."""
    sql = text("""
        SELECT id, cpf_raw, cpf_protected, telefone_raw, telefone_protected,
               pan_raw, pan_protected
        FROM clientes_staging
        WHERE protected = TRUE
        LIMIT 1
    """)
    with engine.connect() as conn:
        row = conn.execute(sql).fetchone()

    if not row:
        return

    console.print("  [bold]FPE Round-trip Verification (row ID=%d):[/bold]" % row.id)

    formatters = {
        "ff-cpf": format_cpf,
    }

    for field, raw_val, enc_val, transformation in [
        ("CPF",      row.cpf_raw,      row.cpf_protected,      "ff-cpf"),
        ("Telefone", row.telefone_raw, row.telefone_protected, "ff-telefone"),
        ("PAN",      row.pan_raw,      row.pan_protected,      "ff-pan"),
    ]:
        try:
            decoded = vault.decode(transformation, enc_val, role_decode)
            fmt = formatters.get(transformation, str)
            match = "✅" if decoded == (raw_val or "") else "❌"
            console.print(
                f"  {match} {field:<10} "
                f"[red]{fmt(raw_val or '')}[/red] → "
                f"[green]{fmt(enc_val or '')}[/green] → "
                f"[blue]{fmt(decoded)}[/blue]"
            )
        except Exception as e:
            console.print(f"  ⚠️  {field} decode failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(vault_addr: str, vault_token: str, count: int) -> None:
    from src.vault.client import VaultTransformClient

    console.print(Panel.fit(
        "[bold]Vault Transform — Retrofit PII Protection Demo[/bold]\n"
        "[dim]Protecting cleartext PII in an existing database, in place[/dim]",
        border_style="cyan",
    ))

    vault = VaultTransformClient(vault_addr=vault_addr, token=vault_token)
    try:
        vault._get_client()
        console.print(f"\n✅ [green]Vault connected:[/green] {vault_addr}\n")
    except Exception as e:
        console.print(f"\n❌ [red]Vault not available: {e}[/red]")
        console.print("   Start services: [bold]docker-compose -f docker/docker-compose.yml up -d[/bold]")
        sys.exit(1)

    engine = create_engine(DB_URL, pool_pre_ping=True, echo=False)

    role_encode = "api-role"
    role_decode = "core-role"

    # ── Step 1: Create staging table ─────────────────────────────────────────
    console.rule("[bold cyan]Step 1 — Create Staging Table[/bold cyan]")
    setup_staging(engine)
    console.print("  ✅ clientes_staging created (cleartext PII columns + protected columns)\n")

    # ── Step 2: Seed cleartext data ──────────────────────────────────────────
    console.rule("[bold cyan]Step 2 — Seed Cleartext PII Data (no Vault)[/bold cyan]")
    seed_cleartext(engine, count)
    console.print(f"  ✅ {count} rows inserted with cleartext PII\n")

    # ── Step 3: Show BEFORE ──────────────────────────────────────────────────
    console.rule("[bold red]Step 3 — BEFORE: Cleartext PII Exposed[/bold red]")
    show_before(engine, limit=count)

    # ── Step 4: Vault protection pass ────────────────────────────────────────
    console.rule("[bold cyan]Step 4 — Vault Transform Protection Pass[/bold cyan]")
    timings = protect_in_place(engine, vault, role=role_encode)

    total_ms = sum(timings.values()) * 1000
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("Transformation",  width=18)
    tbl.add_column("Type",            width=14)
    tbl.add_column("Rows",            width=8,  justify="right")
    tbl.add_column("Vault API (ms)",  width=16, justify="right")

    type_map = {
        "ff-cpf":        "FPE",
        "ff-telefone":   "FPE",
        "ff-pan":        "FPE",
        "mask-email":    "Masking",
        "mask-dob":      "Masking",
        "tok-endereco":  "Tokenisation",
        "tok-saude":     "Tokenisation",
        "tok-raca":      "Tokenisation",
        "tok-religiao":  "Tokenisation",
    }
    for t, elapsed in timings.items():
        tbl.add_row(t, type_map.get(t, "—"), str(count), f"{elapsed*1000:.1f}")

    console.print(tbl)
    console.print(
        f"  ✅ [bold]{count} rows × 6 fields protected in {total_ms:.0f}ms total[/bold] "
        f"— [dim]6 batch API calls[/dim]\n"
    )

    # ── Step 5: Show AFTER ───────────────────────────────────────────────────
    console.rule("[bold green]Step 5 — AFTER: PII Protected In Place[/bold green]")
    show_after(engine, limit=count)

    # ── Step 6: Round-trip verification ─────────────────────────────────────
    console.rule("[bold cyan]Step 6 — FPE Round-trip Verification[/bold cyan]")
    verify_roundtrip(engine, vault, role_decode)

    console.print()
    console.print(Panel.fit(
        "[bold green]Retrofit complete.[/bold green]\n\n"
        "  • Cleartext PII is still in [red]cpf_raw / email_raw / ...[/red] columns — "
        "drop or nullify them after validation.\n"
        "  • Protected values in [green]cpf_protected / email_masked / ...[/green] columns "
        "match the schema used by the main [bold]clientes[/bold] table.\n"
        "  • FPE values are searchable — existing indexes work without changes.\n"
        "  • Masking is irreversible; FPE and tokenisation can be decoded by core-role.",
        border_style="green",
    ))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault Transform Retrofit Demo")
    parser.add_argument("--vault-addr",  default=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"))
    parser.add_argument("--vault-token", default=os.environ.get("VAULT_TOKEN"))
    parser.add_argument("--count",       type=int, default=8)
    args = parser.parse_args()

    if not args.vault_token:
        console.print("❌  VAULT_TOKEN not set. Export it or use: [bold]bash scripts/setup.sh[/bold]")
        sys.exit(1)

    run(args.vault_addr, args.vault_token, args.count)
