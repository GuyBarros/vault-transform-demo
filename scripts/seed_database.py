"""
scripts/seed_database.py — Popula o banco de dados com clientes de teste
com dados PII já protegidos via Vault Transform Engine.

Uso:
    python scripts/seed_database.py --count 50
"""

import sys, random, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import track

load_dotenv()
console = Console()

NOMES = [
    "João Carlos da Silva", "Maria Aparecida Santos", "Carlos Eduardo Oliveira",
    "Ana Paula Costa", "Pedro Henrique Souza", "Juliana Lima", "Roberto Ferreira",
    "Camila Pereira", "Lucas Rodrigues", "Fernanda Alves"
]
DOMINIOS = ["gmail.com", "hotmail.com", "yahoo.com.br", "empresa.com.br", "outlook.com"]
RUAS = ["Rua das Flores", "Av. Paulista", "Rua do Comércio", "Travessa Central", "Alameda Santos"]
CIDADES = ["São Paulo, SP", "Rio de Janeiro, RJ", "Curitiba, PR", "Belo Horizonte, MG"]


def rand_cpf():
    d = [random.randint(0, 9) for _ in range(9)]
    s1 = sum((10 - i) * d[i] for i in range(9)) % 11
    d.append(0 if s1 < 2 else 11 - s1)
    s2 = sum((11 - i) * d[i] for i in range(10)) % 11
    d.append(0 if s2 < 2 else 11 - s2)
    return "".join(map(str, d))


def seed(count: int = 20):
    from src.vault.client import VaultTransformClient
    from src.database.db import CustomerRepository
    from src.api.models import CustomerProtected

    vault = VaultTransformClient()
    repo  = CustomerRepository()

    console.print(f"\n🌱 Populando banco de dados com {count} clientes (PII protegida)...\n")

    success = 0
    for i in track(range(count), description="Inserindo clientes..."):
        nome  = random.choice(NOMES)
        first = nome.split()[0].lower()
        raw   = {
            "nome":     nome,
            "cpf":      rand_cpf(),
            "email":    f"{first}.{i:03d}@{random.choice(DOMINIOS)}",
            "telefone": f"119{''.join([str(random.randint(0,9)) for _ in range(8)])}",
            "pan":      f"4{''.join([str(random.randint(0,9)) for _ in range(15)])}",
            "dob":      f"{random.randint(1,28):02d}/{random.randint(1,12):02d}/{random.randint(1960,2005)}",
            "endereco": f"{random.choice(RUAS)}, {random.randint(1,999)}, {random.choice(CIDADES)}",
        }
        try:
            protected = vault.protect_customer(raw, role="api-role")
            row = CustomerProtected(
                nome=protected["nome"],
                cpf_protected=protected["cpf"],
                email_masked=protected["email"],
                telefone_protected=protected["telefone"],
                pan_protected=protected.get("pan"),
                dob_masked=protected.get("dob"),
                endereco_token=protected.get("endereco"),
            )
            repo.insert(row)
            success += 1
        except Exception as e:
            console.print(f"  ⚠️  Erro no registro {i}: {e}")

    console.print(f"\n✅ [green]{success}/{count} clientes inseridos com PII protegida[/green]")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=20)
    args = p.parse_args()
    seed(args.count)
