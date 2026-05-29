# HashiCorp Vault Transform Secret Engine — Demo LGPD/PII

Projeto de demonstração das capacidades do **Vault Transform Secret Engine** para
proteção de dados pessoais (PII) conforme LGPD — cobrindo **FPE**, **Masking** e
**Tokenização** nos contextos de API REST, Banco de Dados e Pipeline de Dados.

---

## Estrutura do Projeto

```
vault-transform-demo/
├── docker/
│   ├── docker-compose.yml          # Vault dev + PostgreSQL + app
│   └── vault-init.sh               # Bootstrap automático do Vault
├── src/
│   ├── vault/
│   │   ├── client.py               # Cliente Vault (AppRole + Transform API)
│   │   └── config.py               # Configuração de transformações e roles
│   ├── api/
│   │   ├── app.py                  # FastAPI — CRUD de clientes com PII protegida
│   │   └── models.py               # Pydantic models (entrada/saída)
│   ├── database/
│   │   ├── schema.sql              # Schema PostgreSQL + views de suporte
│   │   └── db.py                   # Queries com FPE transparente
│   └── pipeline/
│       ├── batch_protect.py        # Proteção PII em lote (CSV → CSV protegido)
│       └── spark_demo.py           # PySpark UDF com batch_input API
├── scripts/
│   ├── setup_vault.sh              # Configura Transform Engine no Vault
│   ├── seed_database.py            # Popula BD com dados de teste protegidos
│   └── demo_all.py                 # Demo completa: FPE + Masking + Token
├── tests/
│   ├── test_fpe.py                 # Testes unitários FPE (CPF, PAN, telefone)
│   ├── test_masking.py             # Testes masking (e-mail, nome, data)
│   ├── test_tokenization.py        # Testes tokenização (endereço, conta)
│   └── test_api.py                 # Testes integração FastAPI
├── docs/
│   └── LGPD_COMPLIANCE.md          # Mapeamento artigos LGPD × operações
├── requirements.txt
├── .env.example
└── README.md
```

---

## Pré-requisitos

- Docker + Docker Compose
- Python 3.11+
- (Opcional) Apache Spark 3.x para o demo de pipeline

---

## Quick Start — 5 minutos

```bash
# 1. Clonar e entrar no diretório
git clone <repo> vault-transform-demo
cd vault-transform-demo

# 2. Copiar variáveis de ambiente
cp .env.example .env

# 3. Subir Vault (dev mode) + PostgreSQL
docker-compose -f docker/docker-compose.yml up -d

# 4. Configurar o Transform Secret Engine no Vault
bash scripts/setup_vault.sh

# 5. Instalar dependências Python
pip install -r requirements.txt

# 6. Executar demo completa
python scripts/demo_all.py
```

---

## Operações Demonstradas

### FPE — Format Preserving Encryption (FF3-1 / NIST SP 800-38G)

| Dado      | Original             | FPE Protegido        |
|-----------|----------------------|----------------------|
| CPF       | `123.456.789-09`     | `874.231.560-43`     |
| PAN       | `4111111111111111`   | `4823761493025817`   |
| Telefone  | `11998765432`        | `11834127065`        |
| RG        | `123456789`          | `874231560`          |

> O dado FPE preserva o **formato original** — CPF cifrado ainda são 11 dígitos.
> Banco de dados não precisa de `ALTER TABLE`. Índices e buscas funcionam normalmente.

### Masking — Ofuscação Parcial (one-way / irreversível)

| Dado              | Original                    | Mascarado                  |
|-------------------|-----------------------------|----------------------------|
| E-mail            | `joao.silva@empresa.com`    | `j***.***va@e*****.com`    |
| Nome              | `João Carlos da Silva`      | `J*** C***** ** S****`     |
| Data Nascimento   | `15/03/1985`                | `**/**/1985`               |
| CVV               | `123`                       | `***`                      |

> Masking é **irreversível** — adequado para logs, UIs de suporte e dashboards.

### Tokenização Convergente — Token opaco reversível (HMAC)

| Dado             | Original                              | Token                        |
|------------------|---------------------------------------|------------------------------|
| Endereço         | `Rua das Flores, 123, São Paulo, SP`  | `TKN-f3a9b2c1d4e5f6a7`      |
| Conta Bancária   | `BR6000360305000010009795493P1`        | `TKN-aa1bc29de3f40512`       |

> Token convergente: **mesmo dado → mesmo token**. Permite joins em Data Lakes
> sem expor o dado PII real.

---

## Contextos de Integração

### 1. API REST (FastAPI)

```python
# POST /clientes — PII protegida antes de persistir
POST /api/v1/clientes
{
  "nome": "João Silva",
  "cpf": "123.456.789-09",
  "email": "joao@empresa.com",
  "telefone": "(11) 99876-5432",
  "pan": "4111 1111 1111 1111",
  "endereco": "Rua das Flores, 123, SP"
}

# BD recebe:
{
  "nome": "João Silva",
  "cpf_protected": "87423156043",     # FPE
  "email_masked": "j***@e**.com",     # Masking
  "telefone_protected": "11834127065",# FPE
  "pan_protected": "4823761493025817",# FPE
  "endereco_token": "TKN-f3a9b2c1"   # Token
}
```

### 2. Banco de Dados (PostgreSQL)

- Schema com colunas protegidas: `cpf_protected VARCHAR(11)` — mesmo tamanho do CPF
- View `vw_clientes_suporte` — exibe dados mascarados para DBA sem policy decode
- Busca por CPF: aplicação FPE-encode antes do `WHERE` — índice funcional

### 3. Pipeline em Lote (CSV)

```bash
# Proteger arquivo CSV com PII
python src/pipeline/batch_protect.py \
  --input data/clientes_raw.csv \
  --output data/clientes_protected.csv \
  --fields cpf:ff-cpf,email:mask-email,pan:ff-pan,endereco:tok-endereco
```

---

## RBAC — Quem pode fazer o quê

| Perfil              | FPE Encode | FPE Decode | Masking | Tokenize | Detokenize |
|---------------------|:----------:|:----------:|:-------:|:--------:|:----------:|
| APIs de Produção    | ✅         | ❌         | ✅      | ✅       | ❌         |
| Sistemas Core       | ✅         | ✅         | ✅      | ✅       | ✅         |
| Suporte / DBA       | ❌         | ❌         | ✅      | ❌       | ❌         |
| Pipelines ETL       | ✅         | ❌         | ✅      | ✅       | ❌         |
| DPO / Compliance    | ❌         | ❌         | ❌      | ❌       | ❌         |

---

## Conformidade LGPD

| Artigo LGPD   | Obrigação                           | Atendimento                                      |
|---------------|-------------------------------------|--------------------------------------------------|
| Art. 46       | Medidas técnicas de proteção        | FPE/Masking/Token em todas as camadas            |
| Art. 48       | Notificação de incidentes           | Dado FPE em BD não é dado pessoal acessível      |
| Art. 49       | Privacy by Design                   | PII protegida antes de persistir em qualquer BD  |

---

## Variáveis de Ambiente

```bash
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<seu-role-id>
VAULT_SECRET_ID=<seu-secret-id>
VAULT_NAMESPACE=lgpd          # namespace dedicado (Enterprise)
DB_URL=postgresql://user:pass@localhost:5432/demo
```

---

## Referências

- [Vault Transform Secret Engine](https://developer.hashicorp.com/vault/docs/secrets/transform)
- [FF3-1 NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38/g/final)
- [LGPD — Lei nº 13.709/2018](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [hvac Python SDK](https://hvac.readthedocs.io/en/stable/)
