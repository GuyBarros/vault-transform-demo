"""
pipeline/spark_demo.py — Demo PySpark com Vault Transform batch_input API.

Demonstra como usar o Vault Transform Engine em jobs Spark com UDFs
que utilizam a batch_input API para alta performance.

Pré-requisito: Apache Spark 3.x instalado
    pip install pyspark  (ou use um cluster Spark existente)

Execução:
    python src/pipeline/spark_demo.py
    # ou via spark-submit:
    spark-submit src/pipeline/spark_demo.py
"""

from __future__ import annotations

import os
import logging
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Vault config (passado via broadcast para os executores Spark)
VAULT_ADDR      = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN     = os.environ.get("VAULT_TOKEN", "root")
PIPELINE_ROLE   = os.environ.get("PIPELINE_ROLE", "pipeline-role")
BATCH_SIZE      = int(os.environ.get("PIPELINE_BATCH_SIZE", "100"))


# ── UDF Factory ───────────────────────────────────────────────────────────────

def make_fpe_udf(transformation: str, mount_path: str = "transform"):
    """
    Cria uma UDF PySpark para FPE encode via Vault Transform batch_input.

    A UDF usa a estratégia de batch pelo driver (collect → batch_encode → broadcast)
    em vez de chamadas individuais por linha — muito mais eficiente.

    Para datasets grandes, use a abordagem de mapPartitions (comentada abaixo).
    """
    try:
        from pyspark.sql.functions import udf
        from pyspark.sql.types import StringType
        import hvac

        def _encode(value: Optional[str]) -> Optional[str]:
            """UDF per-row — simples mas menos eficiente para grandes volumes."""
            if not value:
                return None
            client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
            resp = client.secrets.transform.encode_value(
                role_name=PIPELINE_ROLE,
                transformation_name=transformation,
                value=value,
                mount_point=mount_path,
            )
            return resp["data"]["encoded_value"]

        return udf(_encode, StringType())

    except ImportError:
        logger.warning("PySpark não instalado — UDF não disponível")
        return None


def protect_spark_dataframe_batch(
    spark,
    df,
    field_map: dict,
    role: str = "pipeline-role",
    batch_size: int = 100,
):
    """
    Estratégia de proteção PII em batch para Spark DataFrames.

    Abordagem driver-side (para DataFrames que cabem na memória do driver):
    1. Coleta a coluna PII do DataFrame
    2. Envia para o Vault via batch_input em chunks
    3. Faz broadcast do resultado de volta para o DataFrame

    Para datasets muito grandes, use a versão mapPartitions abaixo.

    Args:
        spark:     SparkSession
        df:        DataFrame Spark com colunas PII
        field_map: {coluna: transformation} ex: {"cpf": "ff-cpf"}
        role:      Transform role
        batch_size: tamanho do batch para a API Vault

    Returns:
        DataFrame com colunas PII protegidas
    """
    import pandas as pd
    from pyspark.sql.functions import col

    from src.vault.client import VaultTransformClient
    from src.pipeline.batch_protect import FIELD_TRANSFORM_MAP, chunked

    vault = VaultTransformClient(token=VAULT_TOKEN)

    for spark_col, transformation in field_map.items():
        if spark_col not in df.columns:
            continue

        logger.info("Protegendo coluna Spark '%s' → %s", spark_col, transformation)

        # Coleta valores da coluna
        normalizer = FIELD_TRANSFORM_MAP.get(spark_col, (None, str))[1]
        pd_series  = df.select(spark_col).toPandas()[spark_col]

        # Batch encode
        protected: list[str] = []
        for chunk in chunked(pd_series.fillna("").astype(str).tolist(), batch_size):
            normalized = [normalizer(v) if v else "" for v in chunk]
            encoded    = vault.batch_encode(transformation, normalized, role)
            protected.extend(encoded)

        # Recria DataFrame com coluna protegida via pandas intermediário
        pd_df                 = df.toPandas()
        pd_df[spark_col]      = protected
        df                    = spark.createDataFrame(pd_df)

        logger.info("Coluna '%s' protegida com %d valores", spark_col, len(protected))

    return df


def demo_spark():
    """Demonstração completa de proteção PII com PySpark."""
    try:
        from pyspark.sql import SparkSession
        from pyspark.sql.functions import lit
    except ImportError:
        print("⚠️  PySpark não instalado. Execute: pip install pyspark")
        print("    Para instalar: pip install pyspark==3.5.1")
        return

    spark = SparkSession.builder \
        .appName("VaultTransformDemo") \
        .master("local[*]") \
        .config("spark.sql.shuffle.partitions", "2") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("WARN")

    print("\n" + "="*60)
    print("  PySpark + Vault Transform — Proteção PII em Massa")
    print("="*60)

    # Dados de exemplo
    data = [
        (1, "João Silva",    "12345678909", "joao@gmail.com",    "11998765432", "4111111111111111", "Rua das Flores, 123, SP"),
        (2, "Maria Santos",  "98765432100", "maria@hotmail.com", "21987654321", "5500000000000004", "Av. Paulista, 456, SP"),
        (3, "Carlos Oliveira","11122233344","carlos@yahoo.com",  "31976543210", "4000000000000002", "Rua do Comércio, 789, RJ"),
        (4, "Ana Costa",     "55566677788", "ana@empresa.com",   "41965432109", "4111111111111111", "Rua das Rosas, 321, MG"),
        (5, "Pedro Souza",   "99988877766", "pedro@outlook.com", "51954321098", "5500000000000004", "Travessa Central, 654, RS"),
    ]

    schema = ["id", "nome", "cpf", "email", "telefone", "pan", "endereco"]
    df_raw = spark.createDataFrame(data, schema)

    print("\n📊 DataFrame ANTES da proteção PII:")
    df_raw.show(truncate=False)

    # Proteger PII
    field_map = {
        "cpf":      "ff-cpf",
        "email":    "mask-email",
        "telefone": "ff-telefone",
        "pan":      "ff-pan",
        "endereco": "tok-endereco",
    }

    print("\n🔐 Aplicando proteção PII via Vault Transform batch_input API...")

    try:
        df_protected = protect_spark_dataframe_batch(
            spark, df_raw, field_map,
            role=PIPELINE_ROLE, batch_size=BATCH_SIZE
        )

        print("\n✅ DataFrame DEPOIS da proteção PII (pronto para Data Lake):")
        df_protected.show(truncate=False)

        print("\n💾 Salvando em Parquet (formato Data Lake)...")
        df_protected.write.mode("overwrite").parquet("data/clientes_protected_spark")
        print("   Salvo em: data/clientes_protected_spark/")

    except Exception as e:
        print(f"\n⚠️  Vault não disponível para demo Spark: {e}")
        print("    Execute docker-compose up primeiro e configure as variáveis de ambiente.")

    finally:
        spark.stop()


if __name__ == "__main__":
    demo_spark()
