-- =============================================================================
-- schema.sql — PostgreSQL Schema para Demo Vault Transform / LGPD
--
-- Princípio: dados PII NUNCA armazenados em claro.
-- Todas as colunas PII armazenam o valor FPE-cifrado ou tokenizado.
-- O schema é idêntico a um schema convencional — sem ALTER TABLE necessário.
-- =============================================================================

-- Tabela principal de clientes
CREATE TABLE IF NOT EXISTS clientes (
    id                  SERIAL PRIMARY KEY,
    nome                VARCHAR(200) NOT NULL,           -- nome em claro (exibição)

    -- FPE: CPF cifrado mantém 11 dígitos — VARCHAR(11) sem alteração de schema
    cpf_protected       VARCHAR(11)  NOT NULL UNIQUE,

    -- Masking: e-mail mascarado (irreversível — apenas exibição)
    email_masked        VARCHAR(200) NOT NULL,

    -- FPE: telefone cifrado mantém 11 dígitos (DDD + número)
    telefone_protected  VARCHAR(11),

    -- FPE: PAN cifrado mantém 16 dígitos
    pan_protected       VARCHAR(16),

    -- Masking: CVV mascarado (*** — irreversível)
    cvv_masked          VARCHAR(3),

    -- Masking: data nascimento mascarada (preserva ano)
    dob_masked          VARCHAR(20),

    -- Tokenização: endereço substituído por token opaco
    endereco_token      VARCHAR(100),

    -- Tokenização: conta bancária substituída por token
    conta_token         VARCHAR(100),

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índice sobre CPF protegido (FPE preserva unicidade → índice funciona normalmente)
CREATE INDEX IF NOT EXISTS idx_clientes_cpf_protected ON clientes(cpf_protected);
CREATE INDEX IF NOT EXISTS idx_clientes_created_at ON clientes(created_at);

-- =============================================================================
-- VIEW para equipes de suporte e DBA
-- Não requer policy decode no Vault — exibe apenas dados já mascarados
-- Suporte vê o suficiente para identificar o cliente sem acessar PII completa
-- =============================================================================
CREATE OR REPLACE VIEW vw_clientes_suporte AS
SELECT
    id,
    nome,
    -- CPF: mostra apenas os últimos 6 dígitos do CPF FPE-cifrado
    -- O dado exibido não é o CPF real — é uma máscara do dado já cifrado
    CONCAT('***.***.', SUBSTR(cpf_protected, 7, 3), '-', SUBSTR(cpf_protected, 10, 2)) AS cpf_display,
    email_masked,
    -- Telefone: mostra DDD e últimos 4 dígitos do telefone FPE-cifrado
    CONCAT('(', SUBSTR(telefone_protected, 1, 2), ') *****-', SUBSTR(telefone_protected, 8, 4)) AS telefone_display,
    -- PAN: mostra apenas últimos 4 dígitos
    CASE
        WHEN pan_protected IS NOT NULL
        THEN CONCAT('**** **** **** ', SUBSTR(pan_protected, 13, 4))
        ELSE NULL
    END AS pan_display,
    dob_masked,
    -- Token opaco — suporte não consegue ver o endereço real
    endereco_token,
    created_at
FROM clientes;

-- =============================================================================
-- VIEW para auditoria LGPD / DPO
-- Apenas metadados — sem dado PII, nem cifrado
-- =============================================================================
CREATE OR REPLACE VIEW vw_auditoria_lgpd AS
SELECT
    id,
    -- Indica quais campos PII estão presentes (sem revelar o dado)
    CASE WHEN cpf_protected IS NOT NULL THEN 'sim' ELSE 'não' END AS tem_cpf,
    CASE WHEN pan_protected IS NOT NULL THEN 'sim' ELSE 'não' END AS tem_pan,
    CASE WHEN endereco_token IS NOT NULL THEN 'sim' ELSE 'não' END AS tem_endereco,
    CASE WHEN conta_token IS NOT NULL THEN 'sim' ELSE 'não' END AS tem_conta,
    created_at,
    updated_at
FROM clientes;

-- Trigger para atualizar updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON clientes;
CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON clientes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
