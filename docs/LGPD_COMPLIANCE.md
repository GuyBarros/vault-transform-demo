# Mapeamento LGPD × Vault Transform Secret Engine

## Artigos Relevantes e Como São Atendidos

### Art. 6º, X — Responsabilização e Prestação de Contas
**Obrigação:** Adoção de medidas eficazes para proteção de dados pessoais.

**Atendimento:**
- FPE, Masking e Tokenização demonstram adoção de medidas técnicas avançadas
- Audit log imutável por operação constitui evidência de responsabilização
- RBAC por perfil demonstra controle de acesso adequado

---

### Art. 46 — Segurança
**Obrigação:** Medidas técnicas e administrativas para proteção de dados pessoais
de acessos não autorizados e situações acidentais ou ilícitas.

**Atendimento:**
- Dado PII nunca armazenado em claro em BD, logs ou pipelines
- FPE protege na camada de aplicação — TDE (Transparent Data Encryption) do BD
  não protege contra acesso com credencial válida; FPE sim
- Chave criptográfica gerenciada pelo Vault — inacessível às aplicações

---

### Art. 47 — Sigilo
**Obrigação:** Agentes de tratamento devem guardar sigilo dos dados pessoais.

**Atendimento:**
- Masking garante que suporte/DBA vejam apenas dados parcialmente ofuscados
- Policy `encode-only` impede que sistemas de produção acessem dado original
- Decode restrito a sistemas core com autorização documentada do DPO

---

### Art. 48 — Comunicação de Incidentes
**Obrigação:** Comunicar à ANPD e aos titulares incidentes de segurança
com dados pessoais que possam gerar risco ou dano relevante.

**Atendimento:**
- Dado FPE-cifrado em BD **não constitui dado pessoal acessível** sem a
  chave gerenciada pelo Vault — vazamento de backup não expõe PII real
- Reduz drasticamente a obrigação de notificação à ANPD em incidentes de BD
- Mitiga o risco de dano relevante aos titulares em caso de acesso indevido

---

### Art. 49 — Privacy by Design
**Obrigação:** Sistemas de tratamento devem ser estruturados para garantir
segurança e privacidade desde a concepção.

**Atendimento:**
- Dado PII é protegido **antes** de persistir — não como afterthought
- API nunca armazena dado em claro: encode acontece na camada de serviço
- Schema de BD idêntico a convencional — proteção é transparente ao banco

---

### Art. 20 — Revisão de Decisões Automatizadas
**Obrigação:** Direito do titular de solicitar revisão de decisões tomadas
unicamente por meios automatizados.

**Atendimento:**
- FPE e Tokenização são reversíveis para sistemas core autorizados pelo DPO
- Cada operação de decode é auditada no Vault (quem, quando, qual dado)
- Processo de revisão rastreável end-to-end

---

## Matriz de Dados PII × Operação × Artigo LGPD

| Dado PII         | Operação     | Artigo Principal | Justificativa                              |
|------------------|--------------|------------------|--------------------------------------------|
| CPF              | FPE          | Art. 46, 48      | Preserva formato, não é acessível sem chave|
| PAN (cartão)     | FPE          | Art. 46, 48      | Conformidade PCI-DSS 4.0 req. 3            |
| Telefone         | FPE          | Art. 46          | Preserva formato para contato              |
| E-mail           | Masking      | Art. 47          | Irrecuperável — adequado para suporte      |
| Nome             | Masking      | Art. 47          | Iniciais visíveis para identificação       |
| Data Nascimento  | Masking      | Art. 46, 47      | Preserva ano para segmentação etária       |
| CVV              | Masking      | Art. 46, 48      | Dado sensível PCI — masking total          |
| Endereço         | Tokenização  | Art. 46, 48      | Referência consistente sem revelar local   |
| Conta Bancária   | Tokenização  | Art. 46, 48      | Token para correlação em sistemas          |

---

## Evidências de Conformidade para ANPD

1. **Audit log estruturado** por operação Transform — sem valor PII em claro
2. **RBAC demonstrável** — encode-only para produção, decode apenas para core
3. **Testes automatizados** comprovam que PII nunca aparece em resposta de API
4. **Schema de BD** mostra colunas tipadas para dados protegidos (não TEXT genérico)
5. **Privacy by Design** implementado — dado protegido no fluxo de criação de cliente

---

*Este documento deve ser atualizado sempre que novos tipos de dados PII forem
adicionados ao sistema ou quando houver mudanças nas operações de tratamento.*
