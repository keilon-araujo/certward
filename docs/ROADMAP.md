# Roadmap para produção (interno, ~100 aplicações)

Objetivo: levar a aplicação de "CA de laboratório madura" para uma **CA interna
corporativa** confiável, servindo ~100 apps, com a root distribuída por GPO.

**Estratégia (revisada — Plano C):** **manter e endurecer o motor openssl atual**.
O `step-ca` foi avaliado em dev (Fase 2) e **descartado**: no modelo escolhido
(**cert longo + OCSP/CRL**, não vida-curta/ACME) ele daria *menos* do que já
temos — não expõe OCSP e exigiria uma reescrita grande. Como as Fases 0/1 já
entregaram a maior parte do endurecimento, resta fechar os gaps no próprio motor.

> Histórico: a estratégia original era adotar o `step-ca` como motor (Plano B).
> A avaliação da Fase 2 mostrou que, para cert longo + OCSP/CRL, não compensa.

Princípio de sequenciamento: **abstração de motor (`ca_engine`) preservada** — se
um dia fizer sentido trocar, o ponto de extensão continua lá.

---

## Fase 0 — Fundação de código (o que fica) e abstração de motor
*Baixo risco, alto retorno. É a "melhoria de código/linguagem" que você pediu.*

- [x] **Camada `ca_engine`** no backend: interface `CAEngine` + `BashEngine`
      (adaptador atual). `pki.py` = helpers puros; `app.py` = só control plane.
      `EngineError` mapeado para HTTP. Trocar por `StepCaEngine` fica trivial.
- [x] **Testes automatizados** (pytest, 39 testes) do control plane com engine
      FAKE + da lib `pki`. **CI** (GitHub Actions) roda pytest + build das imagens.
      *(a suíte já pegou um bug real: rate-limit de login que nunca bloqueava)*
- [x] **Sessão fora do processo** (token HMAC assinado, stateless) — permite
      múltiplos workers/réplicas; segredo persistido em `/ca/session.secret`;
      troca de senha invalida tokens antigos via versão (`pv`).
- [x] **Containers non-root** (uid 10001 via `user-entrypoint.sh`/gosu) +
      limites de recurso no compose; imagens base pinadas.
- [x] **Pin de dependências** (versões exatas) em `requirements*.txt`.
- [ ] Higiene: remover código morto, padronizar erros/logs estruturados.

## Fase 1 — Ganhos de segurança independentes de motor
*Valem para o bash de hoje E para o step-ca de amanhã.*

- [x] **Name Constraints** na intermediária (`critical`, `permitted;DNS:<domínio>`
      + `localhost`), limitando a CA ao domínio interno. IPs ficam livres (SANs de
      IP seguem válidos). Verificado: cert fora do domínio é rejeitado pela cadeia.
- [x] **Chaves de assinante cifradas em repouso + rekey na renovação**: a
      ferramenta continua gerando a chave, mas ela é **cifrada** (Fernet/KEK) em
      `newcerts/<serial>.key.enc` e o texto claro é **destruído** logo após a
      emissão. A renovação passa a **rekey** (chave nova sempre). O PKCS#12 é
      gerado sob demanda no download, com senha aleatória.
      *(Emissão por CSR fica como extra opcional, não implementado.)*
- [x] **Backups cifrados** (AES-256, `openssl enc -pbkdf2`) + restore **testado**
      (valida o gzip antes de tocar no volume; senha errada não destrói nada).
- [x] **Secrets**: `ADMIN_PASS` e a **KEK** podem vir de **Docker secrets**
      (`/run/secrets`) via overlay `docker-compose.secrets.yml`; env continua como
      fallback para o lab. Com a KEK fora do volume, um vazamento do volume/backup
      não expõe as chaves de assinante.

## Fase 2 — step-ca avaliado (dev) e **descartado**
*Stack opt-in isolado (`docker-compose.stepca.yml`); guia em [STEPCA-DEV.md](STEPCA-DEV.md).*

- [x] Avaliado o `step-ca` em paralelo (2 camadas, policy de nomes, JWK+ACME,
      revogação) — tudo funcionou. **Decisão: não adotar** (ver estratégia acima).
- [x] Achados documentados (sem OCSP; ECDSA default; wildcard exige flag) e
      **plano de HSM/KMS** registrado — reaproveitável se a decisão mudar.

## Fase 3 — Endurecer o motor openssl (Plano C)
- [x] **Chave da intermediária cifrada em repouso** (AES-256); passphrase por
      **Docker secret** `ca_int_pass` (fallback env/local `/ca/int_pass`).
      Emissão/revogação/CRL passam `-passin`; retrocompatível com CAs legadas
      (chave em claro segue assinando). *Resíduo documentado:* a chave do
      **signer OCSP** (delegada, baixo valor, reemissível) segue em claro.
- [x] **Lock de concorrência** (file-lock/flock) em torno de emissão/renovação/
      revogação/CRL — serializa `openssl ca` entre workers/réplicas; sob disputa
      devolve 503 em vez de travar. Verificado: 6 emissões paralelas → `index.txt`
      íntegro, seriais únicos.
- [ ] (Opcional) **Emissão por CSR** — a chave nunca toca a CA.
- [ ] (Upgrade futuro) **PKCS#11/HSM** para a intermediária quando houver hardware.

## Fase 4 — Integração corporativa / produção
- [ ] **SSO + papéis** (emissor / aprovador / leitura) via AD/Entra/OIDC;
      auditoria amarrada a pessoas reais.
- [ ] **Auditoria fora da caixa** (syslog/SIEM), append-only/à prova de adulteração.
- [ ] **OCSP/CRL em HA** + distribuição robusta (web/CDN, cache correto), **DNS interno**
      resolvível para `ca.` / `ocsp.` / `crl.`.
- [ ] **ACME rollout** para as ~100 apps (auto-inscrição/renovação). Onde ACME não
      cabe, automação por CSR.
- [ ] **Monitoração/alertas** de expiração e saúde (e-mail/Slack/monitoramento).
- [ ] **GPO** distribui a **root** (offline + name-constrained).

## Fase 5 — Cutover e operação
- [ ] Piloto (10 apps → 100), runbooks, DR com restore testado.
- [ ] Rotação de intermediária documentada; políticas de validade/renovação.

---

## Não-negociáveis antes do 1º certificado de produção
root **offline** · **name constraints** · emissão por **CSR** (ao menos nos apps
críticos) · **backups cifrados/testados** · **auth real + auditoria fora da caixa**
· **OCSP/CRL em HA** · plano de **renovação automatizada (ACME)**.
