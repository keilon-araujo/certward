# Roadmap para produção (interno, ~100 aplicações)

Objetivo: levar a aplicação de "CA de laboratório madura" para uma **CA interna
corporativa** confiável, servindo ~100 apps, com a root distribuída por GPO.

**Estratégia:** adotar o **Smallstep `step-ca`** como *motor* (emissão, OCSP real,
CRL, ACME, HSM/KMS) e manter a nossa **UI/control plane/auditoria** por cima.
Não investir em endurecer o motor bash/openssl atual — ele será substituído.

Princípio de sequenciamento: **melhorar só o código que sobrevive ao Plano B**
(control plane, UI, auth, testes) + **abstrair o motor** para a troca ser limpa.

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

- [ ] **Name Constraints** na intermediária (limita a CA aos domínios internos).
- [ ] **Emissão por CSR** como caminho de primeira classe (a chave privada
      nunca sai do servidor nem toca a CA). Manter "gera pra mim" só como conveniência.
- [ ] **Backups cifrados** + restore **testado**; nunca exportar chave em claro.
- [ ] **Secrets**: tirar `ADMIN_PASS`/passphrase de `.env` → secret manager /
      Docker secrets.

## Fase 2 — step-ca em paralelo (dev)
- [ ] Subir `step-ca`; hierarquia **root offline** + intermediária com name constraints.
- [ ] **OCSP real** + CRL + **provisioners** (ACME, OIDC/JWK).
- [ ] Validar emissão/revogação/OCSP/ACME em dev.
- [ ] Plano de **HSM/KMS** para a chave da intermediária (PKCS#11 / KMS de nuvem).

## Fase 3 — Rewire do control plane sobre o step-ca
- [ ] Implementar `ca_engine` com **cliente step-ca** (substitui os scripts bash).
- [ ] UI, dashboard, auditoria e ciclo de vida **permanecem**, agora sobre o step-ca.
- [ ] Aposentar `new_cert.sh`/`revoke-cert.sh`/`gen-crl.sh` e o DB do openssl.

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
