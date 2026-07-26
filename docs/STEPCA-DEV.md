# step-ca em paralelo (avaliação / dev) — Fase 2

Stack **opt-in e isolado** para avaliar o [step-ca](https://smallstep.com/docs/step-ca/)
como futuro motor da CA, **sem tocar** na CA atual (bash/openssl). Não compartilha
compose, volume nem rede com `docker-compose.yml`.

Na **Fase 3**, um `StepCaEngine(CAEngine)` pluga no lugar do `BashEngine` e a
UI/API/auditoria **não mudam**. Esta fase serve para validar o motor antes disso.

## Subir

```bash
# 1) senha da CA (NÃO versionada — docker/secrets/ é gitignored)
mkdir -p docker/secrets
openssl rand -base64 24 | tr -d '\n' > docker/secrets/stepca_password

# 2) sobe o step-ca (auto-init: root + intermediária + provisioners JWK e ACME)
docker compose -f docker/docker-compose.stepca.yml up -d

# 3) limita a CA ao domínio interno (equivale ao nameConstraints da CA atual)
./scripts/stepca-set-policy.sh capsule.lab.br

# 4) valida tudo (emissão dentro/fora do domínio, wildcard, ACME, revogação)
./scripts/stepca-smoke.sh capsule.lab.br
```

Derrubar: `docker compose -f docker/docker-compose.stepca.yml down`
(adicione `-v` para **apagar a PKI/estado**).

## O que já foi validado

| Item | Resultado |
|---|---|
| **PKI de 2 camadas** | root **offline-capable** + intermediária (ECDSA P-256), auto-geradas |
| **Provisioner JWK** | emissão via token de admin — OK |
| **Provisioner ACME** | `/acme/acme/directory` publicado (newOrder/newAccount/revokeCert…) |
| **Política de nomes** | só emite dentro do domínio; `evil.example.com` **rejeitado** pela CA |
| **Wildcard** | `*.capsule.lab.br` emitido (requer `allowWildcardNames`) |
| **Revogação** | `step ca revoke` (mTLS cert+chave) — OK |

## Inscrição por ACME (o caminho para as ~100 apps)

Qualquer cliente ACME aponta para o directory da CA e se auto-inscreve/renova.
Primeiro, confie na raiz (`docker compose -f docker/docker-compose.stepca.yml exec
step-ca step certificate fingerprint /home/step/certs/root_ca.crt`), depois:

```bash
# exemplo com o proprio step (dentro do container, ou com o step CLI no host)
step ca certificate app.capsule.lab.br app.crt app.key \
  --provisioner acme --ca-url https://stepca.capsule.lab.br:9000

# ou certbot / acme.sh apontando para:
#   https://stepca.capsule.lab.br:9000/acme/acme/directory
```

## Diferenças importantes vs. a CA atual (achados da avaliação)

- **Sem OCSP.** O step-ca **não** expõe um responder OCSP; o modelo dele é
  **certificados de vida curta** (default ~24h) + **CRL opcional** + revogação
  passiva pela API. Nossa CA atual tem OCSP openssl ao vivo. Decisão de Fase 3:
  ou adotamos o modelo de vida curta (renovação automática por ACME) ou
  habilitamos CRL no step-ca e ajustamos os balanceadores.
- **ECDSA P-256 por padrão** (a nossa é RSA). É configurável no `step ca init`
  (`--key-type RSA --key-size 4096`) se F5/A10 precisarem de RSA.
- **Wildcard** exige `allowWildcardNames: true` na policy (já aplicado pelo
  helper), senão o step-ca barra `*.dominio` mesmo dentro do domínio permitido.
- **Validade curta**: leaves de ~24h por padrão — ótimo com ACME, mas exige
  renovação automática; para uso manual, aumente `claims.maxTLSCertDuration`.

## Plano de HSM/KMS para a chave da intermediária (produção)

O step-ca suporta guardar a chave da intermediária fora do disco:
- **PKCS#11** (HSM/YubiHSM/SoftHSM) e **KMS de nuvem** (AWS KMS, GCP KMS, Azure
  Key Vault) via `kms` no `ca.json`.
- Plano: em produção, raiz **offline** (chave em HSM ou cofre físico) e
  intermediária com a chave em **KMS/HSM** — a CA nunca lê a chave em claro.
  Isso resolve, de vez, o ponto "chave da intermediária em disco" levantado na
  avaliação de produção.

## Próximo (Fase 3)

- Implementar `StepCaEngine(CAEngine)` (cliente do step-ca) substituindo os
  scripts bash; UI, dashboard, auditoria e ciclo de vida **permanecem**.
- Decidir OCSP vs. vida-curta+ACME; habilitar CRL se preciso.
- Migração da confiança (a raiz nova via GPO) e aposentadoria do openssl.
