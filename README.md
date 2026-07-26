# Autoridade Certificadora interna (mTLS para F5 / A10)

CA interna de **duas camadas** (Root offline + Intermediária) com interface web
para o **ciclo de vida completo** dos certificados — emissão, renovação,
revogação, CRL e OCSP — pensada para **mTLS** em F5 BIG-IP e A10 Thunder.

**Nada é fixo em código:** domínio, nome da autoridade, criptografia e validade
são definidos num **assistente no primeiro login**. Nos exemplos usamos
`capsule.lab.br` / "Capsule Corp", mas vale qualquer um.

> Status: madura como ferramenta de laboratório; o caminho para **produção**
> (ex.: ~100 apps internas) está descrito em [`docs/ROADMAP.md`](docs/ROADMAP.md)
> (plano: adotar o `step-ca` como motor mantendo esta UI).

## Início rápido (Docker)

```bash
cp docker/.env.example docker/.env     # ajuste ADMIN_USER / ADMIN_PASS
./bootstrap.sh                         # build + sobe a stack (webui, ocsp, crl, nginx)
```

Abra **`https://<host>/`**, faça login e conclua o **assistente** (cria a
hierarquia, o responder OCSP e o certificado TLS da própria interface). O nginx
sobe com um cert temporário e troca automaticamente pelo cert da sua CA.

Aponte no DNS do lab `admin.` / `ca.` / `ocsp.` do seu domínio para o host Docker
(ou use headers `Host` nos testes). O admin é **HTTPS**; `ca.`/`ocsp.` são **HTTP**
de propósito (AIA/CRL/OCSP usam HTTP).

## Assistente de primeiro login

| Grupo | Campos |
|---|---|
| Identidade | domínio, organização (O), unidade (OU), país (C), estado (ST), cidade (L) |
| Nomes | CN da Root CA e da Intermediate CA (derivados da organização) |
| Hosts (avançado) | `ca.` / `ocsp.` / `admin.` — derivados do domínio, editáveis |
| Cripto/validade (avançado) | chave RSA das CAs e dos folha, digest (sha256/384/512), validade raiz/int/folha/CRL |
| Segurança | passphrase da raiz (+confirmação); **Name Constraints** (liga por padrão: limita a intermediária a emitir só dentro do domínio) |

Só `domínio`, `organização` e `passphrase` são obrigatórios; o resto tem default
derivado. O `openssl.cnf` é renderizado de `openssl.cnf.tmpl` com esses valores.

## Autenticação

Tela de **login com sessão** (token HMAC assinado, stateless). No primeiro acesso
use `ADMIN_USER`/`ADMIN_PASS` do `docker/.env`; depois **troque a senha pela
interface** (fica hasheada com PBKDF2 em `/ca/admin.json`) e use **Sair** para
logout. Há **rate-limit** no login e **trilha de auditoria** (aba Auditoria).
Esqueceu a senha? `make reset-admin` volta a usar o `ADMIN_PASS` do `.env`.

Em produção, tire `ADMIN_PASS` (e a KEK das chaves) do `.env` e use **Docker
secrets** com o overlay `docker/docker-compose.secrets.yml` (a precedência é
`/run/secrets/<nome>` > `<ENV>_FILE` > env).

## Operação do dia a dia (`make`)

```bash
make help                                  # lista os alvos
make up | down | logs | ps                 # ciclo da stack
make issue NAME=app1.<dom> PROFILE=server SANS="DNS:app1.<dom>,IP:10.0.0.10"
make revoke SERIAL=1001 REASON=keyCompromise
make crl ; make ls ; make expiring DAYS=30
make backup BACKUP_PASS=<senha>            # backup CIFRADO -> ./ca-backup.tgz.enc
make restore BACKUP_PASS=<senha>           # restaura ./ca-backup.tgz.enc (valida antes de tocar no volume)
make reset-admin                           # recuperar senha do admin
```

O grosso, porém, é feito pela **UI**: emitir (server/client/dual, wildcard com
apex automático), **renovar** (revogando o antigo ou mantendo os dois; a
renovação faz **rekey**), revogar, regenerar CRL, **consultar OCSP ao vivo**,
decodificar um PEM colado, e baixar `cert` / `chain` / `key` ou um **pacote
`.zip`** (crt+key+chain+p12+senha aleatória).

**Chaves em repouso:** as chaves de assinante são **cifradas** (Fernet/KEK) em
`newcerts/<serial>.key.enc` e o texto claro é destruído após a emissão; o PKCS#12
é gerado sob demanda no download. A KEK vem de Docker secret/`CA_KEK` ou, no lab,
é gerada em `/ca/kek` (nesse caso, proteja-se com o **backup cifrado**).

## Arquitetura

Uma imagem única (`certward`) roda de 3 formas + o nginx, compartilhando o
volume `ca-data` (montado em `/ca`; o código vive em `/opt/ca-app`):

| Serviço | Papel |
|---|---|
| `webui` | API FastAPI + UI (porta 8080, atrás do nginx). Healthcheck ativo. |
| `ocsp`  | responder OCSP; recarrega o `index.txt` periodicamente (`OCSP_RELOAD_INTERVAL`, default 60s) |
| `crl`   | regenera a CRL da intermediária diariamente |
| `nginx` | publica artefatos (`ca.`, HTTP), proxy do OCSP (`ocsp.`, HTTP) e da UI (`admin.`, HTTPS) |

O backend é separado em camadas (para o control plane não depender do motor):

```
webui/backend/
  pki.py         helpers PUROS de PKI (cripto/parse/decode/config) — sem HTTP
  ca_engine.py   interface CAEngine + BashEngine (adaptador: scripts + openssl)
  app.py         control plane FastAPI: HTTP, auth/sessão, auditoria (delega ao engine)
  tests/         pytest do control plane (engine FAKE) + da lib pki
```

Trocar o motor (ex.: por `step-ca`) = escrever um `StepCaEngine(CAEngine)` e
plugar em `get_engine()`; a UI, a API e a auditoria não mudam. Há um stack
**opt-in** para avaliar o step-ca em paralelo (sem tocar na CA atual) —
ver [docs/STEPCA-DEV.md](docs/STEPCA-DEV.md).

Os scripts do motor atual (`scripts/init-ca.sh`, `new_cert.sh`, `revoke-cert.sh`,
`gen-crl.sh`, `issue-admin-cert.sh`, `check-expiring.sh`) + `openssl.cnf.tmpl`
ficam em **`scripts/`** e são copiados (achatados) para `/opt/ca-app` na imagem.

## Desenvolvimento

```bash
cd webui/backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

CI no **GitHub Actions** (`.github/workflows/ci.yml`): roda o `pytest` e faz o
build sanity das imagens Docker em cada push/PR.

## Documentação (`docs/`)

| Arquivo | Conteúdo |
|---|---|
| [`PKI-FLUXO.md`](docs/PKI-FLUXO.md) / `.pdf` | Fluxo dos certificados (hierarquia, CRL, OCSP, revogação, mTLS) com diagramas. |
| [`mTLS-F5-A10.md`](docs/mTLS-F5-A10.md) | Passo a passo de mTLS no F5 BIG-IP e A10 Thunder. |
| [`ROADMAP.md`](docs/ROADMAP.md) | Roadmap para produção (fases; plano B com step-ca). |
| [`MELHORIAS-E-SEGURANCA.md`](docs/MELHORIAS-E-SEGURANCA.md) | Revisão de segurança e melhorias (feito × pendente). |
| [`DESIGN-PROMPT.md`](docs/DESIGN-PROMPT.md) | Prompt para (re)gerar a UI amarrada ao contrato da API. |

## Por que duas camadas

A raiz assina **apenas a intermediária** e depois fica trancada (chave com
passphrase). O dia a dia usa só a intermediária: se ela for comprometida,
revoga-se a intermediária sem refazer a confiança em todos os F5/A10. E o mTLS
nesses balanceadores gira em torno de montar a *chain* (folha → intermediária →
raiz) — que é exatamente o que se treina aqui.
