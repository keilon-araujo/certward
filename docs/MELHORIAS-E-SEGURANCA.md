# Revisão de segurança e sugestões de melhoria

Avaliação honesta do projeto **para uso em laboratório** e o que mudaria para
elevar a barra rumo a algo mais próximo de produção.

## Está bem feito? (resumo)

Para um **lab de mTLS**, sim — a base está sólida e correta:

- Hierarquia **Root + Intermediária** com a chave da raiz protegida por passphrase.
- Chaves privadas com permissão `400`, diretório `private/` `700`.
- **Perfis corretos** (serverAuth / clientAuth / OCSPSigning), SAN obrigatório,
  AIA/CRL embutidos nos certificados-folha.
- **CRL + OCSP** funcionando, com regeneração automática da CRL.
- Admin sobre **HTTPS** com certificado emitido pela própria CA.
- **Validação de entrada** (domínio, país, nomes, tamanhos de chave, digest).
- `unique_subject = no` permite **renovação** do mesmo CN.

Ou seja: como ferramenta de estudo/lab, está bem feito. Os pontos abaixo são o
que separa “lab” de “produção”.

## Pontos de atenção de segurança (ordenados por impacto)

1. **A chave da INTERMEDIÁRIA não tem passphrase** (precisa disso para automação).
   Ela é a “joia da coroa” operacional: quem tiver o volume `ca-data`/o container
   consegue assinar qualquer certificado. Mitigações: restringir acesso ao host e
   ao volume; em cenário sério, mover a assinatura para **HSM/KMS** ou um serviço
   de assinatura isolado.

2. **A raiz “offline” é simbólica** — mora no mesmo volume da intermediária.
   Em produção, a raiz deveria ser gerada e mantida **fora** da VM online
   (máquina isolada/air-gapped), assinar a intermediária e nunca voltar para o
   host que fica exposto.

3. **`ADMIN_PASS` em texto puro** no `docker/.env`/env do container
   (visível em `docker inspect`). O default é um placeholder fraco. Use um
   segredo forte, de preferência via **Docker secrets**, e senha **hasheada** em
   repouso (ver melhoria de login abaixo).

4. **HTTP Basic Auth** — sem logout real, sem bloqueio por tentativa
   (brute-force), conta única compartilhada, sem trilha de quem fez o quê.

5. **Sem trilha de auditoria** de emissão/revogação (quem, quando, por quê).
   Para uma CA, isso importa.

6. **Download de chave privada / `.p12` pela API** — cômodo no lab, arriscado
   fora dele: qualquer um com a credencial admin baixa todas as chaves. Em
   ambiente estrito, a chave privada não deveria ser recuperável após a emissão.

7. **Containers rodam como root.** Ideal: usuário não-root + permissões de arquivo.

8. **Sem rate limiting** no endpoint de login/admin.

## ✅ Já implementado (nesta rodada)

- **Login com sessão (cookie)** no lugar do Basic Auth → **tela de login,
  logout e troca de senha pela interface**, com senha **hasheada** (PBKDF2) em
  `/ca/admin.json`.
- **Rate-limit** no login (bloqueio temporário após tentativas erradas, por IP real).
- **Trilha de auditoria** (aba Auditoria + `/api/audit`): login, emissão,
  revogação, CRL, troca de senha — com usuário, timestamp e IP.
- **Aba Consultar**: decodifica um PEM colado (`/api/decode`).
- **Healthcheck** no compose (nginx só sobe com o webui saudável).
- **Backup/restore** do volume (`make backup` / `make restore`) e
  **`make reset-admin`** (recuperação de senha).
- Remoção do `openssl.cnf` estático vestigial.
- **Renovação pela UI** (botão "Renovar") com as duas opções: revogar o antigo
  ou manter os dois válidos. Downloads passaram a ser **por serial** (chave
  guardada em `newcerts/<serial>.key`), então dois certs do mesmo CN não se
  misturam.
- **Alertas de expiração** no dashboard (lista o que vence em ≤30 dias com botão
  de renovar).
- **Status OCSP ao vivo** por certificado (consulta o responder e mostra
  good/revoked/unknown + verificação da assinatura).
- **Pacote .zip** por certificado: crt + key + chain + p12 + `PASS.txt` (senha
  aleatória de 30 chars, gerada na hora) + `LEIAME.txt`.

## Deixado documentado (fora do escopo de lab)

- **HSM/KMS** para a chave da intermediária e **raiz realmente offline** —
  exigem infraestrutura além do lab; são a evolução natural para produção.
- **Containers non-root** — o volume é criado como root; fazer direito exige
  ajuste de UID/permissões no entrypoint. Baixo ganho no lab, risco de quebra;
  ficou como melhoria futura.
- **ACME** (emissão automatizada estilo step-ca) e **papéis** (emissor × leitura)
  — evoluções maiores.

## Sugestões de melhoria (funcionalidade / qualidade)

- **Login de verdade** (sessão por cookie) no lugar do Basic Auth → habilita
  **tela de login amigável, botão de logout e troca de senha pela interface**.
- **Trilha de auditoria** das ações (emitir/revogar/CRL) com usuário e timestamp.
- **Alertas de expiração**: já existe `check-expiring.sh`; expor na UI e/ou
  disparar e-mail/webhook.
- **Renovação assistida** de certificados (reemitir o mesmo CN — já viável).
- **Auto-renovação do certificado da própria interface** antes de expirar.
- **Backup/restore** do volume `ca-data` (`make backup` / `make restore`).
- **Healthchecks** no compose (`depends_on: condition: service_healthy`).
- **Papéis** (emissor × somente leitura).
- **Aba “Consultar”** que decodifica um PEM colado (o backend já tem `/api/decode`).
- Remover o `openssl.cnf` estático vestigial (o operativo é o renderizado).
- Endpoint **ACME** (estilo step-ca) para emissão automatizada — evolução maior.

## Prioridade sugerida

1. Login com sessão + logout + troca de senha (resolve UX **e** parte de segurança).
2. Trilha de auditoria.
3. Proteger/mover a chave da intermediária (HSM/KMS) — se sair do lab.
4. Containers não-root + Docker secrets para `ADMIN_PASS`.
