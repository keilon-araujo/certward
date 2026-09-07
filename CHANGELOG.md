# Changelog — CertaSync · CA interna

Autoridade certificadora interna do **CertaSync**, ofertada como componente
opcional em VM separada. O formato segue
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o versionamento
segue [SemVer](https://semver.org/lang/pt-BR/).

A versão corrente vive no arquivo [`VERSION`](VERSION) na raiz — é a fonte
única, lida pelo backend e publicada em `GET /api/health`.

---

## [1.2.0] — 2026-09-07

### Adicionado

- **Aba "Tokens" no console.** Criar (nome, escopos, validade), ver o
  segredo **uma única vez** com botão de copiar, listar (prefixo, escopos,
  criado por/em, expira, último uso, status) e revogar com confirmação. A
  API já existia (`/api/service-tokens`); faltava a tela — o runbook mandava
  "console → Tokens de serviço" e o ensaio de instalação do zero mostrou que
  ela não existia. O `ops/criar-token.sh` do kit continua como alternativa
  para automação.

## [1.1.4] — 2026-09-07

### Adicionado

- **`ops/` no kit** — `backup.sh`, `restore.sh`, `backup-agendado.sh` e
  `criar-token.sh`, com o nome do volume (`certward_ca-data`) e a tag da
  imagem do kit já resolvidos. O ensaio de instalação do zero numa VM limpa
  mostrou que o runbook mandava `make backup` e apontava `scripts/`, que só
  existem no repositório — o cliente não tem nenhum dos dois. E o console
  **não tem tela de tokens de serviço** (só a API, que exige sessão):
  `criar-token.sh` faz login e cria o token; a tela fica para a 1.2.

## [1.1.3] — 2026-09-07

### Adicionado

- **Kit de entrega** (`kit/montar-kit.sh`): imagens `certward:<versão>` e
  `certward-nginx:<versão>` para a plataforma do cliente, `docker save`,
  `docker-compose.yml` com tag fixa e sem `build:` (portas 80/443 — a VM da
  CA é dedicada; o 8081/8444 do laboratório era um override local),
  `.env.example` e `SHA256SUMS`. Até aqui a CA só subia por `bootstrap.sh`,
  que faz build a partir do fonte — o cliente não tem o fonte. A
  documentação vai em pacote separado, não no kit.

## [1.1.2] — 2026-09-06

### Corrigido

- **Revogação respondia erro depois de revogar.** `gen-crl.sh` copiava a CRL
  nova por cima de `web/ca.crl`, que fica `444`; como a interface roda sem
  root, o `cp` falhava com "Permission denied" **depois** de o índice já
  estar revogado — a revogação valia, a API devolvia 400 e o cliente
  (CertaSync) reportava "recusou o pedido" (achado E do teste de aceite,
  06/09/2026). A publicação passa a ser por arquivo temporário + `mv -f`,
  para a intermediária e para a raiz, o que também evita leitor pegar CRL
  pela metade.

## [1.1.1] — 2026-09-06

### Corrigido

- **Renovação por CSR de um nome que já tem certificado.** `new_cert.sh`
  recusa emitir quando `certs/<nome>.crt` existe — proteção certa para o
  operador na tela, mas fatal para quem renova pela API: o CertaSync só sabe
  pedir "emita este CSR", e toda renovação de nome existente (certificado da
  própria interface, renovação diária, campanha) morria em "Ja existe".
  Achado no laboratório em 06/09/2026, ao reemitir o certificado da UI.
  `POST /api/certs` aceita agora **`substituir: true`**: o motor arquiva os
  arquivos de trabalho por nome (crt/chain/csr/key) **antes** de chamar o
  script — o que `renew()` já fazia — e emite. A série anterior **não é
  revogada nem some**: fica em `newcerts/<serial>.pem`, válida e baixável por
  série, porque numa renovação o novo só passa a servir depois do deploy.
  Sem o flag, nada muda (a tela continua recusando). O log e a auditoria
  registram a série substituída. Testes em `test_engine_substituir.py`.

## [1.1.0] — 2026-08-22

### Alterado

- **Identidade visual alinhada à marca CertaSync.** A apresentação deste
  console (densidade, cantos, bordas) foi escolhida como direção para os dois
  produtos e **não muda**; muda a identidade: acento azul da marca
  (`#6BB4E8` no escuro, `#12507A` no claro) no lugar do âmbar, "ok" no teal
  de certificado válido, superfícies derivadas de `#0E1418`/`#F5F7F8`, e
  tipografia IBM Plex Sans / IBM Plex Mono / Space Grotesk (títulos) —
  **servida pela própria CA** em `/fonts` (sem CDN). O símbolo do cabeçalho
  passa a ser o "Anel de Renovação" do CertaSync. Lado a lado, CA e
  plataforma deixam de parecer dois fornecedores.

## [1.0.1] — 2026-08-22

### Corrigido

- **Download de certificado de pessoa.** A CA emitia o certificado com CN de
  e-mail (perfil `client`, desde a 1.0.0) e depois **recusava o download por
  série** — `CN do certificado nao mapeavel para arquivo` —, porque a guarda do
  nome de arquivo só aceitava hostname. Achado integrando o CertaSync no
  laboratório em 22/08/2026: a emissão respondia "ok" e o cliente ficava sem o
  certificado. `pki.slug_valido()` aceita hostname/wildcard **e** identificador
  de pessoa (nenhum dos dois admite `/`, então o slug nunca sai do diretório).
  A renovação passa a validar o CN antigo pela mesma regra da emissão
  (`nome_valido(cn, profile)`), em vez de exigir hostname.

## [1.0.0] — 2026-08-19

Primeira versão empacotada para entrega. O que já existia passa a ter versão,
changelog e limites declarados.

### Adicionado

- **Emissão a partir de CSR** (`--csr`): a CA deixa de gerar a chave quando o
  pedido já traz uma. É o que permite ao CertaSync emitir sem que a chave
  privada exista em dois lugares.

- **Tokens de serviço** (`cwt_<kid>_<segredo>`) com escopos
  `certs:issue`/`certs:read`/`certs:revoke`, validade obrigatória e segredo
  exibido uma única vez. HMAC-SHA256 com *pepper* fora do JSON — não bcrypt: a
  entropia do segredo gerado dispensa o custo num caminho que uma esteira
  percorre a cada passo.

  As rotas de administração (setup, senha, gestão de tokens) seguem exigindo
  sessão: é isso que impede qualquer token de alcançá-las por construção.

  O download aceita token **só para material público** (`cert`, `chain`);
  `key` e `bundle` carregam a chave privada e continuam exclusivos de sessão.

- **Validade da CRL publicada em `GET /api/health`**, com `dias_restantes`,
  `vencida` e `gerada_ha_dias`. Sem isso, a falha da regeneração automática só
  aparecia quando a CRL vencia — e CRL vencida não degrada: todo cliente que
  consulta revogação passa a recusar **todos** os certificados desta CA de uma
  vez, os válidos inclusive. O campo `gerada_ha_dias` é o sinal adiantado:
  denuncia a parada em dois dias, não em vinte.

- **`VERSION` + este changelog**, com a versão publicada no `/api/health` e no
  rodapé do console.

### Alterado

- **A regeneração da CRL segue a validade configurada** em vez de 24 h fixas:
  um terço de `crl_days`, entre 1 h e 24 h. Com o padrão de 30 dias são
  precisas três falhas seguidas para a CRL vencer; antes, com `crl_days=1`, a
  primeira falha já bastava.

- **Name Constraint verificada antes de assinar.** O `openssl ca` não a valida
  — quem valida é o verificador —, então a CA emitia certificado que nenhum
  cliente aceita e respondia "ok". A checagem cobre o CN (só quando é nome DNS)
  e cada SAN de DNS; IP e e-mail não são restringidos, porque esta CA declara
  constraint apenas de DNS.

- **O perfil `client` aceita identificador de pessoa** (e-mail/UPN), mantendo a
  validação DNS estrita para `server`.

### Limites declarados desta versão

Não são defeitos — são a fronteira da oferta, e estão no material comercial:

- **Um operador administrador.** Sem papéis, LDAP/AD, SSO ou MFA.
- **Backup por agendamento do sistema operacional** (`make backup` cifrado),
  sem retenção GFS verificada.
- **Trilha de auditoria local** em JSONL, sem envio a SIEM.
- **Sem licenciamento próprio.**
