# Changelog — CertaSync · CA interna

Autoridade certificadora interna do **CertaSync**, ofertada como componente
opcional em VM separada. O formato segue
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o versionamento
segue [SemVer](https://semver.org/lang/pt-BR/).

A versão corrente vive no arquivo [`VERSION`](VERSION) na raiz — é a fonte
única, lida pelo backend e publicada em `GET /api/health`.

---

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
