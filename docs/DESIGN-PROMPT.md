# Prompt para o Claude (design) — UI da Capsule Corp Internal CA

> Copie tudo abaixo da linha e cole no Claude. O retorno deve ser **um único
> arquivo `index.html`** que substitui `webui/frontend/index.html` no nosso backend.

---

Você vai construir a interface web de um **console de administração de uma
Autoridade Certificadora (CA) interna**, chamada **Capsule Corp Internal CA**. É
uma ferramenta de homelab/laboratório de segurança usada por um engenheiro para
gerenciar certificados de mTLS que protegem aplicações web atrás de balanceadores
F5 BIG-IP e A10 Thunder. O público é técnico (1 admin), então priorize densidade
de informação, clareza operacional e confiança — não é um site de marketing.

## Formato do entregável (obrigatório)

- **Um único `index.html` autocontido.** Todo o CSS e JS inline, **sem nenhuma
  dependência externa** (sem CDN, sem Google Fonts, sem imagens remotas, sem
  bibliotecas). O arquivo roda offline atrás de uma CSP estrita. Use apenas
  fontes de sistema (`-apple-system, Segoe UI, Roboto, ...`), SVG inline e emoji.
- **JavaScript puro (vanilla)**, sem framework nem etapa de build. Pode usar
  módulos ES inline e `fetch`.
- **Tema claro E escuro**, seguindo `prefers-color-scheme`, com bom contraste
  (WCAG AA). Layout **responsivo** (funciona em 360px até desktop largo); nada
  de scroll horizontal no body — tabelas largas rolam em container próprio.
- A página é servida na **mesma origem** da API. A autenticação é **HTTP Basic**
  tratada pelo navegador — não construa tela de login; apenas trate respostas
  `401` mostrando um aviso (“sessão expirada, recarregue para autenticar”).

## Contrato da API REST (NÃO invente endpoints — use exatamente estes)

Todas as chamadas são same-origin, prefixo `/api`. Respostas JSON salvo downloads.

- `GET /api/status` →
  ```json
  {
    "initialized": true,
    "configured":  true,
    "config":      {"domain":"...","org":"...","ou":"...","country":"BR","state":"...","locality":"...","root_cn":"...","intermediate_cn":"...","ca_host":"ca...","ocsp_host":"ocsp...","admin_host":"admin...","key_size":4096,"leaf_key_size":2048,"digest":"sha256","root_days":3650,"intermediate_days":1825,"leaf_days":375,"crl_days":30} | null,
    "root":         {"subject":"CN=...","not_before":"ISO","not_after":"ISO","serial":"HEX","sha256":"AA:BB:..."} ,
    "intermediate": {"subject":"...","not_after":"ISO","sha256":"..."} ,
    "ocsp":         {"subject":"...","not_after":"ISO"} | null,
    "crl":          {"last_update":"ISO","next_update":"ISO","revoked_count":3} | null,
    "counts":       {"total":12,"valido":9,"revogado":2,"expirado":1,"expirando_30d":2}
  }
  ```
  (`config` e os blocos de CA são `null` antes do setup. Use `config.org` para o
  título/marca do console.)

- **Assistente de primeiro login** — quando `initialized=false`, mostre um WIZARD
  que coleta a configuração e chama:
  `POST /api/setup` body:
  ```json
  {"domain":"capsule.lab.br","org":"Capsule Corp","ou":"","country":"BR","state":"","locality":"",
   "root_cn":"","intermediate_cn":"","ca_host":"","ocsp_host":"","admin_host":"",
   "key_size":4096,"leaf_key_size":2048,"digest":"sha256","root_days":3650,"intermediate_days":1825,
   "leaf_days":375,"crl_days":30,"passphrase":"..."}
  ```
  → `{"ok":true,"log":"...","config":{...}}`. Campos vazios recebem defaults no
  backend (OU=“&lt;org&gt; CA”, hosts derivados do domínio, etc.). Só `domain`,
  `org` e `passphrase` (≥8) são obrigatórios; `key_size`/`leaf_key_size` ∈
  {2048,3072,4096}; `digest` ∈ {sha256,sha384,sha512}. Operação **demorada
  (30–90s)**: mostre progresso e desabilite o botão. Erros: HTTP 400
  `{"detail":"..."}`; HTTP 409 = CA já inicializada.
- `GET /api/config` → `{"configured":bool,"config":{...}|null}`.

- `GET /api/certs` → lista, cada item:
  ```json
  {
    "serial":"1001", "cn":"app1.capsule.lab.br",
    "profile":"server",          // server | client | dual | ocsp | ?
    "status":"valido",           // valido | revogado | expirado
    "subject":"...", "not_after":"ISO", "days_left":364,
    "revoked_at":"ISO"|null, "revoke_reason":"keyCompromise"|null,
    "sans":["DNS:app1.capsule.lab.br","IP:10.0.0.10"]
  }
  ```

- `GET /api/certs/{serial}` → o item acima + `subject_full`, `issuer`,
  `not_before`, `not_after`, `sha256`, e `pem` (texto do certificado PEM).

- `POST /api/certs` body `{"name":"app1.capsule.lab.br","profile":"server","sans":"DNS:...,IP:...","p12_password":"..."}`
  → `{"ok":true,"log":"..."}`. `sans` é string separada por vírgula, opcional.
  Operação de alguns segundos. Perfis válidos: `server`, `client`, `dual`.

- `POST /api/certs/{serial}/revoke` body `{"reason":"superseded"}` → `{"ok":true,"log":"..."}`.
  Motivos válidos: `superseded, keyCompromise, cessationOfOperation, affiliationChanged, certificateHold, unspecified`.

- `POST /api/crl/regenerate` → `{"ok":true,"log":"..."}`.

- Downloads (retornam arquivo; abra em nova aba ou link direto):
  - `GET /api/download/ca/{artifact}` com `artifact` ∈ `ca.crt, intermediate.crt, ca-chain.crt, ca.crl, root.crl`.
  - `GET /api/certs/{serial}/download/{kind}` com `kind` ∈ `cert, chain, key, p12`.

## Telas e comportamento

1. **Cabeçalho** fixo: marca “Capsule Corp Internal CA” + um selo de estado
   (CA ativa / não inicializada) alimentado por `/api/status`.

2. **Dashboard**
   - Linha de **KPIs**: total, válidos, revogados, expirados, “expiram ≤30d”
     (use cores semânticas: ok/atenção/perigo). Destaque “expiram ≤30d” quando > 0.
   - **Hierarquia da CA** como árvore visual: Root CA → Intermediate CA → OCSP
     responder, cada nó com subject, validade e fingerprint SHA-256 (truncado,
     com botão copiar).
   - **Cartão da CRL**: última/próxima atualização, nº de revogados, e botão
     “Regenerar CRL”. Sinalize se `next_update` estiver próximo/vencido.

3. **Certificados** (tabela)
   - Colunas: serial, CN, perfil (badge colorido por tipo), status (badge),
     expiração (com “dias restantes”, destacando <30d), downloads, ações.
   - **Filtro** por CN/serial em tempo real. Ordenar por expiração/serial.
   - Downloads por linha: `cert`, `chain`, `key`, `p12` (não ofereça download de
     chave/p12 para certs revogados). Um clique na linha abre o **detalhe**.
   - Ação **Revogar** (só em válidos): abre modal com seletor de motivo; ao
     confirmar, chama a API e atualiza tabela + KPIs + CRL.

4. **Detalhe do certificado** (drawer/modal a partir de `/api/certs/{serial}`)
   - Subject completo, issuer, validade, SANs, fingerprint, e o **PEM** em bloco
     monoespaçado com botão copiar. Downloads. Se revogado, mostre data/motivo.

5. **Emitir** (formulário)
   - Campos: nome/hostname (CN), perfil (server/client/dual com explicação curta
     de cada), SANs (com ajuda: `DNS:...,IP:...,email:...`), senha do PKCS#12
     (opcional, para o A10). Validação client-side do nome (`[A-Za-z0-9._-]`).
   - Ao emitir: estado de carregando, depois toast de sucesso + oferecer os
     downloads do cert recém-criado (chain para F5, p12 para A10).

6. **CA / Init** (só relevante quando `initialized=false`)
   - Explica que cria a hierarquia (raiz + intermediária) uma única vez, pede a
     **passphrase da raiz** (com aviso “guarde-a; não é recuperável”), e mostra
     o log do processo. Quando já inicializada, vira um painel com os downloads
     dos artefatos públicos da CA (ca.crt, intermediate.crt, ca-chain.crt, ca.crl).

## Estados que precisam existir

- **Não inicializada**: dashboard/certs mostram vazio elegante convidando a ir em
  “CA / Init”.
- **Carregando / operação longa** (init, emissão, revogação): spinners/skeletons e
  botões desabilitados; nunca deixe a UI parecer travada.
- **Erro de API**: exiba `detail` do JSON de forma legível (é o log do script —
  monoespaçado, com rolagem). Trate `401` e falha de rede.
- **Sucesso**: toasts discretos.

## Direção visual

- Estética de **console de segurança/infra**: sóbrio, técnico, com uma
  personalidade de marca leve (o nome “Capsule Corp” é uma piada de homelab —
  pode ter um toque, tipo um acento âmbar/laranja e um ícone de cápsula 🧪/⚙️,
  mas mantenha credível e profissional; nada infantil).
- Paleta: fundo neutro escuro por padrão, superfícies em camadas, **um** tom de
  acento para ações primárias, e cores semânticas consistentes para status
  (verde=válido, vermelho=revogado, âmbar=expira/expirado). Garanta a versão
  clara igualmente polida.
- Tipografia de sistema; use monoespaçada para serial, fingerprint, PEM e logs.
- Hierarquia visual forte, espaçamento generoso, cantos suavemente arredondados,
  bordas sutis em vez de sombras pesadas. Ícones em SVG inline.
- Acessibilidade: foco visível, labels associadas, contraste AA, navegação por
  teclado nos modais.

## Não faça

- Não use bibliotecas/CDNs/fontes externas nem faça requisições fora de `/api`.
- Não invente campos ou endpoints além do contrato acima.
- Não crie tela de login (a auth é do navegador via Basic).
- Não use dados mockados no arquivo final — tudo vem da API. (Pode montar um modo
  de demonstração opcional, mas o padrão é consumir a API real.)

Entregue o `index.html` completo, pronto para colar em `webui/frontend/index.html`.
