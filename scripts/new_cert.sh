#!/usr/bin/env bash
# ============================================================================
# new_cert.sh - Emite um certificado-folha assinado pela INTERMEDIARIA,
# usando a configuracao gravada no setup (/ca/ca.env).
#
#   ./new_cert.sh <nome> [perfil] ["SANs"] [keytype]
#   ./new_cert.sh --csr <arquivo.csr> <nome> [perfil] ["SANs"]
#     perfil : server (padrao) | client | dual
#     SANs   : lista separada por virgula (ex: "DNS:app1.dom,IP:10.0.0.10")
#
# MODO CSR (--csr): a CA NAO gera chave. Assina a requisicao que veio de fora e
# a chave privada nunca existe aqui. E o modo exigido por quem opera a chave no
# proprio servico (ex.: CertaSync) e um nao-negociavel do roadmap desta CA.
#
# Saidas (em /ca/intermediate/): certs/<nome>.crt e certs/<nome>.chain.crt.
# Sem --csr, tambem <nome>.key (e a copia por serial em newcerts/).
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
CONF="${CONF:-${CA_BASE}/openssl.cnf}"
INT="${CA_BASE}/intermediate"

# Passphrase da intermediaria (chave cifrada em repouso) -> INTPASS=(-passin ...)
. "$(dirname "$0")/lib-intpass.sh"
int_passin_args

: "${CA_DOMAIN:=capsule.lab.br}"
: "${CA_HOST_CA:=ca.${CA_DOMAIN}}"
: "${CA_HOST_OCSP:=ocsp.${CA_DOMAIN}}"
: "${CA_COUNTRY:=BR}"
: "${CA_STATE:=}"
: "${CA_ORG:=Capsule Corp}"
: "${CA_DIGEST:=sha256}"
KEYSIZE="${KEYSIZE:-${CA_LEAF_KEY_SIZE:-2048}}"
DAYS="${DAYS:-${CA_LEAF_DAYS:-375}}"

# --csr <arquivo>: assina requisicao externa; a CA nao gera chave nenhuma.
csr_in=""
if [ "${1:-}" = "--csr" ]; then
    [ $# -ge 3 ] || { echo "Uso: $0 --csr <arquivo.csr> <nome> [perfil] [\"SANs\"]"; exit 1; }
    csr_in="$2"; shift 2
    [ -f "$csr_in" ] || { echo "CSR nao encontrado: $csr_in"; exit 1; }
    openssl req -in "$csr_in" -noout -verify >/dev/null 2>&1 \
        || { echo "CSR invalido (assinatura nao confere): $csr_in"; exit 1; }
fi

[ $# -ge 1 ] || { echo "Uso: $0 [--csr <arquivo>] <nome> [server|client|dual] [\"SANs\"] [ecdsa-p256|ecdsa-p384|rsa-2048|rsa-3072|rsa-4096]"; exit 1; }
name="$1"; profile="${2:-server}"; sans="${3:-}"; keytype="${4:-}"

# No modo CSR o tipo de chave vem do proprio CSR. Aceitar um keytype aqui seria
# prometer o que nao se pode cumprir: a chave ja existe e nao vai mudar.
if [ -n "$csr_in" ] && [ -n "$keytype" ]; then
    echo "Com --csr o tipo de chave vem do proprio CSR; remova o argumento keytype (${keytype})."
    exit 1
fi

# O CN do CSR precisa bater com o nome pedido. Divergencia aqui emite um
# certificado para outro nome sem ninguem perceber.
if [ -n "$csr_in" ]; then
    csr_cn="$(openssl req -in "$csr_in" -noout -subject 2>/dev/null \
              | sed -n 's/.*CN[ ]*=[ ]*\([^,\/]*\).*/\1/p' | sed 's/[[:space:]]*$//')"
    if [ -n "$csr_cn" ] && [ "$csr_cn" != "$name" ]; then
        echo "CN do CSR (${csr_cn}) diferente do nome pedido (${name})."
        exit 1
    fi
fi

case "$profile" in
    server|client|dual) ext="${profile}_cert" ;;
    *) echo "Perfil invalido: $profile (use server|client|dual)"; exit 1 ;;
esac

# Tipo de chave: ECDSA (padrao na UI) ou RSA (legado). Vazio = RSA no tamanho do setup.
case "$keytype" in
    ecdsa-p256) keyalgo=ec;  curve=prime256v1 ;;
    ecdsa-p384) keyalgo=ec;  curve=secp384r1 ;;
    rsa-2048)   keyalgo=rsa; bits=2048 ;;
    rsa-3072)   keyalgo=rsa; bits=3072 ;;
    rsa-4096)   keyalgo=rsa; bits=4096 ;;
    ""|rsa)     keyalgo=rsa; bits="$KEYSIZE" ;;
    *) echo "key_type invalido: $keytype"; exit 1 ;;
esac
is_ec=0; [ "$keyalgo" = ec ] && is_ec=1

# SAN padrao conforme o PROPOSITO. Para pessoa, o identificador nao e um host:
# um e-mail vai em rfc822Name (email:), e um nome proprio nao vira SAN nenhum —
# fica so no CN. Colocar "DNS:joao.silva@dominio" produziria um SAN invalido
# que alguns verificadores rejeitam e outros ignoram, o que e pior.
if [ -z "$sans" ]; then
    case "$profile:$name" in
        server:*)  sans="DNS:${name}" ;;
        *:*@*)     sans="email:${name}" ;;
        *" "*)     sans="" ;;                 # nome com espaco: so CN
        *)         sans="DNS:${name}" ;;
    esac
fi

# Wildcard (*.dominio): garante DNS do wildcard E do dominio nu (apex) no SAN,
# porque o wildcard cobre "algo.dominio" mas NAO o proprio "dominio".
case "$name" in
    \*.*)
        apex="${name#\*.}"
        case ",${sans}," in *",DNS:${name},"*) ;; *) sans="DNS:${name},${sans}" ;; esac
        case ",${sans}," in *",DNS:${apex},"*) ;; *) sans="${sans},DNS:${apex}" ;; esac
        ;;
esac

# A intermediaria e name-constrained: o openssl ca NAO valida isso na assinatura
# (quem valida e o verificador), entao sem esta checagem a CA emite um
# certificado que nenhum cliente aceita — e responde "ok". Comprovado em
# laboratorio: 'openssl verify' devolve "permitted subtree violation".
if [ "${CA_NAME_CONSTRAINTS:-1}" = "1" ] && [ -n "${CA_DOMAIN}" ]; then
    # Valida CN e cada SAN do tipo DNS. Os demais tipos (IP:, email:, URI:) nao
    # sao restringidos por esta CA — ela so declara constraint de DNS —, entao
    # rejeita-los aqui seria inventar regra que o certificado nao carrega.
    # O CN so entra na checagem quando E um nome DNS. Num certificado de pessoa
    # o CN e e-mail ou nome proprio, e a constraint desta CA e de DNS — validar
    # "joao.silva@dominio" como host recusaria o caso de uso do perfil client.
    _cn_dns=""
    case "$name" in
        *@*|*" "*) ;;                 # pessoa: nao e nome DNS
        *) _cn_dns="$name" ;;
    esac
    _fora=""
    _vistos=""
    for _entrada in $_cn_dns $(echo "$sans" | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS:[[:space:]]*//p'); do
        _base="${_entrada#\*.}"
        case " ${_vistos} " in *" ${_entrada} "*) continue ;; esac
        _vistos="${_vistos} ${_entrada}"
        case "$_base" in
            "${CA_DOMAIN}"|*."${CA_DOMAIN}"|localhost) ;;
            *) _fora="${_fora} ${_entrada}" ;;
        esac
    done
    if [ -n "$_fora" ]; then
        echo "Fora da Name Constraint desta CA (${CA_DOMAIN}):${_fora}"
        echo "A intermediaria so pode emitir para ${CA_DOMAIN} e subdominios."
        echo "Assinar assim produziria um certificado que nenhum cliente aceita."
        exit 1
    fi
fi

# CN/SAN usam o nome real (pode ser wildcard *.dominio); os ARQUIVOS usam um
# nome seguro (o '*' vira 'wildcard') para evitar globbing no shell.
fname="${name//\*/wildcard}"

key="${INT}/private/${fname}.key"
csr="${INT}/reqs/${fname}.csr"
crt="${INT}/certs/${fname}.crt"
chain="${INT}/certs/${fname}.chain.crt"
[ -f "$crt" ] && { echo "Ja existe ${crt}. Escolha outro nome ou revogue antes."; exit 1; }

# subject (omite ST se vazio)
subj="/C=${CA_COUNTRY}"
[ -n "${CA_STATE}" ] && subj="${subj}/ST=${CA_STATE}"
subj="${subj}/O=${CA_ORG}/CN=${name}"

if [ -n "$csr_in" ]; then
    # Modo CSR: a chave privada e de quem pediu e NAO passa por aqui.
    echo "==> Usando CSR externo (a CA nao gera chave)"
    cp "$csr_in" "$csr"
    key=""
elif [ "$is_ec" = 1 ]; then
    echo "==> Gerando chave (ECDSA ${curve})"
    openssl ecparam -name "$curve" -genkey -noout -out "$key"
    chmod 400 "$key"
    echo "==> Gerando CSR (CN=${name})"
    openssl req -config "$CONF" -new -"${CA_DIGEST}" -key "$key" -subj "$subj" -out "$csr"
else
    echo "==> Gerando chave (RSA ${bits})"
    openssl genrsa -out "$key" "$bits"
    chmod 400 "$key"
    echo "==> Gerando CSR (CN=${name})"
    openssl req -config "$CONF" -new -"${CA_DIGEST}" -key "$key" -subj "$subj" -out "$csr"
fi

# keyUsage/EKU por perfil. keyEncipherment so faz sentido em RSA (transporte de
# chave); em ECDSA (ECDHE) usa-se apenas digitalSignature.
case "$profile" in
    server) eku="serverAuth" ;;
    client) eku="clientAuth" ;;
    dual)   eku="serverAuth, clientAuth" ;;
esac
if [ "$is_ec" = 0 ] && { [ "$profile" = server ] || [ "$profile" = dual ]; }; then
    ku="digitalSignature, keyEncipherment"
else
    ku="digitalSignature"
fi

extfile="$(mktemp)"; trap 'rm -f "$extfile"' EXIT
cat > "$extfile" <<EOF
[ ${ext} ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, ${ku}
extendedKeyUsage       = critical, ${eku}
${sans:+subjectAltName         = ${sans}}
authorityInfoAccess    = @issuer_info_leaf
crlDistributionPoints  = @crl_info_leaf

[ issuer_info_leaf ]
caIssuers;URI.0 = http://${CA_HOST_CA}/intermediate.crt
OCSP;URI.0      = http://${CA_HOST_OCSP}

[ crl_info_leaf ]
URI.0 = http://${CA_HOST_CA}/ca.crl
EOF

echo "==> Assinando com a intermediaria (perfil: ${profile}, SAN: ${sans})"
openssl ca -config "$CONF" "${INTPASS[@]}" -extfile "$extfile" -extensions "$ext" \
    -days "$DAYS" -notext -md "${CA_DIGEST}" -batch -in "$csr" -out "$crt"

# Guarda a chave POR SERIAL (newcerts/<serial>.key) — assim os downloads e a
# renovacao ficam independentes do CN (permite dois certs do mesmo nome).
# A interface (ca_engine) CIFRA essa chave em repouso e apaga o texto claro
# logo apos a emissao; o serial abaixo diz a ela qual chave proteger.
SER="$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)"
if [ -n "$SER" ] && [ -n "$key" ] && [ -f "$key" ]; then
    cp "$key" "${INT}/newcerts/${SER}.key" && chmod 400 "${INT}/newcerts/${SER}.key"
fi

echo "==> Montando a chain (o PKCS#12 e gerado sob demanda no download, com senha aleatoria)"
cat "$crt" "${INT}/certs/ca-chain.crt" > "$chain"

echo
echo "OK:"
echo "  chain : $chain   <- F5 (SSL profile)"
if [ -n "$csr_in" ]; then
    echo "  chave : NAO gerada (emissao por CSR — a privada ficou com o solicitante)"
    echo "ISSUED_FROM_CSR=1"
fi
echo "ISSUED_SERIAL=${SER}"
openssl x509 -in "$crt" -noout -subject -ext subjectAltName,extendedKeyUsage
