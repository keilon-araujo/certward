#!/usr/bin/env bash
# ============================================================================
# new_cert.sh - Emite um certificado-folha assinado pela INTERMEDIARIA,
# usando a configuracao gravada no setup (/ca/ca.env).
#
#   ./new_cert.sh <nome> [perfil] ["SANs"]
#     perfil : server (padrao) | client | dual
#     SANs   : lista separada por virgula (ex: "DNS:app1.dom,IP:10.0.0.10")
#
# Saidas (em /ca/intermediate/): <nome>.key, certs/<nome>.crt,
#   certs/<nome>.chain.crt (F5), certs/<nome>.p12 (A10).
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
CONF="${CONF:-${CA_BASE}/openssl.cnf}"
INT="${CA_BASE}/intermediate"

: "${CA_DOMAIN:=capsule.lab.br}"
: "${CA_HOST_CA:=ca.${CA_DOMAIN}}"
: "${CA_HOST_OCSP:=ocsp.${CA_DOMAIN}}"
: "${CA_COUNTRY:=BR}"
: "${CA_STATE:=}"
: "${CA_ORG:=Capsule Corp}"
: "${CA_DIGEST:=sha256}"
KEYSIZE="${KEYSIZE:-${CA_LEAF_KEY_SIZE:-2048}}"
DAYS="${DAYS:-${CA_LEAF_DAYS:-375}}"

[ $# -ge 1 ] || { echo "Uso: $0 <nome> [server|client|dual] [\"SANs\"] [ecdsa-p256|ecdsa-p384|rsa-2048|rsa-3072|rsa-4096]"; exit 1; }
name="$1"; profile="${2:-server}"; sans="${3:-}"; keytype="${4:-}"

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
[ -z "$sans" ] && sans="DNS:${name}"

# Wildcard (*.dominio): garante DNS do wildcard E do dominio nu (apex) no SAN,
# porque o wildcard cobre "algo.dominio" mas NAO o proprio "dominio".
case "$name" in
    \*.*)
        apex="${name#\*.}"
        case ",${sans}," in *",DNS:${name},"*) ;; *) sans="DNS:${name},${sans}" ;; esac
        case ",${sans}," in *",DNS:${apex},"*) ;; *) sans="${sans},DNS:${apex}" ;; esac
        ;;
esac

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

if [ "$is_ec" = 1 ]; then
    echo "==> Gerando chave (ECDSA ${curve})"
    openssl ecparam -name "$curve" -genkey -noout -out "$key"
else
    echo "==> Gerando chave (RSA ${bits})"
    openssl genrsa -out "$key" "$bits"
fi
chmod 400 "$key"

echo "==> Gerando CSR (CN=${name})"
openssl req -config "$CONF" -new -"${CA_DIGEST}" -key "$key" -subj "$subj" -out "$csr"

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
subjectAltName         = ${sans}
authorityInfoAccess    = @issuer_info_leaf
crlDistributionPoints  = @crl_info_leaf

[ issuer_info_leaf ]
caIssuers;URI.0 = http://${CA_HOST_CA}/intermediate.crt
OCSP;URI.0      = http://${CA_HOST_OCSP}

[ crl_info_leaf ]
URI.0 = http://${CA_HOST_CA}/ca.crl
EOF

echo "==> Assinando com a intermediaria (perfil: ${profile}, SAN: ${sans})"
openssl ca -config "$CONF" -extfile "$extfile" -extensions "$ext" \
    -days "$DAYS" -notext -md "${CA_DIGEST}" -batch -in "$csr" -out "$crt"

# Guarda a chave POR SERIAL (newcerts/<serial>.key) — assim os downloads e a
# renovacao ficam independentes do CN (permite dois certs do mesmo nome).
# A interface (ca_engine) CIFRA essa chave em repouso e apaga o texto claro
# logo apos a emissao; o serial abaixo diz a ela qual chave proteger.
SER="$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)"
if [ -n "$SER" ]; then cp "$key" "${INT}/newcerts/${SER}.key" && chmod 400 "${INT}/newcerts/${SER}.key"; fi

echo "==> Montando a chain (o PKCS#12 e gerado sob demanda no download, com senha aleatoria)"
cat "$crt" "${INT}/certs/ca-chain.crt" > "$chain"

echo
echo "OK:"
echo "  chain : $chain   <- F5 (SSL profile)"
echo "ISSUED_SERIAL=${SER}"
openssl x509 -in "$crt" -noout -subject -ext subjectAltName,extendedKeyUsage
