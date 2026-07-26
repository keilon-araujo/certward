#!/usr/bin/env bash
# ============================================================================
# init-ca.sh - Cria a PKI de duas camadas em /ca a partir da configuracao
# escolhida no assistente (gravada em /ca/ca.env e /ca/openssl.cnf).
#
#   Root CA (offline/trancada)  ->  Intermediate CA (assina o dia a dia)
#                                     +-> cert do responder OCSP (ocsp.crt)
#
# Roda UMA vez. A chave da RAIZ e criada COM passphrase (CA_ROOT_PASS no
# ambiente para modo nao-interativo, usado pela interface web).
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
CONF="${CONF:-${CA_BASE}/openssl.cnf}"
ROOT="${CA_BASE}/root"
INT="${CA_BASE}/intermediate"
WEB="${CA_BASE}/web"
TLS="${CA_BASE}/tls"

# Passphrase da intermediaria (cifra a chave em repouso). Resolve INTPASS=(-passin ...).
. "$(dirname "$0")/lib-intpass.sh"
int_passin_args

# Defaults (fallback se o ca.env nao existir — mantem o comportamento antigo)
: "${CA_DOMAIN:=capsule.lab.br}"
: "${CA_ORG:=Capsule Corp}"
: "${CA_OU:=${CA_ORG} CA}"
: "${CA_COUNTRY:=BR}"
: "${CA_STATE:=}"
: "${CA_LOCALITY:=}"
: "${CA_ROOT_CN:=${CA_ORG} Root CA}"
: "${CA_INT_CN:=${CA_ORG} Intermediate CA}"
: "${CA_HOST_OCSP:=ocsp.${CA_DOMAIN}}"
: "${CA_OCSP_CN:=${CA_HOST_OCSP}}"
: "${CA_KEY_SIZE:=4096}"
: "${CA_ROOT_DAYS:=3650}"
: "${CA_INT_DAYS:=1825}"
: "${CA_DIGEST:=sha256}"

# Monta um subject omitindo componentes vazios (ST/L opcionais)
mk_subj() {  # $1 = CN
    local s="/C=${CA_COUNTRY}"
    [ -n "${CA_STATE}" ]    && s="${s}/ST=${CA_STATE}"
    [ -n "${CA_LOCALITY}" ] && s="${s}/L=${CA_LOCALITY}"
    s="${s}/O=${CA_ORG}/OU=${CA_OU}/CN=$1"
    printf '%s' "$s"
}
ROOT_SUBJ="$(mk_subj "${CA_ROOT_CN}")"
INT_SUBJ="$(mk_subj "${CA_INT_CN}")"
OCSP_SUBJ="$(mk_subj "${CA_OCSP_CN}")"

mkdir -p "$CA_BASE" 2>/dev/null || true
[ -w "$CA_BASE" ] || { echo "Sem permissao de escrita em ${CA_BASE}"; exit 1; }
[ -f "$CONF" ] || { echo "openssl.cnf ausente em ${CONF} (rode o setup pela interface web)."; exit 1; }

if [ -f "${ROOT}/certs/ca.crt" ]; then
    echo "Ja existe uma CA em ${ROOT}. Abortando para nao sobrescrever."
    exit 1
fi

if [ -n "${CA_ROOT_PASS:-}" ]; then
    PASSOUT=(-passout env:CA_ROOT_PASS); PASSIN=(-passin env:CA_ROOT_PASS)
else
    PASSOUT=(); PASSIN=()
fi

echo "==> Criando estrutura de diretorios"
for d in "$ROOT" "$INT"; do
    mkdir -p "$d"/{certs,crl,newcerts,private,csr}
    chmod 700 "$d/private"
    touch "$d/index.txt"
    # unique_subject=no: permite reemitir/renovar um cert com o mesmo CN
    # (sem isso o openssl recusa um segundo cert valido com o mesmo subject).
    echo 'unique_subject = no' > "$d/index.txt.attr"
    echo 1000 > "$d/serial"
    echo 1000 > "$d/crlnumber"
done
mkdir -p "$INT/reqs" "$WEB" "$TLS"

echo "==> Dominio: ${CA_DOMAIN} | Org: ${CA_ORG} | Chave: RSA ${CA_KEY_SIZE} | Digest: ${CA_DIGEST}"

# --------------------------------------------------------------------------
echo "==> [1/6] Root CA (RSA ${CA_KEY_SIZE}, COM passphrase)"
openssl genrsa -aes256 "${PASSOUT[@]}" -out "${ROOT}/private/ca.key" "${CA_KEY_SIZE}"
chmod 400 "${ROOT}/private/ca.key"
openssl req -config "$CONF" -key "${ROOT}/private/ca.key" "${PASSIN[@]}" \
    -new -x509 -days "${CA_ROOT_DAYS}" -"${CA_DIGEST}" -extensions v3_ca \
    -subj "$ROOT_SUBJ" -out "${ROOT}/certs/ca.crt"
chmod 444 "${ROOT}/certs/ca.crt"

# --------------------------------------------------------------------------
if [ -n "${CA_INT_PASS:-}" ]; then
    echo "==> [2/6] Intermediate CA (RSA ${CA_KEY_SIZE}, chave CIFRADA em repouso)"
    openssl genrsa -aes256 -passout env:CA_INT_PASS -out "${INT}/private/intermediate.key" "${CA_KEY_SIZE}"
else
    echo "==> [2/6] Intermediate CA (RSA ${CA_KEY_SIZE}, SEM passphrase — defina CA_INT_PASS p/ cifrar)"
    openssl genrsa -out "${INT}/private/intermediate.key" "${CA_KEY_SIZE}"
fi
chmod 400 "${INT}/private/intermediate.key"
openssl req -config "$CONF" -key "${INT}/private/intermediate.key" "${INTPASS[@]}" \
    -new -"${CA_DIGEST}" -subj "$INT_SUBJ" -out "${INT}/csr/intermediate.csr"
openssl ca -config "$CONF" -name CA_root "${PASSIN[@]}" -extensions v3_intermediate_ca \
    -days "${CA_INT_DAYS}" -notext -md "${CA_DIGEST}" -batch \
    -in "${INT}/csr/intermediate.csr" -out "${INT}/certs/intermediate.crt"
chmod 444 "${INT}/certs/intermediate.crt"
openssl verify -CAfile "${ROOT}/certs/ca.crt" "${INT}/certs/intermediate.crt"

# --------------------------------------------------------------------------
echo "==> [3/6] Bundle da cadeia (intermediaria + raiz)"
cat "${INT}/certs/intermediate.crt" "${ROOT}/certs/ca.crt" > "${INT}/certs/ca-chain.crt"
chmod 444 "${INT}/certs/ca-chain.crt"

# --------------------------------------------------------------------------
echo "==> [4/6] Certificado do responder OCSP (ocsp.crt / ocsp.key)"
openssl genrsa -out "${INT}/private/ocsp.key" "${CA_KEY_SIZE}"
chmod 400 "${INT}/private/ocsp.key"
openssl req -config "$CONF" -key "${INT}/private/ocsp.key" \
    -new -"${CA_DIGEST}" -subj "$OCSP_SUBJ" -out "${INT}/csr/ocsp.csr"
openssl ca -config "$CONF" "${INTPASS[@]}" -extensions ocsp -days 365 -notext -md "${CA_DIGEST}" -batch \
    -in "${INT}/csr/ocsp.csr" -out "${INT}/certs/ocsp.crt"

# --------------------------------------------------------------------------
echo "==> [5/6] CRLs iniciais + publicacao em ${WEB}"
openssl ca -config "$CONF" -name CA_root "${PASSIN[@]}" -gencrl -out "${ROOT}/crl/root.crl"
openssl ca -config "$CONF" -name CA_intermediate "${INTPASS[@]}" -gencrl -out "${INT}/crl/intermediate.crl"
cp "${ROOT}/certs/ca.crt"            "${WEB}/ca.crt"
cp "${INT}/certs/intermediate.crt"   "${WEB}/intermediate.crt"
cp "${INT}/certs/ca-chain.crt"       "${WEB}/ca-chain.crt"
cp "${INT}/crl/intermediate.crl"     "${WEB}/ca.crl"
cp "${ROOT}/crl/root.crl"            "${WEB}/root.crl"
chmod 444 "${WEB}"/*

# --------------------------------------------------------------------------
echo "==> [6/6] Certificado TLS da interface admin"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
P12_PASS="" "${SELF_DIR}/issue-admin-cert.sh" \
    || echo "  (aviso: falha ao emitir o cert admin; a UI usara o cert temporario)"

cat <<EOF

============================================================
 PKI de ${CA_ORG} criada com sucesso (dominio ${CA_DOMAIN}).

 Raiz:          ${ROOT}/certs/ca.crt          (chave COM passphrase)
 Intermediaria: ${INT}/certs/intermediate.crt
 Cadeia:        ${INT}/certs/ca-chain.crt     (use no F5/A10 e nos servidores)
 OCSP signer:   ${INT}/certs/ocsp.crt
 Publicados em: ${WEB}/

 Emita certificados:  ./new_cert.sh <nome> <server|client|dual> "<SANs>"
============================================================
EOF
