#!/usr/bin/env bash
# ============================================================================
# issue-admin-cert.sh - Emite o certificado TLS da interface web (admin) com a
# propria CA e o publica em ${CA_BASE}/tls/ (FORA do web root). Idempotente.
# O host vem da configuracao do setup (CA_HOST_ADMIN).
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INT="${CA_BASE}/intermediate"
TLS="${CA_BASE}/tls"

: "${CA_DOMAIN:=capsule.lab.br}"
: "${CA_HOST_ADMIN:=admin.${CA_DOMAIN}}"
: "${CA_HOST_CA:=ca.${CA_DOMAIN}}"
: "${CA_HOST_OCSP:=ocsp.${CA_DOMAIN}}"
NAME="${CA_HOST_ADMIN}"

mkdir -p "$TLS"
if [ -f "${TLS}/admin.crt" ] && [ -f "${TLS}/admin.key" ]; then
    echo "[admin-cert] ja existe em ${TLS}; nada a fazer."
    exit 0
fi

if [ ! -f "${INT}/certs/${NAME}.crt" ]; then
    echo "[admin-cert] emitindo ${NAME}"
    # localhost/127.0.0.1 no SAN para acesso local (https://localhost) sem erro de nome.
    P12_PASS="" "${SCRIPT_DIR}/new_cert.sh" "$NAME" server \
        "DNS:${NAME},DNS:${CA_HOST_CA},DNS:${CA_HOST_OCSP},DNS:localhost,IP:127.0.0.1"
fi

cp "${INT}/certs/${NAME}.chain.crt" "${TLS}/admin.crt"
cp "${INT}/private/${NAME}.key"     "${TLS}/admin.key"
chmod 444 "${TLS}/admin.crt"
chmod 400 "${TLS}/admin.key"
echo "[admin-cert] publicado em ${TLS}/admin.{crt,key} (CN=${NAME})"
