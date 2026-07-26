#!/usr/bin/env bash
# ============================================================================
# revoke-cert.sh - Revoga um certificado-folha e republica a CRL.
#
#   ./revoke-cert.sh <caminho-do-cert> [motivo]
#
#   motivo (opcional): unspecified | keyCompromise | CACompromise |
#                      affiliationChanged | superseded | cessationOfOperation |
#                      certificateHold   (padrao: superseded)
#
# Exemplo:
#   ./revoke-cert.sh /ca/intermediate/certs/app1.capsule.lab.br.crt keyCompromise
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
CONF="${CONF:-${CA_BASE}/openssl.cnf}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ $# -ge 1 ] || { echo "Uso: $0 <caminho-do-cert> [motivo]"; exit 1; }
cert="$1"
reason="${2:-superseded}"
[ -f "$cert" ] || { echo "Cert nao encontrado: $cert"; exit 1; }

echo "==> Revogando ${cert} (motivo: ${reason})"
openssl ca -config "$CONF" -revoke "$cert" -crl_reason "$reason"

echo "==> Regenerando e publicando a CRL da intermediaria"
"${SCRIPT_DIR}/gen-crl.sh"

echo "OK. Revogado. A nova CRL ja esta em ${CA_BASE}/web/ca.crl"
echo "    (F5/A10 e clientes OCSP passarao a rejeitar esse certificado)"
