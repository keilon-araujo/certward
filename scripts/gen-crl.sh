#!/usr/bin/env bash
# ============================================================================
# gen-crl.sh - Regenera e publica a CRL da intermediaria (e a da raiz).
#
# A CRL tem validade curta (30 dias, ver default_crl_days), entao precisa ser
# regerada periodicamente MESMO sem revogacoes novas, ou os clientes vao
# considerar a CRL expirada. Rode via systemd timer / cron (ex: diario).
#
#   ./gen-crl.sh            # regenera a CRL da intermediaria + publica
#   ./gen-crl.sh --root     # tambem regenera a CRL da raiz (pede passphrase)
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
[ -f "${CA_BASE}/ca.env" ] && . "${CA_BASE}/ca.env"
CONF="${CONF:-${CA_BASE}/openssl.cnf}"
INT="${CA_BASE}/intermediate"
ROOT="${CA_BASE}/root"
WEB="${CA_BASE}/web"
. "$(dirname "$0")/lib-intpass.sh"; int_passin_args    # INTPASS=(-passin ...) da intermediaria

echo "==> Gerando CRL da intermediaria"
openssl ca -config "$CONF" -name CA_intermediate "${INTPASS[@]}" -gencrl -out "${INT}/crl/intermediate.crl"
# Publica por arquivo temporario + mv: o ca.crl anterior e 444 e o processo
# da interface roda sem root, entao "cp" por cima dele falhava com
# "Permission denied" DEPOIS de o indice ja estar revogado — a revogacao
# valia e a API respondia erro (CertaSync, achado E de 06/09/2026). O mv
# troca o arquivo inteiro de uma vez, o que tambem evita leitor pegar CRL
# pela metade.
cp "${INT}/crl/intermediate.crl" "${WEB}/ca.crl.tmp"
chmod 444 "${WEB}/ca.crl.tmp"
mv -f "${WEB}/ca.crl.tmp" "${WEB}/ca.crl"

if [ "${1:-}" = "--root" ]; then
    echo "==> Gerando CRL da raiz (vai pedir a passphrase da raiz)"
    if [ -n "${CA_ROOT_PASS:-}" ]; then PASSIN=(-passin env:CA_ROOT_PASS); else PASSIN=(); fi
    openssl ca -config "$CONF" -name CA_root "${PASSIN[@]}" -gencrl -out "${ROOT}/crl/root.crl"
    cp "${ROOT}/crl/root.crl" "${WEB}/root.crl.tmp"
    chmod 444 "${WEB}/root.crl.tmp"
    mv -f "${WEB}/root.crl.tmp" "${WEB}/root.crl"
fi

echo "OK. CRL(s) publicada(s) em ${WEB}/"
