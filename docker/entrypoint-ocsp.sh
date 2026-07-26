#!/usr/bin/env bash
# Responder OCSP em container. Espera a CA ser inicializada (via UI) e sobe.
# O laco reinicia o responder caso o openssl ocsp encerre apos uma requisicao.
set -u
CA_BASE="${CA_BASE:-/ca}"
INT="${CA_BASE}/intermediate"

echo "[ocsp] aguardando a CA ser inicializada..."
until [ -f "${INT}/certs/ocsp.crt" ] \
   && [ -f "${INT}/certs/ca-chain.crt" ] \
   && [ -f "${INT}/index.txt" ]; do
    sleep 5
done
echo "[ocsp] CA pronta; iniciando responder na porta 2560"

# O 'openssl ocsp' carrega o index.txt apenas no start. Para que revogacoes
# apareçam no OCSP sem intervencao, recarregamos o responder periodicamente.
# (A CRL ja reflete revogacoes imediatamente; isto cobre o caminho OCSP.)
RELOAD_INTERVAL="${OCSP_RELOAD_INTERVAL:-60}"   # segundos: recarrega o index (emissoes/revogacoes)

while true; do
    openssl ocsp \
        -index "${INT}/index.txt" \
        -port 2560 \
        -rsigner "${INT}/certs/ocsp.crt" \
        -rkey "${INT}/private/ocsp.key" \
        -CA "${INT}/certs/ca-chain.crt" \
        -text &
    OCSP_PID=$!
    sleep "$RELOAD_INTERVAL"
    kill "$OCSP_PID" 2>/dev/null
    wait "$OCSP_PID" 2>/dev/null
    echo "[ocsp] recarregando index.txt"
done
