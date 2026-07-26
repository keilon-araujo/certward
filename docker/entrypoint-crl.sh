#!/usr/bin/env bash
# Regenera a CRL da intermediaria periodicamente (substitui o systemd timer).
set -u
CA_BASE="${CA_BASE:-/ca}"
INT="${CA_BASE}/intermediate"

echo "[crl] aguardando a CA ser inicializada..."
until [ -f "${INT}/certs/intermediate.crt" ]; do
    sleep 5
done

while true; do
    echo "[crl] regenerando CRL $(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)"
    /opt/ca-app/gen-crl.sh || echo "[crl] falha ao gerar CRL"
    sleep 86400   # diario
done
