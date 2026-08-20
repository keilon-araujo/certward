#!/usr/bin/env bash
# Regenera a CRL da intermediaria periodicamente (substitui o systemd timer).
#
# A cadencia SEGUE a validade configurada, em vez de ser 24h fixas: com
# crl_days=30 (padrao) isso da uma regeneracao a cada 10 dias, e sao precisas
# TRES falhas seguidas para a CRL vencer. Com 24h fixas e crl_days=1 nao havia
# margem nenhuma — a primeira falha ja deixava a CRL vencer, e CRL vencida nao
# degrada: todo cliente que consulta revogacao passa a recusar TODOS os
# certificados desta CA de uma vez, validos inclusive.
#
# A falha em si e observavel pelo /api/health da webui, que publica a validade
# restante da CRL: se a regeneracao parar, o numero cai e a plataforma alerta.
set -u
CA_BASE="${CA_BASE:-/ca}"
INT="${CA_BASE}/intermediate"
CONFIG="${CA_BASE}/config.json"

echo "[crl] aguardando a CA ser inicializada..."
until [ -f "${INT}/certs/intermediate.crt" ]; do
    sleep 5
done

_intervalo() {
    # 1/3 da validade da CRL, entre 1h e 24h.
    local dias=30 seg
    if [ -f "$CONFIG" ]; then
        dias="$(python3 - "$CONFIG" <<'PY' 2>/dev/null || echo 30
import json, sys
try:
    print(int(json.load(open(sys.argv[1])).get("crl_days") or 30))
except Exception:
    print(30)
PY
)"
    fi
    [ -z "$dias" ] && dias=30
    seg=$(( dias * 86400 / 3 ))
    [ "$seg" -lt 3600 ] && seg=3600
    [ "$seg" -gt 86400 ] && seg=86400
    echo "$seg"
}

falhas=0
while true; do
    if /opt/ca-app/gen-crl.sh; then
        falhas=0
        echo "[crl] CRL regenerada"
    else
        falhas=$(( falhas + 1 ))
        # Sobe no log do container e, principalmente, deixa de mover o
        # next_update que o /api/health publica.
        echo "[crl] ERRO ao gerar a CRL (falhas seguidas: ${falhas})" >&2
    fi
    sleep "$(_intervalo)"
done
