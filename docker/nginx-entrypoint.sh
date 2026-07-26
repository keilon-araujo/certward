#!/bin/bash
# Sobe o nginx com um cert temporario e, assim que a CA emitir o cert real
# (/ca/tls/admin.*), troca e recarrega. Assim o 443 funciona antes mesmo da CA
# ser inicializada, sem falhar o start.
set -e

watch_ca_cert() {
    while true; do
        if [ -f /ca/tls/admin.crt ] && [ -f /ca/tls/admin.key ]; then
            if ! cmp -s /ca/tls/admin.crt /etc/nginx/tls/admin.crt; then
                cp /ca/tls/admin.crt /etc/nginx/tls/admin.crt
                cp /ca/tls/admin.key /etc/nginx/tls/admin.key
                nginx -s reload 2>/dev/null || true
                echo "[nginx] cert da CA aplicado para o host admin"
            fi
        fi
        sleep 10
    done
}

watch_ca_cert &
exec nginx -g 'daemon off;'
