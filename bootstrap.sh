#!/usr/bin/env bash
# ============================================================================
# bootstrap.sh - Sobe a stack Docker da CA de uma vez. A configuracao (dominio,
# nome da autoridade, etc.) e a inicializacao acontecem no ASSISTENTE do
# primeiro login, na propria interface web.
#
#   ./bootstrap.sh
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE="docker compose -f docker/docker-compose.yml"

echo "==> Preparando .env"
[ -f docker/.env ] || cp docker/.env.example docker/.env

echo "==> Subindo a stack (build + start)"
$COMPOSE up -d --build

echo "==> Aguardando a interface web responder..."
for i in $(seq 1 40); do
    if curl -sk -o /dev/null https://localhost/ 2>/dev/null || curl -s -o /dev/null http://localhost/ 2>/dev/null; then
        echo "    UI no ar."; break
    fi
    sleep 2
done

ADMIN_USER=$(grep -E '^ADMIN_USER=' docker/.env | cut -d= -f2-)
cat <<EOF

============================================================
 Stack no ar. Abra a interface e conclua o ASSISTENTE de
 primeiro login (dominio, nome da autoridade, cripto, etc.):

   UI (admin):   https://<host>/     (tela de login: '${ADMIN_USER:-admin}' / ADMIN_PASS do docker/.env no 1o acesso;
                                       depois troque a senha pela propria interface)

 O assistente grava a configuracao e cria a hierarquia. Depois:
   - Distribuicao: http://<host>/  (Host: ca.<seu-dominio>)   -> ca.crt, ca.crl, ca-chain.crt
   - OCSP:         http://<host>/  (Host: ocsp.<seu-dominio>)

 Aponte no DNS do lab: admin. / ca. / ocsp. <seu-dominio> -> IP do host.
 Comandos uteis: make help
============================================================
EOF
