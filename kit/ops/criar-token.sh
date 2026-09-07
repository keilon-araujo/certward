#!/usr/bin/env bash
# Cria um token de servico na CA para o CertaSync (o console ainda nao tem
# tela para isso; a API exige sessao de administrador).
#   ./criar-token.sh <nome> [escopos] [dias]     ex.: ./criar-token.sh certasync certs:issue,certs:read,certs:revoke 365
# Pede usuario/senha do console; o SEGREDO aparece uma unica vez.
set -euo pipefail
NOME="${1:?nome do token (ex.: certasync)}"
ESCOPOS="${2:-certs:issue,certs:read,certs:revoke}"
DIAS="${3:-365}"
URL="${CA_URL:-https://localhost}"
read -rp "usuario do console [admin]: " U; U="${U:-admin}"
read -rsp "senha do console: " P; echo
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
curl -sk -c "$JAR" -H "Content-Type: application/json" -d "{\"username\":\"$U\",\"password\":\"$P\"}" "$URL/api/login" | grep -q '"ok":true' \
  || { echo "login recusado"; exit 1; }
ESC_JSON="[$(printf '%s' "$ESCOPOS" | sed 's/,/","/g; s/^/"/; s/$/"/')]"
curl -sk -b "$JAR" -H "Content-Type: application/json" \
  -d "{\"name\":\"$NOME\",\"scopes\":$ESC_JSON,\"expires_in_days\":$DIAS}" "$URL/api/service-tokens"
echo; echo "Guarde o campo \"token\" agora — nao sera exibido de novo."
