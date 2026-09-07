#!/usr/bin/env bash
# Restaura um backup cifrado para o volume da CA — SOBRESCREVE tudo.
#   BACKUP_PASS='<senha do backup>' ./restore.sh ca-backup-....tgz.enc
# Pare a stack antes (docker compose down) e suba depois (up -d).
set -euo pipefail
: "${BACKUP_PASS:?Informe BACKUP_PASS='<senha usada no backup>'}"
ARQ="${1:?informe o arquivo .tgz.enc}"
[ -f "$ARQ" ] || { echo "$ARQ nao encontrado"; exit 1; }
VOLUME="${VOLUME:-certward_ca-data}"
IMAGE="${IMAGE:-certward:__VERSAO__}"
DIR="$(cd "$(dirname "$ARQ")" && pwd)"; NOME="$(basename "$ARQ")"
docker run --rm -e BACKUP_PASS --entrypoint sh -v "$VOLUME:/ca" -v "$DIR:/backup:ro" "$IMAGE" \
  -c "set -e; openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in /backup/$NOME -out /tmp/r.tgz; tar tzf /tmp/r.tgz >/dev/null; find /ca -mindepth 1 -delete; tar xzf /tmp/r.tgz -C /ca; rm -f /tmp/r.tgz"
echo "restaurado em $VOLUME. Suba a stack: docker compose up -d"
