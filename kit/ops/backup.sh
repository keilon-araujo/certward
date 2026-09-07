#!/usr/bin/env bash
# Backup CIFRADO (AES-256) do volume da CA — versao do kit (sem Makefile).
#   BACKUP_PASS='<senha forte>' ./backup.sh [destino.tgz.enc]
# Le VOLUME/IMAGE do ambiente; padrao: volume certward_ca-data (compose em
# ~/certward) e a imagem certward:<versao do kit>.
set -euo pipefail
: "${BACKUP_PASS:?Informe BACKUP_PASS='<senha forte>'}"
VOLUME="${VOLUME:-certward_ca-data}"
IMAGE="${IMAGE:-certward:__VERSAO__}"
ALVO="${1:-./ca-backup-$(date -u +%Y%m%d-%H%M%S).tgz.enc}"
docker volume inspect "$VOLUME" >/dev/null 2>&1 || { echo "volume $VOLUME nao existe (docker volume ls)"; exit 1; }
docker run --rm -e BACKUP_PASS --entrypoint sh -v "$VOLUME:/ca:ro" "$IMAGE" \
  -c 'tar czf - -C /ca . | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASS' > "$ALVO"
# Verificar faz parte do backup: decifra e le o tar logo depois de gravar.
docker run --rm -e BACKUP_PASS --entrypoint sh -v "$(cd "$(dirname "$ALVO")" && pwd):/b:ro" "$IMAGE" \
  -c "openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in /b/$(basename "$ALVO") | tar tz > /dev/null" \
  || { echo "ERRO: o backup nao decifra/nao abre — descartado"; rm -f "$ALVO"; exit 1; }
echo "ok: $ALVO ($(du -h "$ALVO" | cut -f1)), verificado. Copie para FORA desta VM."
