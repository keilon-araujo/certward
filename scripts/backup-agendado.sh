#!/usr/bin/env bash
# Backup diario CIFRADO do volume da CA, com retencao por dias e VERIFICACAO.
#
# Pensado para o cron do sistema operacional da VM da CA:
#
#   0 2 * * *  /opt/certward/scripts/backup-agendado.sh >> /var/log/ca-backup.log 2>&1
#
# A senha vem de um arquivo com permissao 600 (BACKUP_PASS_FILE), nunca da
# linha de comando: argumento de processo aparece em `ps` para qualquer
# usuario da maquina.
#
# Verificar faz parte do backup, nao e um extra: arquivo cifrado que nao
# decifra so se revela no dia do desastre, que e o unico dia em que nao
# adianta descobrir. Aqui cada backup e decifrado e o tar e lido logo depois
# de gravado; se falhar, o arquivo e descartado e o script sai com erro para o
# cron reclamar.
set -euo pipefail

DESTINO="${BACKUP_DIR:-/var/backups/certward}"
SENHA_ARQ="${BACKUP_PASS_FILE:-/etc/certward/backup.pass}"
VOLUME="${VOLUME:-docker_ca-data}"
IMAGEM="${IMAGE:-certward:latest}"
MANTER_DIAS="${BACKUP_KEEP_DAYS:-30}"

[ -r "$SENHA_ARQ" ] || { echo "[backup] senha nao legivel em $SENHA_ARQ"; exit 1; }
perm="$(stat -c '%a' "$SENHA_ARQ" 2>/dev/null || stat -f '%A' "$SENHA_ARQ")"
case "$perm" in
    600|400) ;;
    *) echo "[backup] $SENHA_ARQ com permissao $perm — use 600"; exit 1 ;;
esac

mkdir -p "$DESTINO"
carimbo="$(date -u +%Y%m%d-%H%M%S)"
alvo="${DESTINO}/certward-${carimbo}.tgz.enc"

echo "[backup] gerando ${alvo}"
BACKUP_PASS="$(cat "$SENHA_ARQ")" \
docker run --rm -e BACKUP_PASS --entrypoint sh -v "${VOLUME}:/ca:ro" "$IMAGEM" \
    -c 'tar czf - -C /ca . | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASS' \
    > "$alvo"

echo "[backup] verificando"
if ! BACKUP_PASS="$(cat "$SENHA_ARQ")" \
     docker run --rm -e BACKUP_PASS --entrypoint sh -v "${DESTINO}:/b:ro" "$IMAGEM" \
       -c "openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in /b/$(basename "$alvo") | tar tz > /dev/null"; then
    echo "[backup] ERRO: o arquivo gerado nao decifra ou nao abre — descartando"
    rm -f "$alvo"
    exit 1
fi

tam="$(du -h "$alvo" | cut -f1)"
echo "[backup] ok: ${alvo} (${tam}), verificado"

# Retencao: so apaga DEPOIS de um backup bom, nunca antes. Apagar primeiro
# deixaria a janela em que nao existe backup nenhum.
find "$DESTINO" -name 'certward-*.tgz.enc' -type f -mtime "+${MANTER_DIAS}" -print -delete
