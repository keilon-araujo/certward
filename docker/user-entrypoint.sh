#!/usr/bin/env bash
# Entrypoint dos containers que rodam nosso codigo (webui/ocsp/crl).
# Roda como root SO para garantir o dono do volume /ca, depois dropa para 'app'
# e executa o comando real (uvicorn / entrypoint-ocsp.sh / entrypoint-crl.sh).
set -e
if [ "$(id -u)" = "0" ]; then
    mkdir -p /ca
    # ajusta o dono do volume (idempotente); pega arquivos criados antes como root
    chown -R app:app /ca 2>/dev/null || true
    exec gosu app "$@"
fi
exec "$@"
