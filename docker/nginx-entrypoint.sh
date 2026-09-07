#!/bin/sh
# Entrypoint do nginx da CA: serve o certificado TLS emitido pela propria CA
# (/ca/tls/admin.crt, gravado pelo setup) no host admin., e troca a quente
# quando ele muda (renovacao).
#
# Historico: ate a 1.3.0 o vigia rodava em paralelo com a partida do nginx.
# Copiava o certificado enquanto o nginx ja lia o provisorio, chamava
# `nginx -s reload` antes de existir um mestre para recarregar, o `|| true`
# engolia a falha, e o `cmp` seguinte via os arquivos iguais — o provisorio
# "ca-admin-setup-pending" ficava servido para sempre. Achado no ensaio de
# instalacao do zero (07/09/2026): o CertaSync com verificacao TLS ligada
# recusava a CA com "cadeia nao confiavel". Agora: (1) aplica ANTES de subir;
# (2) o vigia so marca como aplicado depois de um reload que deu certo.
set -e

APLICADO=/etc/nginx/tls/.aplicado   # copia do que o nginx REALMENTE carregou

aplicar() {
    cp /ca/tls/admin.crt /etc/nginx/tls/admin.crt
    cp /ca/tls/admin.key /etc/nginx/tls/admin.key
}

# 1) Na partida, sincrono: se a CA ja emitiu o cert do admin, o nginx nasce com ele.
if [ -f /ca/tls/admin.crt ] && [ -f /ca/tls/admin.key ]; then
    aplicar && cp /ca/tls/admin.crt "$APLICADO"
    echo "[nginx] cert da CA carregado na partida"
fi

# 2) Vigia: renovacao/troca do cert do admin. Reload que falha e tentado de novo
#    no proximo ciclo, porque .aplicado so muda depois do sucesso.
watch_ca_cert() {
    while true; do
        sleep 10
        if [ -f /ca/tls/admin.crt ] && [ -f /ca/tls/admin.key ] \
           && ! cmp -s /ca/tls/admin.crt "$APLICADO"; then
            aplicar
            if nginx -t >/dev/null 2>&1 && nginx -s reload; then
                cp /ca/tls/admin.crt "$APLICADO"
                echo "[nginx] cert da CA aplicado para o host admin"
            else
                echo "[nginx] cert novo copiado mas o reload falhou — tento de novo em 10s"
            fi
        fi
    done
}
watch_ca_cert &
exec nginx -g 'daemon off;'
