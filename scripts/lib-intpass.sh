#!/usr/bin/env bash
# Resolve CA_INT_PASS (passphrase da intermediaria) para o -passin do openssl.
# Precedencia (espelha pki.read_secret + fallback local):
#   CA_INT_PASS (env, injetado pela UI)  >  CA_INT_PASS_FILE  >
#   /run/secrets/ca_int_pass  >  ${CA_BASE}/int_pass
# Deixa CA_INT_PASS exportado (pode ficar vazio p/ CA legada com chave em claro).
resolve_int_pass() {
    if [ -n "${CA_INT_PASS:-}" ]; then export CA_INT_PASS; return 0; fi
    if [ -n "${CA_INT_PASS_FILE:-}" ] && [ -f "${CA_INT_PASS_FILE}" ]; then
        CA_INT_PASS="$(cat "${CA_INT_PASS_FILE}")"
    elif [ -f /run/secrets/ca_int_pass ]; then
        CA_INT_PASS="$(cat /run/secrets/ca_int_pass)"
    elif [ -f "${CA_BASE:-/ca}/int_pass" ]; then
        CA_INT_PASS="$(cat "${CA_BASE:-/ca}/int_pass")"
    fi
    export CA_INT_PASS="${CA_INT_PASS:-}"
}

# Monta o array INTPASS=(-passin env:CA_INT_PASS) quando ha passphrase.
# Em chave legada em claro, o openssl ignora o -passin — mas so incluimos se houver.
int_passin_args() {
    resolve_int_pass
    if [ -n "${CA_INT_PASS:-}" ]; then INTPASS=(-passin env:CA_INT_PASS); else INTPASS=(); fi
}
