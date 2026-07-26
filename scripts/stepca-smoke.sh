#!/usr/bin/env bash
# ============================================================================
# stepca-smoke.sh [dominio] — valida o step-ca (dev): emissao JWK dentro/fora do
# dominio, wildcard, endpoint ACME e revogacao. Use APOS stepca-set-policy.sh.
#
#   ./scripts/stepca-smoke.sh capsule.lab.br
# ============================================================================
set -euo pipefail
DOMAIN="${1:-capsule.lab.br}"
CE="docker compose -f docker/docker-compose.stepca.yml exec -T step-ca"
BASE=(--ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt)
PROV=(--provisioner admin-jwk --password-file /run/secrets/stepca_password)
ok(){ echo "  OK: $*"; }; bad(){ echo "  FALHA: $*"; exit 1; }

echo "==> Root fingerprint da CA"
$CE step certificate fingerprint /home/step/certs/root_ca.crt

echo "==> Emissao JWK dentro do dominio (app1.${DOMAIN})"
$CE step ca certificate "app1.${DOMAIN}" /tmp/a.crt /tmp/a.key "${PROV[@]}" "${BASE[@]}" --force >/dev/null 2>&1 \
  && ok "emitido e assinado pela intermediaria" || bad "nao emitiu dentro do dominio"

echo "==> Wildcard dentro do dominio (*.${DOMAIN})"
$CE step ca certificate "*.${DOMAIN}" /tmp/w.crt /tmp/w.key "${PROV[@]}" "${BASE[@]}" --force >/dev/null 2>&1 \
  && ok "wildcard emitido" || bad "wildcard barrado (allowWildcardNames aplicado?)"

echo "==> Prova negativa: fora do dominio (evil.example.com) deve ser REJEITADO"
if $CE step ca certificate evil.example.com /tmp/e.crt /tmp/e.key "${PROV[@]}" "${BASE[@]}" --force >/dev/null 2>&1; then
  bad "cert fora do dominio foi emitido (policy nao aplicada)"
else
  ok "rejeitado pela policy da CA"
fi

echo "==> ACME directory publicado"
$CE wget -qO- --no-check-certificate https://localhost:9000/acme/acme/directory 2>/dev/null | grep -q newOrder \
  && ok "endpoint ACME ativo (newOrder/newAccount/...)" || bad "ACME directory indisponivel"

echo "==> Revogacao (mTLS: cert + chave)"
$CE step ca revoke --cert /tmp/a.crt --key /tmp/a.key "${BASE[@]}" 2>&1 | grep -q "has been revoked" \
  && ok "certificado revogado" || bad "revogacao falhou"

echo "TODOS OS CHECKS DO STEP-CA (DEV) PASSARAM"
