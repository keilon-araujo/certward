#!/usr/bin/env bash
# ============================================================================
# stepca-set-policy.sh <dominio> — aplica uma politica de nomes X.509 no step-ca
# (dev), limitando a CA a emitir apenas dentro do dominio interno + wildcard.
# Equivale, na pratica, ao nameConstraints da nossa CA atual.
#
#   ./scripts/stepca-set-policy.sh capsule.lab.br
#
# Requer python3 no host. Opera sobre o stack opt-in docker-compose.stepca.yml.
# ============================================================================
set -euo pipefail
DOMAIN="${1:-capsule.lab.br}"
COMPOSE="docker compose -f docker/docker-compose.stepca.yml"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "==> Baixando ca.json do container"
$COMPOSE cp step-ca:/home/step/config/ca.json "$TMP/ca.json"

echo "==> Aplicando policy: allow DNS ${DOMAIN} + *.${DOMAIN} (com wildcard)"
DOMAIN="$DOMAIN" python3 - "$TMP/ca.json" <<'PY'
import json, os, sys
p = sys.argv[1]; dom = os.environ["DOMAIN"]
d = json.load(open(p))
d.setdefault("authority", {})["policy"] = {
    "x509": {
        "allow": {"dns": [dom, "*." + dom]},
        "allowWildcardNames": True,   # step-ca barra wildcard por padrao mesmo dentro do dominio
    }
}
json.dump(d, open(p, "w"), indent=3)
print("   policy:", json.dumps(d["authority"]["policy"]["x509"]))
PY

echo "==> Enviando de volta e reiniciando o step-ca"
$COMPOSE cp "$TMP/ca.json" step-ca:/home/step/config/ca.json
$COMPOSE restart step-ca >/dev/null
echo "OK: policy aplicada. Fora do dominio passa a ser rejeitado pela CA."
