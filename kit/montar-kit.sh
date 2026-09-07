#!/usr/bin/env bash
# Monta o kit de entrega da CA interna (CertaSync · CA interna) — imagens
# offline, no mesmo molde do scripts/kit/montar-kit.sh do CertaSync. O
# cliente recebe artefatos executaveis, nao o fonte; a documentacao vai em
# pacote separado (nao entra aqui).
#
# Uso:
#   kit/montar-kit.sh                        # linux/amd64
#   PLATAFORMA=linux/arm64 kit/montar-kit.sh
#   SEM_BUILD=1 kit/montar-kit.sh            # reusa imagens ja taggeadas :$V
#
# Saida: dist/certward-<versao>/
#   certward-<versao>-images.tar.gz   certward:<V> + certward-nginx:<V> (docker load -i)
#   docker-compose.yml                image: fixo na tag, sem bloco build:; portas 80/443
#   .env.example                      copiar para .env e definir ADMIN_PASS
#   SHA256SUMS                        digest de tudo (informe ao cliente)
#
# Portas: 80 (ca./ocsp. — CRL, AIA e OCSP; NAO pode mudar, as URLs vao gravadas
# em cada certificado sem porta) e 443 (admin.). A VM da CA e dedicada; o
# 8081/8444 do laboratorio era um override local porque o CertaSync dividia
# o mesmo host.
set -euo pipefail

RAIZ=$(cd "$(dirname "$0")/.." && pwd)
V=$(tr -d '[:space:]' < "$RAIZ/VERSION")
PLATAFORMA=${PLATAFORMA:-linux/amd64}
SAIDA=${SAIDA:-$RAIZ/dist/certward-$V}
SEM_BUILD=${SEM_BUILD:-}

printf '%s' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "VERSION ($V) nao e SemVer" >&2; exit 1; }

echo "== CA interna $V · $PLATAFORMA → $SAIDA"
rm -rf "$SAIDA"; mkdir -p "$SAIDA"

# 1. Imagens ---------------------------------------------------------------
if [ -z "$SEM_BUILD" ]; then
  echo "-- build certward:$V"
  docker buildx build --platform "$PLATAFORMA" --load -f "$RAIZ/docker/Dockerfile" -t "certward:$V" "$RAIZ"
  echo "-- build certward-nginx:$V"
  docker buildx build --platform "$PLATAFORMA" --load -f "$RAIZ/docker/Dockerfile.nginx" -t "certward-nginx:$V" "$RAIZ"
fi
for img in certward certward-nginx; do
  arq=$(docker image inspect "$img:$V" --format '{{.Os}}/{{.Architecture}}')
  [ "$arq" = "$PLATAFORMA" ] || { echo "$img:$V e $arq, esperado $PLATAFORMA" >&2; exit 1; }
done
echo "-- docker save"
docker save "certward:$V" "certward-nginx:$V" | gzip > "$SAIDA/certward-$V-images.tar.gz"

# 2. Compose do cliente: sem build:, tag fixa ------------------------------
# Cada bloco build: tem 3 linhas (build:/context:/dockerfile:).
awk -v v="$V" '
  /^[[:space:]]+build:[[:space:]]*$/ { pular=2; next }
  pular>0 { pular--; next }
  { gsub(/:latest/, ":" v); print }
' "$RAIZ/docker/docker-compose.yml" \
  | sed 's|^# Suba com:.*|# Suba com:  cp .env.example .env  (defina ADMIN_PASS)  e  docker compose up -d|' \
  > "$SAIDA/docker-compose.yml"
grep -q "build:" "$SAIDA/docker-compose.yml" && { echo "compose ainda tem build:" >&2; exit 1; }
grep -q "certward:$V" "$SAIDA/docker-compose.yml" || { echo "compose sem a tag $V" >&2; exit 1; }
cp "$RAIZ/docker/.env.example" "$SAIDA/.env.example"

# 3. Digests -----------------------------------------------------------------
( cd "$SAIDA" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 | sed 's| \./| |' > SHA256SUMS )
echo "== kit pronto:"; du -sh "$SAIDA"; ls -la "$SAIDA"
echo "-- digest das imagens:"; grep images.tar.gz "$SAIDA/SHA256SUMS"
