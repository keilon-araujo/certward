#!/usr/bin/env bash
# ============================================================================
# check-expiring.sh - Lista certificados VALIDOS que expiram em breve.
#
#   ./check-expiring.sh [dias]     # padrao: 30 dias
#
# Le o index.txt da intermediaria. Linhas 'V' = validos, 'R' = revogados,
# 'E' = expirados. Util no cron para avisar antes do vencimento.
# ============================================================================
set -euo pipefail

CA_BASE="${CA_BASE:-/ca}"
INDEX="${CA_BASE}/intermediate/index.txt"
DAYS="${1:-30}"

[ -f "$INDEX" ] || { echo "index.txt nao encontrado: $INDEX"; exit 1; }

# 'now + DAYS' em epoch, via openssl (portavel, sem depender do date do SO)
limit=$(( $(date +%s) + DAYS*86400 ))
now=$(date +%s)

printf "%-12s %-22s %s\n" "STATUS" "EXPIRA" "SUBJECT"
printf '%.0s-' {1..80}; echo

found=0
while IFS=$'\t' read -r status expdate revdate serial fname subject; do
    [ "$status" = "V" ] || continue
    # expdate no index: YYMMDDHHMMSSZ
    exp_epoch=$(date -j -f "%y%m%d%H%M%SZ" "$expdate" +%s 2>/dev/null \
             || date -d "20${expdate:0:2}-${expdate:2:2}-${expdate:4:2} ${expdate:6:2}:${expdate:8:2}:${expdate:10:2}" +%s 2>/dev/null \
             || echo 0)
    [ "$exp_epoch" -eq 0 ] && continue
    if [ "$exp_epoch" -le "$limit" ]; then
        dias=$(( (exp_epoch - now) / 86400 ))
        printf "%-12s %-22s %s\n" "EXPIRA(${dias}d)" "$expdate" "$subject"
        found=1
    fi
done < "$INDEX"

[ "$found" -eq 0 ] && echo "Nenhum certificado expira nos proximos ${DAYS} dias."
