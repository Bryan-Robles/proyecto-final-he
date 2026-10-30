#!/usr/bin/env bash
# Regresión — la funcionalidad legítima sigue operando tras la mitigación.
# Dueño: Kevin. Uso: contra la instancia LOCAL (vulnerable :4000 y mitigada :4001).
set -euo pipefail

BASE="${BASE:-http://localhost:4001}"

# TODO (Día 5): comprobar flujos legítimos:
#  - la app responde (GET /)
#  - login con credenciales válidas funciona
#  - navegación y operaciones CRUD normales funcionan

echo "[regresion] objetivo: $BASE"
curl -s -o /dev/null -w "GET / -> %{http_code}\n" "$BASE/" || true
