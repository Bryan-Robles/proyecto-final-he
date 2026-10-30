#!/usr/bin/env bash
# V4 — Security Misconfiguration (cabeceras). Dueño: Kevin.
# Uso: contra la instancia LOCAL únicamente.
set -euo pipefail

BASE="${BASE:-http://localhost:4000}"

echo "[V4] cabeceras de $BASE:"
curl -sI "$BASE/" | grep -iE "x-powered-by|x-frame-options|content-security-policy|strict-transport-security" || true

# ANTES: aparece x-powered-by y faltan cabeceras de seguridad.
# DESPUES: helmet las anade / oculta x-powered-by.
