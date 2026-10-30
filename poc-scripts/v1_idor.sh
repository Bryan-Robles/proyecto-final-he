#!/usr/bin/env bash
# V1 — Broken Access Control (IDOR). Dueño: JuanFra.
# Uso: contra la instancia LOCAL únicamente.
set -euo pipefail

BASE="${BASE:-http://localhost:4000}"

# TODO (Día 3): autenticarse como usuario legítimo y guardar la cookie de sesión,
# luego solicitar un recurso asociado a OTRO identificador de usuario y comprobar
# si el servidor lo entrega (vulnerable) o lo rechaza con 403/redirect (mitigado).

echo "[V1] objetivo: $BASE — completar PoC en Dia 3"
