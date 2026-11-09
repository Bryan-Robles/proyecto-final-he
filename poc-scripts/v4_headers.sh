#!/usr/bin/env bash
# =============================================================================
# v4_headers.sh - PoC V4 (Security Misconfiguration / cabeceras HTTP)
#
# Que hace:
#   Pide una URL con curl, lee SOLO las cabeceras de respuesta y decide:
#     - VULNERABLE (exit 1): falta alguna cabecera de seguridad de Helmet 2.3.0
#                            o aparece X-Powered-By (expone Express).
#     - MITIGADO   (exit 0): estan las 5 cabeceras y NO hay X-Powered-By.
#     - ERROR      (exit 2): no se pudo consultar la app (caida, URL mala, etc.).
#       (Se usa un codigo distinto para que "app apagada" nunca se confunda
#        con "VULNERABLE".)
#
# Uso:
#   ./v4_headers.sh                          # por defecto http://localhost:4000/
#   ./v4_headers.sh http://localhost:4001/   # version mitigada
#   TARGET_URL=http://localhost:4001/ ./v4_headers.sh
# =============================================================================

# -u : error si se usa una variable sin definir
# -o pipefail : un pipeline falla si falla cualquiera de sus comandos
# (no usamos -e a proposito: manejamos los codigos de salida a mano)
set -uo pipefail

# --- Configuracion -----------------------------------------------------------
# Prioridad: argumento 1 > variable TARGET_URL > valor por defecto.
URL="${1:-${TARGET_URL:-http://localhost:4000/}}"

# Cabeceras que Helmet 2.3.0 inyecta (en minusculas: HTTP no distingue
# mayusculas/minusculas en nombres de cabecera). NO se exige CSP ni HSTS
# porque esa version de Helmet no las emite.
REQUIRED_HEADERS=(
  "x-frame-options"
  "x-content-type-options"
  "x-download-options"
  "x-dns-prefetch-control"
  "x-xss-protection"
)
# Cabecera que NO debe aparecer (revela la tecnologia del servidor).
FORBIDDEN_HEADER="x-powered-by"

# --- Verificaciones previas --------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl no esta instalado." >&2
  exit 2
fi

# --- Obtener cabeceras -------------------------------------------------------
# -s  : sin barra de progreso        -S : pero muestra errores
# -D -: vuelca las cabeceras a stdout   -o /dev/null : descarta el cuerpo
# --max-time / --connect-timeout : evita que el script se cuelgue
# No usamos -L: Helmet agrega las cabeceras en TODAS las respuestas (tambien
# en un 302), asi que no hace falta seguir redirecciones.
if ! RAW_HEADERS="$(curl -sS -D - -o /dev/null \
      --connect-timeout 5 --max-time 10 "$URL" 2>&1)"; then
  echo "ERROR: no se pudo consultar $URL" >&2
  echo "$RAW_HEADERS" >&2
  exit 2
fi

# Normalizamos: quitamos el \r final de cada linea (HTTP usa CRLF) y pasamos
# todo a minusculas para comparar sin problemas.
HEADERS="$(printf '%s\n' "$RAW_HEADERS" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"

# Linea de estado (ej: "http/1.1 200 ok") solo para mostrar.
STATUS_LINE="$(printf '%s\n' "$HEADERS" | head -n 1)"

# has_header NOMBRE -> exit 0 si la cabecera existe al inicio de alguna linea.
has_header() {
  printf '%s\n' "$HEADERS" | grep -q "^$1:"
}

# --- Analisis ----------------------------------------------------------------
echo "URL analizada : $URL"
echo "Respuesta     : $STATUS_LINE"
echo "-----------------------------------------------"

PROBLEMS=0

for h in "${REQUIRED_HEADERS[@]}"; do
  if has_header "$h"; then
    echo "[OK]    presente : $h"
  else
    echo "[FALTA] ausente  : $h"
    PROBLEMS=$((PROBLEMS + 1))
  fi
done

if has_header "$FORBIDDEN_HEADER"; then
  echo "[FALLA] expuesta : $FORBIDDEN_HEADER (revela el stack tecnologico)"
  PROBLEMS=$((PROBLEMS + 1))
else
  echo "[OK]    oculta   : $FORBIDDEN_HEADER"
fi

echo "-----------------------------------------------"

# --- Veredicto ---------------------------------------------------------------
if [ "$PROBLEMS" -gt 0 ]; then
  echo "VULNERABLE ($PROBLEMS problema(s) de configuracion de cabeceras)"
  exit 1
fi

echo "MITIGADO"
exit 0
