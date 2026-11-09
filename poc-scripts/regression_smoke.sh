#!/usr/bin/env bash
# =============================================================================
# regression_smoke.sh - Prueba de humo de regresion (V4)
#
# Objetivo: comprobar que, tras la mitigacion (helmet + cookie de sesion),
# la app SIGUE funcionando: se puede hacer login y entrar a una ruta interna.
#
# Pasos:
#   1. GET  /login      -> la app responde (200)
#   2. GET  /dashboard sin sesion -> NO debe dar 200 (control negativo)
#   3. POST /login      -> 302 hacia /dashboard (login correcto)
#   4. Verifica que el navegador/curl RECIBIO la cookie de sesion (sessionId).
#      Si falta, casi seguro COOKIE_SECURE=true con servidor HTTP.
#   5. GET  /dashboard con la cookie -> 200 (ruta interna accesible)
#
# Variables de entorno:
#   POC_USER   (obligatoria) usuario de NodeGoat, ej: user1
#   POC_PASS   (obligatoria) contrasena
#   BASE_URL   (opcional)    por defecto http://localhost:4001 (version mitigada)
#   BASE       (opcional)    alias de BASE_URL (igual que v1_idor.sh y v2_nosqli.py)
#   PROTECTED_PATH (opcional) ruta interna a visitar, por defecto /dashboard
#
# Uso:
#   POC_USER=user1 POC_PASS='tu_clave' ./regression_smoke.sh
#
# Codigos de salida: 0 = todo OK, 1 = fallo de la prueba, 2 = error de uso/entorno
# =============================================================================

set -uo pipefail

# --- Configuracion -----------------------------------------------------------
BASE_URL="${BASE_URL:-${BASE:-http://localhost:4001}}"
BASE_URL="${BASE_URL%/}"                      # quita "/" final si lo hay
PROTECTED_PATH="${PROTECTED_PATH:-/dashboard}"

# Las credenciales son obligatorias: si faltan, salimos con codigo 2 (error de uso).
# ${VAR:-} evita el error de "variable sin definir" que provoca set -u.
if [ -z "${POC_USER:-}" ] || [ -z "${POC_PASS:-}" ]; then
  echo "ERROR: define POC_USER y POC_PASS. Ejemplo:" >&2
  echo "  POC_USER=user1 POC_PASS='tu_clave' ./regression_smoke.sh" >&2
  exit 2
fi

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl no esta instalado." >&2; exit 2; }

# --- Carpeta temporal LOCAL y relativa ---------------------------------------
# En Git Bash (Windows) el curl nativo no entiende rutas MSYS como /tmp/...,
# asi que NO usamos mktemp. Nos movemos a la carpeta del script y trabajamos con
# una ruta RELATIVA (./.tmp), que curl.exe resuelve bien desde el directorio actual.
cd "$(dirname "${BASH_SOURCE[0]}")" || { echo "ERROR: no se pudo entrar a la carpeta del script" >&2; exit 2; }

TMP_DIR="./.tmp"
mkdir -p "$TMP_DIR" || { echo "ERROR: no se pudo crear $TMP_DIR" >&2; exit 2; }
# trap: pase lo que pase (exito, error, Ctrl+C) se borra el cookie jar y las cabeceras
# (contienen la sesion). Se borran los archivos y la carpeta solo si queda vacia.
trap 'rm -f "$TMP_DIR/cookies.txt" "$TMP_DIR/login.hdr"; rmdir "$TMP_DIR" 2>/dev/null' EXIT

COOKIE_JAR="$TMP_DIR/cookies.txt"

# --- Utilidades --------------------------------------------------------------
FAILS=0
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS=$((FAILS + 1)); }

# http_code: ejecuta curl y devuelve SOLO el codigo HTTP (000 si no conecta).
# Opciones comunes: -s silencioso, -o /dev/null descarta cuerpo,
# -w imprime el codigo, timeouts para no colgarse. NO sigue redirecciones.
http_code() {
  curl -s -o /dev/null -w '%{http_code}' \
       --connect-timeout 5 --max-time 15 "$@"
}

echo "Objetivo: $BASE_URL  (usuario: $POC_USER)"
echo "-----------------------------------------------"

# --- 1. La app responde ------------------------------------------------------
CODE="$(http_code "$BASE_URL/login")"
if [ "$CODE" = "200" ]; then
  pass "GET /login responde 200"
else
  fail "GET /login devolvio $CODE (000 = app apagada o URL incorrecta)"
  echo "-----------------------------------------------"
  echo "SMOKE TEST: FALLO (la app no responde)"
  exit 1
fi

# --- 2. Control negativo: ruta interna SIN sesion ---------------------------
# Si /dashboard diera 200 sin login, la prueba del paso 5 no demostraria nada.
CODE="$(http_code "$BASE_URL$PROTECTED_PATH")"
if [ "$CODE" = "200" ]; then
  fail "GET $PROTECTED_PATH sin sesion devolvio 200 (la prueba no seria concluyente)"
else
  pass "GET $PROTECTED_PATH sin sesion NO da 200 (devolvio $CODE)"
fi

# --- 3. Login ----------------------------------------------------------------
# -c guarda las cookies recibidas en el jar. Los campos del formulario de
# NodeGoat se llaman userName y password.
# -D "$TMP_DIR/login.hdr" guarda las cabeceras de la respuesta para leer Location.
CODE="$(http_code -c "$COOKIE_JAR" -D "$TMP_DIR/login.hdr" \
        -X POST \
        --data-urlencode "userName=$POC_USER" \
        --data-urlencode "password=$POC_PASS" \
        "$BASE_URL/login")"

LOCATION="$(tr -d '\r' < "$TMP_DIR/login.hdr" 2>/dev/null \
            | awk 'tolower($1)=="location:" {print $2}' | tail -n 1)"

if [ "$CODE" = "302" ] && [ "$LOCATION" = "$PROTECTED_PATH" ]; then
  pass "POST /login -> 302 hacia $LOCATION"
elif [ "$CODE" = "302" ]; then
  fail "POST /login -> 302 pero hacia '$LOCATION' (se esperaba $PROTECTED_PATH)"
else
  # En NodeGoat un login fallido vuelve a mostrar el formulario con 200.
  fail "POST /login devolvio $CODE (credenciales incorrectas o login roto)"
fi

# --- 4. Cookie de sesion recibida -------------------------------------------
# El jar de curl guarda las cookies HttpOnly con prefijo "#HttpOnly_", por eso
# se busca "sessionId" en cualquier parte de la linea.
if grep -q 'sessionId' "$COOKIE_JAR" 2>/dev/null; then
  pass "Se recibio la cookie de sesion (sessionId)"
else
  fail "No se recibio la cookie sessionId (revisa COOKIE_SECURE: con 'true' y HTTP la cookie no se envia)"
fi

# --- 5. Ruta interna CON sesion ---------------------------------------------
# -b envia las cookies guardadas en el jar.
CODE="$(http_code -b "$COOKIE_JAR" "$BASE_URL$PROTECTED_PATH")"
if [ "$CODE" = "200" ]; then
  pass "GET $PROTECTED_PATH con sesion responde 200"
else
  fail "GET $PROTECTED_PATH con sesion devolvio $CODE (la sesion no persiste)"
fi

# --- Veredicto ---------------------------------------------------------------
echo "-----------------------------------------------"
if [ "$FAILS" -eq 0 ]; then
  echo "SMOKE TEST: OK (la app opera normal tras la mitigacion)"
  exit 0
fi
echo "SMOKE TEST: FALLO ($FAILS verificacion(es) fallida(s))"
exit 1
