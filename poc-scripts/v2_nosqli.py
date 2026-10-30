#!/usr/bin/env python3
"""V2 - NoSQL Injection. Dueno: Bryan.
Uso: contra la instancia LOCAL unicamente (http://localhost:4000).
"""
import os

BASE = os.environ.get("BASE", "http://localhost:4000")

# TODO (Dia 3): enviar al endpoint de login un cuerpo JSON cuyos campos sean
# objetos con operadores de consulta Mongo en lugar de cadenas, y comprobar si
# el servidor acepta la sesion (vulnerable) o rechaza las credenciales (mitigado).

if __name__ == "__main__":
    print(f"[V2] objetivo: {BASE} - completar PoC en Dia 3")
