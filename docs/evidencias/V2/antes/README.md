# Evidencia V2 — ANTES (vulnerable)

- `poc_v2_nosqli.txt`: salida del PoC `poc-scripts/v2_nosqli.py` contra `vulnerable/` (`:4000`).

Resultado: la inyección en el parámetro `threshold` (`0' || '1'=='1`) convierte el
filtro `$where` en una condición siempre verdadera y expone las asignaciones de
todos los usuarios (3 filas vs. 1 de la línea base). `EXIT=1` → VULNERABLE.

Reproducir:

```bash
docker compose -f vulnerable/docker-compose.yml up -d --build
BASE=http://localhost:4000 python poc-scripts/v2_nosqli.py
```
