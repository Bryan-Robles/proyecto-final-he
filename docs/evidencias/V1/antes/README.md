# Evidencia V1 — ANTES (vulnerable)

- `poc_v1_idor.txt`: salida del PoC `poc-scripts/v1_idor.sh` contra `vulnerable/` (`:4000`).
- `ui_idor_allocations_3.png`: captura en el navegador de `http://localhost:4000/allocations/3` con la sesión de `user1`: muestra "Asset Allocations for Will Smith".

Condición: entorno local, `vulnerable/` en Docker, seed por defecto; sesión legítima de `user1` (John Doe, `_id` 2).
Commit del PoC: `aedaee5`. Fecha de la ejecución: 2026-11-07T03:24Z (22:24 hora local, 2026-11-06).

Resultado: con la sesión de `user1`, `/allocations/2` (propio) devuelve John Doe y `/allocations/3`
(ajeno) devuelve Will Smith, es decir, datos de otro usuario. Exit code 1 → VULNERABLE.
Los porcentajes cambian en cada arranque del seed; por eso se comparan los nombres, no los números.

Reproducir (la clave demo se pasa por `POC_PASS`, no se publica):

```bash
docker compose -f vulnerable/docker-compose.yml up -d --build
BASE=http://localhost:4000 POC_PASS=<clave_demo_user1> ./poc-scripts/v1_idor.sh
```
