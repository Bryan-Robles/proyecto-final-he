# Evidencia V1 — DESPUÉS (mitigado)

- `poc_v1_idor.txt`: salida del PoC `poc-scripts/v1_idor.sh` contra `mitigated/` (`:4001`), con los casos añadidos tras la revisión del PR.
- `http_403_allocations_3.txt`: `curl -i` de `/allocations/3` y `/allocations/9999` con la sesión de `user1` (respuesta 403) y las líneas `[SEC]` del log del servidor. La cookie se omite.
- `ui_regresion_allocations_2.png`: `http://localhost:4001/allocations/2` con la sesión de `user1`: sigue mostrando "Asset Allocations for John Doe" (regresión).

Condición: entorno local, `mitigated/` reconstruido con el fix (403 + log); sesión legítima de `user1`.
Commit: ver `git log -- mitigated/app/routes/allocations.js`. Fecha de la ejecución: 2026-11-08T04:26Z.

Resultado:
- `/allocations/2` (propio) → 200, John Doe (regresión correcta).
- `/allocations/3` (ajeno) → **403 Forbidden**; el servidor registra `[SEC] Posible IDOR: user 2 pidio "3"`.
- `/allocations/9999` (inexistente) → 403 (no se distingue de "ajeno": evita enumeración).
- `/allocations/3` sin cookie → 302 a `/login` (no cambió; lo resuelve `isLoggedIn`).
- Exit code 0 → MITIGADO.

La versión anterior del fix respondía 200 con los datos de la sesión; se cambió a 403 + log por la revisión del PR.
Sin la captura de UI del 403: la evidencia es la respuesta HTTP en `http_403_allocations_3.txt`.

Reproducir (la clave demo se pasa por `POC_PASS`, no se publica):

```bash
docker compose -f mitigated/docker-compose.yml up -d --build
BASE=http://localhost:4001 POC_PASS=<clave_demo_user1> ./poc-scripts/v1_idor.sh
```
