# Evidencia V1 — DESPUÉS (mitigado)

- `poc_v1_idor.txt`: salida del PoC `poc-scripts/v1_idor.sh` contra `mitigated/` (`:4001`).
- `ui_idor_allocations_3.png`: `http://localhost:4001/allocations/3` con la sesión de `user1`: muestra "Asset Allocations for John Doe" (ya no Will Smith).
- `ui_regresion_allocations_2.png`: `http://localhost:4001/allocations/2` con la sesión de `user1`: sigue mostrando "Asset Allocations for John Doe" (regresión).

Condición: entorno local, `mitigated/` reconstruido con el fix; sesión legítima de `user1`.
Commit del fix: `8379cba` (tag `v1-mitigado`); validación en `6586ffb`. Fecha de la ejecución: 2026-11-07T03:24Z (22:24 hora local, 2026-11-06).

Resultado: `/allocations/2` y `/allocations/3` devuelven ambos los datos de John Doe. El servidor
ignora el id de la URL y usa `req.session.userId`, así que no hay acceso a datos ajenos. Exit code 0 → MITIGADO.

Nota de diseño: la mitigación **no devuelve 403**; responde 200 con los datos del usuario de la sesión.
Por eso el PoC considera mitigado el caso en que el nombre devuelto coincide con el propio.

Reproducir (la clave demo se pasa por `POC_PASS`, no se publica):

```bash
docker compose -f mitigated/docker-compose.yml up -d --build
BASE=http://localhost:4001 POC_PASS=<clave_demo_user1> ./poc-scripts/v1_idor.sh
```
