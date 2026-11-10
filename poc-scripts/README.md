# poc-scripts

Scripts de prueba de concepto, **solo contra la instancia local** (localhost:4000 vulnerable / 4001 mitigada).

| Script | Vuln | Propósito |
|--------|------|-----------|
| `v1_idor.sh` | V1 | Leer datos de otro usuario cambiando el id en `/allocations/:userId` (IDOR) |
| `v2_nosqli.py` | V2 | Inyección NoSQL (`$where`) en el parámetro `threshold` de `/allocations/:userId` |
| `v3_check_hash.js` | V3 | Inspeccionar cómo se almacena el password en Mongo (texto plano vs bcrypt) |
| `v4_headers.sh` | V4 | Revisar cabeceras de seguridad HTTP |
| `regression_smoke.sh` | — | Verificar que la funcionalidad legítima sigue operando |

Todos los scripts imprimen un resultado reproducible (comando → salida) y fijan código de salida:
- `v1_idor.sh`, `v2_nosqli.py`, `v3_check_hash.js`, `v4_headers.sh`: **1 = vulnerable, 0 = mitigado, 2 = error**.
- `regression_smoke.sh` (test de regresión, no PoC): **0 = funcionalidad legítima OK, 1 = algo se rompió, 2 = error**.

Las credenciales demo se pasan por variables de entorno (`POC_PASS`, y `POC_USER` donde aplique), **nunca** en los archivos. `v2_nosqli.py` usa `POC_USER=admin` por defecto; `v1_idor.sh` usa `user1`.
