# poc-scripts

Scripts de prueba de concepto, **solo contra la instancia local** (localhost:4000 vulnerable / 4001 mitigada).

| Script | Vuln | Propósito |
|--------|------|-----------|
| `v1_idor.sh` | V1 | Comprobar acceso a datos de otro usuario cambiando el identificador |
| `v2_nosqli.py` | V2 | Comprobar bypass de login por inyección NoSQL |
| `v3_check_hash.js` | V3 | Inspeccionar cómo se almacena el password en Mongo |
| `v4_headers.sh` | V4 | Revisar cabeceras de seguridad HTTP |
| `regression_smoke.sh` | — | Verificar que la funcionalidad legítima sigue operando |

Cada script debe imprimir resultado reproducible (comando → salida). Rellenar el cuerpo de cada uno en el Día 3 (PoC). Mantener los `TODO` hasta que el dueño de la vulnerabilidad los complete.
