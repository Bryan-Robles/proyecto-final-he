# Evidencia V2 — DESPUÉS (mitigado)

- `poc_v2_nosqli.txt`: salida del PoC `poc-scripts/v2_nosqli.py` contra `mitigated/` (`:4001`), incluye la regresión.

Resultado: la inyección en `threshold` (`0' || '1'=='1`) ya no altera el resultado
(0 filas vs. 1 de la línea base). `EXIT=0` → MITIGADO. Con un `threshold` numérico
válido (10) la funcionalidad legítima sigue operando.

Reproducir:

```bash
docker compose -f mitigated/docker-compose.yml up -d --build
BASE=http://localhost:4001 python poc-scripts/v2_nosqli.py
```
