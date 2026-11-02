# V3 — Evidencia ANTES (vulnerable, :4000)

| Campo | Detalle |
|---|---|
| Condición inicial | `vulnerable/` en Docker, commit `03ae3e5`. Seed por `artifacts/db-reset.js` (3 usuarios). |
| Componente | `app/data/user-dao.js:25` (addUser guarda `password` sin transformar); `:61` comparación `===`; `artifacts/db-reset.js:18,27,35` seed en claro. |
| Herramienta | `poc-scripts/v3_check_hash.js` (Node + driver `mongodb` 2.x, solo lectura, enmascara valores). |
| Comando | `docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js` |
| Resultado | 3/3 usuarios del seed y el usuario creado por `/signup` (`v3test`) clasificados `TEXTO PLANO`. Exit code 1. Ver `poc_v3_seed.txt/.png`, `poc_v3_signup.txt/.png`. |
| Impacto | Cualquier lectura de la colección `users` (NoSQLi V2, backup filtrado, acceso a Mongo, logs de `db-reset`) entrega credenciales reutilizables de inmediato, sin cracking. Facilita toma de cuentas (incluido `admin`) y credential stuffing en otros servicios. OWASP A04:2025 Cryptographic Failures; CWE-256, CWE-312. |

Nota: `/signup` responde `200` en éxito (`session.js` hace `res.render("dashboard")`, sin redirect); la creación se confirma con la fila `_id=4 v3test` en la PoC.

Complemento UI: registro (y login en DESPUÉS) desde el navegador con el usuario `v3web`; la PoC confirma el estado en BD. Ver `ui_*.png`.