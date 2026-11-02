# V3 — Evidencia DESPUÉS (mitigado, :4001)

| Campo | Detalle |
|---|---|
| Condición | `mitigated/` en Docker, commit `f24fca9`. Seed por `artifacts/db-reset.js` (ahora hashea con bcrypt). |
| Cambio aplicado | `bcrypt-nodejs` 0.0.3 reemplazado por `bcryptjs` 2.4.3; `user-dao.js` usa `bcrypt.hash` (cost 12) en signup y `bcrypt.compare(plano, hash)` en login; `db-reset.js` hashea el seed y redacta `password` en logs. |
| Herramienta | `poc-scripts/v3_check_hash.js` (misma PoC del ANTES, sin cambios). |
| Comando | `docker compose -f mitigated/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js` |
| Resultado PoC | 3/3 usuarios del seed y el usuario creado por `/signup` (`v3test`) clasificados `BCRYPT (cost=12)`, prefijo `$2a$12$`, 60 caracteres. 0 inseguros. Exit code 0. Ver `poc_v3_seed.txt/.png`, `poc_v3_signup.txt/.png`. |
| Regresión | Login con contraseña correcta: `v3test`, `admin`, `user1` dan `302` a `/dashboard` o `/benefits`. Contraseña incorrecta da `200` (formulario con error). Ver `regresion_login.txt/.png`. |
| Conclusión | Las contraseñas ya no son recuperables desde la BD: un atacante con lectura de `users` obtiene hashes con sal por usuario y costo 2^12, que exigen fuerza bruta offline lenta. La funcionalidad legítima de signup y login se conserva. |

Nota: los logs de arranque muestran `"password":"[REDACTED]"`; ningún valor en claro ni hash se registra.