# [V1] IDOR / Broken Access Control

## 1. Identificación
- Categoría OWASP: A01:2025 — Broken Access Control (equiv. A01:2021)
- Dueño: JuanFra | Revisor PR: Kevin | Rama: `feat/v1-idor-juanfra` | Commits clave: `aedaee5` (PoC), `2a97698` (fix, tag `v1-mitigado`), `d884c51` (validación)

## 2. Análisis
- Descripción técnica: el endpoint `GET /allocations/:userId` muestra las asignaciones de inversión del usuario cuyo `userId` llega en la URL. El handler toma el `userId` del parámetro de la ruta, no de la sesión, y solo valida que haya sesión iniciada (`isLoggedIn`), sin comprobar que el recurso pertenezca al usuario autenticado. Un usuario logueado puede cambiar el número en la URL y leer datos de otros usuarios (IDOR / escalada horizontal).
- Componente/archivo/config afectada:
  - `vulnerable/app/routes/index.js:63` → `app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);` (solo `isLoggedIn`, sin control de propiedad)
  - `vulnerable/app/routes/allocations.js:17-18` → `const { userId } = req.params;` (toma el id del cliente)
- Causa raíz: la autorización se basa en un identificador controlado por el cliente (`req.params.userId`) en lugar del identificador de la sesión (`req.session.userId`). No hay verificación de que el usuario autenticado sea el dueño del recurso.
- Impacto y riesgo: confidencialidad — exposición de datos financieros de cualquier usuario cambiando un número en la URL. Riesgo alto, explotación trivial, sin necesidad de herramientas.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: usuario legítimo autenticado (cookie `connect.sid` válida).
- Técnica/herramienta: manipulación del parámetro de la URL, automatizada con `poc-scripts/v1_idor.sh` (curl + cookie de sesión).
- Petición/payload/comando ejecutado (la clave demo se pasa por `POC_PASS`, no se publica):
  ```bash
  docker compose -f vulnerable/docker-compose.yml up -d --build
  BASE=http://localhost:4000 POC_PASS=<clave_demo_user1> ./poc-scripts/v1_idor.sh
  ```
  El script inicia sesión como `user1` (John Doe, `_id` 2), pide `/allocations/2` (propio) y `/allocations/3` (ajeno) con la misma cookie y compara los nombres de `Asset Allocations for ...`.
- Resultado obtenido (2026-11-07T03:24Z, commit `aedaee5`):
  ```text
  [V1] POST /login -> 302
  [V1] GET /allocations/2 (propio) -> 200 | Asset Allocations for John Doe
  [V1] GET /allocations/3 (ajeno)  -> 200 | Asset Allocations for Will Smith
  [V1] RESULTADO: VULNERABLE - se leyeron datos de otro usuario (A01:2025)
  ```
  Exit code 1. Evidencia: `docs/evidencias/V1/antes/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Los porcentajes son aleatorios en cada seed, por eso se comparan nombres.
- Explicación del impacto: con una sesión válida se obtienen las asignaciones de un usuario ajeno cambiando solo el id en la URL.

## 4. Mitigación
- Cambio aplicado (solo `mitigated/app/routes/allocations.js`): tomar el `userId` de la sesión, no de la URL, con `const { userId } = req.session;` (el login ya lo guarda en `req.session.userId`, `session.js:116`). El bloque comentado del upstream se conserva como comentario.
- Decisión de diseño: **la mitigación no devuelve 403.** El servidor ignora el id de la URL y responde 200 con los datos del usuario autenticado. Se descartó por ahora la alternativa de devolver 403 si `req.params.userId !== req.session.userId` (salvo admin) por la comparación de tipos número/string; sigue disponible si se quiere mostrar "acceso denegado".
- Justificación técnica: ata la autorización al identificador de sesión del lado servidor, que el cliente no puede manipular.
- Diff:
  ```diff
  - const { userId } = req.params;
  + const { userId } = req.session;
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable, `:4000`): `GET /allocations/3` con la sesión de `user1` devuelve "Will Smith" → `docs/evidencias/V1/antes/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Exit 1.
- DESPUÉS (mitigado, `:4001`): el mismo `GET /allocations/3` devuelve "John Doe", los datos de la sesión (no 403) → `docs/evidencias/V1/despues/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Exit 0.
- Regresión: `GET /allocations/2` en `:4001` sigue mostrando "John Doe" → `docs/evidencias/V1/despues/ui_regresion_allocations_2.png` y la línea del propio en `poc_v1_idor.txt`.
- Limitación: la validación cubre el caso `user1` con ids 2 y 3. No se probó el rol admin ni ids inexistentes.
