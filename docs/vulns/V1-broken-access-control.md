# [V1] IDOR / Broken Access Control

## 1. Identificación
- Categoría OWASP: A01:2025 — Broken Access Control (equiv. A01:2021)
- Dueño: JuanFra | Revisor PR: Kevin | Rama: `feat/v1-idor-juanfra` | Commits clave: `e6d57ff` (PoC), `8379cba` (primer fix, 200), `6586ffb` (validación); ajuste tras la revisión del PR (403 + log, PoC ampliado): `git log --grep='revision PR' --oneline`

## 2. Análisis
- Descripción técnica: el endpoint `GET /allocations/:userId` muestra las asignaciones de inversión del usuario cuyo `userId` llega en la URL. El handler toma el `userId` del parámetro de la ruta, no de la sesión, y solo valida que haya sesión iniciada (`isLoggedIn`), sin comprobar que el recurso pertenezca al usuario autenticado. Un usuario logueado puede cambiar el número en la URL y leer datos de otros usuarios (IDOR / escalada horizontal).
- Componente/archivo/config afectada:
  - `vulnerable/app/routes/index.js:63` → `app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);` (solo `isLoggedIn`, sin control de propiedad)
  - `vulnerable/app/routes/allocations.js:14-16` → `const { userId } = req.params;` (toma el id del cliente)
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
- Resultado obtenido (commit `e6d57ff`, ver `docs/evidencias/V1/antes/poc_v1_idor.txt`):
  ```text
  [V1] POST /login -> 302
  [V1] GET /allocations/2 (propio) -> 200 | Asset Allocations for John Doe
  [V1] GET /allocations/3 (ajeno)  -> 200 | Asset Allocations for Will Smith
  [V1] GET /allocations/9999 (inexistente) -> 500 | <sin datos>
  [V1] GET /allocations/3 (sin cookie) -> 302 (esperado 302 a /login)
  [V1] RESULTADO: VULNERABLE - se leyeron datos de otro usuario (A01:2025)
  ```
  Exit code 1. Evidencia: `docs/evidencias/V1/antes/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Los porcentajes son aleatorios en cada seed, por eso se comparan nombres. Sin cookie, `isLoggedIn` ya redirige a `/login`: el fallo es de autorización, no de autenticación.
- Explicación del impacto: con una sesión válida se obtienen las asignaciones de un usuario ajeno cambiando solo el id en la URL.

## 4. Mitigación
- Cambio aplicado (solo `mitigated/app/routes/allocations.js`, líneas 12-19): el handler compara el id de la URL con el de la sesión y, si no coinciden, responde 403 y registra el intento. La comparación usa `String()` en ambos lados porque la sesión guarda un número y la URL llega como string. El recurso consultado es siempre el de la sesión.
  La ruta en `mitigated/app/routes/index.js:63` **no cambió** (sigue `isLoggedIn` + `displayAllocations`); todo el control está en el handler.
- Historial de la decisión: la primera versión ignoraba el id de la URL y respondía 200 con los datos de la sesión. En la revisión del PR (kevcas19) se señaló que eso rompe la semántica REST, puede mezclar contenido en cachés por URL, deja el intento sin detectar y oculta errores de clientes legítimos. Se adoptó 403 + log.
- Justificación técnica: ata la autorización al identificador de sesión del servidor, que el cliente no puede manipular, y deja una señal de detección (`[SEC] Posible IDOR`). El id de la URL se registra con `JSON.stringify` para evitar inyección de saltos de línea en el log.
- Limitación conocida: se responde 403 también para ids inexistentes (no 404), por lo que no se distingue "no existe" de "no es tuyo", lo que evita enumeración. No hay excepción para el rol admin: un admin que pida el recurso de otro recibe 403.
- Diff:
  ```diff
  - const { userId } = req.params;
  + const sessionUserId = String(req.session.userId);
  + if (String(req.params.userId) !== sessionUserId) {
  +     console.warn(`[SEC] Posible IDOR: user ${sessionUserId} pidio ${JSON.stringify(req.params.userId)}`);
  +     return res.status(403).send("Forbidden");
  + }
  + const userId = req.session.userId;
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable, `:4000`): `GET /allocations/3` con la sesión de `user1` devuelve "Will Smith" → `docs/evidencias/V1/antes/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Exit 1.
- DESPUÉS (mitigado, `:4001`): el mismo `GET /allocations/3` devuelve **403 Forbidden** y el servidor registra `[SEC] Posible IDOR: user 2 pidio "3"` → `docs/evidencias/V1/despues/` (`poc_v1_idor.txt`, `http_403_allocations_3.txt`). Exit 0.
- Casos añadidos tras la revisión:
  - `/allocations/9999` con sesión: ANTES 500 (error no controlado), DESPUÉS 403.
  - `/allocations/3` sin cookie: ANTES y DESPUÉS 302 a `/login` (lo resuelve `isLoggedIn`, no cambió).
- Regresión: `GET /allocations/2` en `:4001` sigue mostrando "John Doe" → `docs/evidencias/V1/despues/ui_regresion_allocations_2.png` y la línea del propio en `poc_v1_idor.txt`.
- Limitación: solo se probó `user1`. No se probó el rol admin; con este fix recibiría 403 al pedir el recurso de otro usuario.
- Fuera de alcance: el parámetro `threshold` del mismo endpoint es el vector de V2 (inyección NoSQL).
