# [V1] IDOR / Broken Access Control

## 1. Identificación
- Categoría OWASP: A01:2025 — Broken Access Control (equiv. A01:2021)
- Dueño: JuanFra | Revisor PR: Kevin | Rama: `feat/v1-idor-juanfra` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: el endpoint `GET /allocations/:userId` muestra las asignaciones de inversión del usuario cuyo `userId` llega en la URL. El handler toma el `userId` del parámetro de la ruta, no de la sesión, y solo valida que haya sesión iniciada (`isLoggedIn`), sin comprobar que el recurso pertenezca al usuario autenticado. Un usuario logueado puede cambiar el número en la URL y leer datos de otros usuarios (IDOR / escalada horizontal).
- Componente/archivo/config afectada:
  - `vulnerable/app/routes/index.js:63` → `app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);` (solo `isLoggedIn`, sin control de propiedad)
  - `vulnerable/app/routes/allocations.js:17-18` → `const { userId } = req.params;` (toma el id del cliente)
- Causa raíz: la autorización se basa en un identificador controlado por el cliente (`req.params.userId`) en lugar del identificador de la sesión (`req.session.userId`). No hay verificación de que el usuario autenticado sea el dueño del recurso.
- Impacto y riesgo: confidencialidad — exposición de datos financieros de cualquier usuario cambiando un número en la URL. Riesgo alto, explotación trivial, sin necesidad de herramientas.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: usuario legítimo autenticado (cookie `connect.sid` válida).
- Técnica/herramienta: manipulación del parámetro de la URL (navegador / curl).
- Petición/payload/comando ejecutado:
  ```bash
  # (Día 3) pedir el recurso de OTRO userId con la sesión propia
  curl -s "http://localhost:4000/allocations/<otro_id>" -H "Cookie: connect.sid=<sesion_propia>"
  ```
- Resultado obtenido: <qué devolvió> (evidencia: `docs/evidencias/V1/antes/...`)
- Explicación del impacto: se obtienen asignaciones de un usuario ajeno.

## 4. Mitigación
- Cambio aplicado: tomar el `userId` de la sesión, no de la URL. En `allocations.js` usar `const { userId } = req.session;` (fix ya señalado en el código vulnerable, línea 14 comentada). Alternativa robusta: mantener `:userId` pero rechazar con 403 si `req.params.userId !== req.session.userId` (salvo rol admin).
- Justificación técnica: ata la autorización al identificador de sesión del lado servidor, que el cliente no puede manipular.
- Diff:
  ```diff
  - const { userId } = req.params;
  + const { userId } = req.session;
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): `GET /allocations/<otro_id>` devuelve datos ajenos → evidencia `docs/evidencias/V1/antes/...`
- DESPUÉS (mitigado): solo devuelve los datos del usuario de la sesión (o 403) → evidencia `docs/evidencias/V1/despues/...`
- Regresión: el usuario sigue viendo SUS propias asignaciones → evidencia ...
