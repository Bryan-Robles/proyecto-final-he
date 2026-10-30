# [V2] NoSQL Injection (Server-Side JS vía `$where`)

## 1. Identificación
- Categoría OWASP: A05:2025 — Injection (equiv. A03:2021)
- Dueño: Bryan | Revisor PR: JuanDa | Rama: `feat/v2-nosqli-bryan` | Commits clave: <hashes>

> **Nota del equipo:** la guía operativa sugería bypass de login con `{"$gt":""}`. En NodeGoat **ese payload no funciona**: el password se compara en JavaScript (`fromDB === fromUser`, `user-dao.js:61`), no dentro de la consulta Mongo, así que un operador no evade el login. La NoSQL Injection real y demostrable es la inyección de JavaScript del lado servidor mediante `$where` en el parámetro `threshold`. Misma categoría OWASP (A05 Injection).

## 2. Análisis
- Descripción técnica: el parámetro `threshold` (query string de `GET /allocations/:userId?threshold=`) se concatena sin sanitizar dentro de una cláusula `$where` de MongoDB. `$where` ejecuta JavaScript en el servidor de base de datos, por lo que un atacante puede inyectar código arbitrario (condiciones siempre verdaderas, bucles, etc.).
- Componente/archivo/config afectada:
  - `vulnerable/app/data/allocations-dao.js:78` → `return { $where: \`this.userId == ${parsedUserId} && this.stocks > '${threshold}'\` };`
  - Entrada: `vulnerable/app/routes/allocations.js:21` (`const { threshold } = req.query;`)
- Causa raíz: concatenación de entrada no confiable dentro de una consulta que ejecuta código (`$where`), sin validación de tipo ni de rango.
- Impacto y riesgo: integridad/confidencialidad y disponibilidad — lectura de registros fuera de criterio e incluso denegación por bucle infinito (`'};while(true){}'`). Riesgo alto.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: usuario autenticado; endpoint de allocations accesible.
- Técnica/herramienta: inyección en el query param `threshold` (navegador / curl).
- Petición/payload/comando ejecutado:
  ```bash
  # (Día 3) inyectar condición siempre verdadera para alterar el filtro
  curl -s "http://localhost:4000/allocations/<id>?threshold=<payload>" -H "Cookie: connect.sid=<sesion>"
  ```
- Resultado obtenido: <registros devueltos fuera del criterio esperado> (evidencia: `docs/evidencias/V2/antes/...`)
- Explicación del impacto: se ejecuta JS arbitrario en el motor Mongo.

## 4. Mitigación
- Cambio aplicado: validar y castear `threshold` a entero y rango permitido antes de la consulta; eliminar `$where` siempre que sea posible (usar operadores nativos `$gt`). El propio código vulnerable incluye el fix comentado (`allocations-dao.js:70-75`): `parseInt(threshold,10)` + rango `0..99`.
- Justificación técnica: elimina la ejecución de código provisto por el usuario y fuerza tipos seguros.
- Diff:
  ```diff
  - return { $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'` };
  + const parsedThreshold = parseInt(threshold, 10);
  + if (parsedThreshold >= 0 && parsedThreshold <= 99) {
  +     return { $where: `this.userId == ${parsedUserId} && this.stocks > ${parsedThreshold}` };
  + }
  + throw `The user supplied threshold: ${parsedThreshold} was not valid.`;
  ```
- Refuerzo adicional: `express-mongo-sanitize` a nivel de app para neutralizar operadores en el cuerpo/params.

## 5. Validación (antes / después)
- ANTES (vulnerable): el payload en `threshold` altera el resultado / ejecuta JS → evidencia `docs/evidencias/V2/antes/...`
- DESPUÉS (mitigado): entrada no numérica se rechaza; el filtro opera solo con enteros → evidencia `docs/evidencias/V2/despues/...`
- Regresión: `threshold` numérico válido sigue filtrando correctamente → evidencia ...
