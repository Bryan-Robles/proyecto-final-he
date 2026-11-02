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
- Condición inicial: `vulnerable/` levantada en `http://localhost:4000`, seed por defecto (3 usuarios: admin, user1, user2). Sesión iniciada con la cuenta demo `admin` / `Admin_123`. Solo entorno local.
- Técnica/herramienta: inyección en el query param `threshold` de `GET /allocations/:userId`, automatizada con `poc-scripts/v2_nosqli.py` (Python, solo lectura). Compara una petición normal contra una con payload.
- Payload: `threshold = 0' || '1'=='1` → el `$where` evaluado queda como `this.userId == 1 && this.stocks > '0' || '1'=='1'`, que por precedencia (`&&` antes de `||`) es siempre verdadero y devuelve todas las asignaciones.
- Comando ejecutado:
  ```bash
  docker compose -f vulnerable/docker-compose.yml up -d --build
  BASE=http://localhost:4000 python poc-scripts/v2_nosqli.py
  ```
- Resultado obtenido:
  ```text
  [V2] Linea base (threshold=0): 1 fila(s) -> ['Node Goat Admin']
  [V2] Con inyeccion:             3 fila(s) -> ['John Doe', 'Node Goat Admin', 'Will Smith']
  [V2] Datos expuestos de otros usuarios: ['John Doe', 'Will Smith']
  [V2] RESULTADO: VULNERABLE - el $where ejecuto la entrada (A05:2025)
  EXIT=1
  ```
  Evidencia: `docs/evidencias/V2/antes/` (`poc_v2_nosqli.txt`, `README.md`).
- Explicación del impacto: una petición legítima (threshold=-1) devuelve solo la asignación del usuario de la sesión; con la inyección, el motor ejecuta la condición como JavaScript y entrega las asignaciones de los 3 usuarios. Confirma ejecución de JS server-side (`$where`) y fuga de datos entre usuarios.

## 4. Mitigación
- Cambio aplicado (`mitigated/app/data/allocations-dao.js`, `getByUserIdAndThreshold`): se valida `threshold` como entero en rango `0..99` con `Number` estricto y **se elimina `$where`**; la consulta usa el operador nativo `$gt` con el valor ya convertido a número. Ninguna entrada del usuario llega a evaluarse como código.
- Justificación técnica:
  - La causa raíz es que la entrada se concatenaba dentro de `$where`, que ejecuta JavaScript en el motor de Mongo. Eliminar `$where` y usar operadores nativos (`$gt`) quita por completo el canal de ejecución de código.
  - `Number("0' || '1'=='1")` es `NaN`, así que el payload se rechaza; `parseInt` sería más laxo (devolvería `0`), por eso se usa `Number` + `Number.isInteger`.
  - Nota: `express-mongo-sanitize` **no** habría frenado este caso: ese middleware quita claves que empiezan por `$`/`.` del body/query, pero aquí el vector es el **valor** de `threshold` interpolado en `$where`, no un operador inyectado como clave. El fix correcto es el saneamiento de tipo + quitar `$where`.
- Diff:
  ```diff
  - return {
  -     $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
  - };
  + const parsedThreshold = Number(threshold);
  + if (!Number.isInteger(parsedThreshold) || parsedThreshold < 0 || parsedThreshold > 99) {
  +     throw `The user supplied threshold: ${threshold} was not valid.`;
  + }
  + return {
  +     userId: parsedUserId,
  +     stocks: { $gt: parsedThreshold }
  + };
  ```

## 5. Validación (antes / después)
Mismo PoC (`poc-scripts/v2_nosqli.py`) contra ambas versiones:

| Prueba | ANTES (`:4000`) | DESPUÉS (`:4001`) |
|--------|-----------------|-------------------|
| Línea base (threshold=0) | 1 fila (admin) | 1 fila (admin) |
| Inyección `0' || '1'=='1` | **3 filas** (admin, John Doe, Will Smith) | **0 filas** |
| Veredicto / exit | VULNERABLE (exit 1) | MITIGADO (exit 0) |
| Regresión (threshold=10) | — | 1 fila propia ✓ |

- ANTES (vulnerable): la inyección ejecuta JS en `$where` y expone datos de otros usuarios → `docs/evidencias/V2/antes/poc_v2_nosqli.txt`
- DESPUÉS (mitigado): `Number(...)` del payload es `NaN` → se rechaza; la inyección no devuelve datos ajenos → `docs/evidencias/V2/despues/poc_v2_nosqli.txt`
- Regresión: con `threshold=10` (entero válido) la funcionalidad legítima sigue devolviendo las asignaciones propias → `docs/evidencias/V2/despues/poc_v2_nosqli.txt`
