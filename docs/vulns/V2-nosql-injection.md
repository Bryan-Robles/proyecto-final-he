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
- Impacto y riesgo: integridad/confidencialidad y disponibilidad — lectura de registros fuera de criterio e incluso denegación de servicio por bucle infinito (`'};while(true){}'`). Riesgo alto.
  > **Nota ética:** el payload de bucle infinito se documenta como riesgo teórico pero **no se ejecutó**: las condiciones del proyecto prohíben ataques de DoS/destructivos. El PoC usa únicamente una condición booleana de solo lectura.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: `vulnerable/` levantada en `http://localhost:4000`, seed por defecto (3 usuarios: admin, user1, user2). Sesión iniciada con la cuenta demo `admin` (la clave se pasa por la variable `POC_PASS`, no se publica en el repo). Solo entorno local.
- Técnica/herramienta: inyección en el query param `threshold` de `GET /allocations/:userId`, automatizada con `poc-scripts/v2_nosqli.py` (Python, solo lectura). Compara una petición normal contra una con payload.
- Payload: `threshold = 0' || '1'=='1` → el `$where` evaluado queda como `this.userId == 1 && this.stocks > '0' || '1'=='1'`, que por precedencia (`&&` antes de `||`) es siempre verdadero y devuelve todas las asignaciones.
- Comando ejecutado:
  ```bash
  docker compose -f vulnerable/docker-compose.yml up -d --build
  BASE=http://localhost:4000 POC_PASS=<clave_demo> python3 poc-scripts/v2_nosqli.py
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
- Explicación del impacto: una petición legítima (threshold=0) devuelve solo la asignación del usuario de la sesión; con la inyección, el motor ejecuta la condición como JavaScript y entrega las asignaciones de los 3 usuarios. Confirma ejecución de JS server-side (`$where`) y fuga de datos entre usuarios.

## 4. Mitigación
- Cambio aplicado (`mitigated/app/data/allocations-dao.js`, `getByUserIdAndThreshold`): se valida `threshold` con la regex `^\d{1,2}$` (string de 1–2 dígitos, 0–99), **se elimina `$where`** y la consulta usa el operador nativo `$gt` con el número ya validado. Si la validación falla, se devuelve el error **por `callback` con un mensaje fijo** (`"Invalid threshold"`), sin incluir la entrada del usuario.
- Justificación técnica:
  - La causa raíz es que la entrada se concatenaba dentro de `$where`, que ejecuta JavaScript en el motor de Mongo. Eliminar `$where` y usar operadores nativos (`$gt`) quita por completo el canal de ejecución de código.
  - **Regex `^\d{1,2}$` y no `Number()`:** `Number()` acepta `"1e1"` (→10), `"0x10"` (→16), espacios (`" 5 "`) y, sobre todo, **no distingue un array**: `?threshold=5&threshold=6` llega como array y lo coacciona. La comprobación `typeof threshold === "string"` + regex cierra todos esos casos.
  - **Error por `callback`, no `throw`, y sin la entrada:** `error-template.html` renderiza `{{error}}` y `server.js` tiene `autoescape: false`. Un `throw` con la entrada cruda (ej. `?threshold=<script>…`) se reflejaría sin escapar → **XSS reflejado** que la versión vulnerable no tenía. Por eso el mensaje es fijo y no contiene la entrada. (Hallazgo de la revisión de @j-david06.)
  - Nota: `express-mongo-sanitize` **no** habría frenado este caso: ese middleware quita claves que empiezan por `$`/`.` del body/query, pero aquí el vector es el **valor** de `threshold`, no un operador como clave. El fix correcto es el saneamiento de tipo + quitar `$where`.
- Diff:
  ```diff
  - const searchCriteria = () => {
  -     if (threshold) {
  -         return { $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'` };
  -     }
  -     return { userId: parsedUserId };
  - };
  - allocationsCol.find(searchCriteria()).toArray((err, allocations) => {
  + let criteria = { userId: parsedUserId };
  + if (threshold !== undefined && threshold !== "") {
  +     if (typeof threshold !== "string" || !/^\d{1,2}$/.test(threshold)) {
  +         return callback(new Error("Invalid threshold"), null);
  +     }
  +     criteria = { userId: parsedUserId, stocks: { $gt: Number(threshold) } };
  + }
  + allocationsCol.find(criteria).toArray((err, allocations) => {
  ```

## 5. Validación (antes / después)
Mismo PoC (`poc-scripts/v2_nosqli.py`) contra ambas versiones:

| Prueba | ANTES (`:4000`) | DESPUÉS (`:4001`) |
|--------|-----------------|-------------------|
| Línea base (threshold=0) | 1 fila (admin) | 1 fila (admin) |
| Inyección `0' || '1'=='1` | HTTP 200, **3 filas** (admin, John Doe, Will Smith) | HTTP 500, **0 filas** |
| Regresión (threshold=10) | HTTP 200 (aceptado) | HTTP 200 (aceptado) |
| XSS `threshold=<script>` | — | no se refleja (mensaje fijo) |
| Veredicto / exit | VULNERABLE (exit 1) | MITIGADO (exit 0) |

> La regresión se mide por el **código HTTP** (válido → 200, inyección → 500), no por el número de filas: `stocks` es aleatorio en el seed (1–40), así que `$gt:10` puede devolver 0 filas de forma legítima.

- ANTES (vulnerable): la inyección ejecuta JS en `$where` y expone datos de otros usuarios → `docs/evidencias/V2/antes/poc_v2_nosqli.txt`
- DESPUÉS (mitigado): el payload no pasa la regex → la petición se rechaza (HTTP 500 con mensaje fijo, sin reflejar la entrada); la inyección no devuelve datos ajenos → `docs/evidencias/V2/despues/poc_v2_nosqli.txt`
- Regresión: con `threshold=10` (entero válido) la funcionalidad legítima sigue devolviendo las asignaciones propias → `docs/evidencias/V2/despues/poc_v2_nosqli.txt`

Reproducir (la clave demo se pasa por `POC_PASS`):

```bash
docker compose -f vulnerable/docker-compose.yml up -d --build
docker compose -f mitigated/docker-compose.yml  up -d --build
BASE=http://localhost:4000 POC_PASS=<clave_demo> python3 poc-scripts/v2_nosqli.py   # exit 1
BASE=http://localhost:4001 POC_PASS=<clave_demo> python3 poc-scripts/v2_nosqli.py   # exit 0
```

## 6. Nota para la sustentación — V2 (inyección) vs V1 (IDOR)
Ambas exponen datos de otros usuarios, pero la causa raíz y la mitigación son distintas:
- **V2 (A05 Injection):** la entrada (`threshold`) se **ejecuta como código** en el motor de Mongo (`$where`). Se cierra saneando el tipo de la entrada y eliminando el canal de ejecución (`$where` → `$gt`).
- **V1 (A01 Broken Access Control):** no hay ejecución de código; el servidor **confía en el `:userId` de la URL** en vez de en la sesión. Se cierra atando la autorización al `userId` de la sesión.
