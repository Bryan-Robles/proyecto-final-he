# Informe Técnico — Proyecto Final Hacking Ético

Universidad del Magdalena · Ingeniería de Sistemas · Periodo 2026-II
Equipo: JuanFra · Bryan · JuanDa · Kevin
Aplicación: OWASP NodeGoat (instancia local controlada)

---

## 1. Descripción y arquitectura del sistema

- **Aplicación/API seleccionada:** OWASP NodeGoat (v1.3.0) — "RetireEasy", app demo de gestión de ahorro para el retiro, deliberadamente vulnerable (OWASP VWAD).
- **Propósito y principales funcionalidades:** registro/login de usuarios, dashboard, perfil, asignaciones de inversión (allocations), contribuciones, beneficios (rol admin), memos y módulo de aprendizaje OWASP Top 10.
- **Tecnologías utilizadas:** Node.js + Express 4, MongoDB (driver `mongodb` 2.x), sesiones con `express-session`, plantillas Swig vía `consolidate`, `bcrypt-nodejs` (presente, sin usar en baseline). Contenedores Docker: servicio `web` (build local, puerto 4000) + `mongo:4.4`.
- **Arquitectura o componentes principales:** patrón rutas → handlers → DAOs.
  - Rutas: `app/routes/` (`index.js` registra endpoints; `session.js`, `allocations.js`, `profile.js`, etc.)
  - Acceso a datos: `app/data/*-dao.js` (`user-dao.js`, `allocations-dao.js`, ...)
  - Vistas: `app/views/*.html` (Swig)
  - Bootstrap/config: `server.js`, `config/config.js`
- **Entorno utilizado para las pruebas:** instancia local en Docker. `vulnerable/` en `http://localhost:4000` (baseline) y `mitigated/` en `http://localhost:4001` (parchada). Verificado: HTTP 200 en login.
- **Superficie de ataque identificada:** formularios de login y signup (`/login`, `/signup`), endpoint parametrizado `/allocations/:userId` con query `threshold`, actualización de perfil (`/profile`), cabeceras HTTP y configuración del servidor, almacenamiento de credenciales en Mongo.

## 2. Caracterización de las cuatro vulnerabilidades

Resumen de las 4 vulnerabilidades (detalle completo en `docs/vulns/Vx-*.md`).

| V# | Vulnerabilidad | Categoría OWASP 2025 | Componente afectado (archivo:línea) | Dueño |
|----|----------------|----------------------|-------------------------------------|-------|
| V1 | IDOR / Broken Access Control | A01:2025 | `routes/allocations.js:16-18` + `routes/index.js:63` | JuanFra |
| V2 | NoSQL Injection (`$where` en `threshold`) | A05:2025 | `data/allocations-dao.js:78` | Bryan |
| V3 | Cryptographic Failures (password en texto plano) | A04:2025 | `data/user-dao.js:25` y `:61` | JuanDa |
| V4 | Security Misconfiguration | A02:2025 | server.js:38-65 (helmet y x-powered-by comentados) y :78-102 (sesión sin cookie) | Kevin |

Detalle completo en `docs/vulns/Vx-*.md` (descripción, causa raíz, impacto, PoC, mitigación, validación).

> **Nota V2:** se descartó el bypass de login con operadores Mongo (`{"$gt":""}`) porque NodeGoat compara el password en JavaScript (`user-dao.js:61`), no en la consulta; ese payload no evade el login. La NoSQL Injection documentada es la inyección de JS server-side vía `$where` en el parámetro `threshold` (misma categoría A05).

## 3. Evidencias de explotación controlada

Por cada vulnerabilidad: condición inicial, técnica/herramienta, petición/payload/comando, resultado obtenido, explicación del impacto. Evidencias reproducibles en `docs/evidencias/Vx/antes/`.

### 3.1 V1 — IDOR / Broken Access Control (JuanFra)

- **Condición inicial:** `vulnerable/` en Docker (`http://localhost:4000`), seed por defecto, sesión legítima de `user1` (John Doe, `_id` 2). Entorno local.
- **Técnica/herramienta:** manipulación del id en la URL, automatizada con `poc-scripts/v1_idor.sh` (curl con cookie de sesión).
- **Comando:**
  ```bash
  BASE=http://localhost:4000 POC_PASS=<clave_demo_user1> ./poc-scripts/v1_idor.sh
  ```
- **Resultado:** login `302`; `/allocations/2` → John Doe; `/allocations/3` → Will Smith; `/allocations/9999` → 500; `/allocations/3` sin cookie → 302 a `/login`. `RESULTADO: VULNERABLE`, exit code 1.
- **Impacto:** cualquier usuario autenticado lee las asignaciones de inversión de otro cambiando un número en la URL.
- **Evidencia:** `docs/evidencias/V1/antes/` (`poc_v1_idor.txt`, `ui_idor_allocations_3.png`). Detalle: `docs/vulns/V1-broken-access-control.md` §3.

### 3.2 V2 — NoSQL Injection (Bryan)

- **Condición inicial:** `vulnerable/` en Docker (`http://localhost:4000`), seed por defecto (3 usuarios: admin, user1=John Doe, user2=Will Smith). Sesión legítima de `admin` (clave por `POC_PASS`). Entorno local.
- **Técnica/herramienta:** inyección en el query param `threshold` de `GET /allocations/:userId`, automatizada con `poc-scripts/v2_nosqli.py` (Python, solo lectura). Compara una petición normal contra una con payload y cuenta las filas `Asset Allocations for ...`.
- **Payload:** `threshold = 0' || '1'=='1`. El `$where` queda como `this.userId == 1 && this.stocks > '0' || '1'=='1'`, que por precedencia (`&&` antes de `||`) es siempre verdadero y devuelve todas las asignaciones.
- **Comando:**
  ```bash
  BASE=http://localhost:4000 POC_PASS=<clave_demo> python3 poc-scripts/v2_nosqli.py
  ```
- **Resultado:** línea base (threshold=0) → 1 fila (admin); con inyección → HTTP 200, **3 filas** (admin, John Doe, Will Smith). `RESULTADO: VULNERABLE`, exit code 1.
- **Impacto:** la entrada del usuario se ejecuta como JavaScript en el motor de Mongo (`$where`), lo que permite leer las asignaciones de otros usuarios (y, en teoría, un DoS por bucle infinito que **no se ejecutó** por las condiciones éticas).
- **Evidencia:** `docs/evidencias/V2/antes/` (`poc_v2_nosqli.txt`, `README.md`). Detalle: `docs/vulns/V2-nosql-injection.md` §3.

### 3.3 V3 — Cryptographic Failures (JuanDa)

- **Condición inicial:** `vulnerable/` en Docker (`http://localhost:4000`, commit `03ae3e5`), seed por defecto con 3 usuarios. Entorno local.
- **Técnica/herramienta:** inspección de solo lectura de la colección `users` con `poc-scripts/v3_check_hash.js`. El script clasifica cada `password` (texto plano / hash rápido sin sal / bcrypt con su cost) y enmascara la salida (primer carácter + longitud).
- **Comando:**
  ```bash
  docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js
  ```
  Se repite tras un registro legítimo vía `POST /signup` (usuario `v3test`), para probar que el fallo está en el código de la aplicación y no solo en el seed.
- **Resultado:** 4/4 usuarios (`admin`, `user1`, `user2`, `v3test`) clasificados `TEXTO PLANO`; `RESULTADO: VULNERABLE`, exit code 1. Los logs de `db-reset.js` también imprimen las contraseñas del seed en cada arranque.
- **Impacto:** quien lea la colección `users` obtiene credenciales utilizables de inmediato, sin cracking, y puede tomar cualquier cuenta, incluida `admin`.
- **Evidencia:** `docs/evidencias/V3/antes/` (`poc_v3_seed.*`, `poc_v3_signup.*`). Detalle: `docs/vulns/V3-crypto-failures.md` §3.

### 3.4 V4 — Security Misconfiguration (Kevin)

- **Condición inicial:** `vulnerable/` en Docker (`http://localhost:4000`), entorno local, sin sesión iniciada.
- **Técnica/herramienta:** inspección de las cabeceras de respuesta HTTP, primero a mano en las herramientas de desarrollador (pestaña Network) y después automatizada con `poc-scripts/v4_headers.sh` (curl lee solo las cabeceras, sin cuerpo, y las compara contra las cinco que emite Helmet 2.3.0).
- **Comando:**
  ```bash
  ./poc-scripts/v4_headers.sh http://localhost:4000/
  ```
- **Resultado:** faltan `x-frame-options`, `x-content-type-options`, `x-download-options`, `x-dns-prefetch-control` y `x-xss-protection`, y la respuesta expone `X-Powered-By: Express`. Son 6 fallas: el script imprime VULNERABLE (6 problema(s) de configuracion de cabeceras) y termina con exit code 1. En el código, `session()` de `vulnerable/server.js` no define `cookie` (el bloque está comentado), así que la cookie de sesión usa el nombre por defecto `connect.sid` y no lleva `Secure` ni `SameSite` (`HttpOnly` ya lo aplica `express-session` por defecto).
- **Impacto:** el servidor revela su tecnología (Express), lo que permite buscar exploits por versión; sin `X-Frame-Options` la app puede incrustarse en un iframe ajeno (clickjacking); sin `nosniff` el navegador puede reinterpretar el tipo de contenido; y una cookie de sesión sin `Secure` ni `SameSite` viaja sin cifrar sobre HTTP y no restringe su envío en peticiones entre sitios.
- **Evidencia:** `docs/evidencias/V4/antes/` (`Evidencia_01_V4_Cabeceras_Vulnerables.png` y `evidencia_vulnerable.txt`). Detalle: `docs/vulns/V4-security-misconfig.md` §3.

## 4. Análisis de impacto y relación con OWASP

Relación vulnerabilidad → impacto (CIA) → riesgo → categoría OWASP, justificando por qué esa categoría y no otra.

### 4.1 V1 — IDOR / Broken Access Control (JuanFra)

| Aspecto | Detalle |
|---|---|
| Impacto CIA | **C: Alto** (datos financieros de otros usuarios). **I: Bajo** (el endpoint solo lee). **A: Bajo.** |
| Probabilidad | Alta: basta una cuenta válida y editar la URL; no requiere herramientas. |
| Riesgo | **Alto.** |
| Categoría | **A01:2025 Broken Access Control**; CWE-639 (autorización basada en una clave controlada por el usuario). |

**Por qué A01 y no otra:** el flujo de autenticación funciona; lo que falta es la comprobación de que el recurso pertenece al usuario autenticado. No es A07 (Authentication Failures) porque la identidad se verifica bien, y no es A05 (Injection) porque no se inyecta código.

### 4.2 V2 — NoSQL Injection (Bryan)

| Aspecto | Detalle |
|---|---|
| Impacto CIA | **C: Alto** (lectura de datos de otros usuarios). **I: Bajo** (solo lectura: el `$where` se evalúa dentro de un `find`; en Mongo 4.4 ese JS no puede escribir datos). **A: Alto potencial** (un `$where` con bucle infinito bloquea el servidor de BD; no se ejecutó). |
| Probabilidad | Alta: basta una cuenta válida y manipular un query param; no requiere herramientas. |
| Riesgo | **Alto.** |
| Categoría | **A05:2025 Injection** (A03:2021); CWE-943, CWE-94. |

**Por qué A05 y no otra:**
- **No es A01 (Broken Access Control) aunque también exponga datos ajenos:** la causa raíz es distinta. En V2 la **entrada se ejecuta como código** en el motor de Mongo (`$where`); en V1 el servidor confía en el `:userId` de la URL sin ejecutar nada. La mitigación también difiere (sanear el tipo de la entrada y quitar `$where` vs. atar la autorización a la sesión).
- **Se descartó el "bypass de login" con `{"$gt":""}`:** NodeGoat compara el password en JavaScript (`user-dao.js:61`), no dentro de la consulta, así que ese operador no evade el login. El vector real y demostrable es la inyección de JS vía `$where` en `threshold`.

### 4.3 V3 — Cryptographic Failures (JuanDa)

| Aspecto | Detalle |
|---|---|
| Impacto CIA | **C: Alto** (todas las contraseñas legibles). **I: Alto** indirecto (con la contraseña se suplanta al usuario y se modifican sus datos, p. ej. contribuciones o perfil). **A: Bajo.** |
| Probabilidad | Media: requiere un vector de lectura de la BD (volcado, backup, acceso a Mongo, logs). En la misma app existe uno (V2, NoSQLi), y las filtraciones de backups son comunes. |
| Riesgo | **Alto.** El daño se extiende fuera de la app por la reutilización de contraseñas (credential stuffing). |
| Categoría | **A04:2025 Cryptographic Failures** (A02:2021); CWE-256, CWE-312. |

**Por qué A04 y no otra:**
- **No es A07 (Authentication Failures):** el flujo de autenticación hace lo que debe (pide y verifica la credencial). Lo que falla es la protección criptográfica del dato en reposo: falta una función de derivación de clave con sal.
- **No es A02 (Security Misconfiguration):** no es un ajuste ni un valor por defecto. Es la ausencia de un control criptográfico en el código de la capa de datos (`user-dao.js`) y en el aprovisionamiento (`db-reset.js`).
- **No se solapa con V2:** V2 es el vector que permite leer datos. V3 determina qué obtiene el atacante cuando los lee. Son fallos de naturaleza distinta y su mitigación es independiente.

### 4.4 V4 — Security Misconfiguration (Kevin)

| Aspecto | Detalle |
|---|---|
| Impacto CIA | **C: Medio** (se expone el stack tecnológico y la cookie de sesión no lleva `Secure`, por lo que viaja sin cifrar sobre HTTP). **I: Medio** indirecto (clickjacking y suplantación con una sesión robada permiten ejecutar acciones como el usuario). **A: Bajo.** |
| Probabilidad | Media: las cabeceras se ven con una sola petición y sin herramientas especiales; aprovechar el iframe o la cookie sin `Secure` ni `SameSite` requiere un sitio atacante o acceso a la red, porque la sesión viaja por HTTP. |
| Riesgo | **Medio-alto.** Por sí sola rara vez da acceso, pero amplifica otras vulnerabilidades de la misma app. |
| Categoría | **A02:2025 Security Misconfiguration** (A05:2021); CWE-16 (configuración), CWE-200 (exposición de información), CWE-1275 (cookie sensible con atributo `SameSite` inadecuado), CWE-1021 (clickjacking). |

**Por qué A02 y no otra:**
- **No es A01 (Broken Access Control):** no falta una comprobación de pertenencia del recurso; lo que falta son controles de endurecimiento del servidor.
- **No es A07 (Authentication Failures):** el login funciona y verifica la credencial. Lo que está mal es la configuración por defecto del middleware de sesión y de las cabeceras.
- **No es A05 (Injection):** no se inyecta código. Esta falla amplifica una inyección (XSS), pero su causa es distinta y su mitigación es independiente.

## 5. Mitigaciones implementadas

Por cada vulnerabilidad: cambio aplicado (código/config/diseño/control), justificación técnica, diff del cambio.

### 5.1 V1 — IDOR / Broken Access Control (JuanFra)

- **Cambio aplicado (solo `mitigated/`):** en `app/routes/allocations.js` (líneas 16-25) el handler compara `String(req.params.userId)` con `String(req.session.userId)`; si no coinciden responde **403** y registra `[SEC] Posible IDOR`. La ruta en `routes/index.js:63` no cambió.
- **Justificación técnica:** la autorización depende del identificador de sesión del servidor, que el cliente no controla, y el intento deja señal de detección. `String()` resuelve la diferencia número (sesión) / string (URL).
- **Decisión de diseño:** la primera versión ignoraba el id de la URL y respondía 200 con los datos de la sesión. En la revisión del PR se cambió a 403 + log por: semántica REST, riesgo de caché por URL, intento sin detectar y errores de cliente ocultos.
- **Diff:**
  ```diff
  - const { userId } = req.params;
  + const sessionUserId = String(req.session.userId);
  + if (String(req.params.userId) !== sessionUserId) {
  +     console.warn(`[SEC] Posible IDOR: user ${sessionUserId} pidio ${JSON.stringify(req.params.userId)}`);
  +     return res.status(403).send("Forbidden");
  + }
  + const userId = req.session.userId;
  ```
  Diff completo con `git diff 47da0cb v1-mitigado -- mitigated/`. Detalle: `docs/vulns/V1-broken-access-control.md` §4.

### 5.2 V2 — NoSQL Injection (Bryan)

- **Cambio aplicado (`mitigated/app/data/allocations-dao.js` + `app/routes/allocations.js`):** `threshold` se valida con `typeof === "string"` + regex `^\d{1,2}$` (entero 0–99); **se elimina `$where`** y la consulta usa el operador nativo `$gt` con el número ya validado. Si la validación falla, se devuelve el error **por `callback` con un mensaje fijo** (`"Invalid threshold"`, marcado con `err.invalidThreshold`), y el handler de la ruta responde **HTTP 400** (error del cliente), sin incluir la entrada del usuario.
- **Justificación técnica:**
  - Eliminar `$where` y usar operadores nativos quita por completo el canal de ejecución de código; ninguna entrada del usuario se evalúa como JS.
  - **Regex y no `Number()`:** `Number()` acepta `"1e1"`, `"0x10"`, espacios y no distingue un array (`?threshold=5&threshold=6`); la comprobación de tipo + regex cierra esos casos.
  - **Error por `callback` con mensaje fijo:** un `throw` con la entrada cruda se reflejaba en la página de error (`error-template.html` usa `{{error}}` y `server.js` tiene `autoescape: false`) → **XSS reflejado** que la versión vulnerable no tenía. Hallazgo de la revisión de `@j-david06`; el mensaje final no contiene la entrada.
  - `express-mongo-sanitize` **no** habría frenado este caso: quita claves `$`/`.` del body/query, pero aquí el vector es el **valor** de `threshold`, no un operador como clave.
- **Diff:**
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
  Commits `4893b99` y `29159a2`; diff completo con `git diff v2-mitigado^1 v2-mitigado -- mitigated/` (solo `allocations-dao.js`). Detalle: `docs/vulns/V2-nosql-injection.md` §4.

### 5.3 V3 — Cryptographic Failures (JuanDa)

- **Cambio aplicado (solo `mitigated/`):**
  1. `bcrypt-nodejs` 0.0.3 (abandonado, *deprecated*) reemplazado por `bcryptjs` 2.4.3: JavaScript puro, sin compilación nativa en `node:12-alpine`.
  2. `app/data/user-dao.js`: `addUser` guarda `bcrypt.hash(password, SALT_ROUNDS)`; `validateLogin` verifica con `bcrypt.compare(plano, hash)` y rechaza las entradas que no sean `string`.
  3. `artifacts/db-reset.js`: el seed se hashea con el mismo costo y `password` aparece como `[REDACTED]` en los logs.
  4. `SALT_ROUNDS = max(10, BCRYPT_SALT_ROUNDS || 12)`.
- **Justificación técnica:**
  - bcrypt es una función de derivación lenta, con sal aleatoria de 128 bits por usuario embebida en el hash y costo exponencial ajustable. Eso anula las rainbow tables y encarece cada intento de fuerza bruta offline. Un hash rápido (MD5/SHA-256) no basta.
  - **Cost 12** (OWASP exige ≥10). Benchmark de `bcryptjs`: unos 325 ms por hash, aceptable en el login y costoso para el atacante.
  - **API asíncrona:** `hashSync`/`compareSync` bloquearían el event loop de Node unos 300 ms por petición.
  - **Orden de argumentos:** `compare(plano, hash)`. Invertido devuelve `false` sin error. El fix comentado del upstream funcionaba solo porque los nombres de los parámetros de `comparePassword` también estaban invertidos; se corrigió la firma.
- **Diff (resumen):**
  ```diff
  - password //received from request param
  + bcrypt.hash(password, SALT_ROUNDS, (err, passwordHash) => { ... password: passwordHash ... })
  ```
  ```diff
  - const comparePassword = (fromDB, fromUser) => { return fromDB === fromUser; }
  + const comparePassword = (plainFromUser, hashFromDB, cb) => bcrypt.compare(plainFromUser, hashFromDB, cb)
  ```
  Commits `af58f1c`, `9c93620` y `f24fca9`; diff completo con `git diff 03ae3e5 v3-mitigado -- mitigated/`. Detalle: `docs/vulns/V3-crypto-failures.md` §4.


### 5.4 V4 — Security Misconfiguration (Kevin)

- **Cambio aplicado (solo `mitigated/`):** en `server.js`:
  1. `app.use(helmet())` con Helmet 2.3.0 (versión fijada en el lockfile), que añade 5 cabeceras: `X-Frame-Options`, `X-Content-Type-Options`, `X-Download-Options`, `X-DNS-Prefetch-Control` y `X-XSS-Protection`.
  2. `app.disable("x-powered-by")` para ocultar la cabecera que expone Express.
  3. Sesión: `key: "sessionId"` (nombre genérico en vez del `connect.sid` por defecto) y `cookie: { httpOnly: true, secure: process.env.COOKIE_SECURE === "true", sameSite: "lax" }`.
- **Justificación técnica:** cada control cierra un vector concreto. `X-Frame-Options: SAMEORIGIN` impide el clickjacking desde otros orígenes; `nosniff` evita que el navegador adivine el tipo de contenido; `httpOnly: true` deja explícito que JavaScript no pueda leer la cookie (ya era el valor por defecto de `express-session`); `SameSite=Lax` evita que se envíe en peticiones POST entre sitios; y ocultar `X-Powered-By` y el nombre por defecto de la cookie reduce la información que recibe un atacante.
- **Decisión de diseño:** la primera versión usaba `secure: true`. En la revisión del PR se demostró que, con `express-session` 1.15.6 y el servidor sirviendo por HTTP (`http.createServer`), la cookie con `Secure` no se emite y la sesión no persiste. Se cambió a `secure: process.env.COOKIE_SECURE === "true"`: queda en `false` por defecto y se activa únicamente cuando el servidor corra bajo HTTPS. También se corrigió la descripción del PR y de la ficha: Helmet 2.3.0 no emite CSP ni HSTS, solo las cinco cabeceras listadas arriba.
- **Riesgo residual:** mientras el servidor use HTTP, la cookie viaja sin el flag `Secure`. Cerrarlo exige servir por HTTPS, algo que queda fuera del alcance de V4.
- **Validación:** `poc-scripts/v4_headers.sh` (cabeceras presentes y `X-Powered-By` ausente) y `poc-scripts/regression_smoke.sh` (login y navegación siguen funcionando). Resultados en la matriz de la sección 6.
- **Diff:**
  ```diff
  + const helmet = require('helmet');
  ...
  + app.use(helmet());
  + app.disable("x-powered-by");
  ...
    app.use(session({
        secret: cookieSecret,
        saveUninitialized: true,
  -     resave: true
  +     resave: true,
  +     key: "sessionId",
  +     cookie: {
  +         httpOnly: true,
  +         secure: process.env.COOKIE_SECURE === "true",
  +         sameSite: "lax"
  +     }
    }));
  ```
  Commits `0f5b8bd`, `d74a853` y `66ba532`. Detalle: `docs/vulns/V4-security-misconfig.md` §4.



## 6. Validación antes/después

Matriz de validación. Por cada vulnerabilidad:
- ANTES (vulnerable): el PoC funciona.
- DESPUÉS (mitigado): el ataque falla o reduce impacto.
- Regresión: la funcionalidad legítima sigue operando.

| V# | Antes | Después | Regresión | Evidencia |
|----|-------|---------|-----------|-----------|
| V1 | PoC en `:4000`: `/allocations/3` con sesión de `user1` → Will Smith, exit 1 | PoC en `:4001`: `/allocations/3` y `/allocations/9999` → 403 + log `[SEC]`, exit 0; sin cookie → 302 a `/login` | `/allocations/2` sigue → John Doe | `docs/evidencias/V1/antes/`, `docs/evidencias/V1/despues/` |
| V2 | PoC en `:4000`: inyección `0' || '1'=='1` → HTTP 200, 3 filas (admin, John Doe, Will Smith), exit 1 | PoC en `:4001`: inyección → HTTP 400, 0 filas, exit 0; `threshold=<script>` no se refleja (sin XSS) | `threshold=10` válido → HTTP 200 (aceptado) | `docs/evidencias/V2/antes/`, `docs/evidencias/V2/despues/` |
| V3 | PoC en `:4000`: 4/4 contraseñas `TEXTO PLANO` (seed + signup), exit 1 | PoC en `:4001`: 4/4 `BCRYPT (cost=12)`, `$2a$12$`, 60 car., exit 0; logs `[REDACTED]` | Login correcto `302` (`v3test`, `admin`, `user1`); incorrecto `200`; signup OK | `docs/evidencias/V3/antes/`, `docs/evidencias/V3/despues/` |
| V4 | PoC en `:4000`: `v4_headers.sh` → 5 cabeceras ausentes + `X-Powered-By: Express`, `VULNERABLE`, exit 1 | PoC en `:4001`: 5 cabeceras de Helmet presentes, sin `X-Powered-By`, `MITIGADO`, exit 0; cookie `sessionId` con `HttpOnly` y `SameSite=Lax` | `regression_smoke.sh` en `:4001` (con `COOKIE_SECURE` sin definir): 5 `[PASS]`, login `302` → `/dashboard`, ruta interna `200` con sesión, `/dashboard` sin sesión no da 200 | `docs/evidencias/V4/antes/` (`evidencia_vulnerable.txt`, `Evidencia_01_V4_Cabeceras_Vulnerables.png`), `docs/evidencias/V4/despues/` (`evidencia_mitigada.txt`, `evidencia_regresion.txt`, `Evidencia_02_V4_Cabeceras_Seguras.png`, `Evidencia_03_V4_Sesion_Activa.png`, `Evidencia_04_V4_Cookie_Flags.png`) |

## 7. Conclusiones y reflexión ética

### 7.1 V1 — IDOR / Broken Access Control (JuanFra)

**Conclusiones técnicas**
- El fallo no estaba en la autenticación (el login funciona y `isLoggedIn` redirige bien sin cookie) sino en la **autorización**: el handler confiaba en un identificador que controla el cliente (`req.params.userId`) en lugar del de la sesión del servidor.
- El arreglo mínimo (usar `req.session.userId`) cerraba la fuga, pero la revisión del PR mostró que no bastaba como diseño: responder 200 con datos de otro usuario rompe la semántica REST, puede mezclar contenido en cachés por URL y no deja señal de ataque. La versión final compara ambos ids, responde **403** y registra `[SEC] Posible IDOR`.
- Una prueba debe cubrir más que el caso feliz: al ampliar el PoC se vio que, en la versión vulnerable, un id inexistente provoca un 500 no controlado, y en la mitigada devuelve 403.
- Limitaciones: solo se probó con `user1`; el rol admin recibe 403 al pedir el recurso de otro usuario (no hay excepción por diseño); la defensa vive en el handler, no en un middleware reutilizable para otras rutas con ids en la URL.

**Reflexión ética**
- Todas las pruebas se hicieron únicamente contra la instancia local en Docker (`:4000` y `:4001`), con las cuentas demo del propio seed del repo. No se tocó infraestructura ni datos de terceros.
- Las claves demo se pasan por la variable `POC_PASS` y no se guardan en scripts ni en evidencias; las capturas y salidas versionadas no contienen credenciales ni cookies de sesión.
- El PoC es de solo lectura: lee una vista ajena, no modifica ni borra datos y no genera carga.
- El mismo trabajo en un sistema real exigiría autorización previa y por escrito, y el hallazgo se reportaría al responsable antes de publicarlo. Un IDOR expone datos personales y financieros, así que el daño de no corregirlo recae sobre las personas usuarias, no sobre la organización.
- La revisión cruzada cambió una decisión de diseño; la sustentación debe presentarla tal cual (qué se hizo primero y por qué se cambió), sin ocultarla.


### 7.2 V2 — NoSQL Injection (Bryan)

**Conclusiones técnicas**
- La causa raíz no es "validar poco" sino **ejecutar la entrada como código**: el valor de `threshold` se interpolaba dentro de un `$where`, que corre JavaScript en el motor de Mongo. El arreglo correcto es quitar el canal de ejecución (`$where` → operador nativo `$gt`) y sanear el tipo de la entrada, no "escapar" el payload.
- La primera mitigación cerraba la inyección pero **abría un XSS reflejado**: el `throw` con la entrada cruda llegaba a la página de error, que renderiza `{{error}}` con `autoescape: false`. Lección: un parche debe revisarse como código nuevo; arreglar la vulnerabilidad objetivo no basta si introduce otra. Lo detectó la revisión cruzada (`@j-david06`), no yo.
- Validar con `Number()` era insuficiente (acepta `"1e1"`, `"0x10"`, espacios y arrays). La regex `^\d{1,2}$` sobre un `string` es más estricta y predecible.
- Un PoC debe poder **fallar de forma honesta**: la primera versión daba "MITIGADO" si el login fallaba. Se añadió un guard de línea base y la medición por código HTTP (válido → 200, inyección → 400), que es determinista pese a que `stocks` es aleatorio en el seed.
- Semántica del error: inicialmente el `threshold` inválido caía al `errorHandler` genérico y devolvía **HTTP 500**. Como es un error del cliente, se marcó el error y el handler de la ruta responde **HTTP 400** con un mensaje fijo (sin reflejar la entrada). El mapeo se hace en el handler y no en el `errorHandler`, que es compartido (V4).

**Reflexión ética**
- Todas las pruebas se hicieron solo contra la instancia local (`:4000` y `:4001`) con las cuentas demo del seed del repo. No se tocó infraestructura ni datos de terceros.
- El payload de **bucle infinito** (`'};while(true){}'`) se documenta como riesgo pero **no se ejecutó**: habría sido un DoS, prohibido por las condiciones del proyecto. El PoC usa solo una condición booleana de lectura.
- Las claves demo se pasan por `POC_PASS` y no se guardan en scripts ni evidencias; las salidas versionadas no contienen credenciales.
- La inyección NoSQL y el IDOR (V1) exponen ambos datos ajenos, pero son fallos distintos; presentarlos como "el mismo bug" sería incorrecto. La sustentación debe explicar por qué V2 es inyección (ejecución de código) y V1 es autorización.

### 7.3 V3 — Cryptographic Failures (JuanDa)

**Conclusión técnica.** El almacenamiento de contraseñas en texto plano (`user-dao.js:25`) y su comparación directa (`fromDB === fromUser`, `user-dao.js:61`) son una falla criptográfica de raíz: cualquier lectura de la base de datos —inyección, volcado, backup mal protegido u operador con acceso— exponía todas las credenciales reutilizables. La causa no fue un algoritmo débil sino la ausencia total de protección sobre un dato que nunca debe ser recuperable.

La mitigación aplicó cifrado de un solo sentido con `bcrypt` (cost=12): salt por usuario en el registro (`bcrypt.hash` asíncrono, `addUser`, `user-dao.js:27`) y verificación con `bcrypt.compare(plainFromUser, hashFromDB, cb)` asíncrono en el login (`user-dao.js:82`), con API asíncrona para no bloquear el event loop. El seed `artifacts/db-reset.js:104` usa `hashSync` por ser un script de un solo uso, de modo que los usuarios demo se crean ya con hash y se eliminan las contraseñas en claro del arranque. Validación antes/después: en `:4000` las 4 contraseñas se leen en texto plano (seed + signup); en `:4001` las 4 persisten como hash `bcrypt` (`$2a$12$`) no reversible, con login legítimo operando (regresión verde). El impacto baja de "exposición total de credenciales" a "hash computacionalmente costoso de revertir", alineado con A04:2025.

**Reflexión ética.** Custodiar credenciales implica responsabilidad directa: una sola decisión de diseño omitida compromete la privacidad de cada usuario registrado. Todo el ejercicio se ejecutó exclusivamente sobre la instancia local controlada, sin tocar sistemas de terceros ni infraestructura institucional. Ninguna contraseña, token o clave propia se versionó: las credenciales de prueba pasan por `POC_PASS`, nunca en archivos. Proteger un secreto no es endurecimiento opcional sino obligación mínima hacia el usuario, y el conocimiento ofensivo adquirido obliga a un uso estrictamente defensivo y autorizado.

### 7.4 V4 — Security Misconfiguration (Kevin)

**Conclusiones técnicas**
- El fallo no estaba en la lógica de la aplicación sino en la **configuración**: Express arranca sin cabeceras de seguridad, revela su tecnología y crea la cookie de sesión con el nombre por defecto y sin `Secure` ni `SameSite`. Los controles existían en el repositorio, pero comentados; una mala configuración es muchas veces un control que está disponible y no se activó.
- Cada cabecera cierra un vector concreto, pero **Helmet 2.3.0 emite solo cinco**. El primer PR afirmaba CSP y HSTS, y la revisión mostró que no era cierto. Lo que se documenta debe salir de lo que el servidor realmente responde (script y capturas), no de lo que se espera de la librería.
- El flag `Secure` no se puede activar a ciegas: con `secure: true` sobre HTTP la cookie no se emite y el login deja de persistir. Una mitigación que rompe la aplicación no es una mitigación; por eso se condicionó a `COOKIE_SECURE` y se añadió la prueba de regresión.
- Una prueba de regresión debe incluir un control negativo y verificar la cookie: `regression_smoke.sh` comprueba que `/dashboard` sin sesión no da 200, que llega `sessionId` y que con ella la ruta interna responde 200.
- Limitaciones: `Secure` queda desactivado en el entorno local (HTTP), así que la cookie viaja sin cifrar; no se probó el flujo completo bajo HTTPS; Helmet 2.3.0 no cubre CSP ni HSTS (exigiría actualizar la dependencia o configurarlos aparte); el script valida la presencia de las cabeceras, no su valor; y `autoescape: false`, CSRF y el HTTP plano quedan fuera de V4 y corresponden a otras vulnerabilidades.

**Reflexión ética**
- Todas las pruebas se hicieron únicamente contra la instancia local en Docker (`:4000` y `:4001`), con la cuenta demo del propio seed del repo. No se tocó infraestructura ni datos de terceros.
- Las credenciales demo se pasan por las variables `POC_USER` y `POC_PASS` y no se guardan en scripts ni en evidencias: el comando registrado en `evidencia_regresion.txt` muestra la clave como `<clave_demo>`. Las capturas muestran el identificador de una sesión de la instancia local de pruebas, sin valor fuera de ese entorno; no contienen contraseñas.
- El PoC es de solo lectura: lee cabeceras de respuesta y la prueba de regresión inicia sesión con la cuenta demo; no modifica ni borra datos y no genera carga.
- El mismo trabajo en un sistema real exigiría autorización previa y por escrito, incluso para un chequeo de cabeceras aparentemente pasivo, y el hallazgo se reportaría al responsable antes de publicarlo. Una mala configuración parece menor, pero un robo de sesión da acceso a una cuenta con datos personales y financieros, y revelar la tecnología facilita elegir un exploit. El daño recae sobre las personas usuarias, no sobre la organización.
- La revisión cruzada corrigió dos afirmaciones del primer PR (las cabeceras CSP/HSTS y `secure: true`); la sustentación debe presentarlo tal cual, y declarar que `Secure` no está activo en el entorno local, sin ocultarlo.

## 8. Referencias

- OWASP Top 10:2025 — https://owasp.org/Top10/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/
- OWASP VWAD — https://vwad.owasp.org/
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat
