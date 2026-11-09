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
| V4 | Security Misconfiguration | A02:2025 | `server.js` (helmet/x-powered-by/cookie/autoescape) | Kevin |

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

## 6. Validación antes/después

Matriz de validación. Por cada vulnerabilidad:
- ANTES (vulnerable): el PoC funciona.
- DESPUÉS (mitigado): el ataque falla o reduce impacto.
- Regresión: la funcionalidad legítima sigue operando.

| V# | Antes | Después | Regresión | Evidencia |
|----|-------|---------|-----------|-----------|
| V1 | PoC en `:4000`: `/allocations/3` con sesión de `user1` → Will Smith, exit 1 | PoC en `:4001`: `/allocations/3` y `/allocations/9999` → 403 + log `[SEC]`, exit 0; sin cookie → 302 a `/login` | `/allocations/2` sigue → John Doe | `docs/evidencias/V1/antes/`, `docs/evidencias/V1/despues/` |
| V2 | | | | |
| V3 | PoC en `:4000`: 4/4 contraseñas `TEXTO PLANO` (seed + signup), exit 1 | PoC en `:4001`: 4/4 `BCRYPT (cost=12)`, `$2a$12$`, 60 car., exit 0; logs `[REDACTED]` | Login correcto `302` (`v3test`, `admin`, `user1`); incorrecto `200`; signup OK | `docs/evidencias/V3/antes/`, `docs/evidencias/V3/despues/` |
| V4 | | | | |

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

## 8. Referencias

- OWASP Top 10:2025 — https://owasp.org/Top10/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/
- OWASP VWAD — https://vwad.owasp.org/
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat
