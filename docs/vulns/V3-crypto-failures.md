# [V3] Cryptographic Failures (almacenamiento de contraseñas en texto plano)

## 1. Identificación
- **Categoría OWASP:** A04:2025 — Cryptographic Failures (equivalente a A02:2021). CWE-256 (Plaintext Storage of a Password), CWE-312 (Cleartext Storage of Sensitive Information).
- **Dueño:** JuanDa (`@j-david06`) | **Revisor PR:** Bryan (`@Bryan-Robles`) | **Rama:** `feat/v3-crypto-juanda` | **Tag:** `v3-mitigado`
- **Commits clave:**

| Commit | Tipo | Contenido |
|---|---|---|
| `b13ec59` | test(v3) | PoC `poc-scripts/v3_check_hash.js` y evidencia ANTES |
| `af58f1c` | feat(v3) | Reemplazo de `bcrypt-nodejs` 0.0.3 por `bcryptjs` 2.4.3 |
| `9c93620` | fix(v3) | Hash en signup (`addUser`) y verificación bcrypt en login (`validateLogin`) |
| `f24fca9` | fix(v3) | Seed (`db-reset.js`) hasheado y logs sin credenciales |
| `046473e` | test(v3) | Evidencia DESPUÉS y regresión de signup/login |

## 2. Análisis
- **Descripción técnica:** al registrar un usuario, la contraseña se guarda tal cual la envía el cliente, en **texto plano**, en la colección `users`. En el login, la verificación es una igualdad de cadenas (`fromDB === fromUser`), no la verificación de un hash. No hay sal ni función de derivación de clave. La librería `bcrypt-nodejs` está importada pero no se usa. El script de inicialización `artifacts/db-reset.js` también inserta los usuarios demo en claro y los imprime en los logs del contenedor en cada arranque.
- **Componentes afectados (versión vulnerable):**
  - `vulnerable/app/data/user-dao.js:27`: `password //received from request param` (se persiste el valor recibido).
  - `vulnerable/app/data/user-dao.js:60`: `return fromDB === fromUser;` (comparación en claro).
  - `vulnerable/app/data/user-dao.js:69`: `comparePassword(password, user.password)`. La firma declara `(fromDB, fromUser)` pero se llama con los argumentos al revés: los nombres de los parámetros están invertidos.
  - `vulnerable/artifacts/db-reset.js:20,28,35`: seed con contraseñas en claro; `:99` y `:110` las imprimen en el log.
- **Causa raíz:** la credencial se trata como un dato ordinario. Falta un control criptográfico de almacenamiento (hash lento con sal) en la capa de acceso a datos, tanto en el flujo de la aplicación (signup) como en el aprovisionamiento (seed).
- **Impacto:** confidencialidad crítica. Cualquier lectura de la colección `users` entrega todas las contraseñas listas para usar, sin necesidad de cracking: un volcado o backup filtrado, el acceso directo a Mongo, otra vulnerabilidad de lectura de datos o los logs del contenedor. Eso permite la toma inmediata de cuentas, incluida `admin`, y credential stuffing en otros servicios donde los usuarios reutilicen la contraseña.
- **Riesgo:** **Alto.** Impacto alto (C) con probabilidad media: requiere un vector de lectura de la BD, que en la misma app existe (ver V2) y en la práctica aparece en filtraciones de backups.

## 3. Explotación controlada (PoC reproducible)
- **Condición inicial:** `vulnerable/` levantada con Docker en `http://localhost:4000`, commit `03ae3e5`, seed por defecto (3 usuarios). Solo entorno local.
- **Técnica/herramienta:** inspección de solo lectura de la colección `users` con `poc-scripts/v3_check_hash.js` (Node + driver `mongodb` 2.x del proyecto). El script clasifica cada `password` como texto plano, hash rápido (MD5/SHA-1/SHA-256/SHA-512 sin sal) o bcrypt (`$2a$`/`$2b$`/`$2y$` y cost). **Enmascara los valores** en la salida: solo muestra el primer carácter y la longitud. Código de salida: 1 si hay inseguros, 0 si todo es bcrypt.
- **Comandos ejecutados:**
  ```bash
  # 1) Estado del seed
  docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js

  # 2) Registro legítimo por la app y nueva inspección
  curl -s -o /dev/null -w "signup %{http_code}\n" -X POST http://localhost:4000/signup \
    --data-urlencode "userName=v3test" --data-urlencode "firstName=V3" --data-urlencode "lastName=Test" \
    --data-urlencode "password=Prueba_123" --data-urlencode "verify=Prueba_123" --data-urlencode "email="
  docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js
  ```
- **Resultado obtenido:**
  ```text
  _id=1   user=admin        TEXTO PLANO                  A******** (len=9)
  _id=2   user=user1        TEXTO PLANO                  U******** (len=9)
  _id=3   user=user2        TEXTO PLANO                  U******** (len=9)
  _id=4   user=v3test       TEXTO PLANO                  P******** (len=10)
  [V3] Total: 4 | inseguros: 4
  [V3] RESULTADO: VULNERABLE - contrasenas recuperables desde la BD (A04:2025)
  ```
  Evidencia: `docs/evidencias/V3/antes/` (`poc_v3_seed.txt/.png`, `poc_v3_signup.txt/.png`, `README.md`).
- **Explicación del impacto:** el usuario creado por el flujo normal de la aplicación (`/signup`) queda en claro, así que el fallo está en el código de la app y no solo en los datos de ejemplo. El valor almacenado es exactamente la contraseña: quien lea la colección inicia sesión como cualquier usuario.

## 4. Mitigación
- **Cambios aplicados (solo en `mitigated/`):**
  1. **Dependencia:** `bcrypt-nodejs` 0.0.3 reemplazado por `bcryptjs` 2.4.3 (`mitigated/package.json:8`, lock actualizado).
  2. **Signup:** `addUser` deriva la contraseña con `bcrypt.hash(password, SALT_ROUNDS, cb)` antes de construir el documento. Solo se persiste el hash (`mitigated/app/data/user-dao.js:24,35`).
  3. **Login:** `comparePassword(plainFromUser, hashFromDB, cb)` usa `bcrypt.compare(plano, hash)` y rechaza las entradas que no sean `string` (`mitigated/app/data/user-dao.js:67-71`).
  4. **Seed:** `db-reset.js` hashea los usuarios demo con el mismo costo antes de insertarlos. En los logs, `password` aparece como `[REDACTED]` y de `insertMany` solo se registra el conteo (`mitigated/artifacts/db-reset.js:12-13` y bloque de inserción).
  5. **Costo:** `SALT_ROUNDS = max(10, BCRYPT_SALT_ROUNDS || 12)`. Por defecto es 12, configurable por variable de entorno, y nunca baja de 10.
- **Justificación técnica:**
  - **bcrypt y no SHA-256/MD5:** los hashes rápidos permiten miles de millones de intentos por segundo en GPU. bcrypt es una función de derivación deliberadamente lenta, con factor de costo ajustable (2^cost rondas de expansión de clave) y sal aleatoria de 128 bits por usuario, embebida en el propio hash (`$2a$12$<22 car. de sal><31 car. de hash>`). La sal anula las rainbow tables y hace que dos usuarios con la misma contraseña tengan hashes distintos.
  - **`bcryptjs` en lugar de `bcrypt-nodejs` o `bcrypt` nativo:** `bcrypt-nodejs` está abandonado y marcado *deprecated* en npm. `bcrypt` (nativo) requiere node-gyp, Python y un compilador en `node:12-alpine`, o binarios precompilados. `bcryptjs` es JavaScript puro, sin compilación, y produce un formato compatible. A cambio es aproximadamente un 30 % más lento, lo que se compensa con el factor de costo.
  - **Cost 12:** OWASP Password Storage Cheat Sheet exige un mínimo de 10 para bcrypt. Benchmark de `bcryptjs` 2.4.3 (Xeon 2.1 GHz): cost 10 ≈ 95 ms, 11 ≈ 142 ms, **12 ≈ 325 ms**, 13 ≈ 628 ms. Con 12, el login cuesta unos 0,3 s, aceptable para el usuario, y cada intento de fuerza bruta offline cuesta lo mismo al atacante.
  - **API asíncrona:** `hashSync`/`compareSync` bloquearían el event loop de Node unos 300 ms por petición y congelarían a todos los usuarios concurrentes. `bcrypt.hash`/`bcrypt.compare` de `bcryptjs` reparten el trabajo con `setImmediate`. En `db-reset.js` se usa `hashSync` porque es un script de un solo uso, no el servidor.
  - **Orden de argumentos:** la firma es `compare(texto_plano, hash)`. Con el orden invertido **devuelve `false` sin lanzar error**, y el login falla en silencio. El fix comentado del upstream (`compareSync(fromDB, fromUser)`) solo funcionaba porque los nombres de los parámetros también estaban invertidos. Se renombraron a `(plainFromUser, hashFromDB)` para que el código sea correcto y legible.
  - **Límite de 72 bytes de bcrypt:** no aplica aquí, porque `PASS_RE` limita la contraseña a 20 caracteres.
  - **Migración:** no hace falta en el laboratorio, porque `db-reset.js` recrea la colección en cada arranque. En producción se aplicaría una migración perezosa: en el siguiente login correcto contra el valor heredado, re-hashear y reemplazar; luego, forzar el reseteo de las cuentas que no inicien sesión.
- **Diff (resumen):**
  ```diff
  - const bcrypt = require("bcrypt-nodejs");
  + const bcrypt = require("bcryptjs");
  + const SALT_ROUNDS = Math.max(10, parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12);
  ```
  ```diff
  -     password //received from request param
  +     bcrypt.hash(password, SALT_ROUNDS, (err, passwordHash) => {
  +         ...
  +         password: passwordHash // V3: nunca se guarda el valor recibido
  ```
  ```diff
  - const comparePassword = (fromDB, fromUser) => {
  -     return fromDB === fromUser;
  + const comparePassword = (plainFromUser, hashFromDB, cb) => {
  +     if (typeof plainFromUser !== "string" || typeof hashFromDB !== "string") {
  +         return cb(null, false);
  +     }
  +     return bcrypt.compare(plainFromUser, hashFromDB, cb);
  ```
  ```diff
  - usersCol.insertMany(USERS_TO_INSERT, ...)
  + const usersToInsert = USERS_TO_INSERT.map((user) => Object.assign({}, user, {
  +     password: bcrypt.hashSync(user.password, SALT_ROUNDS)
  + }));
  + usersCol.insertMany(usersToInsert, ...)
  ```
  Diff completo: `git diff 03ae3e5 v3-mitigado -- mitigated/`.

## 5. Validación (antes / después)

| Prueba | ANTES (`:4000`, vulnerable) | DESPUÉS (`:4001`, mitigado) |
|---|---|---|
| PoC sobre el seed | 3/3 `TEXTO PLANO`, exit 1 | 3/3 `BCRYPT (cost=12)`, `$2a$12$`, len 60, exit 0 |
| PoC tras `/signup` (`v3test`) | `TEXTO PLANO` | `BCRYPT (cost=12)` |
| Logs de `db-reset` | contraseñas en claro | `"password":"[REDACTED]"` |
| Login correcto (`v3test`, `admin`, `user1`) | — | `302` a `/dashboard` o `/benefits` |
| Login incorrecto | — | `200` (formulario con error) |

- **ANTES:** `docs/evidencias/V3/antes/` (`poc_v3_seed.*`, `poc_v3_signup.*`).
- **DESPUÉS:** `docs/evidencias/V3/despues/` (`poc_v3_seed.*`, `poc_v3_signup.*`).
- **Regresión:** `docs/evidencias/V3/despues/regresion_login.txt/.png`. El signup y el login legítimos siguen operando.
- **Pruebas adicionales de la lógica (BD simulada):** login con un objeto como contraseña (`{"$gt":""}`) se rechaza con `invalidPassword` sin lanzar error. Un valor heredado en texto plano en la BD ya no permite iniciar sesión.

## 6. Riesgo residual y fuera de alcance
- **Enumeración de usuarios (A07:2025):** los errores `Invalid password` y `User ... does not exist` distinguen si el usuario existe, y el tiempo de respuesta también: solo se ejecuta bcrypt si el usuario existe. Se documenta pero no se corrige aquí, para mantener las 4 vulnerabilidades de naturaleza distinta.
- **Política de contraseñas débil:** `PASS_RE` acepta 1–20 caracteres de cualquier tipo. bcrypt encarece la fuerza bruta offline, pero no protege contraseñas triviales.
- **Credenciales demo en el código del seed:** `db-reset.js` conserva `Admin_123`, `User1_123` y `User2_123` porque son las credenciales públicas y documentadas del laboratorio, necesarias para la demo. En producción el aprovisionamiento usaría un gestor de secretos o variables de entorno.
- **Sin pepper ni rotación de costo:** mejoras posibles. Un pepper en un secreto del servidor y el re-hash en el login cuando `getRounds(hash) < SALT_ROUNDS`.
