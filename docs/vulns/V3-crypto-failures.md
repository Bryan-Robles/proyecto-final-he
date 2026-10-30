# [V3] Cryptographic Failures (almacenamiento de contraseñas en texto plano)

## 1. Identificación
- Categoría OWASP: A04:2025 — Cryptographic Failures (equiv. A02:2021)
- Dueño: JuanDa | Revisor PR: Bryan | Rama: `feat/v3-crypto-juanda` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: al registrar un usuario, la contraseña se guarda tal cual la envía el cliente, en **texto plano**, en la colección `users`. En el login, la comparación es una igualdad de cadenas (`fromDB === fromUser`), no una verificación de hash. No hay salt ni función de derivación de clave. La librería `bcrypt-nodejs` está importada pero su uso está comentado.
- Componente/archivo/config afectada:
  - `vulnerable/app/data/user-dao.js:25` → `password //received from request param` (se guarda el valor plano)
  - `vulnerable/app/data/user-dao.js:61` → `return fromDB === fromUser;` (comparación en claro)
- Causa raíz: ausencia de hashing con salt en el almacenamiento de credenciales; se trata el password como dato normal.
- Impacto y riesgo: confidencialidad crítica — cualquier acceso a la base (dump, backup, otra vuln) revela todas las contraseñas directamente, con riesgo de reutilización en otros servicios. Riesgo alto.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: acceso de lectura a la Mongo local del laboratorio (vía contenedor).
- Técnica/herramienta: inspección de la colección `users` (mongo shell / script).
- Petición/payload/comando ejecutado:
  ```bash
  # (Día 3) leer un documento de usuario y mostrar el campo password
  docker compose exec mongo mongo nodegoat --quiet --eval 'db.users.findOne({}, {userName:1, password:1})'
  ```
- Resultado obtenido: <password en texto plano> (evidencia: `docs/evidencias/V3/antes/...`)
- Explicación del impacto: las credenciales son legibles directamente.

## 4. Mitigación
- Cambio aplicado: hashear con `bcrypt` + salt al registrar (`addUser`) y comparar con `bcrypt.compareSync` en `validateLogin`. Ambos fixes ya están señalados comentados en el código (`user-dao.js:29` y `:65`). Añadir migración de los hashes existentes.
- Justificación técnica: bcrypt aplica salt por usuario y coste configurable (≥10), haciendo inviable recuperar el password desde el almacenamiento.
- Diff:
  ```diff
  - password //received from request param
  + password: bcrypt.hashSync(password, bcrypt.genSaltSync())
  ```
  ```diff
  - return fromDB === fromUser;
  + return bcrypt.compareSync(fromUser, fromDB);
  ```
  > Ojo con el orden de argumentos de `bcrypt.compareSync(plano, hash)`: validar en el PoC del Día 3.

## 5. Validación (antes / después)
- ANTES (vulnerable): el campo `password` en Mongo está en texto plano → evidencia `docs/evidencias/V3/antes/...`
- DESPUÉS (mitigado): el campo `password` es un hash bcrypt (`$2a$`/`$2b$...`) → evidencia `docs/evidencias/V3/despues/...`
- Regresión: login con credenciales válidas sigue funcionando → evidencia ...
