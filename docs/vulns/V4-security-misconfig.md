# [V4] Security Misconfiguration

## 1. Identificación
- Categoría OWASP: A02:2025 — Security Misconfiguration (equiv. A05:2021)
- Dueño: Kevin | Revisor PR: JuanFra | Rama: `feat/v4-misconfig-kevin` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: la app arranca sin cabeceras de seguridad ni endurecimiento. `helmet` está importado pero comentado, `x-powered-by` no se desactiva (expone Express), la cookie de sesión no tiene flags `HttpOnly`/`Secure`/`SameSite`, el motor de plantillas `swig` tiene `autoescape: false`, CSRF está desactivado y el servidor corre en HTTP plano (sin HTTPS).
- Componente/archivo/config afectada (todo en `vulnerable/server.js`):
  - helmet y `app.disable("x-powered-by")` comentados (bloque A5)
  - `session({... saveUninitialized: true, resave: true ...})` sin `cookie: { httpOnly, secure, sameSite }`
  - `swig.setDefaults({ autoescape: false })`
  - `csrf()` comentado
  - `http.createServer(app)` en vez de HTTPS
- Causa raíz: configuración por defecto/insegura; faltan controles de endurecimiento en el middleware.
- Impacto y riesgo: facilita clickjacking, MIME sniffing, robo de cookie por JS (sin HttpOnly), XSS (autoescape off) y fuga de información tecnológica (`x-powered-by`, stack traces). Riesgo medio-alto por amplificar otras vulnerabilidades.

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: app corriendo en `http://localhost:4000`.
- Técnica/herramienta: inspección de cabeceras HTTP.
- Petición/payload/comando ejecutado:
  ```bash
  curl -sI http://localhost:4000/ | grep -iE "x-powered-by|x-frame-options|content-security-policy|strict-transport-security"
  ```
- Resultado obtenido: <aparece `x-powered-by: Express`, faltan cabeceras de seguridad> (evidencia: `docs/evidencias/V4/antes/...`)
- Explicación del impacto: superficie ampliada por ausencia de controles.

## 4. Mitigación
- Cambio aplicado: habilitar `helmet` (frameguard, noSniff, CSP, HSTS), `app.disable("x-powered-by")`, cookie de sesión `httpOnly`/`secure`/`sameSite`, manejador de errores genérico y, cuando aplique, HTTPS. Todos los fixes están señalados comentados en `server.js`.
- Justificación técnica: cada cabecera/flag cierra un vector concreto (clickjacking, sniffing, robo de cookie, downgrade).
- Diff:
  ```diff
  - // const helmet = require("helmet");
  + const helmet = require("helmet");
  ...
  + app.disable("x-powered-by");
  + app.use(helmet());
  + // session cookie: { httpOnly: true, secure: true, sameSite: "lax" }
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): `curl -sI` muestra `x-powered-by` y faltan cabeceras → evidencia `docs/evidencias/V4/antes/...`
- DESPUÉS (mitigado): helmet añade `X-Frame-Options`, `X-Content-Type-Options`, CSP, HSTS y oculta `x-powered-by` → evidencia `docs/evidencias/V4/despues/...`
- Regresión: la navegación y las funciones de la app siguen operando → evidencia ...
