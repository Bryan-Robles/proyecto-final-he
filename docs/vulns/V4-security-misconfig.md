# [V4] Security Misconfiguration

## 1. Identificación
- Categoría OWASP: A02:2025 — Security Misconfiguration (equiv. A05:2021)
- Dueño: Kevin | Revisor PR: JuanFra | Rama: `feat/v4-sec-misconf-kevin` | Commits clave: Se actualizarán al hacer merge.

## 2. Análisis
- Descripción técnica: la app arranca sin cabeceras de seguridad ni endurecimiento. `helmet` está importado pero comentado, `x-powered-by` no se desactiva (expone Express), la cookie de sesión no tiene flags `HttpOnly`/`Secure`/`SameSite`, el motor de plantillas `swig` tiene `autoescape: false`, CSRF está desactivado y el servidor corre en HTTP plano.
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
- Técnica/herramienta: inspección de cabeceras HTTP en herramientas de desarrollador (pestaña Network).
- Petición/payload/comando ejecutado:
  Petición GET a la ruta raíz `/` (o `/login`).
- Resultado obtenido: La respuesta revela la cabecera `X-Powered-By: Express` y se evidencia la ausencia total de cabeceras de seguridad. Evidencia: `docs/evidencias/V4/antes/Evidencia_01_V4_Cabeceras_Vulnerables.png`.
- Explicación del impacto: superficie ampliada por ausencia de controles y revelación de stack tecnológico.

## 4. Mitigación
- Cambio aplicado: habilitar `helmet` versión 2.3.0 (inyecta `X-Frame-Options`, `X-Content-Type-Options`, `X-Download-Options`, `X-DNS-Prefetch-Control`, `X-XSS-Protection`), `app.disable("x-powered-by")` manual, y cookie de sesión con `httpOnly`, `sameSite: "lax"` y `secure` condicionado a HTTPS.
- Justificación técnica: cada cabecera/flag cierra un vector concreto (clickjacking, sniffing, robo de cookie). El flag `secure` se configuró a través de variable de entorno para no romper la sesión en el entorno local HTTP.
- Diff:
  ```diff
  - // const helmet = require("helmet");
  + const helmet = require("helmet");
  ...
  + app.disable("x-powered-by");
  + app.use(helmet());
  ...
    app.use(session({
        secret: cookieSecret,
        saveUninitialized: true,
        resave: true,
  -     // key: "sessionId",
  +     key: "sessionId",
        cookie: {
  -         httpOnly: true
  +         httpOnly: true,
  +         secure: process.env.COOKIE_SECURE === "true",
  +         sameSite: "lax"
        }
    }));