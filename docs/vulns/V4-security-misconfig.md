# [V4] Security Misconfiguration

## 1. Identificación
- Categoría OWASP: A02:2025 — Security Misconfiguration (equiv. A05:2021)
- Dueño: Kevin | Revisor PR: JuanFranG | Rama: `feat/v4-sec-misconf-kevin` | Commits clave: `0f5b8bd`, `d74a853` (mitigación), `24555f9` (PoC y smoke), `74a4bf4` (ajustes de revisión del PR #10)

## 2. Análisis
- Descripción técnica: la app arranca sin cabeceras de seguridad ni endurecimiento. `helmet` está importado pero comentado, `x-powered-by` no se desactiva (expone Express), la cookie de sesión usa el nombre por defecto `connect.sid` y no define `SameSite` ni `Secure` (`HttpOnly` ya viene activo por defecto en `express-session`; ver `docs/evidencias/V4/antes/evidencia_cookie.txt`), el motor de plantillas `swig` tiene `autoescape: false`, CSRF está desactivado y el servidor corre en HTTP plano.
- Componente/archivo/config afectada (todo en `vulnerable/server.js`):
  - helmet y `app.disable("x-powered-by")` comentados (bloque A5)
  - `session({... saveUninitialized: true, resave: true ...})` sin `key` y sin `cookie: { secure, sameSite }` (el bloque está comentado)
  - `swig.setDefaults({ autoescape: false })`
  - `csrf()` comentado
  - `http.createServer(app)` en vez de HTTPS
- Causa raíz: configuración por defecto/insegura; faltan controles de endurecimiento en el middleware.
- Impacto y riesgo: facilita clickjacking, MIME sniffing, y envío de la cookie en peticiones entre sitios (sin `SameSite`). Riesgo medio-alto por amplificar otras vulnerabilidades. *(Nota: `autoescape: false`, CSRF y HTTP plano están fuera del alcance de V4; corresponden a vulnerabilidades de otros integrantes).*

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: app vulnerable corriendo en `http://localhost:4000`.
- Técnica/herramienta: lectura de las cabeceras de respuesta HTTP, primero a mano en las herramientas de desarrollador (pestaña Network) y después automatizada con `poc-scripts/v4_headers.sh` (curl sin cuerpo, compara contra las 5 cabeceras que emite Helmet 2.3.0 y la ausencia de `X-Powered-By`).
- Petición/payload/comando ejecutado:
  ```bash
  ./poc-scripts/v4_headers.sh http://localhost:4000/
  ```
- Resultado obtenido: faltan `x-frame-options`, `x-content-type-options`, `x-download-options`, `x-dns-prefetch-control` y `x-xss-protection`, y se expone `X-Powered-By: Express`: `VULNERABLE (6 problema(s))`, exit 1. La cookie llega como `connect.sid` con solo `HttpOnly` (por defecto), sin `SameSite` ni `Secure`. Evidencia: `docs/evidencias/V4/antes/` (`evidencia_vulnerable.txt`, `evidencia_cookie.txt`, `Evidencia_01_V4_Cabeceras_Vulnerables.png`), con fecha y commit en cada archivo.
- Explicación del impacto: superficie ampliada por ausencia de controles y revelación del stack tecnológico.

## 4. Mitigación
- Cambio aplicado: habilitar `helmet` versión 2.3.0 (inyecta `X-Frame-Options`, `X-Content-Type-Options`, `X-Download-Options`, `X-DNS-Prefetch-Control`, `X-XSS-Protection`), `app.disable("x-powered-by")` manual, y cookie de sesión con `httpOnly`, `sameSite: "lax"` y `secure` controlado por la variable `COOKIE_SECURE` (solo se activa bajo HTTPS), y nombre de cookie genérico (key: "sessionId") en lugar del nombre por defecto.
- Justificación técnica: cada cabecera/flag cierra un vector concreto (clickjacking, sniffing, robo de cookie). `secure` queda en `false` por defecto porque el servidor usa `http.createServer`. Se activa con `COOKIE_SECURE=true` únicamente cuando el servidor corra bajo HTTPS (bloque HTTPS de `server.js`, hoy comentado). Riesgo residual: en HTTP la cookie viaja sin `Secure`.
- Diff:
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

## 5. Validación (antes / después)
- ANTES (vulnerable, `:4000`): `v4_headers.sh` → `VULNERABLE (6 problema(s))`, exit 1 → `docs/evidencias/V4/antes/evidencia_vulnerable.txt` y `Evidencia_01_V4_Cabeceras_Vulnerables.png`. Cookie `connect.sid` sin `SameSite` → `antes/evidencia_cookie.txt`.
- DESPUÉS (mitigado, `:4001`): `v4_headers.sh` → `MITIGADO`, exit 0 (Helmet 2.3.0 añade las 5 cabeceras y se oculta `X-Powered-By`) → `docs/evidencias/V4/despues/evidencia_mitigada.txt` y `Evidencia_02_V4_Cabeceras_Seguras.png`. Cookie `sessionId` con `HttpOnly; SameSite=Lax` → `despues/evidencia_cookie.txt` y `Evidencia_04_V4_Cookie_Flags.png`.
- Regresión: `poc-scripts/regression_smoke.sh` en `:4001` → 5 `[PASS]` (login 302 a `/dashboard`, cookie `sessionId` recibida, `/dashboard` 200 con sesión y no 200 sin ella) → `despues/evidencia_regresion.txt` y `Evidencia_03_V4_Sesion_Activa.png`.
- Limitación: `Secure` queda en `false` por defecto porque el servidor usa HTTP; con `COOKIE_SECURE=true` sobre HTTP la cookie no se emite y la sesión no persiste. El script valida la presencia de las cabeceras, no su valor.
