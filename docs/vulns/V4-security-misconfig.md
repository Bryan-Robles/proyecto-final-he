# [V4] Security Misconfiguration

## 1. Identificación
- Categoría OWASP: A02:2025 — Security Misconfiguration (equiv. A05:2021)
- Dueño: Kevin | Revisor PR: JuanFranG | Rama: `feat/v4-sec-misconf-kevin` | Commits clave: `0f5b8bd`, `d74a853`, `66ba532`, `d1e7076`, `24555f9` (PoC: `v4_headers.sh`, `regression_smoke.sh` y evidencias)

## 2. Análisis
- Descripción técnica: la app arranca sin cabeceras de seguridad ni endurecimiento. `helmet` está importado pero comentado, `x-powered-by` no se desactiva (expone Express), la cookie de sesión no tiene flags `HttpOnly`/`Secure`/`SameSite`, el motor de plantillas `swig` tiene `autoescape: false`, CSRF está desactivado y el servidor corre en HTTP plano.
- Componente/archivo/config afectada (todo en `vulnerable/server.js`):
  - helmet y `app.disable("x-powered-by")` comentados (bloque A5)
  - `session({... saveUninitialized: true, resave: true ...})` sin `cookie: { httpOnly, secure, sameSite }`
  - `swig.setDefaults({ autoescape: false })`
  - `csrf()` comentado
  - `http.createServer(app)` en vez de HTTPS
- Causa raíz: configuración por defecto/insegura; faltan controles de endurecimiento en el middleware.
- Impacto y riesgo: facilita clickjacking, MIME sniffing, y robo de cookie por JS (sin HttpOnly). Riesgo medio-alto por amplificar otras vulnerabilidades. *(Nota: `autoescape: false`, CSRF y HTTP plano están fuera del alcance de V4; corresponden a vulnerabilidades de otros integrantes).*

## 3. Explotación controlada (PoC reproducible)
## 3. Explotación controlada (PoC reproducible)
- Condición inicial: app vulnerable corriendo en `http://localhost:4000`.
- Técnica/herramienta: script PoC `poc-scripts/v4_headers.sh` (usa `curl`). Pide la URL, lee solo las cabeceras de respuesta y comprueba que estén las 5 cabeceras de seguridad de Helmet 2.3.0 y que `X-Powered-By` no aparezca. Códigos de salida: `1` = VULNERABLE, `0` = MITIGADO, `2` = error (app apagada o URL incorrecta). *(La inspección manual en la pestaña Network del navegador da el mismo resultado, pero el script lo hace reproducible.)*
- Petición/payload/comando ejecutado:
  ```bash
  ./poc-scripts/v4_headers.sh http://localhost:4000/
  ```
- Resultado obtenido: el script reporta `VULNERABLE (6 problema(s) de configuracion de cabeceras)`: faltan las 5 cabeceras de seguridad y se expone `x-powered-by`, que revela el stack tecnológico (Express). Salida completa en `docs/evidencias/V4/antes/evidencia_vulnerable.txt` y captura en `docs/evidencias/V4/antes/Evidencia_01_V4_Cabeceras_Vulnerables.png`.
  ```text
  URL analizada : http://localhost:4000/
  Respuesta     : http/1.1 302 found
  -----------------------------------------------
  [FALTA] ausente  : x-frame-options
  [FALTA] ausente  : x-content-type-options
  [FALTA] ausente  : x-download-options
  [FALTA] ausente  : x-dns-prefetch-control
  [FALTA] ausente  : x-xss-protection
  [FALLA] expuesta : x-powered-by (revela el stack tecnologico)
  -----------------------------------------------
  VULNERABLE (6 problema(s) de configuracion de cabeceras)
  ```
- Explicación del impacto: superficie ampliada por ausencia de controles y revelación de stack tecnológico.

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
## 5. Validación (antes / después)
- ANTES (vulnerable): `./poc-scripts/v4_headers.sh http://localhost:4000/` reporta `VULNERABLE (6 problema(s))`; el panel de red muestra `x-powered-by` expuesto y faltan cabeceras de seguridad → evidencia `docs/evidencias/V4/antes/evidencia_vulnerable.txt` y captura `docs/evidencias/V4/antes/Evidencia_01_V4_Cabeceras_Vulnerables.png`.
- DESPUÉS (mitigado, app en `http://localhost:4001`): `./poc-scripts/v4_headers.sh http://localhost:4001/` reporta `MITIGADO`; Helmet 2.3.0 añade las 5 cabeceras de seguridad y se oculta `x-powered-by` → evidencia `docs/evidencias/V4/despues/evidencia_mitigada.txt` y captura `docs/evidencias/V4/despues/Evidencia_02_V4_Cabeceras_Seguras.png`.
- Regresión: `./poc-scripts/regression_smoke.sh` contra la app mitigada pasa las 5 verificaciones (`SMOKE TEST: OK`). La navegación y el inicio de sesión operan sin romperse bajo HTTP (POST /login responde 302 hacia /dashboard con la sesión activa) → evidencia `docs/evidencias/V4/despues/evidencia_regresion.txt` y captura `docs/evidencias/V4/despues/Evidencia_03_V4_Sesion_Activa.png`. Flags de la cookie (HttpOnly, SameSite=Lax) → captura `docs/evidencias/V4/despues/Evidencia_04_V4_Cookie_Flags.png`.