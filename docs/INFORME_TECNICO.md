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
| V1 | IDOR / Broken Access Control | A01:2025 | `routes/allocations.js:17-18` + `routes/index.js:63` | JuanFra |
| V2 | NoSQL Injection (`$where` en `threshold`) | A05:2025 | `data/allocations-dao.js:78` | Bryan |
| V3 | Cryptographic Failures (password en texto plano) | A04:2025 | `data/user-dao.js:25` y `:61` | JuanDa |
| V4 | Security Misconfiguration | A02:2025 | `server.js` (helmet/x-powered-by/cookie/autoescape) | Kevin |

Detalle completo en `docs/vulns/Vx-*.md` (descripción, causa raíz, impacto, PoC, mitigación, validación).

> **Nota V2:** se descartó el bypass de login con operadores Mongo (`{"$gt":""}`) porque NodeGoat compara el password en JavaScript (`user-dao.js:61`), no en la consulta; ese payload no evade el login. La NoSQL Injection documentada es la inyección de JS server-side vía `$where` en el parámetro `threshold` (misma categoría A05).

## 3. Evidencias de explotación controlada

Por cada vulnerabilidad: condición inicial, técnica/herramienta, petición/payload/comando, resultado obtenido, explicación del impacto. Evidencias reproducibles en `docs/evidencias/Vx/antes/`.

## 4. Análisis de impacto y relación con OWASP

Relación vulnerabilidad → impacto (CIA) → riesgo → categoría OWASP, justificando por qué esa categoría y no otra.

## 5. Mitigaciones implementadas

Por cada vulnerabilidad: cambio aplicado (código/config/diseño/control), justificación técnica, diff del cambio.

## 6. Validación antes/después

Matriz de validación. Por cada vulnerabilidad:
- ANTES (vulnerable): el PoC funciona.
- DESPUÉS (mitigado): el ataque falla o reduce impacto.
- Regresión: la funcionalidad legítima sigue operando.

| V# | Antes | Después | Regresión | Evidencia |
|----|-------|---------|-----------|-----------|
| V1 | | | | |
| V2 | | | | |
| V3 | | | | |
| V4 | | | | |

## 7. Conclusiones y reflexión ética

## 8. Referencias

- OWASP Top 10:2025 — https://owasp.org/Top10/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/
- OWASP VWAD — https://vwad.owasp.org/
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat
