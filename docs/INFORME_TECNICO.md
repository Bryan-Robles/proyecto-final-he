# Informe Técnico — Proyecto Final Hacking Ético

Universidad del Magdalena · Ingeniería de Sistemas · Periodo 2026-II
Equipo: JuanFra · Bryan · JuanDa · Kevin
Aplicación: OWASP NodeGoat (instancia local controlada)

---

## 1. Descripción y arquitectura del sistema

- Aplicación/API seleccionada:
- Propósito y principales funcionalidades:
- Tecnologías utilizadas:
- Arquitectura o componentes principales:
- Entorno utilizado para las pruebas:
- Superficie de ataque identificada:

## 2. Caracterización de las cuatro vulnerabilidades

Resumen de las 4 vulnerabilidades (detalle completo en `docs/vulns/Vx-*.md`).

| V# | Vulnerabilidad | Categoría OWASP 2025 | Componente afectado | Dueño |
|----|----------------|----------------------|---------------------|-------|
| V1 | IDOR / Broken Access Control | A01:2025 | | JuanFra |
| V2 | NoSQL Injection | A05:2025 | | Bryan |
| V3 | Cryptographic Failures (hash) | A04:2025 | | JuanDa |
| V4 | Security Misconfiguration | A02:2025 | | Kevin |

Para cada una: descripción técnica, componente/código/config afectada, causa raíz, categoría OWASP, impacto y riesgo.

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
