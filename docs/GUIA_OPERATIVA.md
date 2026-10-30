# Guía Operativa — Proyecto Final Hacking Ético (7 días)

Universidad del Magdalena · Ingeniería de Sistemas · Periodo 2026-II
Equipo (4): JuanFra · Bryan · JuanDa · Kevin

Panel de control del proyecto. Marcar los `[ ]` a medida que se avanza. Cada vulnerabilidad sigue el ciclo obligatorio: **Identificación → Análisis → Explotación controlada → Mitigación → Validación**.

## Caja de ética (leer antes de teclear nada)
- Solo sobre la instancia local/controlada de la app aprobada por el docente.
- Nada de terceros, infraestructura institucional, credenciales reales ni datos personales.
- Prohibido DoS / ataques destructivos. No tirar la app ni borrar datos de forma irreversible.
- Sanitizar siempre antes de `git push`: nada de contraseñas, tokens, claves, `.env` o secretos en el repo.
- Evidencias reproducibles: comando → resultado, con fecha/hora y commit asociado.

## App y vulnerabilidades
App: **OWASP NodeGoat** (Node + Express + MongoDB). Levantar: `docker-compose up` → http://localhost:4000

Regla de oro: las 4 vulnerabilidades deben caer en **categorías OWASP distintas** (no valen 2 instancias del mismo fallo).

| V# | Vulnerabilidad | OWASP 2025 | Dueño (R) | Revisor PR |
|----|----------------|-----------|-----------|-----------|
| V1 | IDOR / Broken Access Control | A01:2025 | JuanFra | Kevin |
| V2 | NoSQL Injection | A05:2025 | Bryan | JuanDa |
| V3 | Cryptographic Failures (hash) | A04:2025 | JuanDa | Bryan |
| V4 | Security Misconfiguration | A02:2025 | Kevin | JuanFra |

## Git: ramas, commits, PRs
- Ramas: `baseline/vulnerable` (tag `v0-vulnerable`) + una `feat/v<N>-<slug>-<autor>` por vuln.
- Commits (Conventional Commits): `feat` (PoC), `fix` (mitigación), `test` (validación), `docs`, `chore`, `refactor`.
- Tags de hito: `v0-vulnerable`, `v<N>-mitigado`.
- Flujo PR: cada integrante trabaja su rama → abre PR a `main` → revisión cruzada obligatoria por otro integrante → merge solo tras aprobación.
- Trazabilidad: 1 vuln = 1 rama = 1 PR por integrante + commits con su autoría.

## Cronograma 7 días
- **Día 1 — Setup + selección (JuanFra):** elegir app y pedir aprobación docente (bloqueante); levantar con Docker; crear repo + estructura + `.gitignore` + `.env.example`; commit base + `baseline/vulnerable` + tag `v0-vulnerable` + push.
- **Día 2 — Caracterización + recon (JuanFra):** documentar sistema (propósito, tecnologías, arquitectura, entorno, superficie de ataque); reconocimiento de rutas/endpoints/parámetros/roles; pre-identificar y confirmar las 4 vulns; crear `INFORME_TECNICO.md` + 4 plantillas `vulns/Vx-*.md`.
- **Día 3 — Explotación / PoC (Bryan + JuanDa fuerte; JuanFra y Kevin en paralelo):** cada uno ejecuta el PoC reproducible de SU vuln; guardar evidencia "ANTES" en `docs/evidencias/Vx/antes/` y script en `poc-scripts/`; commits `feat(vX)`.
- **Día 4 — Mitigación (Bryan + JuanDa lideran):** implementar mitigación en `mitigated/` con justificación técnica; commits `fix(vX)`; tag `vX-mitigado`; empieza revisión cruzada de PRs.
- **Día 5 — Validación + regresión (Kevin lidera scripts):** reejecutar cada PoC contra `mitigated/` (debe fallar/reducir impacto), evidencia "DESPUÉS"; `regression_smoke.sh` confirma funcionalidad legítima; cerrar cada `vulns/Vx-*.md`.
- **Día 6 — Freeze + limpieza + informe (equipo):** code freeze, merge de los 4 PRs a `main`; barrido de secretos (`gitleaks detect --source .`); prueba completa de funcionalidad legítima; consolidar `INFORME_TECNICO.md` + referencias.
- **Día 7 — Simulacro de sustentación (equipo, vale 75 pts):** dejar ambas versiones corriendo (`:4000` vulnerable, `:4001` mitigada); rotación cruzada (cada uno explica las 4); 2 rondas de preguntas; verificar que los PoC corren en frío sin internet.

## Sustentación (75 pts) — guion por vulnerabilidad (~90 s)
1. "Esta es V_, categoría OWASP A0X:2025." (una frase de qué es)
2. Mostrar el ataque en `:4000` → funciona. (impacto)
3. Mostrar el mismo ataque en `:4001` → falla. (mitigación)
4. Mostrar el diff del código que lo arregla + regresión (login normal sigue andando).

Dominio cruzado: el docente elige al azar, cada integrante debe poder explicar y demostrar las 4.

## Checklist maestro de entrega
- [ ] 4 vulnerabilidades de categorías OWASP distintas, ciclo completo en cada una.
- [ ] Informe técnico con las 8 secciones.
- [ ] Repo con `vulnerable/` + `mitigated/` (o ramas/tags), README, `poc-scripts/`, evidencias.
- [ ] PR y commits verificables de los 4 integrantes.
- [ ] Validación antes/después + regresión de funcionalidad legítima.
- [ ] Repo sin secretos (gitleaks limpio).
- [ ] Equipo capaz de defender cualquiera de las 4 en vivo.

## Referencias
- OWASP Top 10:2025 — https://owasp.org/Top10/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/
- OWASP VWAD — https://vwad.owasp.org/
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat
- Conventional Commits — https://www.conventionalcommits.org/
