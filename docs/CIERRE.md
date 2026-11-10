# Cierre del proyecto (Día 6)

Universidad del Magdalena · Hacking Ético · 2026-II
Equipo: JuanFra · Bryan · JuanDa · Kevin

Documento de cierre: estado final del repositorio antes de la sustentación.

**Evaluación (confirmada con el docente):** 30 pts entrega + 90 pts sustentación = **120 pts**.

## Estado final

Las **cuatro** vulnerabilidades están identificadas, explotadas, mitigadas y validadas,
cada una en categoría OWASP distinta y con su ciclo completo documentado.

| V# | Vulnerabilidad | OWASP 2025 | Dueño | Tag | Estado |
|----|----------------|-----------|-------|-----|--------|
| V1 | IDOR / Broken Access Control | A01:2025 | JuanFra | `v1-mitigado` | ✅ |
| V2 | NoSQL Injection (`$where`) | A05:2025 | Bryan | `v2-mitigado` | ✅ |
| V3 | Cryptographic Failures (passwords) | A04:2025 | JuanDa | `v3-mitigado` | ✅ |
| V4 | Security Misconfiguration | A02:2025 | Kevin | `v4-mitigado` | ✅ |

Baseline vulnerable: tag `v0-vulnerable`.

## Checklist maestro de entrega

- [x] 4 vulnerabilidades de categorías OWASP distintas, ciclo completo en cada una.
- [x] Informe técnico con las 8 secciones (`docs/INFORME_TECNICO.md`).
- [x] Repo con `vulnerable/` + `mitigated/`, `README`, `poc-scripts/`, evidencias.
- [x] Fichas por vulnerabilidad (`docs/vulns/V1..V4-*.md`).
- [x] PR y commits verificables de los 4 integrantes (revisión cruzada por CODEOWNERS).
- [x] Validación antes/después + regresión de funcionalidad legítima.
- [x] Tags `v0-vulnerable` y `v<N>-mitigado` para las 4.
- [x] Repo sin secretos reales (ver `docs/evidencias/barrido_secretos.txt`; gitleaks en CI en verde).
- [ ] Equipo capaz de defender cualquiera de las 4 en vivo (simulacro, Día 7).

## Integridad del repositorio

- **CI activo y bloqueante en `main`:** `lint` + `gitleaks` (checks requeridos) y `smoke-docker` (informativo). `main` protegida: merge solo por PR con ≥1 aprobación, ramas al día y conversaciones resueltas.
- **Barrido de secretos:** limpio. Detalle en `docs/evidencias/barrido_secretos.txt`.
- **Alcance:** las 4 vulnerabilidades elegidas están corregidas; `mitigated/` conserva a propósito otras debilidades fuera del alcance (autoescape, CSRF, HTTP) — documentadas en el informe, sección "Alcance y limitaciones conocidas".

## Cómo correr todo en frío (sustentación)

```bash
# Terminal A - versión vulnerable
docker compose -f vulnerable/docker-compose.yml up -d --build   # http://localhost:4000

# Terminal B - versión mitigada
docker compose -f mitigated/docker-compose.yml up -d --build    # http://localhost:4001

# PoC (la clave demo se pasa por POC_PASS, nunca en archivos)
BASE=http://localhost:4000 POC_PASS=<clave> POC_USER=user1 ./poc-scripts/v1_idor.sh      # exit 1
BASE=http://localhost:4000 POC_PASS=<clave>                python3 poc-scripts/v2_nosqli.py   # exit 1
docker compose -f vulnerable/docker-compose.yml exec -T web node - < poc-scripts/v3_check_hash.js  # exit 1
BASE=http://localhost:4000                                 ./poc-scripts/v4_headers.sh      # exit 1
# repetir con BASE=http://localhost:4001 -> exit 0 (mitigado)
```

## Pendiente (Día 7, requiere al equipo)

- Simulacro de sustentación cruzada: cada integrante explica y demuestra las 4 vulnerabilidades (el docente elige al azar). La defensa vale 90 de los 120 pts.
- Verificar que los PoC corren en frío, sin internet, en el equipo de la demo.
