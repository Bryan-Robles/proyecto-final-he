# Guía de contribución

Flujo de trabajo del equipo para el proyecto final de Hacking Ético.

## Ramas
- `main`: protegida. Solo entra por Pull Request con **≥1 aprobación**.
- `baseline/vulnerable`: snapshot de la app vulnerable (tag `v0-vulnerable`).
- Una rama por vulnerabilidad: `feat/v<N>-<slug>-<autor>`.

## Commits (Conventional Commits)
`tipo(alcance): descripción` — tipos: `feat` (PoC), `fix` (mitigación), `test` (validación), `docs`, `chore`, `refactor`.

## Pull Requests
1. Trabaja tu rama y rellena la plantilla de PR (se carga sola).
2. Abre el PR hacia `main`. Un compañero (el revisor del área) lo aprueba.
3. Deben pasar los checks de CI (`lint`, `gitleaks`).
4. Resuelve los comentarios antes de mergear.

## Reglas de oro
- Solo se ataca la instancia **local** de la app aprobada. Nada de terceros.
- Prohibido DoS / ataques destructivos.
- **Nunca** subir contraseñas, tokens, claves ni `.env`. Usar valores de ejemplo.
- Evidencias reproducibles: comando → resultado, con fecha/hora y commit.

## Alcance del código
- `vulnerable/`: app sin tocar (baseline). **No modificar.**
- `mitigated/`: aquí van las correcciones.
