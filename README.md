# Proyecto Final — Hacking Ético (2026-II)

**Análisis, explotación y mitigación de vulnerabilidades en aplicaciones web y APIs**

Ingeniería de Sistemas · Universidad del Magdalena · Periodo 2026-II

## Equipo

| Rol | Integrante | Vulnerabilidad (dueño) | Categoría OWASP 2025 |
|-----|-----------|------------------------|----------------------|
| Setup/repo/base | JuanFra | V1 – IDOR / Broken Access Control | A01:2025 |
| PoC/mitigación | Bryan | V2 – NoSQL Injection | A05:2025 |
| PoC/mitigación | JuanDa | V3 – Cryptographic Failures (hash) | A04:2025 |
| Scripts/validación/informe | Kevin | V4 – Security Misconfiguration | A02:2025 |

Todos revisan y dominan las 4. Revisión cruzada de PRs obligatoria.

## Aplicación objetivo

**OWASP NodeGoat** (Node.js + Express + MongoDB) — aplicación deliberadamente vulnerable del OWASP VWAD, aprobada por el docente.

Repositorio upstream: https://github.com/OWASP/NodeGoat

> **Alcance ético:** todas las pruebas se ejecutan únicamente sobre la instancia local/controlada de NodeGoat. Nada de terceros, infraestructura institucional, credenciales reales ni datos personales. Prohibido DoS o ataques destructivos.

## Cómo levantar el entorno

### Versión vulnerable (baseline)

```bash
cd vulnerable
docker-compose up        # app en http://localhost:4000 + MongoDB
```

### Versión mitigada

```bash
cd mitigated
docker-compose up        # app en http://localhost:4001 + MongoDB
```

Para la sustentación se dejan **ambas corriendo en paralelo** (4000 vulnerable, 4001 mitigada) para mostrar antes/después sin rebuilds en vivo.

El usuario de prueba se crea desde la propia app (*Sign up*) o con el seed incluido.

## Estructura del repositorio

```
proyecto-final-he/
├── README.md                     # este archivo
├── docs/
│   ├── GUIA_OPERATIVA.md         # panel de control del proyecto (7 días)
│   ├── INFORME_TECNICO.md        # informe de 8 secciones
│   ├── vulns/                    # plantilla por vulnerabilidad (V1–V4)
│   └── evidencias/               # capturas, gifs, salidas de consola (antes/despues)
├── vulnerable/                   # NodeGoat SIN parchar (baseline)
├── mitigated/                    # NodeGoat YA parchado
├── poc-scripts/                  # scripts de PoC + regresión
├── .gitignore                    # ignora .env, *.key, *.pem, node_modules, dumps
└── .env.example                  # variables SIN valores reales
```

## Flujo de trabajo

- 1 vulnerabilidad = 1 rama `feat/v<N>-<slug>-<autor>` = 1 PR hacia `main`, revisado por otro integrante.
- Commits con [Conventional Commits](https://www.conventionalcommits.org/): `feat` (PoC), `fix` (mitigación), `test` (validación), `docs`.
- Tags de hito: `v0-vulnerable` (base), `v<N>-mitigado` por vulnerabilidad.
- Las evidencias deben ser reproducibles: comando → resultado, con fecha/hora y commit asociado.

## Evaluación

| Componente | Puntaje |
|-----------|---------|
| Entrega del proyecto | 25 pts |
| Sustentación y defensa técnica | 75 pts |
| **Total** | **100 pts** |
