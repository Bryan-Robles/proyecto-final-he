# [V2] NoSQL Injection

## 1. Identificación
- Categoría OWASP: A05:2025 — Injection (equiv. A03:2021)
- Dueño: Bryan | Revisor PR: JuanDa | Rama: `feat/v2-nosqli-bryan` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: <qué es y por qué ocurre>
- Componente/archivo/config afectada: <ruta/archivo:línea> (login / consultas Mongo)
- Causa raíz: <el porqué real, no el síntoma>
- Impacto y riesgo: <confidencialidad/integridad/disponibilidad; quién se afecta>

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: <estado/usuario de partida>
- Técnica/herramienta: <curl / Burp / script>
- Petición/payload/comando ejecutado:
  ```bash
  <comando exacto>
  ```
- Resultado obtenido: <qué devolvió> (evidencia: `docs/evidencias/V2/antes/...`)
- Explicación del impacto: <qué significa ese resultado>

## 4. Mitigación
- Cambio aplicado: validación y casting de tipos + `express-mongo-sanitize` + consultas parametrizadas
- Justificación técnica: <por qué esto cierra la causa raíz>
- Diff:
  ```diff
  - <línea vulnerable>
  + <línea corregida>
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): el PoC funciona → evidencia `docs/evidencias/V2/antes/...`
- DESPUÉS (mitigado): el PoC falla/reduce impacto → evidencia `docs/evidencias/V2/despues/...`
- Regresión: la funcionalidad legítima sigue operando → evidencia ...
