# [V1] IDOR / Broken Access Control

## 1. Identificación
- Categoría OWASP: A01:2025 — Broken Access Control (equiv. A01:2021)
- Dueño: JuanFra | Revisor PR: Kevin | Rama: `feat/v1-idor-juanfra` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: <qué es y por qué ocurre>
- Componente/archivo/config afectada: <ruta/archivo:línea>
- Causa raíz: <el porqué real, no el síntoma>
- Impacto y riesgo: <confidencialidad/integridad/disponibilidad; quién se afecta>

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: <estado/usuario de partida>
- Técnica/herramienta: <curl / Burp / script>
- Petición/payload/comando ejecutado:
  ```bash
  <comando exacto>
  ```
- Resultado obtenido: <qué devolvió> (evidencia: `docs/evidencias/V1/antes/...`)
- Explicación del impacto: <qué significa ese resultado>

## 4. Mitigación
- Cambio aplicado: autorización server-side atada al `userId` de la sesión, no al valor enviado por el cliente
- Justificación técnica: <por qué esto cierra la causa raíz>
- Diff:
  ```diff
  - <línea vulnerable>
  + <línea corregida>
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): el PoC funciona → evidencia `docs/evidencias/V1/antes/...`
- DESPUÉS (mitigado): el PoC falla/reduce impacto → evidencia `docs/evidencias/V1/despues/...`
- Regresión: la funcionalidad legítima sigue operando → evidencia ...
