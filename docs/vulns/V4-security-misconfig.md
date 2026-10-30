# [V4] Security Misconfiguration

## 1. Identificación
- Categoría OWASP: A02:2025 — Security Misconfiguration (equiv. A05:2021)
- Dueño: Kevin | Revisor PR: JuanFra | Rama: `feat/v4-misconfig-kevin` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: <qué es y por qué ocurre>
- Componente/archivo/config afectada: <ruta/archivo:línea> (cabeceras de seguridad, `x-powered-by`, manejo de errores)
- Causa raíz: <el porqué real, no el síntoma>
- Impacto y riesgo: <confidencialidad/integridad/disponibilidad; quién se afecta>

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: <estado/usuario de partida>
- Técnica/herramienta: <inspección de cabeceras HTTP / script>
- Petición/payload/comando ejecutado:
  ```bash
  <comando exacto>
  ```
- Resultado obtenido: <aparece x-powered-by y faltan cabeceras> (evidencia: `docs/evidencias/V4/antes/...`)
- Explicación del impacto: <qué significa ese resultado>

## 4. Mitigación
- Cambio aplicado: `helmet`, desactivar `x-powered-by`, error handler genérico, cookies `HttpOnly`/`Secure`/`SameSite`
- Justificación técnica: <por qué esto cierra la causa raíz>
- Diff:
  ```diff
  - <línea vulnerable>
  + <línea corregida>
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): faltan cabeceras / se expone `x-powered-by` / stack traces verbosos → evidencia `docs/evidencias/V4/antes/...`
- DESPUÉS (mitigado): helmet añade/oculta cabeceras, errores genéricos → evidencia `docs/evidencias/V4/despues/...`
- Regresión: la navegación/funcionalidad legítima sigue operando → evidencia ...
