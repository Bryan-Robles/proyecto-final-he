# [V3] Cryptographic Failures (almacenamiento débil de contraseñas)

## 1. Identificación
- Categoría OWASP: A04:2025 — Cryptographic Failures (equiv. A02:2021)
- Dueño: JuanDa | Revisor PR: Bryan | Rama: `feat/v3-crypto-juanda` | Commits clave: <hashes>

## 2. Análisis
- Descripción técnica: <qué es y por qué ocurre>
- Componente/archivo/config afectada: <ruta/archivo:línea> (registro de usuario / almacenamiento de password)
- Causa raíz: <el porqué real, no el síntoma>
- Impacto y riesgo: <confidencialidad/integridad/disponibilidad; quién se afecta>

## 3. Explotación controlada (PoC reproducible)
- Condición inicial: <estado/usuario de partida>
- Técnica/herramienta: <inspección de almacenamiento en Mongo / script>
- Petición/payload/comando ejecutado:
  ```bash
  <comando exacto>
  ```
- Resultado obtenido: <texto plano / hash débil> (evidencia: `docs/evidencias/V3/antes/...`)
- Explicación del impacto: <qué significa ese resultado>

## 4. Mitigación
- Cambio aplicado: `bcrypt` con salt (coste ≥ 10) + migración de hashes existentes
- Justificación técnica: <por qué esto cierra la causa raíz>
- Diff:
  ```diff
  - <línea vulnerable>
  + <línea corregida>
  ```

## 5. Validación (antes / después)
- ANTES (vulnerable): el password se guarda en plano/hash débil → evidencia `docs/evidencias/V3/antes/...`
- DESPUÉS (mitigado): el password se guarda como hash bcrypt (`$2b$...`) → evidencia `docs/evidencias/V3/despues/...`
- Regresión: login válido sigue funcionando → evidencia ...
