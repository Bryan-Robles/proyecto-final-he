<!-- Plantilla de PR del proyecto. Rellena todas las secciones. -->

## Vulnerabilidad
- **V#:** <V1 / V2 / V3 / V4>
- **Categoría OWASP:** <A0X:2025 — Nombre>
- **Ficha:** `docs/vulns/Vx-....md`

## Resumen del PoC
<Qué demuestra la prueba de concepto y cómo se reproduce.>

## Cambio de mitigación
<Qué se modificó en `mitigated/` (código/config) y por qué cierra la causa raíz.>

## Validación antes / después
| Prueba | ANTES (`:4000`) | DESPUÉS (`:4001`) |
|--------|-----------------|-------------------|
| PoC    |                 |                   |
| Regresión (func. legítima) | — |             |

Evidencias: `docs/evidencias/Vx/antes/` y `docs/evidencias/Vx/despues/`.

## Checklist
- [ ] Solo se tocó `mitigated/` (la versión `vulnerable/` queda intacta).
- [ ] La PoC falla o reduce impacto tras la mitigación.
- [ ] La funcionalidad legítima sigue operando (regresión).
- [ ] Sin contraseñas, tokens ni secretos en el código, logs o evidencias.
- [ ] Ficha `docs/vulns/Vx-....md` actualizada.
