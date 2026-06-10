# data/ — Snapshot de la base de datos

> Forma de distribución de los datos de esta entrega: **snapshot versionado
> sin texto de terceros**, verificado contra la BD canónica (decisión del
> autor, 10-jun-2026).

## `ransomware_intel.db` — snapshot reproducible SIN texto de terceros

Snapshot de la BD canónica del proyecto generado el **10-jun-2026** con una
única transformación respecto al original:

- **`articles.body` = NULL en las 3.871 filas.** El campo contenía el texto
  íntegro de artículos de 13 fuentes (≈35 MB de contenido con copyright de
  terceros: BleepingComputer, CrowdStrike, Microsoft…). Redistribuirlo
  excedería el derecho de cita y la excepción de minería de textos
  (Directiva (UE) 2019/790, RDL 24/2021), que ampara la *extracción*, no la
  *redistribución* del corpus. Se conservan los metadatos completos de cada
  artículo: `url`, `source`, `headline/title`, `published_utc`, `body_hash`,
  `simhash`, estado de procesamiento.
- **`pc_heartbeat` vaciada** (1 fila de telemetría de runtime del PC del
  autor, sin valor analítico).

Todo lo demás está **íntegro**: `extractions` (2.977), `ttp_verdicts`
(3.057), `ttp_verdicts_v2` (6.701), `calibration_sample` (484, ground truth
humano), `demo_jobs`/`demo_events`, esquema e índices completos.

## Qué se reproduce con el snapshot (verificado)

**Todas las cifras estrella del TFG.** Ningún script de análisis lee
`articles.body` (verificado por auditoría y re-ejecución): los 6 scripts de
la tabla de reproducción del [README raíz](../README.md) generan CSVs
**byte-idénticos** a los de referencia ejecutados contra la BD completa
(única excepción: orden de filas dentro de empates en
`normalized_emergence.csv`, dependiente del estado físico de la BD;
conjuntos de filas idénticos).

Lo que **no** se puede hacer con el snapshot, por diseño:

- La página `/corpus` de la demo no mostraría el cuerpo de los artículos
  (la demo pública del tribunal corre contra la BD completa en el servidor).
- Re-ejecutar la **extracción** o el **benchmark de extractores** (necesitan
  el texto de los artículos, además de GPU y claves de API). Quedan fuera
  del alcance de la reproducción, como documenta la memoria (Anexo B).

## Cómo regenerar el corpus completo

El corpus full-text se reconstruye con el propio repositorio: los spiders de
`scrapy_project/` recolectan las URLs (conservadas en `articles.url`) y
`scrapy_project/preprocess.py` ingesta los CSV con la misma deduplicación
SimHash. Una recolección nueva no será idéntica (los sitios cambian), pero el
procedimiento es el mismo que generó el corpus original.

## `mitre_attack_cache.json`

Snapshot congelado de 835 técnicas MITRE ATT&CK (nombre + descripción
truncada) usado como contexto del juez v2. Se conserva congelado para que el
juicio sea reproducible exactamente (un re-parse del bundle CTI actual daría
un catálogo distinto).

**Atribución:** las técnicas y definiciones proceden de MITRE ATT&CK® —
*reproduced with permission of The MITRE Corporation*
(© The MITRE Corporation). MITRE ATT&CK® es una marca registrada de
The MITRE Corporation. (Cubre también `pc/mitre_techniques.json`.)
