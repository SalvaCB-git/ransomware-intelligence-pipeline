# scrapy_project/: Recolección del corpus

Subsistema de recolección: spiders Scrapy → CSV → `preprocess.py` →
SQLite (`data/ransomware_intel.db`) con deduplicación SimHash 64-bit.

## Spiders

**Activos (14):** `bc_site` (BleepingComputer, fuente principal),
`cisa_stopransomware`, `cisco_talos`, `crowdstrike_blog`, `dfir_report`,
`elastic_security`, `huntress`, `microsoft_security`, `red_canary`,
`sentinelone_blog`, `talos_blog` (segundo spider de Cisco Talos, vía
sitemap), `trendmicro_research`, `unit42`, `welivesecurity`, todos con
sufijo `_ransomware` en su `name`.

**Bloqueados (2):** `sophos_news` y `kaspersky_securelist` existen pero el
vendor bloquea la IP del servidor OCI; se conservan por honestidad
metodológica (están documentados como bloqueados en el README raíz).

**Convención de nombre:** `<fuente>_ransomware`, solo minúsculas, dígitos y
`_`. El panel Flask los detecta con un regex que exige que `name` sea un
atributo de clase indentado (`app.py`, `get_available_spiders`).

## Ejecución

```bash
# Un spider, limitado a 5 páginas (prueba)
cd scrapy_project/bcddg
scrapy crawl bc_site_ransomware -s CLOSESPIDER_PAGECOUNT=5 -s LOG_LEVEL=INFO

# Crawl completo a CSV
scrapy crawl <spider> -o ../../outputs/<spider>_$(date +%Y%m%d_%H%M%S).csv

# Todos los spiders operativos en lote
./run_all.sh
```

En el despliegue Docker los crawls se lanzan desde el panel Flask (`/run`)
y el preprocesado con `POST /trigger/preprocess`.

## Esquemas CSV que espera `preprocess.py`

- **Grupo A** (`source, published_utc, headline, url, body`): bc_site,
  cisco_talos, crowdstrike_blog, microsoft_security, talos_blog,
  dfir_report, elastic_security, huntress, cisa, kaspersky_securelist,
  sophos_news.
- **Grupo B** (`source, url, title, date, body`): unit42, welivesecurity,
  trendmicro_research, red_canary, sentinelone_blog.

Para añadir una fuente nueva: usar uno de los dos esquemas (o añadir el
mapping a `SOURCE_MAP` en `preprocess.py`).

## Otros ficheros

- `preprocess.py`: ingesta CSV→SQLite, dedup SimHash, normalización de
  fechas y fuentes. Importado también por los tests.
- `migrate_schema.py`, `migrate_judge.py`, `migrate_calibration.py`:
  migraciones del esquema núcleo (extractions, ttp_verdicts,
  calibration_sample) con su procedencia documentada (seed=42, estratos).
- `migrations/`: migraciones idempotentes posteriores (demo, heartbeat,
  judge v2, dedup). `migrate_dedup_extractions.py` es histórico: documenta
  cómo se depuró el corpus limpio; no re-ejecutar.
- `requirements.txt`: dependencias pineadas del contenedor.

## Ética del crawling

`ROBOTSTXT_OBEY=True` global (`bcddg/settings.py`); cinco spiders anti-bot
lo desactivan con justificación comentada en cada fichero. Detalle y
discusión en el README raíz (§Ética del scraping) y en la memoria del TFG.
