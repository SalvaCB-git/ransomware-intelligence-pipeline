# Ransomware Intelligence Pipeline

**Autor:** Salvador Cascón Bertomeu · **TFG 2026** · **Tutor:** Alejandro José Freire Mendoza

Pipeline end-to-end de recolección automatizada y análisis semántico de threat
intelligence sobre ransomware. Combina scraping continuo de 13 fuentes públicas,
extracción de TTPs (MITRE ATT&CK) con LLM local (Qwen 2.5 14B + RAG), validación
con segundo LLM externo (Gemma 4 26B vía API) y análisis longitudinal del corpus
2021-2026. Construido para responder los 5 objetivos del contrato del TFG y
sostener una publicación académica posterior con FIU.

> **Este README es la guía del repositorio.** La narrativa académica completa
> (motivación, diseño, calibración, evaluación, hallazgos) está en la **memoria
> del TFG**, que acompaña a esta entrega; aquí está lo necesario para entender
> la estructura, arrancar el sistema y **reproducir las cifras**.
>
> **Demo desplegada (pública, solo lectura):**
> <https://scraper.143.47.55.55.sslip.io/demo>

---

## Arquitectura

```
                   ┌───────────────────────────────────────────┐
                   │  Servidor OCI (ARM Always Free, 24/7)    │
                   │                                          │
 Spiders Scrapy ─► │  CSV ── preprocess.py ──► SQLite (WAL)   │
 13 fuentes        │       (SimHash dedup, ~3.871 art.)       │
                   │                ▲                         │
                   │                │                         │
                   │       [REST API endpoints]               │
                   │  ┌─────────────────────────────────────┐│
                   │  │ /api/ttps/acquire_batch  (lock 3h)  ││
                   │  │ /api/ttps/commit_batch   (atómico)  ││
                   │  │ /api/judge/acquire_batch            ││
                   │  │ /api/judge/commit_batch (idempotent)││
                   │  │ /api/demo/heartbeat   (PC bridge)   ││
                   │  └─────────────────────────────────────┘│
                   │                ▲                         │
                   │       HTTP Basic Auth (Flask)            │
                   └────────────────┼─────────────────────────┘
                                    │ HTTPS (NPM + Let's Encrypt)
        ┌───────────────────────────┼───────────────────────────┐
        │ PC local (Linux, NVIDIA GPU 12 GB+ VRAM, Ollama)     │
        │                                                       │
        │  pc/run_extraction.py                                 │
        │   1. acquire_batch → 50 articles                      │
        │   2. prefilter.py (heurísticas + cosine ≥ 0,55)       │
        │   3. RAG: ChromaDB MITRE + tool_lookup → Qwen 14B     │
        │   4. commit_batch                                     │
        │                                                       │
        │  pc/demo_worker.py — heartbeat + jobs en vivo         │
        │  pc/run_judge.py   — judge v1 (Qwen)                  │
        │                                                       │
        │  Judge v2 (Gemma 4 26B vía Google AI Studio API)      │
        │  reside en el SERVIDOR (judge_core.py + judge_v2.py)  │
        └───────────────────────────────────────────────────────┘
```

---

## Resultados estrella

- **F1 = 0,726** · MCC = 0,577 (pipeline completo, Post-hoc Candidate Validation, N=377)
- **Krippendorff α = 0,6461** [0,5439–0,7490] sobre **N=278** (muestra de diseño estratificada de 384; 106 quedaron sin veredicto v2) — supera el umbral 0,60 del Objetivo 3
- **Coincidencia humano ↔ Gemma 4** sobre conf=1.0: humano 41,0 % (N=100) vs Gemma 41,27 % (N=4.437); ambas vías sitúan ~59 % de falsos positivos (apoya H-2). Nota: muestras anidadas (99/100), no independientes; el TOST no prueba equivalencia a ±5 pp
- **Corrección de errores E1** (abstracción vaga): juez v2 corrige el **96,9 %** de los E1 del juez v1

Detalle por objetivo + evidencia documental en
[DEFENSA_OBJETIVOS_CONTRATO.md](DEFENSA_OBJETIVOS_CONTRATO.md).

---

## Datos incluidos en el repositorio

`data/ransomware_intel.db` es un **snapshot reproducible** de la BD canónica
**sin el campo `articles.body`** (el texto íntegro de artículos de terceros no
se redistribuye, por copyright). Conserva íntegros los metadatos de los 3.871
artículos y todas las tablas derivadas (extractions, veredictos v1/v2, ground
truth humano). **Todas las cifras de la tabla de reproducción se reproducen con
este snapshot** (verificado: ningún script de análisis lee `body`). Detalle,
caveats y cómo regenerar el corpus completo: [data/README.md](data/README.md).

> El snapshot es la opción de distribución **provisional**; la decisión
> definitiva (snapshot versionado / release asset / Zenodo con DOI) se tomará
> antes de la publicación del repositorio.

---

## Cómo arrancar desde cero

### Servidor (OCI / Docker)

```bash
# Desde la raíz de este repositorio (clonado o descomprimido)

# .env (gitignored, crear a mano — plantilla en .env.example)
cat > .env <<EOF
GOOGLE_API_KEY=<tu_key_AI_Studio>
BASIC_AUTH_USER=<usuario_para_endpoints_mutacion>
BASIC_AUTH_PASS=<contraseña>
EOF

docker network create monitor_net   # la red es external en docker-compose.yml
docker compose up -d
docker logs -f scraper              # verificar arranque
```

Flask queda en `127.0.0.1:7000` dentro del host (no expuesto al exterior).
En el despliegue original, NGINX Proxy Manager hace TLS + reverse proxy desde
`https://scraper.143.47.55.55.sslip.io`.

### PC (extracción + judge local con GPU)

Prerequisitos: Python 3.10+, Ollama corriendo en `localhost:11434`,
modelo `qwen2.5:14b-instruct-q4_K_M` descargado (`ollama pull qwen2.5:14b-instruct-q4_K_M`),
GPU NVIDIA con 12 GB+ de VRAM (probado: RTX 4070 Ti).

```bash
cd pc

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt          # ver pc/README.md

# pc/.env (gitignored, crear a mano — plantilla en pc/.env.example)
cat > .env <<EOF
SCRAPER_URL=https://scraper.143.47.55.55.sslip.io
BASIC_AUTH_USER=<mismo_que_servidor>
BASIC_AUTH_PASS=<mismo_que_servidor>
GOOGLE_API_KEY=<opcional, solo para benchmark v2>
EOF

python3 build_index.py                   # una sola vez, ~5 min — bundle STIX MITRE → ChromaDB
python3 run_extraction.py --batch-size 50   # producción: lote, prefilter, RAG, commit
```

Detalle del pipeline PC + descripción script-a-script en
[pc/README.md](pc/README.md).

### Análisis (numpy / scipy / krippendorff / matplotlib)

Los 7 scripts de análisis (`evaluation_f1.py`, `krippendorff_segmented.py`, …)
viven en la raíz del repo y se ejecutan desde un venv local **separado** del
contenedor (las deps científicas no se instalan en Python 3.14 ARM64 — wheels no
disponibles).

```bash
python3 -m venv .venv-analysis && source .venv-analysis/bin/activate
pip install -r requirements-analysis.txt
python3 evaluation_f1.py                  # genera outputs/evaluation_f1/
```

---

## Cómo reproducir los resultados estrella

Todos los scripts leen por defecto `data/ransomware_intel.db` (el snapshot
incluido) y escriben sus CSVs en `outputs/` (se crea al ejecutar).

| Cifra                                | Script                       | Output                                                            |
|--------------------------------------|------------------------------|--------------------------------------------------------------------|
| F1 = 0,726 · MCC = 0,577             | `evaluation_f1.py`           | `outputs/evaluation_f1/primary_metrics.csv` + 9 CSVs adicionales   |
| α = 0,6461 estratificada (Objetivo 3) | `krippendorff_segmented.py`  | `outputs/krippendorff_segmented/{headline,argumentacion}.{csv,md}` |
| Longitudinal 2021-2025 (11 MK + SNIP) | `longitudinal_analysis.py`   | `outputs/longitudinal/` (10 CSVs)                                  |
| Co-occurrence + ARM + centralidad    | `cooccurrence_analysis.py`   | `outputs/cooccurrence/` (5 CSVs, BH-sig: T1490→T1486, T1047→T1486) |
| JSON adherence = 96,34 %             | `json_adherence.py`          | `outputs/json_adherence/`                                          |
| Catalog-lag (4 técnicas estrictas)   | `mitre_catalog_lag.py`       | `outputs/catalog_lag/catalog_lag_strict.csv` (+ caveat D1)         |
| Convergencia 41,0 / 41,3 (humano vs Gemma) | (consulta directa a BD)  | `calibration_sample` (control N=100) + `ttp_verdicts_v2` (N=4.437) |

Notas de ejecución:

- Cada script corre **sin argumentos** salvo `longitudinal_analysis.py`, que
  necesita el destino explícito: `python3 longitudinal_analysis.py --csv-dir
  outputs/longitudinal`. Las figuras se generan después con
  `longitudinal_figures.py` (lee esos CSVs).
- `evaluation_f1.py`, `krippendorff_segmented.py` y `longitudinal_figures.py`
  necesitan el venv `.venv-analysis` (numpy/scipy/krippendorff/matplotlib);
  `longitudinal_analysis.py`, `cooccurrence_analysis.py`, `json_adherence.py` y
  `mitre_catalog_lag.py` son stdlib puro (basta `python3` ≥ 3.8).
- `mitre_catalog_lag.py` descarga en runtime los bundles STIX históricos de
  MITRE (requiere red la primera vez; quedan cacheados en `outputs/`).

---

## Tests

Núcleo determinista (sin red/BD/GPU), en el host:

```bash
python3 -m venv .venv-dev && .venv-dev/bin/pip install -r requirements-dev.txt
.venv-dev/bin/pytest tests/ -q          # 22 passed, 1 skipped
```

El `skipped` es la **suite de validación estadística**
(`tests/test_analysis_vs_reference.py`): valida las implementaciones propias
(F1, MCC, precision/recall/balanced-accuracy/kappa, Fisher, Benjamini-Hochberg,
Mann-Kendall, TOST, bootstrap BCa) contra scikit-learn/scipy/statsmodels/networkx.
Requiere la pila científica, en un venv aparte:

```bash
python3 -m venv .venv-validation
.venv-validation/bin/pip install pytest -r requirements-validation.txt
.venv-validation/bin/pytest tests/test_analysis_vs_reference.py -q   # 13 passed
```

> `pytest tests/` (núcleo) **no** valida las cifras del TFG; esa validación es la
> de 13 tests de arriba. Un `skipped` del núcleo no es un fallo. Detalle en
> [tests/README.md](tests/README.md).

---

## Seguridad

La superficie pública es `https://scraper.143.47.55.55.sslip.io`, servida por
NGINX Proxy Manager (NPM) con certificado Let's Encrypt. El binding interno del
contenedor Flask está sellado a `127.0.0.1:7000` en `docker-compose.yml`; no
hay forma de alcanzarlo sin pasar por NPM.

**Autenticación.** Las páginas de demo (`/`, `/demo`, `/pipeline`, `/corpus`,
`/longitudinal`, `/arm`, `/judge`, `/calibration-stats`, `/catalog-lag`,
`/calibration`) y las APIs JSON de solo lectura que consumen son **públicas
por diseño** — el tribunal y revisores externos las cargan sin credenciales.

Los endpoints de **mutación** y los del **pipeline cliente-servidor** están
protegidos por HTTP Basic Auth implementado en Flask (variables
`BASIC_AUTH_USER` y `BASIC_AUTH_PASS` en `.env`, validadas con
`hmac.compare_digest`). Los 13 endpoints protegidos:

- POST `/run`, `/stop`, `/upload_spider`, `/trigger/preprocess`
- POST `/api/ttps/commit_batch`, GET `/api/ttps/acquire_batch`
- POST `/api/judge/commit_batch`, GET `/api/judge/acquire_batch`
- POST `/api/calibration/verdict`, `/api/calibration/reconcile`
- POST `/api/demo/heartbeat`, `/api/demo/job/event`
- POST `/api/demo/jobs` (GET de la misma ruta sigue público — listado de jobs para el dashboard)

NPM se configura como reverse proxy en modo **Publicly Accessible** (TLS +
forwarding, sin Access List propia). Las credenciales viven en una sola capa
(Flask) para evitar la incompatibilidad de doble Basic Auth en cascada con la
misma credencial: dos cerrojos con la misma llave no son dos cerrojos, y
mantener dos credenciales distintas requería propagar dos juegos de secretos a
los clientes del PC. La decisión es deliberada: simplicidad operativa y una
única fuente de verdad para la autenticación de la API.

**Trabajo futuro post-defensa:** defensa en profundidad real con credenciales
distintas en cada capa (NPM Access List con credencial A, Flask Basic Auth
con credencial B, propagación coordinada a los clientes). Documentado para
posible iteración del paper con FIU.

---

## Ética del scraping y limitaciones de los datos

**robots.txt.** El crawler respeta `robots.txt` por defecto (`ROBOTSTXT_OBEY=True`
global). Cinco blogs anti-bot (CrowdStrike, Cisco Talos, Trend Micro, Sophos,
Kaspersky) se crawlean con `ROBOTSTXT_OBEY=False`: su `robots.txt` bloquea el
listado/sitemap aunque el contenido es público y los ToS permiten su lectura;
**no se eluden controles de acceso** (autenticación, paywalls). No se republica el
texto íntegro de terceros — el uso es minería de textos (Directiva (UE) 2019/790,
RDL 24/2021), y este repositorio distribuye el corpus **sin** el texto de los
artículos ([data/README.md](data/README.md)). Detalle en la memoria (§ética del
scraping).

**`published_utc` de CrowdStrike.** Los 507 artículos de CrowdStrike (~13 % del
corpus) tienen `published_utc` no fiable: colapsan a 2 fechas de crawl (el parser
de fecha falló y se almacenó la del crawl). Por eso CrowdStrike se **excluye de
todo análisis temporal** (`TEMPORAL_EXCLUDED` en `longitudinal_analysis.py` y
`mitre_catalog_lag.py`). No afecta a F1/α/JSON ni a las cifras no temporales.

**Atribución MITRE ATT&CK®.** Las técnicas y definiciones de
`data/mitre_attack_cache.json` y `pc/mitre_techniques.json` proceden de MITRE
ATT&CK® — *reproduced with permission of The MITRE Corporation*
(© The MITRE Corporation). MITRE ATT&CK® es una marca registrada de The MITRE
Corporation.

---

## Estructura del repositorio

```
ransomware-intelligence-pipeline/
├── README.md                         # esta guía
├── app.py                            # Flask (2.4k líneas) — UI + API + auth
├── judge_core.py                     # SYSTEM_PROMPT + call_gemini (compartido)
├── judge_v2.py                       # CLI offline: validate / rejudge / rejudge_conf1
├── judge_bench.py                    # bench de determinismo del juez (temperature=0)
├── Dockerfile · docker-compose.yml   # build + binding 127.0.0.1:7000
├── .env.example                      # plantilla de configuración del servidor
├── requirements-analysis.txt         # deps de los scripts de análisis (.venv-analysis)
├── requirements-dev.txt              # deps de la suite de tests (.venv-dev)
├── requirements-validation.txt       # deps de la validación estadística (.venv-validation)
├── data/
│   ├── ransomware_intel.db           # snapshot SIN articles.body (ver data/README.md)
│   ├── mitre_attack_cache.json       # catálogo MITRE congelado (juez v2)
│   └── README.md                     # qué es el snapshot, caveats, atribución
├── scrapy_project/
│   ├── README.md                     # spiders, esquemas CSV, ejecución
│   ├── preprocess.py                 # CSV → SQLite + SimHash dedup
│   ├── requirements.txt              # deps del contenedor (scrapy, flask, …)
│   ├── migrate_*.py · migrations/    # migraciones de esquema (idempotentes)
│   └── bcddg/bcddg/spiders/          # 14 spiders activos + 2 bloqueados
├── pc/                               # cliente local (extracción + judge v1 + demo worker)
│   ├── README.md · .env.example
│   ├── build_index.py · prefilter.py · rag_extractor.py
│   ├── run_extraction.py · run_judge.py · demo_worker.py
│   └── benchmark.py · run_benchmark_v2.py · evaluate_benchmark.py · …
├── templates/ · static/              # Jinja2 + Tailwind/HTMX/Chart.js/D3 (CDN)
├── tests/                            # pytest: núcleo determinista + validación estadística
├── evaluation_f1.py · krippendorff_segmented.py · longitudinal_analysis.py
├── cooccurrence_analysis.py · longitudinal_figures.py · json_adherence.py
├── mitre_catalog_lag.py
├── benchmark_v2_results/             # crudos del benchmark v2 de extractores
└── outputs/                          # CSVs de análisis (gitignored, se regeneran)
```

---

## Documentación del repositorio

- **[DEFENSA_OBJETIVOS_CONTRATO.md](DEFENSA_OBJETIVOS_CONTRATO.md)** — evidencia de cumplimiento de los 5 objetivos contractuales, cifra a cifra, con el script y el CSV que respaldan cada una.
- **[pc/README.md](pc/README.md)** — pipeline PC: instalación, flujos, limitaciones conocidas.
- **[scrapy_project/README.md](scrapy_project/README.md)** — spiders, esquemas CSV, ejecución.
- **[tests/README.md](tests/README.md)** — qué se testea, cómo, y qué no (y por qué).
- **[data/README.md](data/README.md)** — el snapshot de BD: qué contiene, qué reproduce, atribución.
- **[benchmark_v2_results/README.md](benchmark_v2_results/README.md)** — crudos del benchmark de extractores.
- La narrativa académica completa está en la **memoria del TFG** (no incluida en el repo; el tribunal dispone de ella).

---

## Licencia y autoría

**Salvador Cascón Bertomeu** — Trabajo Fin de Grado 2026.
Tutor: Alejandro José Freire Mendoza.
Colaboración académica: Florida International University, Group G-013
(mentor: Weidong Zhu) — base del paper conjunto en preparación
(objetivo USENIX / ACM CCS / NDSS, finales 2026).

Sin licencia formal hasta la defensa del TFG (todos los derechos reservados
por defecto; el repositorio se distribuye al tribunal con fines de evaluación
académica). La decisión de licencia (MIT / Apache 2.0 / académica restrictiva)
se tomará tras la entrega, coordinada con FIU.
