# pc/ — Cliente local del pipeline

Lado PC del pipeline de extracción semántica de TTPs sobre threat intelligence
de ransomware. Lo que vive aquí: extracción RAG con Qwen 2.5 14B sobre GPU
local, judge v1 (Qwen como juez), demo worker para el bridge PC↔servidor en
vivo, y el benchmark v2 multi-modelo. Vive separado del servidor porque los
modelos pesados no caben en el contenedor Docker (ARM64, sin GPU); este
directorio se sincroniza al PC y se ejecuta desde allí, comunicándose con el
servidor por HTTPS+Basic Auth.

El judge v2 (Gemma 4 26B vía Google AI Studio API) **NO está aquí** —
reside en el servidor (`judge_core.py` + `judge_v2.py` en la raíz del repo)
desde la sesión 28, para liberar GPU y centralizar la API key de Google.

Contexto general del proyecto y arquitectura: [`../README.md`](../README.md).

---

## Prerequisitos

- **Python 3.10+** (verificado en Linux Mint con 3.11).
- **Ollama** corriendo en `localhost:11434` con el modelo:
  ```bash
  ollama pull qwen2.5:14b-instruct-q4_K_M
  ```
- **GPU NVIDIA con ≥12 GB de VRAM** (probado: RTX 4070 Ti, driver 590.48.01, CUDA 13.1).
- **Acceso de red** al servidor en `https://scraper.143.47.55.55.sslip.io` (via NPM + Let's Encrypt).
- **Opcional:** Google AI Studio API key (solo si vas a correr `run_benchmark_v2.py`, que llama a Gemma 4 API en paralelo con Qwen local).

---

## Instalación

```bash
# Sincronizar pc/ del repo al directorio local del PC
scp -r <usuario>@<servidor>:~/services/scraper/pc ~/Tfg-llm   # o clona este repositorio
cd ~/Tfg-llm

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

> **Nota:** `requirements.txt` está pineado a versiones verificadas en el
> venv real del PC (Linux Mint 22, Python 3.11, CUDA 13.1) al cerrar la
> auditoría pre-entrega de mayo 2026.

---

## Configuración (`pc/.env`)

```ini
SCRAPER_URL=https://scraper.143.47.55.55.sslip.io
BASIC_AUTH_USER=<usuario_misma_credencial_que_servidor>
BASIC_AUTH_PASS=<contraseña_misma_credencial_que_servidor>
GOOGLE_API_KEY=<opcional, solo para run_benchmark_v2.py>
BENCHMARK_DB=./calibration.db   # opcional, path snapshot BD para benchmark v2
```

`BASIC_AUTH_USER` y `BASIC_AUTH_PASS` autentican las peticiones del PC contra
el servidor (Flask Basic Auth, 13 endpoints protegidos del pipeline
cliente-servidor). Debe coincidir con el `.env` del servidor. Si faltan, los
scripts loggean un WARNING al arrancar y envían las peticiones sin auth (el
servidor las aceptará solo si está en modo pass-through, es decir, si su
propio `.env` tampoco tiene las variables).

`GOOGLE_API_KEY` y `BENCHMARK_DB` solo los lee `run_benchmark_v2.py`. El resto
de scripts funciona sin ellas.

---

## Caveat operativo — `SERVER_URL` parcialmente hardcoded

Solo `demo_worker.py` lee `SCRAPER_URL` desde el entorno. Los otros dos
clientes del servidor (`run_extraction.py:29` y `run_judge.py:31`) tienen el
URL hardcoded como:

```python
SERVER_URL = "https://scraper.143.47.55.55.sslip.io"
```

Si el servidor cambiase de URL (e.g. migración de OCI a otro proveedor, o
dominio propio), hay que editar esos 2 scripts a mano. Es deuda técnica
documentada; no se arregla en esta entrega por criterio "no tocar lo que
funciona ahora mismo y no rompe nada".

---

## Flujos de ejecución

### 1. Construir índice MITRE (una sola vez, ~5 min)

```bash
python3 build_index.py
```

Descarga el bundle STIX oficial de MITRE ATT&CK (~15 MB), genera embeddings
con `all-MiniLM-L6-v2` sobre la descripción completa de cada técnica + sub-técnica
(691 entradas, v18.0 al menos), y persiste el ChromaDB en `./mitre_index/`
(~200 MB). Genera también `mitre_techniques.json` para validación post-extracción.
Tras esto, no hace falta regenerar a menos que MITRE publique una versión nueva
o cambies la lógica de embedding.

### 2. Extracción de TTPs en producción

```bash
python3 run_extraction.py --batch-size 50
```

Bucle: `acquire_batch` (lock 3h) → `prefilter` (heurísticas + cosine ≥0,55)
→ `RagExtractor` (Qwen 2.5 14B vía Ollama con `num_ctx=12288`, `num_predict=6144`)
→ `commit_batch`. Estados emitidos por artículo: `completed` / `filtered` /
`failed` / `dry-run`. Soporta SIGINT para hacer commit parcial limpio antes
de salir. Logs en stdout; recomendado redirigir a `nohup ... &` o `tee`.

### 3. Judge v1 (Qwen local como juez)

```bash
python3 run_judge.py --limit 50
python3 run_judge.py --dry-run --max-batches 1 --limit 5    # smoke test
```

Re-juzga TTPs con `confidence=0.75` extraídos en producción. Mismo modelo
(`qwen2.5:14b-instruct-q4_K_M`) con prompt distinto que detecta menciones
hipotéticas/defensivas. CLI manual; no daemon.

### 4. Demo worker (bridge PC↔servidor para demo en vivo)

```bash
python3 demo_worker.py                       # foreground (Ctrl+C para parar)
systemctl --user start demo_worker           # como servicio systemd (recomendado)
```

Daemon en bucle. POST `/api/demo/heartbeat` cada 2s con metadata
(GPU memory, modelos Ollama disponibles, current_job_id). El servidor responde
con `{next_job}` si hay queued y el PC dice `current_job_id=null`. Worker
emite eventos por etapa (`prefilter.start/end`, `rag_extract.start/end`)
a `/api/demo/job/event`. Cuando termina `rag_extract.end`, el servidor lanza
judge v2 (Gemma 4 vía API) en thread daemon.

### 5. Benchmark v2 (4 extractores comparados)

```bash
scp <usuario>@<servidor>:~/services/scraper/data/ransomware_intel.db ./calibration.db
nohup python3 run_benchmark_v2.py > benchmark_v2.log 2>&1 &
tail -f benchmark_v2.log
```

Corre Qwen 3.5 9B (Ollama local) y Gemma 4 26B (Google AI Studio API) en
paralelo sobre los ~400 artículos de `calibration_sample` — no compiten por
recursos. Tiempo total ≈ max(GPU, API) ≈ 3-4 horas. Genera JSONL con
extracciones raw en `../benchmark_v2_results/`.

### 6. Evaluar benchmark v2

```bash
python3 evaluate_benchmark.py
```

Calcula Partial Precision / Partial Recall / Partial F1 sobre ground truth
humano (`calibration_sample`). Los resultados están parcialmente sesgados
porque el ground truth se generó desde las extracciones de Qwen 2.5 14B
(documentado en la memoria del TFG, §benchmark de extractores).

### 7. Krippendorff α sobre calibración humana

```bash
python3 compute_alpha.py --db ../data/ransomware_intel.db
python3 compute_alpha.py --db ../data/ransomware_intel.db --bootstrap 5000   # más iter
```

Genera α ordinal con bootstrap BCa 95%. Útil para reproducir la cifra del
Objetivo 3 (α=0,6461) desde una copia local de la BD. El **snapshot incluido
en el repo** (`data/ransomware_intel.db`) sirve para esto (la tabla
`calibration_sample` está íntegra); el benchmark v2 del flujo 5, en cambio,
necesita una copia de la BD **con** `articles.body` (re-extrae desde el texto).

---

## Scripts ↔ propósito (referencia rápida)

| Script                  | Propósito                                              | Uso                                  |
|-------------------------|---------------------------------------------------------|---------------------------------------|
| `build_index.py`        | Construir ChromaDB MITRE                                | una vez                               |
| `prefilter.py`          | Heurísticas + cosine ≥0,55                              | importado por `run_extraction`        |
| `rag_extractor.py`      | RAG con Qwen + ChromaDB                                 | importado por `run_extraction` + benchmarks |
| `run_extraction.py`     | Pipeline extracción producción                          | CLI manual                            |
| `run_judge.py`          | Judge v1 (Qwen)                                         | CLI manual                            |
| `demo_worker.py`        | Bridge PC↔servidor para demo en vivo                    | systemd daemon                        |
| `benchmark.py`          | Benchmark v1 (Qwen 2.5 14B vs Llama 3.1 8B)             | CLI                                   |
| `run_benchmark_v2.py`   | Benchmark v2 (Qwen 3.5 + Gemma 4 API en paralelo)       | CLI                                   |
| `evaluate_benchmark.py` | P/R/F1 sobre benchmark v2                               | CLI                                   |
| `compute_alpha.py`      | α Krippendorff sobre calibración                        | CLI                                   |
| `explore_corpus.py`     | CLI exploratorio (ejecutar vía SSH en servidor — path BD hardcoded) | exploración manual           |
| `mitre_techniques.json` | Catálogo MITRE parseado (output de `build_index`)       | datos                                 |

---

## Limitaciones conocidas

1. **Qwen 3.5 9B falla como extractor** por *thinking mode* que agota
   `num_predict=32768` en ~98% de artículos sin llegar a generar JSON.
   Documentado en la memoria del TFG (§benchmark de extractores). No
   usar como extractor de producción.

2. **Claude Opus pendiente de evaluación.** `../benchmark_v2_results/claude_opus/extractions.jsonl`
   contiene las extracciones raw de 402 artículos generadas en sesión 30, pero
   `evaluate_benchmark.py` no las ha procesado: el JSONL se generó en el
   servidor y no se copió al PC a tiempo. Pendiente para la fase 2 del paper
   con FIU; no bloquea la entrega del TFG (cifras estrella son independientes).

3. **`rag_extractor.py` tool_lookup — corregido en código; corpus extraído pre-fix.**
   El matcher de herramientas YA usa word boundaries (`_TOOL_PATTERNS` con `\b`,
   `rag_extractor.py:96-101`): "Conti" ya no matchea dentro de "continuously". El
   corpus limpio de 2.355 TTPs se extrajo ANTES del fix y **no se re-extrae**
   (criterio de congelación: las cifras ya están validadas y citadas en la
   memoria del TFG).

4. **`compute_alpha.py` importa `numpy` y `krippendorff` lazy** (dentro de
   función). Requiere venv con esas deps. Probablemente compartible con el
   venv de los scripts de análisis del servidor
   ([`../requirements-analysis.txt`](../requirements-analysis.txt)),
   pero no se ha verificado compatibilidad cruzada con `chromadb` /
   `sentence-transformers` del venv del PC. Si lo ejecutas en el PC,
   instala explícitamente `numpy>=1.26 krippendorff>=0.6` en el venv del PC
   o falla con `ImportError`.

---

## Relación con el servidor

- **`/api/ttps/acquire_batch`** + **`/api/ttps/commit_batch`** — flujo de extracción.
  Lock 3h en `acquire_batch`, INSERT atómico en `commit_batch`. Llamados por
  `run_extraction.py`.
- **`/api/judge/acquire_batch`** + **`/api/judge/commit_batch`** — flujo de judge v1.
  Llamados por `run_judge.py` (idempotente vía `INSERT OR IGNORE`).
- **`/api/demo/heartbeat`** + **`/api/demo/job/event`** — bridge PC↔servidor.
  El worker mantiene viva la presencia del PC en la UI; el servidor le pasa
  jobs queued cuando llegan.
- **Judge v2 (Gemma 4 26B)** vive en el servidor (`judge_core.py` + `judge_v2.py`
  + thread daemon disparado por `_spawn_judge_thread` cuando llega
  `rag_extract.end`). No corre desde el PC. La API key de Google reside solo
  en el `.env` del servidor.

Para el cuadro completo de la API expuesta por el servidor y los endpoints
NO protegidos por Basic Auth (páginas UI + APIs read-only), ver la sección
**Seguridad** del [`../README.md`](../README.md) raíz.
