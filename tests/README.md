# Tests unitarios

Suite de tests del **núcleo determinista** del pipeline. Cubre las funciones
puras (sin red, BD ni GPU) que sostienen la corrección del sistema: dedup
SimHash, normalización de datos, heurísticas de pre-filtrado, resolución de
técnicas MITRE y detección de spiders.

## Cómo ejecutar (en el HOST, nunca en el contenedor)

```bash
cd <ruta-del-repositorio>
python3 -m venv .venv-dev
.venv-dev/bin/pip install -r requirements-dev.txt
.venv-dev/bin/pytest tests/ -v
```

> ⚠ Los tests corren en el **host** (venv `.venv-dev`), no en el contenedor:
> el contenedor usa Python 3.14 ARM64 sin wheels de varias deps, y además no
> se instalan herramientas de test en producción.

## Validación estadística (suite aparte)

`test_analysis_vs_reference.py` valida las implementaciones estadísticas propias
del análisis (MCC, **F1/precision/recall/balanced-accuracy/kappa**, Fisher,
Benjamini-Hochberg, betweenness de Brandes, PageRank, Mann-Kendall, TOST,
bootstrap BCa) **contra** scikit-learn / scipy / statsmodels / networkx. Requiere
la pila científica, así que hace `importorskip` y **se SALTA con `pytest tests/`**
(la suite core no se rompe: aparece como `1 skipped`). Para ejecutarla:

```bash
python3 -m venv .venv-validation
.venv-validation/bin/pip install pytest -r requirements-validation.txt
.venv-validation/bin/pytest tests/test_analysis_vs_reference.py -v   # 13 passed
```

> Importante: `pytest tests/` (core) **no** valida las cifras del TFG; esa
> validación es la de arriba (13 tests). Un `skipped` del core no es un fallo.

## Qué se testea

| Fichero | Módulo bajo test | Funciones |
|---|---|---|
| `test_preprocess.py` | `scrapy_project/preprocess.py` | `_simhash`, `_hamming`, `normalize_date`, `clean_text`, `detect_schema` |
| `test_prefilter.py` | `pc/prefilter.py` | `_check_ioc_rule`, `_find_ioc_hits`, `_check_attck_vocab_rule`, `_check_tools_rule`, `_run_level1`, `_chunk_body` |
| `test_judge_core.py` | `judge_core.py` | `lookup_technique` |
| `test_app_spiders.py` | `app.py` | `get_available_spiders` |
| `test_analysis_vs_reference.py` *(validación, venv aparte)* | `evaluation_f1.py`, `cooccurrence_analysis.py`, `longitudinal_analysis.py` | métricas y tests estadísticos vs scikit-learn/scipy/statsmodels/networkx (13 tests; ver sección anterior) |

Cada función se prueba con el caso normal **y** sus bordes (entrada vacía, sin
coincidencia, duplicado, frontera de umbral, regex).

## Notas de implementación (ver `conftest.py`)

- **`preprocess.py` no importa en Python 3.8** porque usa anotaciones
  PEP585/604 (`set[str]`, `str | None`) sin `from __future__ import
  annotations`. El fixture `preprocess` lo carga prefijando ese import (las
  anotaciones se vuelven cadenas perezosas, PEP563) — así se ejercita el
  fichero de producción **sin modificarlo** y sin exigir un intérprete nuevo.
- **`_simhash` y Python 3.8**: `_simhash` llama a `hashlib.md5(..,
  usedforsecurity=False)`, kwarg que existe desde 3.9. En el host (3.8) el
  fixture `preprocess_simhash` inyecta un `md5` compat que ignora ese flag
  (no altera el digest). En el contenedor (3.14) y en 3.9+ no se toca nada.
- **`prefilter.py` y `judge_core.py` importan limpios** en el host: usan
  `from __future__ import annotations` y sus dependencias pesadas (chromadb,
  sentence-transformers) son lazy; `judge_core` solo necesita `requests`.
- **`app.get_available_spiders`** se importa real bajo aislamiento: `app.py`
  importa flask/apscheduler (ausentes en el host) y hace `os.makedirs('/app')`
  al importar, así que el fixture stubea esos módulos y parchea `makedirs`.
  `init_runtime()`/scheduler solo corren bajo `__main__`. Si el aislamiento
  fallara, esos 3 tests hacen `skip` (no rompen la suite).

## Qué NO se testea (y por qué) — trabajo futuro

- **Integración y end-to-end**: spiders contra sitios vivos, llamadas reales a
  Ollama/Qwen y a la API de Gemma, rutas Flask con BD real. Excluido por el
  alto coste de *mocking* (HTML de 13 fuentes, salidas no deterministas de
  LLMs, estado de SQLite). Documentado como trabajo post-defensa.
- **Nivel 2 del prefilter** (`_run_level2`, `filter_article`): requiere
  ChromaDB + SentenceTransformer (GPU/embeddings), fuera del alcance unitario.
- **`call_gemini` / `load_mitre_definitions`** (`judge_core`): hacen I/O de
  red/disco; se probarían con mocks en la fase de tests de integración.
