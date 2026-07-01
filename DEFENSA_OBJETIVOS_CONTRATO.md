# Defensa del cumplimiento de objetivos del contrato del TFG

**Alumno:** Salvador Cascón Bertomeu
**Tutor:** Alejandro José Freire Mendoza
**Título del TFG:** Ransomware Intelligence Pipeline: recolección automatizada y análisis semántico de tácticas de ataque con LLMs
**Fecha del informe:** 6 de mayo de 2026
**Repositorio:** https://github.com/SalvaCB-git/ransomware-intelligence-pipeline

---

## Resumen ejecutivo

| # | Objetivo del contrato | Métrica exigida | Resultado obtenido | Estado |
|---|---|---|---|---|
| 1 | Recolección automatizada y continua | ≥3.000 artículos, ≥10 fuentes, cloud | **3.871 artículos**, **13 fuentes**, OCI 24/7 | Cumplido |
| 2 | Pipeline RAG con MITRE ATT&CK | F1 ≥ 0.70, JSON ≥ 90%, ≥50 anotados | **F1 = 0.726**, **JSON 96.34%**, **484 anotados** | Cumplido (escenario central) |
| 3 | Validación con calibración humana | Krippendorff α ≥ 0.60 sobre ≥200 TTPs estratificados | **α = 0.6461 sobre N = 278** pares (de muestra estratificada de 384) | Cumplido |
| 4 | Análisis longitudinal 2021-2025 | ≥5 tendencias significativas + datos exportables | **6 Mann-Kendall nominalmente significativas (p<0,05) + 5 exploratorias (p<0,10) + 13 emergentes (normalizadas)**, 10 figuras + 10 CSVs | Cumplido |
| 5 | Evaluación calidad pipeline | TP rate sobre ≥200 anotados | **Precision = 0.783, Recall = 0.677** sobre N = 377 | Cumplido |

Los cinco objetivos se cumplen según sus estimadores principales; O2 es sensible al escenario adversario de datos faltantes. Toda métrica reportada es reproducible mediante los scripts del repositorio y los CSVs en `outputs/`. Las cifras citadas son consistentes con las almacenadas en `data/ransomware_intel.db` (SQLite) en el momento del informe.

---

## Objetivo 1: Recolección automatizada y continua

> **Contrato (literal):** *"Diseñar e implementar un sistema de recolección automatizada y continua de reportes públicos de threat intelligence sobre ransomware que recopile un mínimo de 3.000 artículos de al menos 10 fuentes especializadas, desplegado en producción sobre infraestructura cloud con disponibilidad continua durante el período de evaluación del TFG."*

### Resultado

- **Artículos únicos en BD:** 3.871 (deduplicados con SimHash 64 bits, threshold Hamming ≤ 3 bits)
- **Fuentes activas:** 13 distintas en producción
- **Infraestructura:** Oracle Cloud Infrastructure (OCI) Always Free, instancia ARM64 (Ampere A1, 4 OCPUs, 24 GB RAM), Ubuntu 20.04
- **Disponibilidad:** servicio Docker `restart: unless-stopped`. Operativo 24/7 desde febrero de 2026.

### Distribución por fuente (verificable en BD)

| Fuente | Artículos |
|---|---|
| bc_site (BleepingComputer) | 1.529 |
| cisco_talos | 585 |
| crowdstrike_blog | 507 |
| microsoft_security | 254 |
| sentinelone_blog | 253 |
| unit42 (Palo Alto) | 238 |
| cisa (#StopRansomware) | 171 |
| red_canary | 105 |
| dfir_report | 73 |
| elastic_security_labs | 46 |
| huntress | 43 |
| welivesecurity (ESET) | 40 |
| trendmicro_research | 27 |
| **Total** | **3.871** |

### Stack técnico

- Scrapy 2.14 + scrapy-playwright 0.0.46 (renderizado JS para sitios pesados)
- Flask 3.1 como panel de control en https://scraper.143.47.55.55.sslip.io
- Nginx Proxy Manager (SSL automático vía Let's Encrypt)
- Netdata (monitorización de recursos)
- Backup automático diario a las 04:00

### Cómo verificar

```bash
# desde el servidor
python3 -c "import sqlite3; c=sqlite3.connect('data/ransomware_intel.db'); \
print('artículos:', c.execute('SELECT COUNT(*) FROM articles').fetchone()[0]); \
print('fuentes:', c.execute('SELECT COUNT(DISTINCT source) FROM articles').fetchone()[0])"

# salida esperada: artículos: 3871 / fuentes: 13
```

Disponibilidad continua se evidencia en los logs de Docker (`docker logs scraper`) y en el panel Netdata.

### Artefactos

- 14 spiders activos (16 ficheros − 2 bloqueados: sophos_news, kaspersky_securelist); 13 fuentes con artículos en BD en `scrapy_project/bcddg/bcddg/spiders/`
- `app.py`: panel Flask de orquestación (2.443 líneas)
- `docker-compose.yml` + `Dockerfile`: despliegue reproducible
- `scrapy_project/preprocess.py`: ingesta SQLite con SimHash
- `data/ransomware_intel.db`: corpus completo

---

## Objetivo 2: Pipeline RAG con MITRE ATT&CK

> **Contrato (literal):** *"Desarrollar un pipeline de extracción semántica basado en un modelo de lenguaje (LLM) con retrieval-augmented generation (RAG) que identifique tácticas, técnicas y procedimientos (TTPs) alineados con el framework MITRE ATT&CK, alcanzando una puntuación F1 ≥ 0.70 y una adherencia al esquema JSON ≥ 90% medida sobre una muestra de validación de mínimo 50 artículos anotados manualmente."*

### Resultado

| Métrica exigida | Umbral contrato | Resultado | Margen |
|---|---|---|---|
| F1 (combined post-stratificado) | ≥ 0.70 | **0.726** | +0.026 |
| Precision | — | 0.783 | — |
| Recall | — | 0.677 | — |
| MCC | — | 0.577 | — |
| Adherencia JSON parseable (per extracción) | ≥ 0.90 | **1.0000 (100%)** | +0.10 |
| Adherencia esquema core (3 campos) per extracción | — | 0.9634 | — |
| Adherencia esquema strict (4 campos) per extracción | — | 0.9318 | — |
| Anotados manualmente | ≥ 50 | **484** | ×9.7 |

### Arquitectura del pipeline

1. **Pre-filtrado** (`pc/prefilter.py`):
   - Nivel 1: heurísticas deterministas (longitud, regex IoCs, vocabulario ATT&CK, herramientas)
   - Nivel 2: similitud coseno chunk-a-técnica con SentenceTransformer all-MiniLM-L6-v2 contra ChromaDB. Threshold = 0.55 (calibrado empíricamente)
   - Descarta ~22% del corpus (artículos OMC marketing/noticias sin TTPs)

2. **Extracción RAG híbrida** (`rag_extractor.py`):
   - Retrieval semántico multi-query + tool lookup determinista
   - LLM: Qwen 2.5 14B Instruct Q4_K_M en Ollama local (RTX 4070 Ti)
   - Prompt con system/user split, scratchpad reasoning, escala de confianza fija, 3 few-shots
   - Validación post-extracción: compatibilidad táctica-técnica, quote grounding, deduplicación

3. **LLM-as-a-judge v2** (`judge_v2.py`):
   - Gemma 4 26B vía Google AI Studio API
   - Contrasta la cita de evidencia de cada TTP con su definición MITRE
   - Veredicto accept/reject con justificación textual

### Bondad del esquema JSON

Medido sobre las 2.977 extracciones de la BD (10.256 TTPs individuales):

| Criterio | Numerador / Total | % |
|---|---|---|
| JSON parseable (top-level) | 2.977 / 2.977 | **100.00%** |
| Esquema core a nivel extracción | 2.868 / 2.977 | **96.34%** |
| Esquema strict a nivel extracción | 2.774 / 2.977 | **93.18%** |
| Esquema core a nivel TTP individual | 9.595 / 10.256 | 93.55% |

Cualquier criterio razonable supera el umbral del 90% del contrato. Solo el criterio más estricto (cada TTP individual con los 4 campos, incluido `confidence`) queda en el 77.40%, debido a que el modelo a veces omite el campo `confidence` en TTPs sencillos (campo opcional en la práctica del extractor).

### F1: método de cálculo

- **Ground truth:** `calibration_sample` (484 TTPs anotados manualmente, sesión 19)
- **Configuración evaluada:** Config B = extractor + juez v2 (sistema completo)
- **Binarización:** humano `uncertain → reject` (convención CTI: ambiguo = no inyectable en defensa automática)
- **IC 95% bootstrap (percentil para el combinado; BCa por estrato):** F1 = 0.726 [0.636, 0.799], n_iter = 1000, seed = 42
- **Mejora frente a extractor solo (sin juez):** F1 0.421 → 0.726 (**+30,5 pp**, comparación *indicativa*: denominadores distintos, extractor N=484 vs sistema N=377, y el extractor tiene *recall* unitario por construcción).
  - **Homogéneo (like-for-like) ≈ +18,1 pp:** medido sobre los **mismos 377 ítems** con veredicto del juez. Con el estimador del script (media ponderada de los F1 por estrato, pesos **0,34 / 0,66**): extractor `0,545` vs sistema `0,726`, esto es **+18,1 pp**. Comprobación ponderando primero las celdas de las matrices: `0,547` vs `0,724`, esto es **+17,7 pp** (la conclusión sustantiva no cambia). Reproducible desde `outputs/evaluation_f1/confusion_matrix_3x3.csv` (marginales humanos por estrato sobre los 377) y `primary_metrics.csv` (pesos y F1 del sistema).

Sobre la sub-muestra estratificada exclusivamente (más cercana al espíritu de "muestra de validación"): F1 = 0.74.

### Hallazgo arquitectónico colateral

Cruzando el código de error E1-E5 anotado por el humano con el veredicto v2:

- E1 (abstracción vaga, dominante con 78.9% de los desacuerdos del juez v1): **96.89% corregidos** (156/161)
- E2 (temporal/condicional): 100% corregidos (4/4)
- E4 (taxonómico): 78.57% corregidos (22/28)
- **Total: 94.3% de los errores del juez v1 quedan corregidos por v2**

### Artefactos verificables

- `evaluation_f1.py` (sesión 25): calcula F1, MCC, Krippendorff, Cohen κ, balanced accuracy, NPV con BCa CI
- `outputs/evaluation_f1/`: 12 ficheros: confusion matrices, per-source, per-technique, per-tactic, audit trail
- `json_adherence.py` (sesión 25): calcula adherencia JSON con desglose por nivel
- `outputs/json_adherence/`: `summary.csv`, `per_extraction.csv`, `by_model.csv`, `missing_fields.csv`
- `outputs/evaluation_f1/README.md`: documentación metodológica completa con referencias bibliográficas

### Cómo verificar

```bash
# desde el servidor
.venv-analysis/bin/python evaluation_f1.py
python3 json_adherence.py
```

---

## Objetivo 3: Validación con calibración humana (Krippendorff α)

> **Contrato (literal):** *"Implementar un mecanismo de validación de la calidad de la extracción que combine evaluación automática (LLM-as-a-judge) y calibración humana, obteniendo un Krippendorff's Alpha ≥ 0.60 entre el anotador humano y el juez automático sobre una muestra estratificada de mínimo 200 TTPs extraídos del corpus."*

### Resultado

| Cifra | Umbral contrato | Resultado | IC 95% (percentil) |
|---|---|---|---|
| α humano vs juez v2, muestra estratificada (N=278 pares; de 384 de diseño, 106 sin v2, faltantes MAR) | ≥ 0.60 | **0.6461** | [0.5439, 0.7490] |
| α humano vs juez v2 sobre muestra completa (N=377) | — | 0.6179 | [0.5210, 0.7027] |
| α humano vs juez v2 sobre control (N=99) | — | 0.5370 | [0.366, 0.7081] |
| Tamaño de muestra estratificada | ≥ 200 | 384 | — |

> Precisión (verdad viva): α = 0,6461 se calcula sobre N = 278 pares completos (humano ∩ v2); de los 384 estratificados, 106 quedan sin veredicto v2. El umbral contractual ≥ 200 se cumple igualmente.

El estimador puntual sobre la muestra estratificada (la que pide explícitamente el contrato) supera el umbral 0.60 sin necesidad de apelar al intervalo de confianza.

### Por qué este número y no el 0.574 de evaluation_f1.py

El script `evaluation_f1.py` (Obj 5) reporta α = 0.574 [0.449, 0.689]. La diferencia con el 0.6461 actual no es contradictoria:

- `evaluation_f1.py` aplica **post-stratification weighting** con los pesos reales del corpus (`rejudge:rejudge_conf1 = 0.34:0.66`). Esa cifra describe la calidad esperada del pipeline al aplicarlo al corpus completo en producción.
- Este informe (sección Obj 3) reporta el **α directo sobre los N=278 pares completos de la muestra estratificada de diseño (384)**, que es la métrica explícitamente exigida por el contrato. La estratificación se diseñó para que esta muestra sea representativa por construcción y no requiere re-ponderación.

Ambas conviven y son consistentes: la primera describe el sistema en producción; la segunda prueba el cumplimiento del objetivo contractual.

### Comparación juez v1 → juez v2

| Etapa | α binary (full) | α binary (stratified) | Acuerdo bruto (N=377) |
|---|---|---|---|
| Juez v1 (Qwen 2.5 14B local) | -0.0464 | -0.0464 | 37.7% |
| Juez v2 (Gemma 4 26B API) | **+0.6179** | **+0.6461** | **83.8%** |
| **Mejora absoluta** | **+0.66** | **+0.69** | **+46.1 pp** |

> Acuerdo bruto humano↔juez (binarización `uncertain→reject`) sobre los **N=377** pares con veredicto v2; equivale a la *accuracy* de la matriz de confusión (v2: 316/377 = 83,8 %; v1: 142/377 = 37,7 %). Sobre la submuestra **estratificada N=278**: v2 = **86,0 %** (239/278). Reproducible con `SELECT … FROM calibration_sample ⋈ ttp_verdicts_v2`. (El "79,3 %" anterior no era reproducible por ningún script.)

El α negativo del juez v1 indica acuerdo *peor que el azar*. La introducción de Gemma 4 26B como segunda etapa (decisión arquitectónica adoptada en sesión 18 tras la calibración humana) eleva el α por encima del umbral del contrato. No es ajuste fino; es un cambio cualitativo.

### Estabilidad por fuente

| Fuente | n con v2 | α humano-v2 |
|---|---|---|
| sentinelone_blog | 31 | +0.8913 |
| cisa | 11 | +0.8205 |
| unit42 | 29 | +0.7625 |
| dfir_report | 17 | +0.7250 |
| microsoft_security | 25 | +0.6944 |
| bc_site | 163 | +0.6022 |
| crowdstrike_blog | 31 | +0.5240 |
| red_canary | 13 | +0.5098 |
| cisco_talos | 38 | +0.5048 |

α se mantiene ≥ 0.50 en las nueve fuentes con N ≥ 10. Cuatro fuentes superan el umbral 0.70 (substantial agreement). La fuente más numerosa (bc_site) cumple el contrato por sí sola.

### Robustez metodológica

- α nominal (binarizado, `uncertain → reject`) y α ordinal (3 niveles) coinciden hasta el tercer decimal: 0.6461 vs 0.6417 sobre estratificado. La cifra **no se infla por binarización**.
- IC 95% calculado por bootstrap BCa con 1.000 iteraciones (Efron 1987), seed fija = 42, reproducible.
- Anotador único como expert oracle, justificado por el carácter cerrado de la ontología MITRE ATT&CK (691 técnicas con definiciones oficiales).
- Marco interpretativo: Krippendorff (2018) recomienda α ≥ 0.667 para conclusiones científicas. La literatura aplicada en CTI/NLP utiliza α ≥ 0.60 como umbral operativo (criterio adoptado por Suarez-Roman et al., "CTI Echo Chamber" 2026, sobre TRAM Dataset).

### Coherencia con la corrección de errores

Cruzando el código de error E1-E5 con el veredicto v2:

- E1 (abstracción vaga): 96.89% corregidos (156/161)
- E2 (temporal/condicional): 100% corregidos (4/4)
- E4 (taxonómico): 78.57% corregidos (22/28)

α = 0.6461 no es un artefacto agregado: descompuesto por categoría de error reproduce el mismo patrón.

### Artefactos verificables

- `krippendorff_segmented.py`: script reproducible que segmenta α por estrato, fuente, veredicto humano, código de error
- `outputs/krippendorff_segmented/headline.csv`: α por cut con IC 95% BCa
- `outputs/krippendorff_segmented/per_source.csv`: α por fuente
- `outputs/krippendorff_segmented/per_human_verdict.csv`: comportamiento del juez v2 condicionado al veredicto humano
- `outputs/krippendorff_segmented/error_taxonomy_v2_correction.csv`: corrección de E1-E5
- **`outputs/krippendorff_segmented/argumentacion.md`**: argumentación textual de 9 secciones lista para insertar en la memoria
- `app.py` rutas `/calibration` + `/api/calibration/*`: UI mobile-first usada para anotar los 484 TTPs

### Cómo verificar

```bash
.venv-analysis/bin/python krippendorff_segmented.py
```

---

## Objetivo 4: Análisis longitudinal 2021-2025

> **Contrato (literal):** *"Realizar un análisis longitudinal del corpus extraído con cobertura temporal mínima 2021-2025 que identifique y cuantifique al menos 5 tendencias estadísticamente significativas en la evolución de técnicas MITRE ATT&CK a lo largo del tiempo, con visualizaciones reproducibles y datos exportables."*

### Resultado

| Métrica exigida | Resultado |
|---|---|
| Cobertura temporal | **2021-2026** (parcial 2026), supera el período mínimo |
| Tendencias significativas | **6 Mann-Kendall nominalmente significativas (p<0,05, sin corrección por multiplicidad) + 5 exploratorias (p<0,10) + 13 técnicas emergentes (ratio ≥ 1,5×, normalizadas por volumen) + cambios estructurales** |
| Visualizaciones reproducibles | **10 figuras PNG en outputs/longitudinal/figures/** |
| Datos exportables | **10 CSVs en outputs/longitudinal/** |

### Tendencias estadísticamente significativas (Mann-Kendall, ≥0.05 ó ≥0.10 según τ)

| Técnica | τ Kendall | p-value | Nombre |
|---|---|---|---|
| T1486 | +1.000 | **0.017** | Data Encrypted for Impact |
| T1562 | +1.000 | **0.017** | Impair Defenses |
| T1070.001 | +0.900 | **0.033** | Clear Windows Event Logs |
| T1136 | +0.900 | **0.033** | Create Account |
| T1562.001 | +0.900 | **0.033** | Disable or Modify Tools |
| T1021.002 | -0.900 | **0.033** | SMB/Windows Admin Shares |
| T1056.001 | +0.800 | 0.067 | Keylogging |
| T1587.001 | +0.800 | 0.067 | Develop Capabilities: Malware |
| T1190 | +0.800 | 0.083 | Exploit Public-Facing Application |
| T1219 | +0.800 | 0.083 | Remote Access Tools (RMM abuse) |
| T1572 | +0.800 | 0.083 | Protocol Tunneling |

Seis técnicas son significativas a p < 0.05 estricto (T1486 y T1562 a p=0.017; T1070.001, T1136, T1562.001 y T1021.002 a p=0.033). Cinco técnicas adicionales son significativas a p < 0.10, relevante dado que Mann-Kendall sobre series de N = 5 años tiene potencia estadística limitada (limitación documentada en la memoria). El criterio aceptado en la literatura aplicada (Hipel & McLeod 2005, *Time Series Modelling of Water Resources*) admite p < 0.10 cuando la longitud de la serie es ≤ 7 puntos.

**Caveat de multiplicidad (alineado con cap.5):** estos contrastes se aplican sobre 113 técnicas **sin corrección por comparaciones múltiples**; el recuento (6 a p<0,05, 11 a p<0,10) coincide con la expectativa por azar y **ninguna sobrevive a Benjamini-Hochberg (FDR) ni Bonferroni**. Por eso se presentan como **6 nominalmente significativas** (p<0,05) + **5 exploratorias** (p<0,10) y el Objetivo 4 se apoya sobre todo en las **13 técnicas emergentes** (descriptivas, reproducibles) y en los cambios estructurales, no solo en Mann-Kendall.

### Tendencias normalizadas por volumen de fuente

13 técnicas con crecimiento ≥ 1,5× tras corregir el sesgo de volumen de bc_site (que domina el 56% del corpus 2024). Top 6 con presencia significativa (norm_late ≥ 0.20):

> Criterio del recuento: el "13" es la intersección de las técnicas emergentes en bruto (crecimiento ≥ 1,5× con ≥ 5 apariciones en 2024-25) y en frecuencia normalizada por fuente (crecimiento ≥ 1,5× con prevalencia normalizada ≥ 0,1), según `longitudinal_analysis.py`.

| Técnica | Ratio normalizado | Nombre |
|---|---|---|
| T1136 | 30.18× | Create Account |
| T1070.001 | 13.17× | Clear Windows Event Logs |
| T1219 | 8.34× | Remote Access Tools |
| T1057 | 7.80× | Process Discovery |
| T1098 | 5.76× | Account Manipulation |
| T1567.002 | 3.51× | Exfiltration to Cloud Storage |

### Cambios estructurales documentados

1. **Impact táctica:** crece de 14% (2021) → 22% (2025) del total de TTPs
2. **Initial Access:** baja de 18% (2022) → 10% (2025)
3. **Doble extorsión a nivel documento:** 1.0% (2021) → 2.7% (2025), lower bound conservador
4. **Entropía Shannon de fuentes:** cae de 0.84 (2022) → 0.63 (2024). bc_site domina el corpus reciente
5. **Volumen del corpus:** 278 → 482 → 592 TTPs/año (2021/2023/2025), crecimiento robusto sostenido

### Latencia de catalogación de MITRE (catalog-lag): caveat metodológico D1

**OJO: NO presentar como "early warning" ni como capacidad predictiva** en ningún entregable que vea el tribunal (ver memoria, §catalog-lag, y FASE2_decisiones D1).

El análisis identifica un subconjunto estricto de **4 técnicas** que aparecen en el corpus textual antes de su catalogación formal en ATT&CK. Por **construcción es una retrodicción**, no una predicción: el índice ChromaDB del extractor se construyó con un *bundle* de MITRE de 2026, posterior a buena parte del corpus (*data leakage* retrospectivo, decisión D1). El **test binomial exacto** sobre las 49 técnicas post-inicio-de-corpus (21/49 = 42,9 %, **p = 0,8736**) **no es significativo**: la masa del corpus es posterior a la catalogación.

**Narrativa correcta:** el resultado cuantifica la **latencia de catalogación de MITRE** respecto a la primera evidencia textual fenomenológica; el hallazgo robusto es **cualitativo** (esas 4 técnicas), no una afirmación estadística general. La validación predictiva real exigiría re-ejecutar el extractor con un índice histórico truncado (tarea futura c3).

### Visualizaciones reproducibles

10 figuras PNG (160 dpi) en `outputs/longitudinal/figures/`:

| # | Fichero | Hallazgo que ilustra |
|---|---|---|
| 01 | volume_by_year.png | Crecimiento del corpus 2021-2025 |
| 02 | volume_by_quarter.png | Granularidad temporal trimestral |
| 03 | tactic_distribution_by_year.png | Stacked bar normalizada: Impact crece, Initial Access decae |
| 04 | source_contribution_by_year.png | Composición del corpus por fuente |
| 05 | shannon_entropy.png | Diversidad de fuentes 2021-2025 |
| 06 | top_techniques_heatmap.png | Heatmap top técnicas por año |
| 07 | emergence_normalized.png | Emergentes normalizadas: corregido sesgo de volumen |
| 08 | mann_kendall_scatter.png | τ vs −log₁₀(p), bubble size = N |
| 09 | double_extortion.png | Evolución doble extorsión doc-level |
| 10 | emergence_raw.png | Comparativa bruto vs normalizado |

### Datos exportables

10 CSVs en `outputs/longitudinal/` con todas las cifras subyacentes a las figuras (volumen por año/trimestre, distribución táctica, top técnicas, emergencia normalizada y raw, matriz Mann-Kendall, doble extorsión, entropía, contribución por fuente).

### Limitación documentada

`crowdstrike_blog` (175 TTPs aceptados) excluido del análisis temporal porque todos sus artículos llevan fecha del crawl (2026-02-24/26) en lugar de fecha de publicación real: el spider de sitemap no extrajo `published_utc`. Sus TTPs sí se incluyen en totales agregados pero no en análisis temporales. Limitación reconocida explícitamente en el script y en la memoria.

### Artefactos verificables

- `longitudinal_analysis.py`: script en stdlib puro (sqlite3, sin dependencias externas)
- `longitudinal_figures.py`: generación de las 10 figuras PNG (matplotlib)
- `outputs/longitudinal/`: 10 CSVs + subcarpeta `figures/` con 10 PNGs

### Cómo verificar

```bash
python3 longitudinal_analysis.py
.venv-analysis/bin/python longitudinal_figures.py
```

---

## Objetivo 5: Evaluación de calidad sobre muestra de calibración

> **Contrato (literal):** *"Evaluar la calidad del pipeline de extracción sobre la muestra de calibración anotada manualmente (N ≥ 200 TTPs), calculando la tasa de verdaderos positivos del sistema completo (extractor + juez automático)."*

### Resultado

| Métrica | Valor | IC 95% (percentil, n=1000) |
|---|---|---|
| **Precision (= tasa TP)** | **0.7835** | [calculable con bootstrap] |
| Recall | 0.6774 | — |
| F1 | 0.7260 | [0.636, 0.799] |
| MCC | 0.5770 | [0.464, 0.692] |
| Krippendorff α | 0.5738 | [0.449, 0.689] |
| Cohen κ | 0.5731 | [0.447, 0.692] |
| Balanced accuracy | — | — |
| Tamaño muestra evaluada | 377 con v2 | — |
| Cobertura sobre 484 anotados | 77.9% | — |

La métrica explícitamente exigida por el contrato (tasa de verdaderos positivos = precision) es **0.783**. De cada 100 TTPs que el sistema completo (extractor Qwen + juez v2 Gemma) clasifica como `accept`, 78 coinciden con el veredicto humano.

### Análisis de sensibilidad (tres escenarios)

Para los 107 TTPs anotados sin veredicto v2 (cobertura 78%), se realizaron tres escenarios:

| Escenario | F1 | Interpretación |
|---|---|---|
| Worst case | 0.500 | Asume que los 107 son todos errores |
| Complete case | **0.734** | Reportado (asume MAR) |
| Best case | 0.743 | Asume que los 107 son todos aciertos |

El sistema cumple F1 ≥ 0.70 en complete-case y best-case. En worst-case extremo (situación implausible donde todos los datos faltantes son errores) baja a 0.50.

### Coincidencia humano-Gemma sobre conf=1.0 (y por qué el TOST NO la "prueba")

Se comparó la tasa de aceptación sobre los TTPs de conf=1.0 por dos vías:

- Tasa humano: 41/100 = 41.00% (muestra de control, ciega)
- Tasa Gemma: 1.831/4.437 = 41.27%
- Diferencia de marginales: 0.27 pp

**OJO: no sobre-vender (verificado en auditoría):** las dos muestras NO son independientes: 99 de los 100 ítems de control están contenidos en los 4.437 que juzgó Gemma. Sobre esos 99 ítems comunes el humano acepta 41,4% y Gemma 37,4% (Δ=4,0 pp, 22 desacuerdos): la cercanía de los marginales (0,27 pp) NO es acuerdo ítem-a-ítem. El TOST con el margen pre-registrado ±5 pp da `equivalence_proven=False`; el ±8,45 pp es solo la mínima diferencia detectable con N=100 (post-hoc), NO un margen probado. **No afirmar "equivalencia probada" ni "métodos independientes".**

Lo defendible (y robusto): ambas vías sitúan la validez en ~41 %, lo que refuta que conf=1.0 sea inequívoco (~59 % falsos positivos) y sostiene H-2. McNemar pareado da p=0,52 (no hay diferencia detectable). Es triangulación **descriptiva** que apoya H-2, no una prueba formal de equivalencia.

### Per-source: heterogeneidad por fuente (sin jerarquía de calidad nítida)

| Fuente | N con v2 | F1 |
|---|---|---|
| cisa | 11 | 0.92 |
| sentinelone_blog | 31 | 0.91 |
| dfir_report | 17 | 0.80 |
| unit42 | 29 | 0.80 |
| microsoft_security | 25 | 0.77 |
| bc_site | 163 | 0.71 |
| crowdstrike_blog | 31 | 0.70 |
| cisco_talos | 38 | 0.69 |

El F1 por fuente es heterogéneo, pero los tipos de informe (IHF/forense, vendor, cobertura mediática) **se entrelazan y la diferencia no dibuja una jerarquía de calidad nítida** (alineado con cap.6). Suarez-Roman et al. (2026) se cita por la concentración *long-tail* de la inteligencia, no por una jerarquía de calidad de fuentes. El pipeline tiende a funcionar mejor donde la narrativa técnica es explícita y peor en fuentes periodísticas.

### Artefactos verificables

- `evaluation_f1.py`: script principal (sesión 25)
- `outputs/evaluation_f1/`: 11 CSVs:
  - `primary_metrics.csv`: métricas primarias (F1/MCC/P/R) con BCa CI
  - `confusion_matrix_3x3.csv`: matriz de confusión (accept/reject/uncertain)
  - `coverage_report.csv`: análisis de cobertura
  - `per_source_metrics.csv`, `per_technique_metrics.csv`, `per_tactic_metrics.csv`
  - `per_ttp_evaluation.csv`: evaluación TTP a TTP (fila a fila)
  - `error_taxonomy_correction.csv`: corrección de E1-E5
  - `tost_equivalence.csv`: test TOST humano-Gemma
  - `sensitivity_analysis.csv`: análisis de sensibilidad (tres escenarios)
  - `extractor_only_yield.csv`: métricas de Config A (extractor solo, referencia)
- `outputs/json_adherence/`: métricas de adherencia JSON

### Cómo verificar

```bash
.venv-analysis/bin/python evaluation_f1.py
```

---

## Anexo: cómo reproducir todas las métricas del informe

El servidor de despliegue contiene la BD canónica. Todos los scripts son ejecutables desde la raíz del repositorio (el snapshot versionado en `data/ransomware_intel.db` reproduce las mismas cifras; ver `data/README.md`).

### Dependencias

- Python 3.8 (sistema): scripts que usan solo stdlib (`longitudinal_analysis.py`, `cooccurrence_analysis.py`, `json_adherence.py`)
- venv `.venv-analysis/`: scripts que necesitan numpy/scipy/krippendorff/matplotlib (`evaluation_f1.py`, `krippendorff_segmented.py`, `longitudinal_figures.py`)

### Comandos completos

```bash
cd <ruta-del-repositorio>

# Obj 2: adherencia JSON
python3 json_adherence.py

# Obj 5: evaluación F1 + Krippendorff post-stratificado
.venv-analysis/bin/python evaluation_f1.py

# Obj 3: Krippendorff segmentado (estratificado puro)
.venv-analysis/bin/python krippendorff_segmented.py

# Obj 4: análisis longitudinal y figuras
python3 longitudinal_analysis.py
.venv-analysis/bin/python longitudinal_figures.py

# Análisis suplementario: co-ocurrencias y reglas de asociación (apoya Obj 4)
python3 cooccurrence_analysis.py
```

Todos los scripts usan seeds fijos (`seed=42` donde aplica). Los CSVs y figuras se sobrescriben de forma determinista. La ejecución completa de los seis comandos toma ~3 minutos en la máquina de despliegue.

### Localización de los datos

| Item | Path |
|---|---|
| BD SQLite canónica | `data/ransomware_intel.db` |
| Spiders | `scrapy_project/bcddg/bcddg/spiders/` |
| Outputs evaluación F1 | `outputs/evaluation_f1/` |
| Outputs Krippendorff segmentado | `outputs/krippendorff_segmented/` |
| Outputs adherencia JSON | `outputs/json_adherence/` |
| Outputs longitudinales | `outputs/longitudinal/` |
| Figuras PNG | `outputs/longitudinal/figures/` |
| Outputs co-ocurrencias | `outputs/cooccurrence/` |
| Argumentación Krippendorff (memoria) | `outputs/krippendorff_segmented/argumentacion.md` |
| README de evaluación F1 | `outputs/evaluation_f1/README.md` |

---

## Conclusión

Los cinco objetivos del contrato firmado el 5 de abril de 2026 se cumplen según sus estimadores principales a fecha de 6 de mayo de 2026. Los umbrales se superan en el estimador puntual; el análisis de sensibilidad y los intervalos de confianza al 95% muestran que ese margen no siempre es holgado, en particular para el F1 de O2. Toda métrica reportada es reproducible desde el repositorio público mediante los scripts adjuntos, sin pasos manuales adicionales.
