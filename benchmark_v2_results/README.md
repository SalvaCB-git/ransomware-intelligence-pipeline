# benchmark_v2_results/

Resultados crudos del **benchmark v2 de extractores** (sesión 30, 22-may-2026).
Comparativa de 4 modelos como extractores raw sobre los 402 artículos de
`calibration_sample`.

Detalles del diseño experimental, resultados y conclusiones en la memoria del
TFG (§benchmark de extractores).

---

## `claude_opus/`

### `extractions.jsonl`

Extracciones raw producidas por **Claude Opus** (vía ventana CC separada, no API
batch) sobre los 402 artículos del `calibration_sample`. Una línea JSON por
artículo. Estructura compatible con la del resto de extractores del benchmark
(`benchmark.py` en `pc/`).

**Estado de evaluación:** **pendiente**. La evaluación parcial registrada en
la memoria (§benchmark, tabla con Qwen 2.5, Gemma 4 y Qwen 3.5) **no incluye
Claude Opus** porque el JSONL se generó directamente en el servidor y no se
copió al PC a tiempo para el run de `pc/evaluate_benchmark.py`.

Para evaluar:

```bash
# En PC (con el venv del proyecto):
scp <usuario>@<servidor>:~/services/scraper/benchmark_v2_results/claude_opus/extractions.jsonl \
    ~/Documentos/Tfg-llm/benchmark_v2_results/claude_opus/
cd ~/Documentos/Tfg-llm
python3 pc/evaluate_benchmark.py   # evalúa todos los JSONL presentes (sin flags)
```

Esto produce P/R/F1 sobre `calibration_sample` con las mismas reglas TP/FP/FN/Unknown
del resto del benchmark.

**Uso esperado:** input para la **fase 2 del benchmark** (extractor permisivo +
juez estricto, ver la memoria §benchmark) en el paper conjunto con FIU.
**No bloquea la entrega del TFG**: el corpus limpio definitivo (2.355 TTPs) y
las cifras estrella (F1=0,726, convergencia 41,0/41,4) son independientes de
esta evaluación pendiente.

### `write_batch_034_040.py`

Script **one-shot** usado durante la sesión 30 para escribir los batches
específicos 034-040 al JSONL durante la captura interactiva de extracciones de
Claude Opus. **No reutilizable** y **no documenta una API pública**: se
conserva como traza del procedimiento manual.
