#!/usr/bin/env python3
"""
run_benchmark_v2.py Benchmark de extracción RAG: Qwen 3 14B y Gemma 4 26B API.

Ejecuta ambos modelos EN PARALELO sobre los ~300 artículos de calibration_sample:
  - Qwen 3 14B: Ollama local (GPU)
  - Gemma 4 26B: Google AI Studio API (HTTP, no consume GPU)
Como no compiten por recursos, el tiempo total es max(Qwen 3, Gemma API),
aproximadamente 3-4 horas.

Qwen 2.5 14B (el modelo actual) NO se vuelve a ejecutar: sus resultados ya
están guardados en la BD.

Uso:
  cd ~/Documentos/Tfg-llm
  source venv/bin/activate
  ollama pull qwen3.5                            # si no lo tienes
  scp <usuario>@<servidor>:~/services/scraper/data/ransomware_intel.db ./calibration.db
  nohup python3 run_benchmark_v2.py > benchmark_v2.log 2>&1 &
  tail -f benchmark_v2.log

Resultados en benchmark_v2_results/:
  - qwen35/extractions.jsonl
  - gemma4_26b/extractions.jsonl
  - qwen25_14b/extractions.jsonl   (sacado de la BD, no reejecutado)
  - comparison.json                 (tabla P/R/F1 de los tres)
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
import threading
from pathlib import Path
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

from rag_extractor import RagExtractor, SYSTEM_PROMPT

# --- Configuración ---
DB_PATH = Path(os.environ.get("BENCHMARK_DB", "./calibration.db"))
RESULTS_DIR = Path("benchmark_v2_results")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GEMMA_MODEL = "gemma-4-26b-a4b-it"
GEMMA_DELAY_S = 4.0
MAX_BODY_CHARS = 20_000
MAX_BODY_CHARS_API = 12_000  # Gemma API: prompt más corto para evitar 500/502
MAX_CANDIDATES_API = 25      # Gemma API: menos candidatos (frente a los 50 por defecto)

MODELS = [
    ("qwen35",     "ollama", "qwen3.5:latest"),
    ("gemma4_26b", "api",    GEMMA_MODEL),
]

# --- Helpers de BD ---
def load_benchmark_articles(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT DISTINCT a.id AS article_id, a.title, a.body, a.source, a.published_utc
        FROM calibration_sample cs
        JOIN articles a ON a.id = cs.article_id
        WHERE a.body IS NOT NULL AND length(a.body) > 100
        ORDER BY a.id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_human_verdicts(db_path: Path) -> dict:
    """Devuelve un dict {(article_id, technique_id): verdict}."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT article_id, technique_id, human_blind_verdict
        FROM calibration_sample WHERE human_blind_verdict IS NOT NULL
    """).fetchall()
    conn.close()
    return {(r["article_id"], r["technique_id"]): r["human_blind_verdict"] for r in rows}


def extract_qwen25_from_db(db_path: Path) -> Path:
    """Saca los resultados de Qwen 2.5 que ya están en la BD (no reejecuta nada).

    Recupera las extractions y los ttp_verdicts_v2 de los artículos de calibration_sample.
    """
    out_dir = RESULTS_DIR / "qwen25_14b"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "extractions.jsonl"
    if out_file.exists() and out_file.stat().st_size > 0:
        print("[qwen25_14b] Ya se extrajo de la BD, lo salto")
        return out_file

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT DISTINCT e.article_id, a.source, e.ttps, e.valid_ttp_count,
               e.elapsed_seconds, e.model
        FROM calibration_sample cs
        JOIN extractions e ON e.article_id = cs.article_id
        JOIN articles a ON a.id = cs.article_id
        ORDER BY e.article_id
    """).fetchall()
    conn.close()

    with open(out_file, "w") as f:
        for r in rows:
            try:
                ttps = json.loads(r["ttps"]) if r["ttps"] else []
            except json.JSONDecodeError:
                ttps = []
            f.write(json.dumps({
                "article_id": r["article_id"],
                "source": r["source"],
                "model": r["model"] or "qwen2.5:14b-instruct-q4_K_M",
                "error": None,
                "ttps": ttps,
                "valid_ttp_count": r["valid_ttp_count"] or len(ttps),
                "elapsed_seconds": r["elapsed_seconds"],
            }, ensure_ascii=False) + "\n")

    print(f"[qwen25_14b] {len(rows)} extractions extraídas de la BD {out_file}")
    return out_file


# --- Ollama con thinking (Qwen 3) ---
import re as _re_mod

def call_ollama_think(model: str, system_prompt: str, user_prompt: str,
                      timeout: int = 1800) -> dict:
    """Llama a Ollama SIN format:json para que Qwen 3 active su modo thinking.

    Timeout de 1800s (30 min): el thinking puede generar miles de tokens
    antes de producir el JSON. num_predict=16384 deja sitio para el thinking
    y para el JSON de salida.
    """
    payload = {
        "model": model,
        "system": system_prompt,
        "prompt": user_prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 32768,
            "num_ctx": 12288,
            "repeat_penalty": 1.02,
        },
    }
    start = time.time()
    try:
        resp = requests.post("http://localhost:11434/api/generate",
                             json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        elapsed = time.time() - start
        raw = data.get("response", "")

        # Limpiar la respuesta: quitar <think>...</think> y cualquier texto fuera del JSON
        clean = _re_mod.sub(r'<think>.*?</think>', '', raw, flags=_re_mod.DOTALL).strip()
        # Si vino envuelto en ```json...```, quedarse con el contenido
        if '```json' in clean:
            clean = clean.split('```json')[1].split('```')[0].strip()
        elif '```' in clean:
            clean = clean.split('```')[1].split('```')[0].strip()
        # Quedarse desde el primer { en adelante
        start_idx = clean.find('{')
        if start_idx >= 0:
            clean = clean[start_idx:]

        return {
            "raw": clean,
            "elapsed": round(elapsed, 1),
            "tokens": data.get("eval_count", 0),
            "tok_per_sec": round(data.get("eval_count", 0) / elapsed, 1) if elapsed > 0 else 0,
            "error": None,
        }
    except Exception as e:
        return {"raw": "", "elapsed": round(time.time() - start, 1),
                "tokens": 0, "tok_per_sec": 0, "error": str(e)}


# --- Backend de Gemma API ---
def call_gemma_api(system_prompt: str, user_prompt: str, retries: int = 3) -> dict:
    # La API key va en el header x-goog-api-key, NO en la URL (evita que str(e) de
    # un HTTPError la filtre al JSONL de resultados).
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{GEMMA_MODEL}:generateContent")
    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "response_mime_type": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 8192,
            "response_schema": {
                "type": "OBJECT",
                "properties": {
                    "reasoning": {"type": "STRING"},
                    "ransomware_family": {"type": "STRING"},
                    "ttps": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "evidence_quote": {"type": "STRING"},
                                "tactic_id": {"type": "STRING"},
                                "technique_id": {"type": "STRING"},
                                "confidence": {"type": "NUMBER"},
                            },
                            "required": ["evidence_quote", "tactic_id",
                                         "technique_id", "confidence"],
                        },
                    },
                    "unmapped_behaviors": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                    },
                },
                "required": ["reasoning", "ransomware_family", "ttps"],
            },
        },
    }
    for attempt in range(retries):
        start = time.time()
        try:
            r = requests.post(url, json=payload, timeout=300,
                              headers={"x-goog-api-key": GOOGLE_API_KEY})
            if r.status_code == 429:
                time.sleep(30 * (attempt + 1))
                continue
            r.raise_for_status()
            elapsed = time.time() - start
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            return {"raw": text, "elapsed": round(elapsed, 1),
                    "tokens": len(text) // 4, "tok_per_sec": 0, "error": None}
        except (requests.ConnectionError, requests.Timeout):
            time.sleep(5)
        except Exception as e:
            return {"raw": "", "elapsed": round(time.time() - start, 1),
                    "tokens": 0, "tok_per_sec": 0,
                    "error": re.sub(r"key=[\w-]+", "key=***", str(e))}
    return {"raw": "", "elapsed": 0, "tokens": 0, "tok_per_sec": 0,
            "error": "Gemma no respondió tras reintentos"}


# --- Runner genérico ---
def run_model(tag: str, backend: str, model_id: str,
              extractor: RagExtractor, articles: list[dict]):
    """Ejecuta la extracción para un modelo. Reanuda automáticamente usando el JSONL."""
    out_dir = RESULTS_DIR / tag
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "extractions.jsonl"

    done_ids = set()
    if out_file.exists():
        with open(out_file) as f:
            for line in f:
                try:
                    done_ids.add(json.loads(line)["article_id"])
                except (json.JSONDecodeError, KeyError):
                    pass

    pending = [a for a in articles if a["article_id"] not in done_ids]
    total = len(articles)
    print(f"  [{tag}] {len(done_ids)} ya procesados, {len(pending)} pendientes de {total}")

    with open(out_file, "a") as fout:
        for i, art in enumerate(pending):
            aid = art["article_id"]
            n = len(done_ids) + i + 1
            try:
                body = (art["body"] or "")[:MAX_BODY_CHARS]
                print(f"  [{tag}] [{n}/{total}] art={aid} ({art['source']}) ",
                      end="", flush=True)

                # Para el backend API: recortar body y candidatos para evitar 500/502
                if backend == "api":
                    body_for_prompt = body[:MAX_BODY_CHARS_API]
                    candidates = extractor.retrieve_candidates(body_for_prompt)
                    if len(candidates) > MAX_CANDIDATES_API:
                        candidates = candidates[:MAX_CANDIDATES_API]
                else:
                    candidates = extractor.retrieve_candidates(body)

                user_prompt = extractor.build_user_prompt(
                    body[:MAX_BODY_CHARS_API] if backend == "api" else body,
                    candidates,
                )

                if backend == "ollama":
                    response = call_ollama_think(model_id, SYSTEM_PROMPT,
                                                 user_prompt, timeout=1800)
                else:
                    response = call_gemma_api(SYSTEM_PROMPT, user_prompt)
                    time.sleep(GEMMA_DELAY_S)

                if response["error"]:
                    result = {"article_id": aid, "source": art["source"],
                              "model": model_id, "error": response["error"],
                              "ttps": [], "valid_ttp_count": 0,
                              "elapsed_seconds": response["elapsed"]}
                    print(f"ERROR: {response['error'][:60]}")
                else:
                    try:
                        parsed = json.loads(response["raw"])
                    except json.JSONDecodeError:
                        try:
                            parsed, _ = json.JSONDecoder().raw_decode(
                                response["raw"].strip())
                        except (json.JSONDecodeError, ValueError):
                            parsed = {"ttps": []}

                    validation = extractor.validate(parsed, body, candidates)
                    result = {
                        "article_id": aid, "source": art["source"],
                        "model": model_id, "error": None,
                        "ttps": validation["ttps"],
                        "valid_ttp_count": validation["valid_count"],
                        "total_raw_ttps": len(parsed.get("ttps", [])),
                        "validation_issues": validation["issues"],
                        "candidates_count": len(candidates),
                        "elapsed_seconds": response["elapsed"],
                        "tokens": response["tokens"],
                        "tok_per_sec": response["tok_per_sec"],
                    }
                    print(f" {validation['valid_count']} TTPs "
                          f"({response['elapsed']}s)")

                fout.write(json.dumps(result, ensure_ascii=False) + "\n")
                fout.flush()

            except Exception as exc:
                # No dejar nunca que una excepción mate el thread en silencio
                import traceback
                print(f"EXCEPTION art={aid}: {exc}", flush=True)
                traceback.print_exc()
                error_result = {
                    "article_id": aid, "source": art.get("source", "?"),
                    "model": model_id, "error": f"uncaught: {exc}",
                    "ttps": [], "valid_ttp_count": 0,
                    "elapsed_seconds": 0,
                }
                fout.write(json.dumps(error_result, ensure_ascii=False) + "\n")
                fout.flush()

    print(f"  [{tag}] Completado {out_file}")


# --- Evaluación contra la verdad humana ---
def evaluate(tag: str, extractions_file: Path, human_verdicts: dict) -> dict:
    model_ttps = {}
    total_extracted = 0
    errors = 0
    with open(extractions_file) as f:
        for line in f:
            row = json.loads(line)
            aid = row["article_id"]
            if row.get("error"):
                errors += 1
            tids = set()
            for ttp in row.get("ttps", []):
                tid = ttp.get("technique_id", "")
                if tid:
                    tids.add(tid)
            model_ttps[aid] = tids
            total_extracted += len(tids)

    tp = fp = fn = 0
    for (aid, tid), verdict in human_verdicts.items():
        human_pos = (verdict == "accept")
        model_has = tid in model_ttps.get(aid, set())
        if human_pos and model_has:     tp += 1
        elif human_pos and not model_has: fn += 1
        elif not human_pos and model_has: fp += 1

    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    metrics = {
        "tag": tag, "tp": tp, "fp": fp, "fn": fn,
        "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
        "n_articles": len(model_ttps), "n_ttps_extracted": total_extracted,
        "n_errors": errors, "n_human_annotations": len(human_verdicts),
    }
    print(f"  [{tag}] P={p:.3f} R={r:.3f} F1={f1:.3f} "
          f"(TP={tp} FP={fp} FN={fn}, {total_extracted} TTPs, {errors} errores)")
    return metrics


# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Benchmark RAG extractor")
    parser.add_argument("--db", type=Path, default=DB_PATH,
                        help="Ruta a la BD SQLite que contiene calibration_sample")
    parser.add_argument("--evaluate-only", action="store_true",
                        help="Solo evaluar los resultados ya generados, sin ejecutar los modelos")
    args = parser.parse_args()

    db = args.db
    print("=" * 70)
    print("BENCHMARK v2 Qwen 2.5 (BD) + Qwen 3 (Ollama) + Gemma 4 (API)")
    print(f"  Fecha: {datetime.now().isoformat()}")
    print(f"  BD:    {db}")
    print("=" * 70)

    if not db.exists():
        print(f"\nBD no encontrada: {db}")
        print("  scp <usuario>@<servidor>:~/services/scraper/data/ransomware_intel.db ./calibration.db")
        sys.exit(1)

    RESULTS_DIR.mkdir(exist_ok=True)

    # Siempre: sacar los resultados de Qwen 2.5 de la BD (es instantáneo)
    extract_qwen25_from_db(db)

    articles = load_benchmark_articles(db)
    human_verdicts = load_human_verdicts(db)
    print(f"  {len(articles)} artículos, {len(human_verdicts)} anotaciones humanas\n")

    if not args.evaluate_only:
        # Comprobar qué modelos están disponibles
        ollama_ok = False
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            available = {m["name"] for m in r.json().get("models", [])}
            ollama_ok = "qwen3.5:latest" in available
            if not ollama_ok:
                print("qwen3.5:latest no encontrado en Ollama. Ejecuta: ollama pull qwen3.5")
                print(f"  Modelos disponibles: {available}")
        except Exception:
            print("Ollama no accesible")

        api_ok = bool(GOOGLE_API_KEY)
        if not api_ok:
            print("GOOGLE_API_KEY no encontrada Gemma 4 se saltará")

        if not ollama_ok and not api_ok:
            print("\nNingún modelo nuevo disponible.")
            print("  ollama pull qwen3.5")
            print("  .env con GOOGLE_API_KEY=...")
            sys.exit(1)

        # Inicializar el extractor (ChromaDB se comparte entre threads)
        extractor = RagExtractor()

        # --- Lanzar los modelos en paralelo ---
        threads = []

        if ollama_ok:
            t_ollama = threading.Thread(
                target=run_model,
                args=("qwen35", "ollama", "qwen3.5:latest", extractor, articles),
                name="qwen35",
            )
            threads.append(t_ollama)

        if api_ok:
            t_api = threading.Thread(
                target=run_model,
                args=("gemma4_26b", "api", GEMMA_MODEL, extractor, articles),
                name="gemma4",
            )
            threads.append(t_api)

        print(f"Lanzando {len(threads)} threads en paralelo: "
              f"{[t.name for t in threads]}")  # uno por modelo
        print("---" * 70)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print("\nTodos los modelos han terminado.")

    # --- Evaluación ---
    print(f"\n{'='*70}")
    print("EVALUACIÓN CONTRA LA VERDAD DE REFERENCIA HUMANA")
    print(f"{'='*70}\n")

    all_metrics = {}
    for tag in ["qwen25_14b", "qwen35", "gemma4_26b"]:
        f = RESULTS_DIR / tag / "extractions.jsonl"
        if f.exists() and f.stat().st_size > 0:
            metrics = evaluate(tag, f, human_verdicts)
            all_metrics[tag] = metrics
            with open(RESULTS_DIR / tag / "summary.json", "w") as sf:
                json.dump(metrics, sf, indent=2)
        else:
            print(f"  [{tag}] sin resultados, lo salto")

    if all_metrics:
        with open(RESULTS_DIR / "comparison.json", "w") as f:
            json.dump(all_metrics, f, indent=2)

        print(f"\n{'='*70}")
        print("TABLA COMPARATIVA")
        print(f"{'='*70}")
        print(f"{'Modelo':<16} {'P':>7} {'R':>7} {'F1':>7} {'TTPs':>7} "
              f"{'TP':>5} {'FP':>5} {'FN':>5} {'Err':>5}")
        print("---" * 70)
        for tag, m in all_metrics.items():
            print(f"{tag:<16} {m['precision']:>7.3f} {m['recall']:>7.3f} "
                  f"{m['f1']:>7.3f} {m['n_ttps_extracted']:>7} "
                  f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['n_errors']:>5}")

    print(f"\n Resultados en: {RESULTS_DIR.absolute()}")


if __name__ == "__main__":
    main()
