#!/usr/bin/env python3
"""
evaluate_benchmark.py Compara los extractores frente al ground truth humano.

Evalúa cada modelo del benchmark v2 contra las anotaciones humanas guardadas en
calibration_sample. Como el ground truth es parcial (solo cubre las técnicas que
Qwen 2.5 llegó a extraer), las métricas son "parciales":

  Partial Recall  = TP / (TP + FN)
    TP = técnicas que el modelo extrae y que en calibration_sample están como accept.
    FN = técnicas marcadas como accept en calibration_sample que el modelo no llega a extraer.

  Partial Precision = TP / (TP + FP_known)
    FP_known = técnicas extraídas por el modelo que aparecen en
               calibration_sample marcadas como reject o uncertain.

  NOTA: las técnicas que el modelo extrae pero que no aparecen en
        calibration_sample no se pueden juzgar con este ground truth.
        Las contamos como "unknown" y no afectan a precision.

Cómo se usa:
    python3 evaluate_benchmark.py

Requisitos:
    pip install tabulate
"""

import json
import os
import sqlite3
from collections import defaultdict

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# --- Configuración ---
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "calibration.db")

RESULTS_DIR = os.path.join(HERE, "benchmark_v2_results")

# Claude Opus vive en el servidor: copia el JSONL aquí si lo quieres incluir
# o pon directamente la ruta absoluta.
CLAUDE_OPUS_JSONL = os.path.expanduser(
    "~/Documentos/Tfg-llm/benchmark_v2_results/claude_opus/extractions.jsonl"
)

MODELS = {
    "qwen25_14b": os.path.join(RESULTS_DIR, "qwen25_14b", "extractions.jsonl"),
    "gemma4_26b": os.path.join(RESULTS_DIR, "gemma4_26b", "extractions.jsonl"),
    "qwen35":     os.path.join(RESULTS_DIR, "qwen35",     "extractions.jsonl"),
    "claude_opus": CLAUDE_OPUS_JSONL,
}

# --- Ground truth ---
def load_ground_truth(db_path):
    """
    Devuelve:
      gt_accept[article_id] = conjunto de technique_id marcados por el anotador humano como "accept".
      gt_reject[article_id] = conjunto de technique_id marcados como "reject" o "uncertain".
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT e.article_id, c.technique_id, c.human_blind_verdict
        FROM calibration_sample c
        JOIN extractions e ON e.id = c.extraction_id
        WHERE c.human_blind_verdict IS NOT NULL
    """)
    rows = cur.fetchall()
    con.close()

    gt_accept  = defaultdict(set)
    gt_reject  = defaultdict(set)
    for art_id, tech, verdict in rows:
        if verdict == "accept":
            gt_accept[art_id].add(tech)
        else:
            gt_reject[art_id].add(tech)

    return gt_accept, gt_reject


def load_extractions(jsonl_path):
    """Devuelve un dict article_id -> conjunto de technique_id que extrajo el modelo."""
    if not os.path.exists(jsonl_path):
        return None
    extracted = defaultdict(set)
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            art_id = d.get("article_id")
            if art_id is None:
                continue
            for ttp in d.get("ttps") or []:
                tid = ttp.get("technique_id")
                if tid:
                    extracted[art_id].add(tid)
    return extracted


# --- Evaluación ---
def evaluate(model_name, extracted, gt_accept, gt_reject):
    """
    Recorre los artículos con ground truth y calcula las métricas parciales.
    """
    if extracted is None:
        return None

    tp = fn = fp_known = unknown = total_extracted = 0

    # Nos quedamos solo con los artículos que tienen ground truth.
    all_gt_articles = set(gt_accept.keys()) | set(gt_reject.keys())

    for art_id in all_gt_articles:
        model_techs   = extracted.get(art_id, set())
        accept_techs  = gt_accept.get(art_id, set())
        reject_techs  = gt_reject.get(art_id, set())

        for tech in model_techs:
            total_extracted += 1
            if tech in accept_techs:
                tp += 1
            elif tech in reject_techs:
                fp_known += 1
            else:
                unknown += 1  # esta técnica no tiene veredicto humano

        # FN: técnicas accept que al modelo se le han pasado.
        fn += len(accept_techs - model_techs)

    precision_partial = tp / (tp + fp_known) if (tp + fp_known) > 0 else float("nan")
    recall_partial    = tp / (tp + fn)        if (tp + fn) > 0        else float("nan")

    if precision_partial > 0 and recall_partial > 0:
        f1 = 2 * precision_partial * recall_partial / (precision_partial + recall_partial)
    else:
        f1 = float("nan")

    return {
        "model": model_name,
        "tp": tp,
        "fp_known": fp_known,
        "fn": fn,
        "unknown": unknown,
        "total_extracted": total_extracted,
        "precision_partial": precision_partial,
        "recall_partial": recall_partial,
        "f1_partial": f1,
    }


# --- Main ---
def fmt(x):
    if isinstance(x, float):
        if x != x:  # nan
            return "N/A"
        return f"{x:.3f}"
    return str(x)


def main():
    print(f"Cargando el ground truth desde {DB_PATH} ...")
    gt_accept, gt_reject = load_ground_truth(DB_PATH)
    n_arts_with_gt = len(set(gt_accept.keys()) | set(gt_reject.keys()))
    total_accept = sum(len(v) for v in gt_accept.values())
    total_reject = sum(len(v) for v in gt_reject.values())
    print(f"  Artículos con ground truth: {n_arts_with_gt}")
    print(f"  Técnicas marcadas accept por humano: {total_accept}")
    print(f"  Técnicas marcadas reject por humano: {total_reject}")
    print()

    results = []
    for model_name, jsonl_path in MODELS.items():
        extracted = load_extractions(jsonl_path)
        if extracted is None:
            print(f"  [{model_name}] no encuentro el JSONL: {jsonl_path}")
            continue
        r = evaluate(model_name, extracted, gt_accept, gt_reject)
        if r:
            results.append(r)
            print(f"  [{model_name}] evaluado: {r['total_extracted']} TTPs extraídas en artículos con GT")

    print()
    print("=" * 72)
    print("  RESULTADOS BENCHMARK v2")
    print("=" * 72)

    headers = ["Modelo", "TP", "FP(known)", "FN", "Unknown",
               "Precision*", "Recall*", "F1*"]
    rows = [
        [
            r["model"],
            r["tp"],
            r["fp_known"],
            r["fn"],
            r["unknown"],
            fmt(r["precision_partial"]),
            fmt(r["recall_partial"]),
            fmt(r["f1_partial"]),
        ]
        for r in sorted(results, key=lambda x: -x.get("f1_partial", 0) if x.get("f1_partial") == x.get("f1_partial") else -1)
    ]

    if HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="github"))
    else:
        print("\t".join(headers))
        for row in rows:
            print("\t".join(str(x) for x in row))

    print()
    print("* Métricas parciales: se calculan solo sobre artículos con anotación humana.")
    print("  'Unknown' = técnicas que el modelo extrae pero sin veredicto humano (no penalizan).")
    print("  Precision = TP/(TP+FP_known); ignora Unknown.")
    print("  Recall    = TP/(TP+FN); sobre técnicas accept que el modelo debería haber encontrado.")

    # Guardamos el CSV
    out_csv = os.path.join(HERE, "benchmark_v2_evaluation.csv")
    with open(out_csv, "w") as f:
        f.write(",".join(headers) + "\n")
        for row in rows:
            f.write(",".join(str(x) for x in row) + "\n")
    print(f"\n  Resultados guardados en: {out_csv}")


if __name__ == "__main__":
    main()
