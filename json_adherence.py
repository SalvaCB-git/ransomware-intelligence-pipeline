#!/usr/bin/env python3
"""
Adherencia al schema JSON del pipeline de extracción LLM.

Reporta la adherencia a tres niveles de exigencia, tanto por extracción
como por TTP:
    parseable:  json.loads(extractions.ttps) no falla.
    core:       cada TTP trae {technique_id, tactic_id, evidence_quote}.
    strict:     core + {confidence}.

Requerido por el contrato del TFG (Objetivo 2): adherencia al schema JSON
>= 90%.

Uso:
    python3 json_adherence.py [--db PATH] [--csv-dir DIR]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
from collections import Counter


HERE = os.path.dirname(os.path.abspath(__file__))
DB_DEFAULT = os.path.join(HERE, "data", "ransomware_intel.db")
CSV_DIR_DEFAULT = os.path.join(HERE, "outputs", "json_adherence")

CORE_FIELDS = frozenset({"technique_id", "tactic_id", "evidence_quote"})
STRICT_FIELDS = CORE_FIELDS | frozenset({"confidence"})


def _header(title):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def save_csv(path, rows, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def collect_adherence_stats(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("SELECT id, model, ttps, valid_ttp_count FROM extractions")
    rows = cur.fetchall()

    n_ext = len(rows)
    n_parseable = 0
    n_ext_core = 0
    n_ext_strict = 0
    n_ttps = 0
    n_ttps_core = 0
    n_ttps_strict = 0

    by_model = {}
    missing_field_counter = Counter()
    per_ext_rows = []

    for ext_id, model, ttps_text, valid_count in rows:
        model_stats = by_model.setdefault(model, {
            "n_ext": 0, "n_parseable": 0, "n_ext_core": 0, "n_ext_strict": 0,
            "n_ttps": 0, "n_ttps_core": 0, "n_ttps_strict": 0,
        })
        model_stats["n_ext"] += 1

        try:
            ttps = json.loads(ttps_text) if ttps_text else []
            parseable = isinstance(ttps, list)
        except json.JSONDecodeError:
            parseable = False
            ttps = []

        if parseable:
            n_parseable += 1
            model_stats["n_parseable"] += 1

        ext_core_ok = parseable
        ext_strict_ok = parseable
        ttps_in_ext = 0
        ttps_core_in_ext = 0
        ttps_strict_in_ext = 0

        for ttp in ttps if parseable else []:
            if not isinstance(ttp, dict):
                ext_core_ok = False
                ext_strict_ok = False
                continue
            n_ttps += 1
            model_stats["n_ttps"] += 1
            ttps_in_ext += 1
            if CORE_FIELDS.issubset(ttp.keys()):
                n_ttps_core += 1
                model_stats["n_ttps_core"] += 1
                ttps_core_in_ext += 1
            else:
                ext_core_ok = False
                for missing in CORE_FIELDS - set(ttp.keys()):
                    missing_field_counter[missing] += 1
            if STRICT_FIELDS.issubset(ttp.keys()):
                n_ttps_strict += 1
                model_stats["n_ttps_strict"] += 1
                ttps_strict_in_ext += 1
            else:
                ext_strict_ok = False
                if "confidence" not in ttp.keys():
                    missing_field_counter["confidence"] += 1

        if ext_core_ok:
            n_ext_core += 1
            model_stats["n_ext_core"] += 1
        if ext_strict_ok:
            n_ext_strict += 1
            model_stats["n_ext_strict"] += 1

        per_ext_rows.append([
            ext_id, model, int(parseable), ttps_in_ext,
            ttps_core_in_ext, ttps_strict_in_ext,
            int(ext_core_ok), int(ext_strict_ok),
        ])

    return {
        "db_path": db_path,
        "n_ext": n_ext,
        "n_parseable": n_parseable,
        "n_ext_core": n_ext_core,
        "n_ext_strict": n_ext_strict,
        "n_ttps": n_ttps,
        "n_ttps_core": n_ttps_core,
        "n_ttps_strict": n_ttps_strict,
        "by_model": by_model,
        "missing_field_counter": missing_field_counter,
        "per_ext_rows": per_ext_rows,
    }


def print_report(stats):
    db_path = stats["db_path"]
    n_ext = stats["n_ext"]
    n_parseable = stats["n_parseable"]
    n_ext_core = stats["n_ext_core"]
    n_ext_strict = stats["n_ext_strict"]
    n_ttps = stats["n_ttps"]
    n_ttps_core = stats["n_ttps_core"]
    n_ttps_strict = stats["n_ttps_strict"]
    by_model = stats["by_model"]
    missing_field_counter = stats["missing_field_counter"]

    # --- imprimir informe ---
    _header("JSON ADHERENCE REPORT")
    print(f"DB:               {db_path}")
    print(f"Total extractions: {n_ext}")
    print(f"Total TTPs:        {n_ttps}")
    print()
    print("Per-extraction adherence (todos los TTPs de la fila pasan):")
    print(f"  parseable:                  {n_parseable}/{n_ext} ({100*n_parseable/n_ext:.2f}%)")
    print(f"  core (3 fields):            {n_ext_core}/{n_ext} ({100*n_ext_core/n_ext:.2f}%)")
    print(f"  strict (core + confidence): {n_ext_strict}/{n_ext} ({100*n_ext_strict/n_ext:.2f}%)")
    print()
    print("Per-TTP adherence:")
    print(f"  core:                       {n_ttps_core}/{n_ttps} ({100*n_ttps_core/n_ttps:.2f}%)")
    print(f"  strict:                     {n_ttps_strict}/{n_ttps} ({100*n_ttps_strict/n_ttps:.2f}%)")
    print()
    print("Conteo de campos ausentes (por TTP, pueden solaparse):")
    for field, n in missing_field_counter.most_common():
        print(f"  {field:20s} {n}")
    print()
    print("Por modelo:")
    for model, model_stats in sorted(by_model.items()):
        print(f"  {model}")
        if model_stats["n_ext"]:
            print(f"    parseable: {model_stats['n_parseable']}/{model_stats['n_ext']} ({100*model_stats['n_parseable']/model_stats['n_ext']:.2f}%)")
            print(f"    ext core:  {model_stats['n_ext_core']}/{model_stats['n_ext']} ({100*model_stats['n_ext_core']/model_stats['n_ext']:.2f}%)")
            print(f"    ext strict:{model_stats['n_ext_strict']}/{model_stats['n_ext']} ({100*model_stats['n_ext_strict']/model_stats['n_ext']:.2f}%)")
        if model_stats["n_ttps"]:
            print(f"    ttp core:  {model_stats['n_ttps_core']}/{model_stats['n_ttps']} ({100*model_stats['n_ttps_core']/model_stats['n_ttps']:.2f}%)")
            print(f"    ttp strict:{model_stats['n_ttps_strict']}/{model_stats['n_ttps']} ({100*model_stats['n_ttps_strict']/model_stats['n_ttps']:.2f}%)")


def write_csv_reports(stats, csv_dir):
    n_ext = stats["n_ext"]
    n_parseable = stats["n_parseable"]
    n_ext_core = stats["n_ext_core"]
    n_ext_strict = stats["n_ext_strict"]
    n_ttps = stats["n_ttps"]
    n_ttps_core = stats["n_ttps_core"]
    n_ttps_strict = stats["n_ttps_strict"]
    by_model = stats["by_model"]
    missing_field_counter = stats["missing_field_counter"]
    per_ext_rows = stats["per_ext_rows"]

    # --- escribir los CSV ---
    summary_rows = [
        ["parseable_per_ext", n_parseable, n_ext, round(100*n_parseable/n_ext, 4)],
        ["core_per_ext", n_ext_core, n_ext, round(100*n_ext_core/n_ext, 4)],
        ["strict_per_ext", n_ext_strict, n_ext, round(100*n_ext_strict/n_ext, 4)],
        ["core_per_ttp", n_ttps_core, n_ttps, round(100*n_ttps_core/n_ttps, 4)],
        ["strict_per_ttp", n_ttps_strict, n_ttps, round(100*n_ttps_strict/n_ttps, 4)],
    ]
    save_csv(os.path.join(csv_dir, "summary.csv"), summary_rows,
             ["metric", "numerator", "denominator", "percent"])

    save_csv(os.path.join(csv_dir, "per_extraction.csv"), per_ext_rows,
             ["extraction_id", "model", "parseable", "ttps_in_ext",
              "ttps_core_ok", "ttps_strict_ok", "ext_core_ok", "ext_strict_ok"])

    by_model_rows = []
    for model, model_stats in sorted(by_model.items()):
        by_model_rows.append([
            model, model_stats["n_ext"], model_stats["n_parseable"], model_stats["n_ext_core"], model_stats["n_ext_strict"],
            model_stats["n_ttps"], model_stats["n_ttps_core"], model_stats["n_ttps_strict"],
        ])
    save_csv(os.path.join(csv_dir, "by_model.csv"), by_model_rows,
             ["model", "n_ext", "parseable", "ext_core", "ext_strict",
              "n_ttps", "ttp_core", "ttp_strict"])

    save_csv(os.path.join(csv_dir, "missing_fields.csv"),
             [(f, n) for f, n in missing_field_counter.most_common()],
             ["field", "n_ttps_missing"])

    print()
    print(f"CSVs written to: {csv_dir}")


def evaluate(db_path, csv_dir):
    stats = collect_adherence_stats(db_path)
    print_report(stats)
    write_csv_reports(stats, csv_dir)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=DB_DEFAULT)
    p.add_argument("--csv-dir", default=CSV_DIR_DEFAULT)
    args = p.parse_args()
    evaluate(args.db, args.csv_dir)


if __name__ == "__main__":
    main()
