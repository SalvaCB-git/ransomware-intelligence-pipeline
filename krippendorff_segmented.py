#!/usr/bin/env python3
"""
Análisis segmentado del alpha de Krippendorff para el Objetivo 3 de la
memoria TFG.

Calcula alpha (humano vs juez v2) sobre varios cortes de calibration_sample
para dar una visión más rica que la cifra titular 0.574 de evaluation_f1.py:
    - corpus completo vs estratificado vs control
    - por fuente (N >= 10)
    - por verdict de v1 (¿corrige v2 igual de bien en cada categoría de v1?)
    - por código de la taxonomía de errores (E1-E5)
    - humano binarizado (uncertain -> reject) frente a ordinal (3 niveles
      para v1, 2 para v2)
    - baseline de v1 como referencia (alpha = -0.1452 reportado en la
      sesión 19)
Incluye intervalos de confianza al 95% por BCa bootstrap para las filas
titulares.

Uso:
    .venv-analysis/bin/python \
        krippendorff_segmented.py [--db PATH] [--csv-dir DIR] [--bootstrap-iter N]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
from collections import Counter, defaultdict

import numpy as np
import krippendorff


HERE = os.path.dirname(os.path.abspath(__file__))
DB_DEFAULT = os.path.join(HERE, "data", "ransomware_intel.db")
CSV_DIR_DEFAULT = os.path.join(HERE, "outputs", "krippendorff_segmented")

BIN_HUMAN = {"accept": 1, "reject": 0, "uncertain": 0}
BIN_V = {"accept": 1, "reject": 0}


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


def load_samples(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT c.id, c.sample_type, c.extraction_id, c.ttp_index,
               c.technique_id, c.source, c.human_blind_verdict,
               v.verdict AS v2_verdict,
               c.llm_verdict AS v1_verdict,
               c.error_taxonomy_code,
               e.ttps
        FROM calibration_sample c
        LEFT JOIN ttp_verdicts_v2 v
          ON v.extraction_id = c.extraction_id AND v.ttp_index = c.ttp_index
        LEFT JOIN extractions e ON e.id = c.extraction_id
        WHERE c.human_blind_verdict IS NOT NULL
        ORDER BY c.id
    """)
    out = []
    for row in cur.fetchall():
        cs_id, sample_type, extraction_id, ttp_index, technique_id, source, \
            human_verdict, v2_verdict, v1_verdict, error_code, ttps_json = row
        tactic_id = None
        try:
            ttps = json.loads(ttps_json)
            if 0 <= ttp_index < len(ttps):
                tactic_id = ttps[ttp_index].get("tactic_id")
        except (json.JSONDecodeError, TypeError, KeyError, IndexError):
            pass
        out.append({
            "cs_id": cs_id, "sample_type": sample_type,
            "tech": technique_id, "tactic_id": tactic_id, "source": source,
            "human": human_verdict, "v2": v2_verdict, "v1": v1_verdict,
            "err": error_code,
        })
    con.close()
    return out


# ---- utilidades de alpha --------------------------------------------------

def _alpha(y_true, y_pred, level):
    if len(y_true) == 0:
        return float("nan")
    data = np.array([y_true, y_pred])
    try:
        return float(krippendorff.alpha(reliability_data=data,
                                        level_of_measurement=level))
    except Exception:
        return float("nan")


def alpha_nominal(y_true, y_pred):
    return _alpha(y_true, y_pred, "nominal")


def alpha_ordinal(y_true, y_pred):
    return _alpha(y_true, y_pred, "ordinal")


def stats_norm_ppf(p):
    from scipy.stats import norm
    return float(norm.ppf(np.clip(p, 1e-9, 1 - 1e-9)))


def stats_norm_cdf(z):
    from scipy.stats import norm
    return float(norm.cdf(z))


def bootstrap_ci(metric_fn, y1, y2, n_iter, rng, alpha_level=0.05):
    """Intervalo de confianza BCa al 95% para una métrica tipo alpha sobre
    los arrays emparejados y1, y2."""
    n = len(y1)
    if n < 5:
        return float("nan"), float("nan")
    point = metric_fn(y1, y2)
    if not np.isfinite(point):
        return float("nan"), float("nan")
    boot = np.empty(n_iter)
    for i in range(n_iter):
        idx = rng.integers(0, n, n)
        boot[i] = metric_fn(y1[idx], y2[idx])
    boot = boot[np.isfinite(boot)]
    if len(boot) < 50:
        return float("nan"), float("nan")
    # Corrección de sesgo.
    z0 = stats_norm_ppf(np.mean(boot < point))
    # Aceleración por jackknife.
    jack = np.empty(n)
    for i in range(n):
        mask = np.ones(n, dtype=bool)
        mask[i] = False
        jack[i] = metric_fn(y1[mask], y2[mask])
    jack = jack[np.isfinite(jack)]
    jbar = np.mean(jack)
    num = np.sum((jbar - jack) ** 3)
    den = 6.0 * (np.sum((jbar - jack) ** 2) ** 1.5)
    a_hat = num / den if den != 0 else 0.0
    # Percentiles BCa.
    z_lo = stats_norm_ppf(alpha_level / 2)
    z_hi = stats_norm_ppf(1 - alpha_level / 2)
    p_lo = stats_norm_cdf(z0 + (z0 + z_lo) / (1 - a_hat * (z0 + z_lo)))
    p_hi = stats_norm_cdf(z0 + (z0 + z_hi) / (1 - a_hat * (z0 + z_hi)))
    return float(np.quantile(boot, p_lo)), float(np.quantile(boot, p_hi))


# ---- utilidades de segmentación -------------------------------------------

def to_binary(samples, judge_key):
    human_labels, judge_labels = [], []
    for s in samples:
        if s["human"] is None or s[judge_key] is None:
            continue
        if s[judge_key] not in BIN_V:
            # v1 puede traer "uncertain": lo colapsamos a reject para la
            # vista binaria.
            if s[judge_key] == "uncertain":
                judge_value = 0
            else:
                continue
        else:
            judge_value = BIN_V[s[judge_key]]
        human_labels.append(BIN_HUMAN[s["human"]])
        judge_labels.append(judge_value)
    return np.array(human_labels), np.array(judge_labels)


def to_ordinal(samples, judge_key):
    """Ordinal de 3 niveles: reject=0, uncertain=1, accept=2 (v2 no tiene
    uncertain)."""
    ORDINAL_LEVELS = {"reject": 0, "uncertain": 1, "accept": 2}
    human_labels, judge_labels = [], []
    for s in samples:
        if s["human"] is None or s[judge_key] is None:
            continue
        if s["human"] not in ORDINAL_LEVELS or s[judge_key] not in ORDINAL_LEVELS:
            continue
        human_labels.append(ORDINAL_LEVELS[s["human"]])
        judge_labels.append(ORDINAL_LEVELS[s[judge_key]])
    return np.array(human_labels), np.array(judge_labels)


# ---- análisis -------------------------------------------------------------

def analyze_headline(samples, csv_dir, n_iter, rng):
    rows = []
    cuts = [
        ("full", samples),
        ("stratified", [s for s in samples if s["sample_type"] == "stratified"]),
        ("control", [s for s in samples if s["sample_type"] == "control"]),
    ]
    for label, sub in cuts:
        for judge in ("v1", "v2"):
            h, j = to_binary(sub, judge)
            n = len(h)
            alpha_binary = alpha_nominal(h, j)
            ci_lo, ci_hi = bootstrap_ci(alpha_nominal, h, j, n_iter, rng) if n >= 5 else (float("nan"), float("nan"))
            rows.append([label, judge, "binary", n, round(alpha_binary, 4),
                         round(ci_lo, 4), round(ci_hi, 4)])
            h, j = to_ordinal(sub, judge)
            alpha_ordinal_val = alpha_ordinal(h, j)
            rows.append([label, judge, "ordinal", len(h), round(alpha_ordinal_val, 4), "", ""])

    save_csv(os.path.join(csv_dir, "headline.csv"), rows,
             ["cut", "judge", "level", "n", "alpha", "ci95_lo", "ci95_hi"])
    _header("HEADLINE alpha by cut and judge")
    print(f"{'cut':<12} {'judge':<5} {'lvl':<8} {'n':>4}  alpha  CI95")
    for r in rows:
        ci = f"[{r[5]}, {r[6]}]" if r[5] != "" else ""
        print(f"  {r[0]:<10} {r[1]:<5} {r[2]:<8} {r[3]:>4}  {r[4]:>.4f}  {ci}")


def analyze_per_source(samples, csv_dir, min_n=10):
    by_src = defaultdict(list)
    for s in samples:
        if s["source"]:
            by_src[s["source"]].append(s)
    rows = []
    for src, sub in sorted(by_src.items()):
        if len(sub) < min_n:
            continue
        for judge in ("v1", "v2"):
            h, j = to_binary(sub, judge)
            if len(h) < min_n:
                continue
            a = alpha_nominal(h, j)
            rows.append([src, judge, len(h), round(a, 4),
                         int(sum(h)), int(len(h) - sum(h)),
                         int(sum(j)), int(len(j) - sum(j))])
    save_csv(os.path.join(csv_dir, "per_source.csv"), rows,
             ["source", "judge", "n", "alpha_binary",
              "human_accepts", "human_rejects",
              "judge_accepts", "judge_rejects"])
    _header(f"PER-SOURCE alpha (binary, N>={min_n})")
    print(f"{'source':<22} {'judge':<5} {'n':>4} {'alpha':>7}  h+/h-  v+/v-")
    for r in rows:
        print(f"  {r[0]:<20} {r[1]:<5} {r[2]:>4}  {r[3]:>+.4f}  "
              f"{r[4]}/{r[5]:<4}  {r[6]}/{r[7]}")


def analyze_per_v1_verdict(samples, csv_dir):
    """¿Corrigió v2 igual de bien los accepts y los rejects de v1?"""
    rows = []
    for v1cat in ("accept", "reject", "uncertain"):
        sub = [s for s in samples if s["v1"] == v1cat]
        if not sub:
            continue
        h_v2, j_v2 = to_binary(sub, "v2")
        n = len(h_v2)
        if n == 0:
            continue
        a = alpha_nominal(h_v2, j_v2)
        agree = int(np.sum(h_v2 == j_v2))
        rows.append([v1cat, n, round(a, 4), agree, n - agree,
                     round(100 * agree / n, 2)])
    save_csv(os.path.join(csv_dir, "per_v1_verdict.csv"), rows,
             ["v1_verdict", "n", "alpha_human_v2", "agree", "disagree", "agree_pct"])
    _header("PER v1 VERDICT does v2 correct accepts and rejects equally?")
    for r in rows:
        print(f"  v1={r[0]:<10} n={r[1]:>4}  alpha={r[2]:>+.4f}  agree={r[3]}/{r[1]} ({r[5]}%)")


def analyze_error_taxonomy(samples, csv_dir):
    """De los 237 desacuerdos humano-v1, ¿qué fracción arregla v2 por
    código E?"""
    by_code = Counter()
    fixed_by_v2 = Counter()
    total_anno = Counter()
    for s in samples:
        if s["err"]:
            by_code[s["err"]] += 1
            if s["human"] is not None and s["v2"] is not None:
                # "Arreglado por v2" = v2 coincide con el humano tras
                # binarizar.
                hb = BIN_HUMAN[s["human"]]
                vb = BIN_V.get(s["v2"], 0)
                if hb == vb:
                    fixed_by_v2[s["err"]] += 1
                total_anno[s["err"]] += 1
    rows = []
    for code in sorted(by_code, key=lambda c: -by_code[c]):
        ta = total_anno[code]
        fx = fixed_by_v2[code]
        pct = round(100 * fx / ta, 2) if ta else 0
        rows.append([code, by_code[code], ta, fx, pct])
    save_csv(os.path.join(csv_dir, "error_taxonomy_v2_correction.csv"), rows,
             ["error_code", "n_total", "n_with_v2", "n_corrected_by_v2", "pct_corrected"])
    _header("ERROR TAXONOMY fraction corrected by v2")
    for r in rows:
        print(f"  {r[0]:<6}  total={r[1]:>4}  with_v2={r[2]:>4}  fixed={r[3]}  ({r[4]}%)")


def analyze_per_human_verdict(samples, csv_dir):
    """Por categoría del humano: ¿reproduce v2 igual de bien los accepts y
    rejects del anotador humano?"""
    rows = []
    for hcat in ("accept", "reject", "uncertain"):
        sub = [s for s in samples if s["human"] == hcat and s["v2"] is not None]
        if not sub:
            continue
        v2_acc = sum(1 for s in sub if s["v2"] == "accept")
        v2_rej = sum(1 for s in sub if s["v2"] == "reject")
        n = len(sub)
        rows.append([hcat, n, v2_acc, v2_rej,
                     round(100 * v2_acc / n, 2),
                     round(100 * v2_rej / n, 2)])
    save_csv(os.path.join(csv_dir, "per_human_verdict.csv"), rows,
             ["human_verdict", "n", "v2_accept", "v2_reject", "v2_accept_pct", "v2_reject_pct"])
    _header("PER HUMAN VERDICT what does v2 do?")
    for r in rows:
        print(f"  human={r[0]:<10} n={r[1]:>4}  v2_acc={r[2]} ({r[4]}%)  v2_rej={r[3]} ({r[5]}%)")


def analyze_sample_type_x_human(samples, csv_dir):
    rows = []
    for stype in ("stratified", "control"):
        for hcat in ("accept", "reject", "uncertain"):
            sub = [s for s in samples if s["sample_type"] == stype and s["human"] == hcat]
            with_v2 = [s for s in sub if s["v2"] is not None]
            v2_acc = sum(1 for s in with_v2 if s["v2"] == "accept")
            rows.append([stype, hcat, len(sub), len(with_v2), v2_acc,
                         len(with_v2) - v2_acc])
    save_csv(os.path.join(csv_dir, "sample_type_x_human.csv"), rows,
             ["sample_type", "human", "n", "n_with_v2", "v2_accept", "v2_reject"])
    _header("SAMPLE_TYPE × HUMAN VERDICT × V2")
    print(f"{'sample_type':<12} {'human':<10} {'n':>4} {'with_v2':>7} {'v2_acc':>7} {'v2_rej':>7}")
    for r in rows:
        print(f"  {r[0]:<10} {r[1]:<10} {r[2]:>4} {r[3]:>7} {r[4]:>7} {r[5]:>7}")


# ---- main -----------------------------------------------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=DB_DEFAULT)
    p.add_argument("--csv-dir", default=CSV_DIR_DEFAULT)
    p.add_argument("--bootstrap-iter", type=int, default=1000)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    rng = np.random.default_rng(args.seed)
    samples = load_samples(args.db)
    print(f"Loaded {len(samples)} calibration_sample rows")
    print(f"  with v2 verdict: {sum(1 for s in samples if s['v2'] is not None)}")
    print(f"  with v1 verdict: {sum(1 for s in samples if s['v1'] is not None)}")

    analyze_headline(samples, args.csv_dir, args.bootstrap_iter, rng)
    analyze_per_source(samples, args.csv_dir)
    analyze_per_v1_verdict(samples, args.csv_dir)
    analyze_error_taxonomy(samples, args.csv_dir)
    analyze_per_human_verdict(samples, args.csv_dir)
    analyze_sample_type_x_human(samples, args.csv_dir)

    print()
    print(f"CSVs written to: {args.csv_dir}")


if __name__ == "__main__":
    main()
