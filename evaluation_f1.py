#!/usr/bin/env python3
"""
Validación post-hoc de candidatos del pipeline de extracción de TTPs.

Compara dos configuraciones contra el calibration_sample anotado por humano
(N=484):
    Config A (solo extractor):       cada TTP que produce Qwen 2.5 14B cuenta como "accept".
    Config B (extractor + juez):     un TTP se acepta solo si Gemma 4 26B (juez v2) lo acepta.

Salidas:
    1. Cobertura (484 anotados, 377 con veredicto v2).
    2. Matriz de confusión 3x3 (humano × v2_verdict) por estrato.
    3. Métricas principales (MCC, Krippendorff alpha, kappa de Cohen, F1, P,
       R, balanced accuracy) con intervalos de confianza al 95% por bootstrap
       BCa (1000 iteraciones).
    4. Análisis de sensibilidad de tres escenarios para los 107 veredictos v2 que
       faltan (worst_case / complete_case / best_case).
    5. Test de equivalencia TOST para la convergencia humano-Gemma 4 sobre
       conf=1.0 (p_human=41/100 vs p_gemma=accepts/total sobre rejudge_conf1).
    6. Anexo: métricas del extractor solo, sobre N=484.
    7. Audit trail por TTP.

Uso:
    .venv-analysis/bin/python evaluation_f1.py [...]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
from collections import Counter

import numpy as np
import scipy.stats as stats
import krippendorff


HERE = os.path.dirname(os.path.abspath(__file__))
DB_DEFAULT = os.path.join(HERE, "data", "ransomware_intel.db")
CSV_DIR_DEFAULT = os.path.join(HERE, "outputs", "evaluation_f1")

# Binarización: el "uncertain" del humano se colapsa a "reject" (equivalencia
# operativa en CTI: un TTP ambiguo no se puede meter en un pipeline de defensa
# automatizada).
BIN_HUMAN = {"accept": 1, "reject": 0, "uncertain": 0}
BIN_V2 = {"accept": 1, "reject": 0}


# ---- Helpers de IO ---------------------------------------------------

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
    print(f"  -> guardado {path}")


def load_data(db_path):
    """Devuelve (samples, sm_verdict).

    samples: lista de dicts, uno por cada fila de calibration_sample con
             human_blind_verdict no nulo, juntado con ttp_verdicts_v2
             (LEFT JOIN, así que v2 puede ser None). Incluye tactic_id
             (parseado del JSON extractions.ttps), llm_verdict (v1) y
             error_taxonomy_code para los análisis suplementarios.
    sm_verdict: dict[(source_mode, verdict)] = conteo, usado en el TOST.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT
            c.id, c.sample_type, c.extraction_id, c.ttp_index,
            c.technique_id, c.source, c.human_blind_verdict, v.verdict,
            c.llm_verdict, c.error_taxonomy_code, e.ttps
        FROM calibration_sample c
        LEFT JOIN ttp_verdicts_v2 v
          ON v.extraction_id = c.extraction_id AND v.ttp_index = c.ttp_index
        LEFT JOIN extractions e ON e.id = c.extraction_id
        WHERE c.human_blind_verdict IS NOT NULL
        ORDER BY c.id
    """)
    samples = []
    for row in cur.fetchall():
        cs_id, stype, eid, idx, tech, source, human_verdict, v2_verdict, v1, err_code, ttps_json = row
        tactic_id = None
        try:
            ttps = json.loads(ttps_json)
            if 0 <= idx < len(ttps):
                tactic_id = ttps[idx].get("tactic_id")
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
        samples.append({
            "cs_id": cs_id, "sample_type": stype,
            "extraction_id": eid, "ttp_index": idx,
            "technique_id": tech, "tactic_id": tactic_id,
            "source": source, "human": human_verdict, "v2": v2_verdict,
            "v1": v1, "error_code": err_code,
        })

    cur.execute("SELECT source_mode, verdict, COUNT(*) FROM ttp_verdicts_v2 GROUP BY source_mode, verdict")
    sm_verdict = {(r[0], r[1]): r[2] for r in cur.fetchall()}
    con.close()
    return samples, sm_verdict


# ---- Funciones de métricas -------------------------------------------

def confusion(y_true, y_pred):
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    return tp, fp, fn, tn


def m_mcc(y_true, y_pred):
    tp, fp, fn, tn = confusion(y_true, y_pred)
    denom = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denom == 0:
        return np.nan
    return (tp * tn - fp * fn) / denom


def m_f1(y_true, y_pred):
    tp, fp, fn, _ = confusion(y_true, y_pred)
    if tp == 0 and (fp == 0 and fn == 0):
        return np.nan
    if tp == 0:
        return 0.0
    p = tp / (tp + fp)
    r = tp / (tp + fn)
    return 2 * p * r / (p + r) if (p + r) > 0 else np.nan


def m_precision(y_true, y_pred):
    tp, fp, _, _ = confusion(y_true, y_pred)
    return tp / (tp + fp) if (tp + fp) > 0 else np.nan


def m_recall(y_true, y_pred):
    tp, _, fn, _ = confusion(y_true, y_pred)
    return tp / (tp + fn) if (tp + fn) > 0 else np.nan


def m_balanced_accuracy(y_true, y_pred):
    tp, fp, fn, tn = confusion(y_true, y_pred)
    sens = tp / (tp + fn) if (tp + fn) > 0 else np.nan
    spec = tn / (tn + fp) if (tn + fp) > 0 else np.nan
    if np.isnan(sens) or np.isnan(spec):
        return np.nan
    return (sens + spec) / 2


def m_npv(y_true, y_pred):
    _, _, fn, tn = confusion(y_true, y_pred)
    return tn / (tn + fn) if (tn + fn) > 0 else np.nan


def m_accuracy(y_true, y_pred):
    tp, fp, fn, tn = confusion(y_true, y_pred)
    n = tp + fp + fn + tn
    return (tp + tn) / n if n > 0 else np.nan


def m_krippendorff(y_true, y_pred):
    if len(y_true) == 0:
        return np.nan
    data = np.array([y_true, y_pred])
    try:
        return float(krippendorff.alpha(reliability_data=data, level_of_measurement="nominal"))
    except Exception:
        return np.nan


def m_cohens_kappa(y_true, y_pred):
    if len(y_true) == 0:
        return np.nan
    po = float(np.mean(y_true == y_pred))
    p_t1 = float(np.mean(y_true == 1))
    p_p1 = float(np.mean(y_pred == 1))
    pe = p_t1 * p_p1 + (1 - p_t1) * (1 - p_p1)
    if pe == 1:
        return np.nan
    return (po - pe) / (1 - pe)


def metrics_full(y_true, y_pred):
    """Todas las métricas más la matriz de confusión cruda. Se usa en el análisis de sensibilidad."""
    tp, fp, fn, tn = confusion(y_true, y_pred)
    return {
        "n": int(tp + fp + fn + tn),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "mcc": m_mcc(y_true, y_pred),
        "f1": m_f1(y_true, y_pred),
        "precision": m_precision(y_true, y_pred),
        "recall": m_recall(y_true, y_pred),
        "balanced_accuracy": m_balanced_accuracy(y_true, y_pred),
        "npv": m_npv(y_true, y_pred),
        "accuracy": m_accuracy(y_true, y_pred),
    }


# ---- Bootstrap BCa ---------------------------------------------------

def bootstrap_bca(metric_fn, y_true, y_pred, n_iter, rng, alpha=0.05):
    """Intervalo de confianza BCa al 95% para una métrica. Devuelve (point, ci_low, ci_high)."""
    n = len(y_true)
    point = metric_fn(y_true, y_pred)
    if np.isnan(point) or n == 0:
        return point, np.nan, np.nan

    boot = np.empty(n_iter)
    for b in range(n_iter):
        idx = rng.integers(0, n, size=n)
        boot[b] = metric_fn(y_true[idx], y_pred[idx])
    valid = boot[~np.isnan(boot)]
    if len(valid) < 10:
        return point, np.nan, np.nan

    # Corrección de sesgo z0
    prop_below = float(np.mean(valid < point))
    if prop_below in (0.0, 1.0):
        z0 = 0.0
    else:
        z0 = stats.norm.ppf(prop_below)

    # Aceleración por jackknife
    jk = np.empty(n)
    for i in range(n):
        mask = np.ones(n, dtype=bool)
        mask[i] = False
        jk[i] = metric_fn(y_true[mask], y_pred[mask])
    jk_valid = jk[~np.isnan(jk)]
    if len(jk_valid) < 2:
        a = 0.0
    else:
        jk_mean = jk_valid.mean()
        num = np.sum((jk_mean - jk_valid) ** 3)
        denom = 6 * (np.sum((jk_mean - jk_valid) ** 2) ** 1.5)
        a = num / denom if denom > 0 else 0.0

    z_lo = stats.norm.ppf(alpha / 2)
    z_hi = stats.norm.ppf(1 - alpha / 2)

    def adjust(z_a):
        denom_in = 1 - a * (z0 + z_a)
        if denom_in == 0:
            return alpha / 2 if z_a < 0 else 1 - alpha / 2
        return float(stats.norm.cdf(z0 + (z0 + z_a) / denom_in))

    a_lo = adjust(z_lo)
    a_hi = adjust(z_hi)
    a_lo = min(max(a_lo, 0.001), 0.999)
    a_hi = min(max(a_hi, 0.001), 0.999)

    ci_low = float(np.quantile(valid, a_lo))
    ci_high = float(np.quantile(valid, a_hi))
    return float(point), ci_low, ci_high


# ---- TOST -----------------------------------------------------------

def tost_two_proportions(p1, n1, p2, n2, delta, alpha=0.05):
    """Two One-Sided Tests para la equivalencia de dos proporciones independientes.

    H0_lower: p1 - p2 <= -delta   (se rechaza si la diferencia observada > -delta)
    H0_upper: p1 - p2 >=  delta   (se rechaza si la diferencia observada <  delta)
    La equivalencia queda probada si ambas se rechazan al nivel alpha.
    """
    diff = p1 - p2
    se = np.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)

    z_low = (diff - (-delta)) / se
    p_low = 1 - stats.norm.cdf(z_low)

    z_high = (diff - delta) / se
    p_high = stats.norm.cdf(z_high)

    # Delta mínimo a partir del cual quedaría probada la equivalencia al
    # nivel alpha, dadas la diferencia observada y el error estándar. Sirve
    # como "margen detectable post-hoc".
    z_alpha = stats.norm.ppf(1 - alpha)
    delta_min_lower = -diff + z_alpha * se   # margen necesario para que p_low < alpha
    delta_min_upper = diff + z_alpha * se    # margen necesario para que p_high < alpha
    delta_min = float(max(delta_min_lower, delta_min_upper))

    return {
        "p1": p1, "n1": n1, "p2": p2, "n2": n2, "delta": delta,
        "observed_difference": float(diff), "standard_error": float(se),
        "p_low": float(p_low), "p_high": float(p_high),
        "equivalence_proven": (p_low < alpha) and (p_high < alpha),
        "delta_min": delta_min,
    }


# ---- Sensibilidad (tres escenarios) ---------------------------------

def sensitivity_scenarios(samples):
    """Tres escenarios de imputación para los veredictos v2 que faltan.

    complete_case: descarta los missing (se reduce la N).
    worst_case: el juez predice lo contrario del veredicto humano binarizado.
    best_case: el juez predice lo mismo que el veredicto humano binarizado.
    """
    out = {}

    cc = [s for s in samples if s["v2"] is not None]
    yh_cc = np.array([BIN_HUMAN[s["human"]] for s in cc])
    yv_cc = np.array([BIN_V2[s["v2"]] for s in cc])
    out["complete_case"] = metrics_full(yh_cc, yv_cc)

    yh_all = np.array([BIN_HUMAN[s["human"]] for s in samples])
    y_best = []
    y_worst = []
    for s in samples:
        h_bin = BIN_HUMAN[s["human"]]
        if s["v2"] is None:
            y_best.append(h_bin)
            y_worst.append(1 - h_bin)
        else:
            v_bin = BIN_V2[s["v2"]]
            y_best.append(v_bin)
            y_worst.append(v_bin)
    out["best_case"] = metrics_full(yh_all, np.array(y_best))
    out["worst_case"] = metrics_full(yh_all, np.array(y_worst))
    return out


# ---- Extracción por estrato ----------------------------------------

def get_arrays(samples, sample_type):
    """Devuelve los arrays numpy (y_human, y_v2) de un estrato (solo los que tengan v2)."""
    if sample_type == "combined":
        ss = [s for s in samples if s["v2"] is not None]
    else:
        ss = [s for s in samples if s["sample_type"] == sample_type and s["v2"] is not None]
    y_h = np.array([BIN_HUMAN[s["human"]] for s in ss])
    y_v = np.array([BIN_V2[s["v2"]] for s in ss])
    return y_h, y_v


# ---- Análisis principal --------------------------------------------

METRIC_FNS = [
    ("mcc", m_mcc),
    ("krippendorff_alpha", m_krippendorff),
    ("cohens_kappa", m_cohens_kappa),
    ("f1", m_f1),
    ("precision", m_precision),
    ("recall", m_recall),
    ("balanced_accuracy", m_balanced_accuracy),
]


def analyze_coverage(samples, csv_dir):
    _header("1. COBERTURA")
    rows = []
    for stype in ("stratified", "control"):
        sset = [s for s in samples if s["sample_type"] == stype]
        total = len(sset)
        with_v2 = sum(1 for s in sset if s["v2"] is not None)
        h_dist = Counter(s["human"] for s in sset)
        v2_dist = Counter(s["v2"] for s in sset if s["v2"] is not None)
        print(f"  {stype}: total={total} with_v2={with_v2} excluded={total - with_v2}")
        print(f"    human  : {dict(h_dist)}")
        print(f"    v2     : {dict(v2_dist)}")
        rows.append([
            stype, total, with_v2, total - with_v2,
            h_dist.get("accept", 0), h_dist.get("reject", 0), h_dist.get("uncertain", 0),
            v2_dist.get("accept", 0), v2_dist.get("reject", 0),
        ])
    save_csv(f"{csv_dir}/coverage_report.csv", rows,
             ["sample_type", "n_total", "n_with_v2", "n_excluded",
              "h_accept", "h_reject", "h_uncertain", "v2_accept", "v2_reject"])


def analyze_confusion_matrix(samples, csv_dir):
    _header("2. MATRIZ DE CONFUSIÓN  (humano x v2)")
    rows = []
    for stype in ("stratified", "control", "combined"):
        if stype == "combined":
            ss = [s for s in samples if s["v2"] is not None]
        else:
            ss = [s for s in samples if s["sample_type"] == stype and s["v2"] is not None]
        print(f"\n  {stype} (N={len(ss)})")
        print(f"  {'':<18} {'v2=accept':>11} {'v2=reject':>11}")
        for h in ("accept", "reject", "uncertain"):
            count_v2_accept = sum(1 for s in ss if s["human"] == h and s["v2"] == "accept")
            count_v2_reject = sum(1 for s in ss if s["human"] == h and s["v2"] == "reject")
            print(f"  human={h:<12} {count_v2_accept:>11} {count_v2_reject:>11}")
            rows.append([stype, h, "accept", count_v2_accept])
            rows.append([stype, h, "reject", count_v2_reject])
    save_csv(f"{csv_dir}/confusion_matrix_3x3.csv", rows,
             ["scope", "human_verdict", "v2_verdict", "count"])


def analyze_primary_metrics(samples, sm_verdict, csv_dir, n_iter, rng):
    _header(f"3. MÉTRICAS PRINCIPALES  (bootstrap BCa al 95%, n_iter={n_iter})")
    rows = []

    # --- Por estrato (intervalos BCa) ---
    per_strat_arrays = {}
    for stype in ("stratified", "control"):
        y_h, y_v = get_arrays(samples, stype)
        per_strat_arrays[stype] = (y_h, y_v)
        n = len(y_h)
        print(f"\n  {stype}  (N={n}, uncertain -> reject)")
        for mname, fn in METRIC_FNS:
            point, lo, hi = bootstrap_bca(fn, y_h, y_v, n_iter, rng)
            print(f"    {mname:<20} {point:>+7.4f}   [{lo:>+7.4f}, {hi:>+7.4f}]")
            rows.append([stype, mname, n, point, lo, hi])

    # --- Combinado: ponderación post-estratificación ---
    # Pesos = composición del corpus por source_mode (rejudge -> stratified, rejudge_conf1 -> control)
    n_strat_corpus = sum(sm_verdict.get(("rejudge", v), 0) for v in ("accept", "reject"))
    n_ctrl_corpus = sum(sm_verdict.get(("rejudge_conf1", v), 0) for v in ("accept", "reject"))
    total_corpus = n_strat_corpus + n_ctrl_corpus
    w_strat = n_strat_corpus / total_corpus
    w_ctrl = n_ctrl_corpus / total_corpus

    print("\n  combined  (pesos por post-estratificación)")
    print(f"    pesos: stratified={w_strat:.4f} ({n_strat_corpus} veredictos v2), "
          f"control={w_ctrl:.4f} ({n_ctrl_corpus} veredictos v2)")

    n_combined = sum(len(per_strat_arrays[s][0]) for s in ("stratified", "control"))
    for mname, fn in METRIC_FNS:
        # Calcula las distribuciones bootstrap por estrato (determinista, comparten el mismo rng)
        strat_boots = {}
        strat_points = {}
        for stype in ("stratified", "control"):
            y_h, y_v = per_strat_arrays[stype]
            n = len(y_h)
            arr = np.empty(n_iter)
            for b in range(n_iter):
                idx = rng.integers(0, n, size=n)
                arr[b] = fn(y_h[idx], y_v[idx])
            strat_boots[stype] = arr
            strat_points[stype] = fn(y_h, y_v)

        comb_point = w_strat * strat_points["stratified"] + w_ctrl * strat_points["control"]
        comb_boots = w_strat * strat_boots["stratified"] + w_ctrl * strat_boots["control"]
        valid = comb_boots[~np.isnan(comb_boots)]
        if len(valid) >= 10:
            ci_lo = float(np.quantile(valid, 0.025))
            ci_hi = float(np.quantile(valid, 0.975))
        else:
            ci_lo = ci_hi = float("nan")
        print(f"    {mname:<20} {comb_point:>+7.4f}   [{ci_lo:>+7.4f}, {ci_hi:>+7.4f}]")
        rows.append(["combined_weighted", mname, n_combined, float(comb_point), ci_lo, ci_hi])

    save_csv(f"{csv_dir}/primary_metrics.csv", rows,
             ["scope", "metric", "n", "point_estimate", "ci_low_95", "ci_high_95"])


def analyze_sensitivity(samples, csv_dir):
    _header("4. ANÁLISIS DE SENSIBILIDAD  (tres escenarios sobre los 107 veredictos v2 ausentes)")
    rows = []
    for stype in ("stratified", "control", "combined"):
        if stype == "combined":
            ss = samples
        else:
            ss = [s for s in samples if s["sample_type"] == stype]
        sens = sensitivity_scenarios(ss)
        print(f"\n  {stype}")
        print(f"    {'escenario':<14} {'N':>5} {'MCC':>8} {'F1':>8} {'P':>8} {'R':>8} {'Acc':>8}")
        for sc in ("worst_case", "complete_case", "best_case"):
            m = sens[sc]
            print(f"    {sc:<14} {m['n']:>5} {m['mcc']:>+8.3f} {m['f1']:>+8.3f} "
                  f"{m['precision']:>+8.3f} {m['recall']:>+8.3f} {m['accuracy']:>+8.3f}")
            rows.append([stype, sc, m["n"], m["mcc"], m["f1"], m["precision"],
                         m["recall"], m["accuracy"], m["balanced_accuracy"], m["npv"],
                         m["tp"], m["fp"], m["fn"], m["tn"]])
    save_csv(f"{csv_dir}/sensitivity_analysis.csv", rows,
             ["scope", "scenario", "n", "mcc", "f1", "precision", "recall",
              "accuracy", "balanced_accuracy", "npv", "tp", "fp", "fn", "tn"])


def analyze_tost(samples, sm_verdict, csv_dir, delta):
    _header("5. TEST DE EQUIVALENCIA TOST  (humano vs Gemma 4, estrato conf=1.0)")
    ctrl = [s for s in samples if s["sample_type"] == "control"]
    n_human = len(ctrl)
    h_accept = sum(1 for s in ctrl if s["human"] == "accept")
    p_human = h_accept / n_human

    g_accept = sm_verdict.get(("rejudge_conf1", "accept"), 0)
    g_reject = sm_verdict.get(("rejudge_conf1", "reject"), 0)
    n_gemma = g_accept + g_reject
    p_gemma = g_accept / n_gemma if n_gemma > 0 else float("nan")

    tost = tost_two_proportions(p_human, n_human, p_gemma, n_gemma, delta)

    print(f"\n  Humano (muestra de control, N={n_human}): accept={h_accept}, ratio={p_human:.4f}")
    print(f"  Gemma 4 (rejudge_conf1, N={n_gemma}): accept={g_accept}, ratio={p_gemma:.4f}")
    print(f"  Diferencia observada (p_human - p_gemma): {tost['observed_difference']:+.4f}")
    print(f"  Error estándar: {tost['standard_error']:.4f}")
    print(f"  Margen de equivalencia Δ: ±{delta:.3f}")
    print(f"  TOST p_low = {tost['p_low']:.4f}   p_high = {tost['p_high']:.4f}")
    proven = "SÍ" if tost["equivalence_proven"] else "NO"
    print(f"  -> ¿Queda probada la equivalencia dentro de ±{delta*100:.1f}pp?: {proven}")
    print(f"  -> Margen más estrecho que se puede probar (Δ_min): ±{tost['delta_min']*100:.2f}pp")
    if not tost["equivalence_proven"]:
        print(f"     (con N_human={n_human}, los datos prueban equivalencia dentro de "
              f"±{tost['delta_min']*100:.1f}pp a α=0.05; márgenes más estrechos exigen N mayor)")

    save_csv(f"{csv_dir}/tost_equivalence.csv",
             [[p_human, n_human, p_gemma, n_gemma, delta,
               tost["observed_difference"], tost["standard_error"],
               tost["p_low"], tost["p_high"], tost["equivalence_proven"],
               tost["delta_min"]]],
             ["p_human", "n_human", "p_gemma", "n_gemma", "delta",
              "observed_difference", "standard_error", "p_low", "p_high",
              "equivalence_proven", "delta_min"])


def analyze_extractor_only(samples, csv_dir):
    _header("6. ANEXO SOLO EXTRACTOR  (N=484, uncertain -> reject)")
    rows = []
    for stype in ("stratified", "control", "combined"):
        if stype == "combined":
            ss = samples
        else:
            ss = [s for s in samples if s["sample_type"] == stype]
        y_h = np.array([BIN_HUMAN[s["human"]] for s in ss])
        y_v = np.ones_like(y_h)
        m = metrics_full(y_h, y_v)
        print(f"  {stype:<10} (N={m['n']:>3})  P={m['precision']:.4f}  "
              f"R={m['recall']:.4f}  F1={m['f1']:.4f}  MCC={m['mcc']}")
        rows.append([stype, m["n"], m["precision"], m["recall"], m["f1"],
                     m["mcc"], m["tp"], m["fp"], m["fn"], m["tn"]])
    save_csv(f"{csv_dir}/extractor_only_yield.csv", rows,
             ["scope", "n", "precision", "recall", "f1", "mcc", "tp", "fp", "fn", "tn"])


def write_audit(samples, csv_dir):
    rows = []
    for s in samples:
        h_bin = BIN_HUMAN[s["human"]]
        v2 = s["v2"]
        v_bin = BIN_V2[v2] if v2 is not None else None
        # El extractor "predice accept" para todo, así que solo acierta cuando human=accept
        ext_correct = 1 if h_bin == 1 else 0
        if v_bin is None:
            pipe_correct = ""
        else:
            pipe_correct = 1 if v_bin == h_bin else 0
        excluded = 1 if v2 is None else 0
        rows.append([
            s["cs_id"], s["extraction_id"], s["ttp_index"], s["technique_id"],
            s["sample_type"], s["source"], s["human"],
            v2 if v2 is not None else "MISSING",
            ext_correct, pipe_correct, excluded,
        ])
    save_csv(f"{csv_dir}/per_ttp_evaluation.csv", rows,
             ["cs_id", "extraction_id", "ttp_index", "technique_id",
              "sample_type", "source", "human_blind", "v2_verdict",
              "extractor_correct", "pipeline_correct", "excluded"])


# ---- Análisis suplementarios (por fuente, por táctica, E1-E5) --------

def _group_metrics(group_samples, group_label):
    """Calcula las métricas de la Config B sobre un subconjunto (que debe tener
    v2). Devuelve fila más dict."""
    y_human = np.array([BIN_HUMAN[s["human"]] for s in group_samples])
    y_v2 = np.array([BIN_V2[s["v2"]] for s in group_samples])
    m = metrics_full(y_human, y_v2)
    h_acc_rate = float(np.mean(y_human)) if len(y_human) > 0 else float("nan")
    return [
        group_label, m["n"], h_acc_rate,
        m["mcc"], m["f1"], m["precision"], m["recall"],
        m["balanced_accuracy"], m["accuracy"],
        m["tp"], m["fp"], m["fn"], m["tn"],
    ]


def _print_row_with_balacc(label, row):
    _, n, h_rate, mcc, f1, p, r, balanced_accuracy, _acc, _tp, _fp, _fn, _tn = row
    print(f"  {label:<22} {n:>4} {h_rate*100:>6.1f}% {mcc:>+7.3f} {f1:>+7.3f} "
          f"{p:>+7.3f} {r:>+7.3f} {balanced_accuracy:>+7.3f}")


def _print_row_no_balacc(label, row):
    _, n, h_rate, mcc, f1, p, r, _bacc, _acc, _tp, _fp, _fn, _tn = row
    print(f"  {label:<14} {n:>4} {h_rate*100:>6.1f}% {mcc:>+7.3f} {f1:>+7.3f} "
          f"{p:>+7.3f} {r:>+7.3f}")


def analyze_by_dimension(samples, csv_dir, *, section_label, key_fn,
                         table_header, dash_width, print_row,
                         csv_path, id_column, min_n=0, with_other=False):
    """Helper común a los análisis suplementarios por dimensión (fuente,
    técnica, táctica). Agrupa los samples con v2 según key_fn y reproduce, sin
    cambios, la tabla y el CSV de la dimensión correspondiente."""
    _header(section_label)
    by_key = {}
    for s in samples:
        if s["v2"] is None:
            continue
        by_key.setdefault(key_fn(s), []).append(s)

    rows = []
    print(table_header)
    print("  " + "-" * dash_width)
    for key, group_samples in sorted(by_key.items(), key=lambda x: -len(x[1])):
        if len(group_samples) < min_n:
            continue
        row = _group_metrics(group_samples, key)
        print_row(row[0], row)
        rows.append(row)

    # Fila agregada para los grupos que no llegan al umbral (solo por fuente)
    if with_other:
        small = [s for k, group_samples in by_key.items() if len(group_samples) < min_n for s in group_samples]
        if small:
            row = _group_metrics(small, f"_other_(N<{min_n})")
            print_row(row[0], row)
            rows.append(row)

    save_csv(csv_path, rows,
             [id_column, "n", "human_accept_rate", "mcc", "f1", "precision",
              "recall", "balanced_accuracy", "accuracy", "tp", "fp", "fn", "tn"])


def analyze_per_source(samples, csv_dir, min_n=10):
    analyze_by_dimension(
        samples, csv_dir,
        section_label=f"7. MÉTRICAS POR FUENTE  (Config B, fuentes con N >= {min_n})",
        key_fn=lambda s: s["source"],
        table_header=f"  {'fuente':<22} {'N':>4} {'h_acc%':>7} {'MCC':>7} {'F1':>7} {'P':>7} {'R':>7} {'BalAcc':>7}",
        dash_width=76,
        print_row=_print_row_with_balacc,
        csv_path=f"{csv_dir}/per_source_metrics.csv",
        id_column="source",
        min_n=min_n,
        with_other=True,
    )


def analyze_per_technique(samples, csv_dir, min_n=5):
    analyze_by_dimension(
        samples, csv_dir,
        section_label=f"8. MÉTRICAS POR TÉCNICA  (Config B, técnicas con N >= {min_n})",
        key_fn=lambda s: s["technique_id"],
        table_header=f"  {'técnica':<14} {'N':>4} {'h_acc%':>7} {'MCC':>7} {'F1':>7} {'P':>7} {'R':>7}",
        dash_width=60,
        print_row=_print_row_no_balacc,
        csv_path=f"{csv_dir}/per_technique_metrics.csv",
        id_column="technique_id",
        min_n=min_n,
    )


def analyze_per_tactic(samples, csv_dir):
    analyze_by_dimension(
        samples, csv_dir,
        section_label="9. MÉTRICAS POR TÁCTICA  (Config B)",
        key_fn=lambda s: s["tactic_id"] or "unknown",
        table_header=f"  {'táctica':<14} {'N':>4} {'h_acc%':>7} {'MCC':>7} {'F1':>7} {'P':>7} {'R':>7}",
        dash_width=60,
        print_row=_print_row_no_balacc,
        csv_path=f"{csv_dir}/per_tactic_metrics.csv",
        id_column="tactic_id",
    )


def analyze_error_taxonomy(samples, csv_dir):
    """Para los samples que tienen veredicto v1 (stratified) y un
    error_taxonomy_code (es decir, hubo desacuerdo entre v1 y humano), mide
    cuántas veces el v2 corrige al v1.

    Tres categorías:
      v1_FP_corrected_by_v2: v1=accept, human=reject, v2=reject  (rescate)
      v1_FN_corrected_by_v2: v1=reject, human=accept, v2=accept  (rescate, raro)
      v1_error_repeated_by_v2: el v2 mantiene el mismo veredicto erróneo que v1
    """
    _header("10. TAXONOMÍA DE ERRORES (E1-E5) × VEREDICTO v2  (¿v2 corrige los errores de v1?)")

    # Solo stratified con v2 disponible y un código de error
    eligible = [s for s in samples
                if s["sample_type"] == "stratified"
                and s["v2"] is not None
                and s["error_code"] is not None
                and s["v1"] is not None]
    print(f"  Desacuerdos elegibles (stratified, con v1 + v2 + código de error): {len(eligible)}")

    rows = []
    print(f"\n  {'error':<7} {'N':>4} {'v1_FP':>7} {'v1_FN':>7} "
          f"{'corregido':>10} {'repetido':>10} {'corr%':>7}")
    print("  " + "-" * 60)

    by_code = {}
    for s in eligible:
        by_code.setdefault(s["error_code"], []).append(s)

    for code in sorted(by_code.keys()):
        ss = by_code[code]
        n = len(ss)
        v1_fp = sum(1 for s in ss if s["v1"] == "accept" and s["human"] == "reject")
        v1_fn = sum(1 for s in ss if s["v1"] == "reject" and s["human"] == "accept")
        # Los 'uncertain' del v1 no cuentan ni como FP ni como FN (se asumen ambiguos)
        corrected = sum(1 for s in ss if BIN_V2.get(s["v2"], -1) == BIN_HUMAN[s["human"]])
        repeated = n - corrected
        corr_pct = corrected / n if n > 0 else float("nan")
        print(f"  {code:<7} {n:>4} {v1_fp:>7} {v1_fn:>7} "
              f"{corrected:>10} {repeated:>10} {corr_pct*100:>6.1f}%")
        rows.append([code, n, v1_fp, v1_fn, corrected, repeated, corr_pct])

    # Agregado total
    if eligible:
        n = len(eligible)
        corrected = sum(1 for s in eligible if BIN_V2.get(s["v2"], -1) == BIN_HUMAN[s["human"]])
        v1_fp = sum(1 for s in eligible if s["v1"] == "accept" and s["human"] == "reject")
        v1_fn = sum(1 for s in eligible if s["v1"] == "reject" and s["human"] == "accept")
        rows.append(["_total", n, v1_fp, v1_fn, corrected, n - corrected,
                     corrected / n])
        print(f"  {'TOTAL':<7} {n:>4} {v1_fp:>7} {v1_fn:>7} "
              f"{corrected:>10} {n - corrected:>10} {corrected/n*100:>6.1f}%")

    save_csv(f"{csv_dir}/error_taxonomy_correction.csv", rows,
             ["error_code", "n", "v1_FP", "v1_FN",
              "v2_corrected", "v2_repeated_v1_error", "correction_rate"])


def write_readme(csv_dir, n_iter, seed, delta):
    path = f"{csv_dir}/README.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""# Salidas de Evaluation F1

Generado por `evaluation_f1.py` (seed={seed}, n_iter={n_iter}, delta={delta}).

## Metodología

Esto es un **análisis post-hoc de validación de candidatos**: la ground truth
anotada por el humano (`calibration_sample`, N=484) está formada únicamente
por TTPs que produjo el extractor (Qwen 2.5 14B). Por diseño, el recall del
extractor sobre el corpus completo de artículos es **inobservable**.

Se evalúan dos configuraciones:

- **Config A Solo extractor.** Cada TTP producido se trata como una predicción
  "accept". Recall = 100% por construcción. Precisión = ratio base de
  aceptación humana. La F1 sale como consecuencia mecánica.
- **Config B Extractor + juez v2 (Gemma 4 26B).** Un TTP queda "aceptado"
  solo si Gemma 4 lo acepta. Esto sí es un clasificador binario real, con
  matriz de confusión 2x2 completa.

Mapeo binario: el `uncertain` humano se colapsa a `reject` (equivalencia
operativa en CTI: un TTP ambiguo no se puede meter en un pipeline de defensa
automatizada).

Cobertura: de los 484 TTPs anotados, solo 377 (78%) tienen veredicto v2; los
otros 107 no fueron juzgados ni en modo rejudge ni en rejudge_conf1 (en su
mayoría rejects de stratified, más 1 timeout de control). El análisis
complete-case se calcula sobre N=377; el análisis de sensibilidad acota el
impacto de los 107 ausentes.

## Ficheros

- `coverage_report.csv` N anotados, N con v2 y distribuciones por sample_type.
- `confusion_matrix_3x3.csv` humano × v2 (descriptiva).
- `primary_metrics.csv` MCC, Krippendorff α, κ de Cohen, F1, P, R y balanced
  accuracy con intervalos BCa al 95% por bootstrap ({n_iter} iteraciones,
  seed={seed}). Scopes: stratified, control, combined_weighted
  (post-estratificación).
- `sensitivity_analysis.csv` tres escenarios para los 107 excluidos:
  worst_case (el juez predice lo contrario del humano), complete_case (los
  descarta), best_case (el juez predice perfectamente).
- `tost_equivalence.csv` Two One-Sided Tests para la convergencia humano vs
  Gemma 4 en el estrato conf=1.0 (Δ=±{delta}).
- `extractor_only_yield.csv` métricas de la Config A sobre N=484.
- `per_ttp_evaluation.csv` audit trail con una fila por cada TTP anotado.
- `per_source_metrics.csv` métricas de la Config B desglosadas por spider de
  origen (fuentes con N >= 10; las pequeñas se agregan).
- `per_technique_metrics.csv` métricas de la Config B por technique_id de
  MITRE (solo técnicas con N >= 5).
- `per_tactic_metrics.csv` métricas de la Config B agregadas por táctica de MITRE.
- `error_taxonomy_correction.csv` para los TTPs stratified en los que v1
  discrepó del humano (anotados con códigos E1/E2/E4), ¿qué fracción corrige
  el v2? Cuantifica el valor arquitectónico que aporta el juez v2 sobre el v1.

## Limitaciones (para la memoria del TFG)

1. **El recall del extractor es inobservable** (sesgo de selección inherente a
   la evaluación post-hoc; ver TTPDrill ACSAC 2017, AttacKG ESORICS 2022,
   IntelEX USENIX 2025 para la aproximación tradicional con ground truth
   exhaustivo, y Ragas EACL 2024 para evaluación RAG sin referencia).
2. **Un único anotador**, justificado como "oráculo experto" dado que MITRE
   ATT&CK es una ontología cerrada y la anotación se hizo a ciegas.
3. **Variabilidad de routing del MoE** en Gemma 4 26B podría introducir
   varianza estocástica entre hipotéticas re-ejecuciones (el rejudge fue una
   única pasada determinista).
4. **Posible contaminación por preentrenamiento**: los reports públicos de CTI
   pueden solaparse con el corpus de preentrenamiento de Gemma 4.
5. **Intervalos amplios en control (N=99)**, el bootstrap BCa lo hace explícito.
6. **MCC indefinido en Config A (solo extractor)**: la predicción del
   extractor es constante ("accept" para todo TTP producido), lo que anula el
   denominador del MCC. Para la Config A solo se reportan Precision y F1.
7. **Equivalencia TOST**: con N=100 en la muestra de control, el margen de
   equivalencia más estrecho demostrable a α=0.05 es aproximadamente ±8.5pp
   (ver `tost_equivalence.csv`, columna `delta_min`). No se puede probar
   formalmente la equivalencia dentro del Δ=±5pp originalmente propuesto con
   esta N, aunque la diferencia observada es de solo 0.27pp.
8. **Artefactos puntuales en el reasoning de Gemma 4**: la inspección
   cualitativa encontró corrupciones raras en el campo reasoning (por
   ejemplo, "T14486" en vez de "T1486", unicode espurio). La etiqueta del
   verdict no se ve afectada; solo la justificación en texto libre. Probable
   inestabilidad del routing MoE bajo inferencia cuantizada sobre vocabulario
   de CTI fuera de dominio.
9. **7 filas de calibration_sample** apuntan a extraction_id que ya no existen
   en `extractions` (huérfanas tras la migración de dedup de la sesión 22). Se
   mantienen vía LEFT JOIN: el `tactic_id` queda a null en esos casos, pero
   `human_blind_verdict` y `v2_verdict` siguen disponibles.

## Mejoras futuras (fuera del alcance de esta iteración)

Estas exigen volver a ejecutar judge_v2 sobre el corpus y quedaron aparcadas:

- **Re-prompting few-shot del juez v2**: meter 5-10 ejemplos de falso negativo
  encontrados en la inspección cualitativa (p. ej. T1486 rechazado en
  "deployed and executed ALPHV ransomware") para relajar la adherencia
  ontológica del juez, que es demasiado estricta. Se espera que suba el
  recall hacia 0.80+ sin perder precisión.
- **Calibrar la temperatura del juez v2** (forzar 0.0 determinista) debería
  reducir los artefactos en el reasoning causados por la varianza del
  routing MoE.
- **Anotar unos 200 TTPs de control más** para estrechar el margen de
  equivalencia TOST de ±8.5pp a ±5pp. Costoso en tiempo humano y no
  estrictamente necesario: Δ_min=8.5pp ya es publicable.
""")
    print(f"  -> guardado {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Validación post-hoc de candidatos (F1) del pipeline de extracción de TTPs")
    parser.add_argument("--db", default=DB_DEFAULT)
    parser.add_argument("--csv-dir", default=CSV_DIR_DEFAULT)
    parser.add_argument("--bootstrap-iter", type=int, default=1000)
    parser.add_argument("--equivalence-margin", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)

    print(f"Cargando datos desde {args.db} ...")
    samples, sm_verdict = load_data(args.db)
    n_with_v2 = sum(1 for s in samples if s["v2"] is not None)
    print(f"  {len(samples)} filas de calibration_sample con human_blind_verdict")
    print(f"  {n_with_v2}/{len(samples)} tienen veredicto v2")

    analyze_coverage(samples, args.csv_dir)
    analyze_confusion_matrix(samples, args.csv_dir)
    analyze_primary_metrics(samples, sm_verdict, args.csv_dir, args.bootstrap_iter, rng)
    analyze_sensitivity(samples, args.csv_dir)
    analyze_tost(samples, sm_verdict, args.csv_dir, args.equivalence_margin)
    analyze_extractor_only(samples, args.csv_dir)
    write_audit(samples, args.csv_dir)
    analyze_per_source(samples, args.csv_dir)
    analyze_per_technique(samples, args.csv_dir)
    analyze_per_tactic(samples, args.csv_dir)
    analyze_error_taxonomy(samples, args.csv_dir)
    write_readme(args.csv_dir, args.bootstrap_iter, args.seed, args.equivalence_margin)

    print()
    print("=" * 72)
    print("  Evaluación terminada.")
    print("=" * 72)


if __name__ == "__main__":
    main()
