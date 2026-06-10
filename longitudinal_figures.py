#!/usr/bin/env python3
"""
Figuras reproducibles para el análisis longitudinal (TFG, Objetivo 4).

Lee los CSV producidos por longitudinal_analysis.py y genera PNGs estáticos
listos para la memoria. Volver a ejecutar el script regenera todo.

Uso:
    .venv-analysis/bin/python longitudinal_figures.py \
        [--csv-dir DIR] [--fig-dir DIR] [--dpi N]
"""
from __future__ import annotations

import argparse
import csv
import os
from collections import OrderedDict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


HERE = os.path.dirname(os.path.abspath(__file__))
CSV_DIR_DEFAULT = os.path.join(HERE, "outputs", "longitudinal")
FIG_DIR_DEFAULT = os.path.join(HERE, "outputs", "longitudinal", "figures")


# ---------- estilo compartido ---------------------------------------------

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.constrained_layout.use": True,
})

TACTIC_PALETTE = {
    "Impact": "#c0392b",
    "InitAcc": "#2980b9",
    "DefEva": "#8e44ad",
    "CredAcc": "#16a085",
    "Exec": "#d35400",
    "Persist": "#7f8c8d",
    "C2": "#27ae60",
    "LatMov": "#e67e22",
    "ResDev": "#34495e",
    "Discov": "#f39c12",
    "Exfil": "#2c3e50",
    "PrivEsc": "#9b59b6",
    "Collect": "#1abc9c",
    "Recon": "#95a5a6",
}


# ---------- utilidades de IO ----------------------------------------------

def read_csv(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save(fig, fig_dir, name, dpi):
    os.makedirs(fig_dir, exist_ok=True)
    out = os.path.join(fig_dir, name)
    fig.savefig(out, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


def parse_int(raw):
    return int(raw) if raw not in ("", "-") else 0


def parse_float(raw):
    try:
        return float(raw)
    except ValueError:
        return float("nan")


# ---------- figuras --------------------------------------------------------

def fig_volume_by_year(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "volume_by_year.csv"))
    years = [int(r["year"]) for r in rows]
    ttps = [int(r["ttps"]) for r in rows]
    yoy_pct = [r["yoy_pct"].replace("%", "").replace("+", "") for r in rows]
    yoy_pct = [float(x) if x not in ("", "-") else None for x in yoy_pct]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(years, ttps, color="#2980b9", edgecolor="white")
    for bar, n in zip(bars, ttps):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 8,
                str(n), ha="center", va="bottom", fontsize=9)
    ax.set_xlabel("Año")
    ax.set_ylabel("TTPs aceptados")
    ax.set_title("Volumen anual de TTPs validados (corpus 2021-2026)")
    ax.set_xticks(years)
    save(fig, fig_dir, "01_volume_by_year.png", dpi)


def fig_volume_by_quarter(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "volume_by_quarter.csv"))
    years = [int(r["year"]) for r in rows]
    matrix = np.array([[parse_int(r[q]) for q in ("Q1", "Q2", "Q3", "Q4")] for r in rows])

    fig, ax = plt.subplots(figsize=(6, 3.5))
    im = ax.imshow(matrix, aspect="auto", cmap="YlOrRd")
    ax.set_xticks(range(4))
    ax.set_xticklabels(["Q1", "Q2", "Q3", "Q4"])
    ax.set_yticks(range(len(years)))
    ax.set_yticklabels(years)
    ax.set_title("TTPs por trimestre (heatmap)")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            v = matrix[i, j]
            if v:
                ax.text(j, i, v, ha="center", va="center",
                        color="white" if v > matrix.max() / 2 else "black", fontsize=9)
    fig.colorbar(im, ax=ax, label="TTPs")
    save(fig, fig_dir, "02_volume_by_quarter.png", dpi)


def fig_tactic_distribution(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "tactic_distribution_by_year.csv"))
    years = [int(r["year"]) for r in rows]
    tactics = [k for k in rows[0].keys() if k not in ("year", "total_ttps")]
    counts = np.array([[parse_int(r[t]) for t in tactics] for r in rows], dtype=float)
    totals = counts.sum(axis=1, keepdims=True)
    pct = (counts / totals) * 100

    # Ordenamos tácticas por prevalencia media (las mayores abajo del stack).
    order = np.argsort(-pct.mean(axis=0))
    tactics_ord = [tactics[i] for i in order]
    pct_ord = pct[:, order]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bottom = np.zeros(len(years))
    for i, t in enumerate(tactics_ord):
        ax.bar(years, pct_ord[:, i], bottom=bottom, label=t,
               color=TACTIC_PALETTE.get(t, "#999"), edgecolor="white", linewidth=0.5)
        bottom += pct_ord[:, i]
    ax.set_xlabel("Año")
    ax.set_ylabel("% de TTPs")
    ax.set_title("Distribución de tácticas MITRE ATT&CK por año")
    ax.set_xticks(years)
    ax.set_ylim(0, 100)
    ax.legend(loc="center left", bbox_to_anchor=(1.0, 0.5), ncol=1, fontsize=8)
    save(fig, fig_dir, "03_tactic_distribution_by_year.png", dpi)


def fig_source_contribution(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "source_contribution_by_year.csv"))
    years_cols = [k for k in rows[0].keys() if k not in ("source", "total")]
    years = [int(y) for y in years_cols]
    sources = [r["source"] for r in rows]
    matrix = np.array([[parse_int(r[y]) for y in years_cols] for r in rows], dtype=float)

    # Normalizamos a porcentaje por año (por columna).
    col_sum = matrix.sum(axis=0, keepdims=True)
    col_sum[col_sum == 0] = 1
    pct = (matrix / col_sum) * 100

    # Ordenamos fuentes por contribución total (de mayor a menor).
    totals = matrix.sum(axis=1)
    order = np.argsort(-totals)
    sources_ord = [sources[i] for i in order]
    pct_ord = pct[order, :]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    cmap = plt.get_cmap("tab20")
    bottom = np.zeros(len(years))
    for i, s in enumerate(sources_ord):
        ax.bar(years, pct_ord[i, :], bottom=bottom, label=s,
               color=cmap(i % 20), edgecolor="white", linewidth=0.5)
        bottom += pct_ord[i, :]
    ax.set_xlabel("Año")
    ax.set_ylabel("% del corpus")
    ax.set_title("Composición del corpus por fuente (% por año)")
    ax.set_xticks(years)
    ax.set_ylim(0, 100)
    ax.legend(loc="center left", bbox_to_anchor=(1.0, 0.5), ncol=1, fontsize=8)
    save(fig, fig_dir, "04_source_contribution_by_year.png", dpi)


def fig_shannon_entropy(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "shannon_entropy.csv"))
    years = [int(r["year"]) for r in rows]
    norm = [parse_float(r["entropy_normalized"]) for r in rows]
    bits = [parse_float(r["entropy_bits"]) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(years, norm, "o-", color="#16a085", linewidth=2,
            markersize=8, label="Entropía normalizada")
    ax.set_xlabel("Año")
    ax.set_ylabel("Entropía normalizada de fuentes")
    ax.set_title("Diversidad de fuentes (Shannon entropy)")
    ax.set_xticks(years)
    ax.set_ylim(0, 1)
    ax.axhline(0.8, color="grey", linestyle="--", alpha=0.5,
               label="Umbral diversidad alta (≥0.8)")
    for x, y, b in zip(years, norm, bits):
        ax.annotate(f"{y:.2f}\n({b:.2f} bits)", (x, y),
                    textcoords="offset points", xytext=(0, 10),
                    ha="center", fontsize=8)
    ax.legend()
    save(fig, fig_dir, "05_shannon_entropy.png", dpi)


def fig_top_techniques_heatmap(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "top_techniques_by_year.csv"))
    by_year = OrderedDict()
    for r in rows:
        by_year.setdefault(int(r["year"]), []).append(
            (int(r["rank"]), r["technique_id"], r["name"], int(r["count"])))
    years = sorted(by_year.keys())

    # Universo = top-N técnicas considerando todos los años.
    universe = []
    for y in years:
        for rank, tid, name, count in by_year[y]:
            if tid not in [u[0] for u in universe]:
                universe.append((tid, name))
    universe = universe[:15]  # limitamos para que la figura sea legible

    matrix = np.zeros((len(universe), len(years)))
    for j, y in enumerate(years):
        count_by_tid = {tid: count for rank, tid, name, count in by_year[y]}
        for i, (tid, _) in enumerate(universe):
            matrix[i, j] = count_by_tid.get(tid, 0)

    fig, ax = plt.subplots(figsize=(7, max(4, 0.4 * len(universe))))
    im = ax.imshow(matrix, aspect="auto", cmap="Blues")
    ax.set_xticks(range(len(years)))
    ax.set_xticklabels(years)
    ax.set_yticks(range(len(universe)))
    ax.set_yticklabels([f"{tid} {name[:35]}" for tid, name in universe], fontsize=8)
    ax.set_title("Top técnicas frecuencia anual")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            v = int(matrix[i, j])
            if v:
                ax.text(j, i, v, ha="center", va="center",
                        color="white" if v > matrix.max() / 2 else "black", fontsize=8)
    fig.colorbar(im, ax=ax, label="Conteo TTPs")
    save(fig, fig_dir, "06_top_techniques_heatmap.png", dpi)


def fig_emergence_normalized(csv_dir, fig_dir, dpi):
    norm_rows = read_csv(os.path.join(csv_dir, "normalized_emergence.csv"))
    raw_rows = read_csv(os.path.join(csv_dir, "technique_emergence.csv"))

    # Conjunto ROBUSTO: técnicas emergentes tanto en el conteo bruto
    # (crecimiento >= 1.5x con >= 5 apariciones en 2024-25) como tras normalizar
    # por volumen de fuente (crecimiento >= 1.5x con prevalencia normalizada
    # >= 0.10). Es el mismo criterio (intersección) que la tabla de la memoria,
    # de modo que figura y tabla muestran exactamente el mismo conjunto.
    raw_emergent = {
        r["technique_id"] for r in raw_rows
        if parse_float(r["growth_ratio"]) >= 1.5 and parse_float(r["count_2024_25"]) >= 5
    }
    robust = []
    for r in norm_rows:
        ratio = parse_float(r["growth_ratio"])
        norm_late = parse_float(r["norm_late_2024_25"])
        if (np.isfinite(ratio) and ratio >= 1.5 and norm_late >= 0.10
                and r["technique_id"] in raw_emergent):
            robust.append((r, ratio))

    robust.sort(key=lambda x: x[1], reverse=True)
    if not robust:
        return

    labels = [f"{r['technique_id']} {r['name'][:32]}" for r, _ in robust]
    ratios = [g for _, g in robust]

    fig, ax = plt.subplots(figsize=(8.5, max(4.5, 0.42 * len(robust))))
    colors = ["#c0392b" if g >= 5 else ("#e67e22" if g >= 2.5 else "#f1c40f") for g in ratios]
    bars = ax.barh(range(len(robust)), ratios, color=colors, edgecolor="white")
    xmax = max(ratios) * 1.18
    for i, (bar, g) in enumerate(zip(bars, ratios)):
        ax.text(bar.get_width() + xmax * 0.01, i, f"{g:.2f}×",
                va="center", fontsize=9)
    ax.axvline(1.0, color="grey", linestyle="--", alpha=0.6,
               label="ratio = 1 (sin cambio)")
    ax.set_yticks(range(len(robust)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, xmax)
    ax.set_xlabel("Ratio de crecimiento (2024-25 / 2021-23, normalizado)")
    ax.set_title("Técnicas emergentes robustas (normalizado por volumen de fuente)",
                 fontsize=11)
    ax.legend(loc="lower right")
    save(fig, fig_dir, "07_emergence_normalized.png", dpi)


def fig_mann_kendall(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "mann_kendall_prevalence_matrix.csv"))
    items = []
    for r in rows:
        try:
            tau = float(r["tau"].replace("+", ""))
            p = float(r["p_value"])
            items.append((r["technique_id"], r["name"], tau, p, r["category"], int(r["total"])))
        except (ValueError, KeyError):
            continue

    if not items:
        return

    # Scatter de Mann-Kendall: tau vs -log10(p_value), tamaño = conteo total.
    taus = [it[2] for it in items]
    ps = [it[3] for it in items]
    totals = [it[5] for it in items]
    nlogp = [-np.log10(p) if p > 0 else 4 for p in ps]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    sizes = [max(20, t * 4) for t in totals]
    sc = ax.scatter(taus, nlogp, s=sizes, c=taus, cmap="RdYlGn",
                    vmin=-1, vmax=1, alpha=0.75, edgecolor="black", linewidth=0.5)

    # Línea de umbral de significancia (p=0.05 -> -log10(p)=1.301).
    ax.axhline(-np.log10(0.05), color="red", linestyle="--", alpha=0.6,
               label="p = 0.05")
    ax.axvline(0, color="grey", linestyle=":", alpha=0.5)

    # Anotamos las técnicas más significativas.
    annotated = 0
    for tid, name, tau, p, cat, total in items:
        if p < 0.10 or abs(tau) >= 0.7:
            ax.annotate(tid, (tau, -np.log10(p) if p > 0 else 4),
                        textcoords="offset points", xytext=(5, 5),
                        fontsize=8)
            annotated += 1
            if annotated > 12:
                break

    ax.set_xlabel("Kendall τ (signo y magnitud de la tendencia)")
    ax.set_ylabel("-log₁₀(p)")
    ax.set_title("Mann-Kendall tendencias por técnica (tamaño = N total)")
    fig.colorbar(sc, ax=ax, label="τ")
    ax.legend(loc="upper left")
    save(fig, fig_dir, "08_mann_kendall_scatter.png", dpi)


def fig_double_extortion(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "double_extortion_doc_level.csv"))
    years = [int(r["year"]) for r in rows]
    has_encrypt = [parse_int(r["has_encrypt"]) for r in rows]
    has_exfil = [parse_int(r["has_exfil"]) for r in rows]
    has_both = [parse_int(r["has_both"]) for r in rows]
    rate = [parse_float(r["rate"].replace("%", "")) for r in rows]

    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    width = 0.27
    x = np.arange(len(years))
    ax1.bar(x - width, has_encrypt, width, color="#c0392b", label="T1486 (cifrado)")
    ax1.bar(x, has_exfil, width, color="#34495e", label="TA0010 (exfiltración)")
    ax1.bar(x + width, has_both, width, color="#16a085", label="Ambos (doble extorsión)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(years)
    ax1.set_xlabel("Año")
    ax1.set_ylabel("Documentos")
    ax1.set_title("Doble extorsión a nivel documento (lower bound)")
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.plot(x, rate, "o-", color="#9b59b6", linewidth=2,
             markersize=8, label="% docs con ambas")
    ax2.set_ylabel("% docs con ambas (línea)")
    ax2.spines["right"].set_visible(True)
    ax2.legend(loc="upper right")
    save(fig, fig_dir, "09_double_extortion.png", dpi)


def fig_emergence_raw(csv_dir, fig_dir, dpi):
    rows = read_csv(os.path.join(csv_dir, "technique_emergence.csv"))
    rows = [r for r in rows if parse_float(r["growth_ratio"]) >= 2.0
            and parse_int(r["total"]) >= 5]
    rows.sort(key=lambda r: parse_float(r["growth_ratio"]), reverse=True)
    rows = rows[:12]
    if not rows:
        return

    labels = [f"{r['technique_id']} {r['name'][:30]}" for r in rows]
    ratios = [parse_float(r["growth_ratio"]) for r in rows]
    totals = [parse_int(r["total"]) for r in rows]

    fig, ax = plt.subplots(figsize=(7.5, max(4, 0.4 * len(rows))))
    bars = ax.barh(range(len(rows)), ratios, color="#8e44ad", edgecolor="white")
    for i, (bar, g, t) in enumerate(zip(bars, ratios, totals)):
        ax.text(bar.get_width() + 0.1, i, f"{g:.2f}×  (N={t})",
                va="center", fontsize=8)
    ax.axvline(1.0, color="grey", linestyle="--", alpha=0.6)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Ratio raw 2024-25 / 2021-23")
    ax.set_title("Emergencia raw (sin normalizar) comparar con figura 7")
    save(fig, fig_dir, "10_emergence_raw.png", dpi)


# ---------- main -----------------------------------------------------------


ALL_FIGS = [
    fig_volume_by_year,
    fig_volume_by_quarter,
    fig_tactic_distribution,
    fig_source_contribution,
    fig_shannon_entropy,
    fig_top_techniques_heatmap,
    fig_emergence_normalized,
    fig_mann_kendall,
    fig_double_extortion,
    fig_emergence_raw,
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv-dir", default=CSV_DIR_DEFAULT)
    parser.add_argument("--fig-dir", default=FIG_DIR_DEFAULT)
    parser.add_argument("--dpi", type=int, default=160)
    args = parser.parse_args()

    print(f"Reading CSVs from: {args.csv_dir}")
    print(f"Writing figures to: {args.fig_dir}")
    print()
    for make_figure in ALL_FIGS:
        try:
            make_figure(args.csv_dir, args.fig_dir, args.dpi)
        except FileNotFoundError as e:
            print(f"  skipped {make_figure.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR in {make_figure.__name__}: {e}")
            raise
    print()
    print("Done.")


if __name__ == "__main__":
    main()
