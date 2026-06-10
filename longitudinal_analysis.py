#!/usr/bin/env python3
"""
Análisis longitudinal del corpus limpio (2.355 TTPs aceptados por el judge v2).

Uso:
    python longitudinal_analysis.py [--db PATH] [--csv-dir DIR]

Salidas:
    1. Volumen a lo largo del tiempo (por año y por trimestre)
    2. Distribución de tácticas por año
    3. Técnicas top por año
    4. Aparición de técnicas (ratio de crecimiento bruto 2024-25 vs 2021-23)
    5. Contribución por fuente y año
    6. Tendencia de la doble extorsión (a nivel de documento, T1486 ∩ TA0010)
    7. Análisis de emergencia normalizado por fuente (corrección de sesgo estilo SNIP)
    8. Entropía de Shannon de la diversidad de fuentes por año
    9. Test de tendencia de Mann-Kendall + matriz Prevalencia-Tendencia
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
from collections import defaultdict

DB_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "ransomware_intel.db")
MITRE_CACHE = os.path.join(os.path.dirname(__file__), "data", "mitre_attack_cache.json")

# Todos los artículos de crowdstrike_blog llevan la fecha del crawl
# (2026-02-24/26) en lugar de su fecha real de publicación: el sitemap que usa
# el spider no incluye campos lastmod. Por eso quedan excluidos de cualquier
# análisis temporal y solo cuentan en los agregados generales.
TEMPORAL_EXCLUDED = {"crowdstrike_blog"}

TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Etiquetas cortas para las tablas (así las columnas no se ensanchan tanto)
TACTIC_SHORT = {
    "TA0001": "InitAcc",
    "TA0002": "Exec",
    "TA0003": "Persist",
    "TA0004": "PrivEsc",
    "TA0005": "DefEva",
    "TA0006": "CredAcc",
    "TA0007": "Discov",
    "TA0008": "LatMov",
    "TA0009": "Collect",
    "TA0010": "Exfil",
    "TA0011": "C2",
    "TA0040": "Impact",
    "TA0042": "ResDev",
    "TA0043": "Recon",
}


def load_corpus(db_path: str) -> list[dict]:
    """Devuelve una lista de diccionarios, uno por cada TTP aceptado, con
    fecha, fuente, technique y tactic."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT
            v.extraction_id,
            v.ttp_index,
            v.technique_id,
            v.source_mode,
            a.published_utc,
            a.source,
            e.ttps
        FROM ttp_verdicts_v2 v
        JOIN extractions e ON e.id = v.extraction_id
        JOIN articles a ON a.id = v.article_id
        WHERE v.verdict = 'accept'
        ORDER BY a.published_utc
    """)
    rows = cur.fetchall()
    con.close()

    corpus = []
    skipped = 0
    excluded_temporal = 0
    for ext_id, idx, tech_id, source_mode, pub_utc, source, ttps_json in rows:
        if not pub_utc:
            skipped += 1
            continue
        ttps = json.loads(ttps_json)
        if idx >= len(ttps):
            skipped += 1
            continue

        tactic_id = ttps[idx].get("tactic_id") or "unknown"
        # Para agregar usamos la técnica padre, pero conservamos la subtécnica
        # para el detalle.
        parent_id = tech_id.split(".")[0] if "." in tech_id else tech_id

        year = pub_utc[:4]
        month = int(pub_utc[5:7]) if len(pub_utc) >= 7 else 1
        quarter = f"{year}-Q{(month - 1) // 3 + 1}"

        temporal_ok = source not in TEMPORAL_EXCLUDED
        if not temporal_ok:
            excluded_temporal += 1

        corpus.append({
            "tech_id": tech_id,        # ID completo (p. ej. T1003.006)
            "parent_id": parent_id,    # padre (p. ej. T1003)
            "tactic_id": tactic_id,
            "source_mode": source_mode,
            "year": year,
            "quarter": quarter,
            "source": source,
            "temporal_ok": temporal_ok,
        })

    if skipped:
        print(f"[warn] descartados {skipped} TTPs (sin fecha o índice fuera de rango)")
    if excluded_temporal:
        print(f"[info] {excluded_temporal} TTPs de {TEMPORAL_EXCLUDED} quedan fuera de los análisis temporales (fechas poco fiables)")
    return corpus


def load_technique_names(cache_path: str) -> dict[str, str]:
    if not os.path.exists(cache_path):
        return {}
    with open(cache_path) as f:
        cache = json.load(f)
    return {k: v.get("name", k) for k, v in cache.items()}


def load_article_counts(db_path: str) -> dict[str, dict[str, int]]:
    """Devuelve {source: {year: n_articles}}, que será el denominador para
    normalizar.

    Cuenta todos los artículos con fecha conocida y datos temporales fiables
    (descarta las fuentes en TEMPORAL_EXCLUDED). Los estados 'completed' y
    'filtered' juntos abarcan todos los artículos que el pipeline llegó a
    evaluar.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    placeholders = ",".join("?" for _ in TEMPORAL_EXCLUDED)
    cur.execute(f"""
        SELECT source, substr(published_utc, 1, 4) AS yr, COUNT(*) AS n
        FROM articles
        WHERE processing_state IN ('completed', 'filtered')
          AND published_utc IS NOT NULL AND published_utc != ''
          AND source NOT IN ({placeholders})
        GROUP BY source, yr
    """, list(TEMPORAL_EXCLUDED))  # nosec B608 -- placeholders generados; valores por parámetros
    counts: dict[str, dict[str, int]] = defaultdict(dict)
    for src, yr, n in cur.fetchall():
        counts[src][yr] = n
    con.close()
    return counts


# --- Mann-Kendall (Python puro, distribución exacta para series cortas) ---
# Para n=5 el p-value a dos colas se calcula por PERMUTACIÓN EXACTA, enumerando
# las 5!=120 ordenaciones de los valores observados y contando cuántas alcanzan
# |S'| >= |S_obs|. Es tie-aware: con empates (frecuentes en conteos enteros) S
# puede ser IMPAR, caso que una tabla de claves solo-pares trataría como p=1,0
# (falso negativo). Validado contra scipy.stats.kendalltau(method='exact') en
# ausencia de empates (|S|=10 -> 2/120 = 0,0167, etc.).


def mann_kendall(x: list) -> tuple:
    """Test de tendencia de Mann-Kendall.

    Devuelve (tau, p_value, direction):
      - tau  : correlación de rangos de Kendall [-1, 1]
      - p    : p-value a dos colas (exacto para n=5, aproximación normal para el resto)
      - dir  : 'increasing' | 'decreasing' | 'stable'
    """
    import math
    from collections import Counter as _Counter

    n = len(x)
    if n < 4:
        return 0.0, 1.0, "stable"

    S = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            d = x[j] - x[i]
            if d > 0:
                S += 1
            elif d < 0:
                S -= 1

    max_pairs = n * (n - 1) / 2
    tau = S / max_pairs

    if n == 5:
        # Permutación exacta tie-aware: fracción de las 120 ordenaciones de x
        # cuyo |S'| iguala o supera el |S| observado (p a dos colas).
        from itertools import permutations as _perms
        s_obs = abs(S)
        all_perms = list(_perms(x))
        ge = sum(
            1 for perm in all_perms
            if abs(sum((perm[j] > perm[i]) - (perm[j] < perm[i])
                       for i in range(n - 1) for j in range(i + 1, n))) >= s_obs
        )
        p = ge / len(all_perms)
    else:
        tie_correction = sum(
            t * (t - 1) * (2 * t + 5)
            for t in _Counter(x).values()
            if t > 1
        )
        var_S = (n * (n - 1) * (2 * n + 5) - tie_correction) / 18
        if var_S <= 0:
            p = 1.0
        else:
            Z = (abs(S) - 1) / math.sqrt(var_S)
            p = math.erfc(Z / math.sqrt(2))

    direction = "increasing" if S > 0 else ("decreasing" if S < 0 else "stable")
    return tau, p, direction


# --- helpers ---
def _counter_to_sorted(counts: dict) -> list[tuple]:
    return sorted(counts.items(), key=lambda x: -x[1])


def _pct(n, total):
    return f"{100*n/total:.1f}%" if total else "0.0%"


def _header(title: str):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def save_csv(path: str, rows: list[list], header: list[str]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"  guardado {path}")


# --- funciones de análisis ---
def analysis_volume(corpus: list[dict], csv_dir: str | None):
    _header("1. VOLUMEN A LO LARGO DEL TIEMPO")

    tc = [r for r in corpus if r["temporal_ok"]]
    years = sorted(set(r["year"] for r in tc))
    quarters = sorted(set(r["quarter"] for r in tc))

    by_year: dict[str, dict] = defaultdict(lambda: {"ttps": 0, "articles": set()})
    by_quarter: dict[str, dict] = defaultdict(lambda: {"ttps": 0, "articles": set()})

    for r in tc:
        by_year[r["year"]]["ttps"] += 1
        by_year[r["year"]]["articles"].add((r["source"], r["quarter"]))  # proxy de artículo
        by_quarter[r["quarter"]]["ttps"] += 1

    # Se usa el conteo de TTPs (no de artículos) como métrica de volumen: el
    # corpus ya cargado no trae article_id y aproximarlo por (source, quarter)
    # introduce ruido.

    print("\nPor año:")
    print(f"  {'Año':<6} {'TTPs':>6}  {'YoY Δ':>8}  {'YoY %':>7}")
    print("  " + "-" * 34)
    prev = None
    year_rows = []
    for yr in years:
        n = by_year[yr]["ttps"]
        if prev is not None:
            delta = n - prev
            pct = f"{100*delta/prev:+.1f}%"
        else:
            delta = "-"
            pct = "-"
        print(f"  {yr:<6} {n:>6}  {str(delta):>8}  {pct:>7}")
        year_rows.append([yr, n, delta, pct])
        prev = n

    print("\nPor trimestre (TTPs):")
    print("  " + "  ".join(f"{q[-2:]}" for q in quarters))
    qyr: dict[str, dict[str, int]] = defaultdict(dict)
    for r in corpus:
        yr = r["year"]
        q = r["quarter"][-2:]  # Q1/Q2/Q3/Q4
        qyr[yr][q] = qyr[yr].get(q, 0) + 1

    quarter_rows = []
    for yr in years:
        row_vals = [qyr[yr].get(f"Q{i}", 0) for i in range(1, 5)]
        print(f"  {yr}: " + "  ".join(f"{v:>4}" for v in row_vals))
        quarter_rows.append([yr] + row_vals)

    if csv_dir:
        save_csv(f"{csv_dir}/volume_by_year.csv", year_rows, ["year", "ttps", "yoy_delta", "yoy_pct"])
        save_csv(f"{csv_dir}/volume_by_quarter.csv", quarter_rows, ["year", "Q1", "Q2", "Q3", "Q4"])


def analysis_tactics(corpus: list[dict], csv_dir: str | None):
    _header("2. DISTRIBUCIÓN DE TÁCTICAS POR AÑO")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    years = sorted(set(r["year"] for r in tc))
    by_year_tactic: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    year_totals: dict[str, int] = defaultdict(int)
    for r in tc:
        by_year_tactic[r["year"]][r["tactic_id"]] += 1
        year_totals[r["year"]] += 1

    # Imprime la tabla con las tácticas en columnas y los años en filas.
    # Solo se muestran las tácticas que aparecen en el corpus.
    active_tactics = sorted(
        {t for yr in by_year_tactic.values() for t in yr},
        key=lambda t: -sum(by_year_tactic[yr].get(t, 0) for yr in years)
    )

    col_w = 9
    header_parts = [f"{'Año':<6}"] + [f"{TACTIC_SHORT.get(t, t):>{col_w}}" for t in active_tactics]
    print("  " + " ".join(header_parts))
    print("  " + "-" * (7 + (col_w + 1) * len(active_tactics)))

    csv_rows = []
    for yr in years:
        total = year_totals[yr]
        vals = [by_year_tactic[yr].get(t, 0) for t in active_tactics]
        pcts = [f"{100*v/total:.0f}%" if total else "0%" for v in vals]
        print("  " + f"{yr:<6} " + " ".join(f"{p:>{col_w}}" for p in pcts))
        csv_rows.append([yr, total] + vals)

    if csv_dir:
        hdr = ["year", "total_ttps"] + [f"{TACTIC_SHORT.get(t, t)}" for t in active_tactics]
        save_csv(f"{csv_dir}/tactic_distribution_by_year.csv", csv_rows, hdr)

    # Además, mostramos los conteos absolutos de las tácticas más usadas
    print("\n  (los valores son % de TTPs de ese año; excluye el 2026 parcial y crowdstrike_blog)")

    print("\n  Top 5 tácticas en total (2021-2025):")
    tac_total = defaultdict(int)
    for yr in years:
        for t, n in by_year_tactic[yr].items():
            tac_total[t] += n
    for t, n in _counter_to_sorted(tac_total)[:5]:
        name = TACTIC_NAMES.get(t, t)
        total_all = sum(tac_total.values())
        print(f"    {t} {name:<22} {n:>4}  ({_pct(n, total_all)})")


def analysis_top_techniques(corpus: list[dict], tech_names: dict[str, str], csv_dir: str | None):
    _header("3. TÉCNICAS TOP POR AÑO")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    years = sorted(set(r["year"] for r in tc))

    by_year_tech: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in tc:
        by_year_tech[r["year"]][r["tech_id"]] += 1

    csv_rows = []
    for yr in years:
        top = _counter_to_sorted(by_year_tech[yr])[:10]
        print(f"\n  {yr}  (total {sum(by_year_tech[yr].values())} TTPs)")
        print(f"  {'Rank':<5} {'ID':<14} {'Nombre':<38} {'N':>4}")
        print("  " + "-" * 65)
        for rank, (tid, n) in enumerate(top, 1):
            name = tech_names.get(tid, tech_names.get(tid.split(".")[0], ""))[:37]
            print(f"  {rank:<5} {tid:<14} {name:<38} {n:>4}")
            csv_rows.append([yr, rank, tid, name, n])

    if csv_dir:
        save_csv(f"{csv_dir}/top_techniques_by_year.csv", csv_rows,
                 ["year", "rank", "technique_id", "name", "count"])


def analysis_emergence(corpus: list[dict], tech_names: dict[str, str], csv_dir: str | None):
    _header("4. APARICIÓN DE TÉCNICAS (2024-2025 vs 2021-2023)")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    by_tech_year: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in tc:
        by_tech_year[r["tech_id"]][r["year"]] += 1

    early_years = {"2021", "2022", "2023"}
    late_years = {"2024", "2025"}

    results = []
    for tech, by_year in by_tech_year.items():
        early = sum(by_year.get(yr, 0) for yr in early_years)
        late = sum(by_year.get(yr, 0) for yr in late_years)
        total = early + late
        if total < 5:
            continue  # filtra ruido
        first_year = min((yr for yr in by_year if by_year[yr] > 0), default="?")
        growth = late / early if early > 0 else float("inf")
        results.append({
            "tech": tech,
            "early": early,
            "late": late,
            "total": total,
            "first_year": first_year,
            "growth": growth,
        })

    # Emergentes: late > early y crecimiento ≥ 1.5×
    emerging = sorted(
        [r for r in results if r["growth"] >= 1.5 and r["late"] >= 5],
        key=lambda x: -x["growth"]
    )
    # En declive: early > late y crecimiento ≤ 0.5×
    declining = sorted(
        [r for r in results if r["growth"] <= 0.5 and r["early"] >= 5],
        key=lambda x: x["growth"]
    )
    # Nuevas en 2024+: first_year >= 2024
    new_recent = sorted(
        [r for r in results if r["first_year"] >= "2024"],
        key=lambda x: -x["late"]
    )

    def print_table(rows, label):
        print(f"\n  {label}")
        print(f"  {'ID':<14} {'Nombre':<36} {'2021-23':>7} {'2024-25':>7} {'Crec.':>8} {'1ª':>6}")
        print("  " + "-" * 79)
        for r in rows[:15]:
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:35]
            g = f"{r['growth']:.1f}×" if r["growth"] != float("inf") else "new"
            print(f"  {r['tech']:<14} {name:<36} {r['early']:>7} {r['late']:>7} {g:>8} {r['first_year']:>6}")

    print_table(emerging, "TÉCNICAS EMERGENTES (crecimiento ≥1.5× en 2024-25 vs 2021-23, n≥5):")
    print_table(declining, "TÉCNICAS EN DECLIVE (caída ≤0.5×, n inicial ≥5):")
    print_table(new_recent, "TÉCNICAS NUEVAS (primera vez vistas en 2024+, total n≥5):")

    # Primera aparición por año
    first_by_year: dict[str, list] = defaultdict(list)
    for tech, by_year in by_tech_year.items():
        fy = min((yr for yr in by_year if by_year[yr] > 0), default=None)
        if fy:
            first_by_year[fy].append(tech)

    print("\n  Técnicas que aparecen por primera vez en cada año:")
    for yr in sorted(first_by_year.keys()):
        print(f"    {yr}: {len(first_by_year[yr])} técnicas nuevas")

    if csv_dir:
        rows_csv = []
        for r in sorted(results, key=lambda x: -x["total"]):
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:60]
            g = f"{r['growth']:.2f}" if r["growth"] != float("inf") else "inf"
            rows_csv.append([r["tech"], name, r["early"], r["late"], r["total"], g, r["first_year"]])
        save_csv(f"{csv_dir}/technique_emergence.csv", rows_csv,
                 ["technique_id", "name", "count_2021_23", "count_2024_25", "total", "growth_ratio", "first_year"])


def analysis_sources(corpus: list[dict], csv_dir: str | None):
    _header("5. CONTRIBUCIÓN POR FUENTE A LO LARGO DEL TIEMPO")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    years = sorted(set(r["year"] for r in tc))
    sources = sorted(set(r["source"] for r in tc))

    by_src_year: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in tc:
        by_src_year[r["source"]][r["year"]] += 1

    src_totals = {s: sum(by_src_year[s].values()) for s in sources}
    sources_sorted = sorted(sources, key=lambda s: -src_totals.get(s, 0))

    col_w = 6
    print(f"\n  {'Fuente':<28} " + " ".join(f"{yr:>{col_w}}" for yr in years) + f"  {'Total':>{col_w}}")
    print("  " + "-" * (30 + (col_w + 1) * len(years) + 8))
    csv_rows = []
    for src in sources_sorted:
        vals = [by_src_year[src].get(yr, 0) for yr in years]
        total = sum(vals)
        print(f"  {src:<28} " + " ".join(f"{v:>{col_w}}" for v in vals) + f"  {total:>{col_w}}")
        csv_rows.append([src] + vals + [total])

    if csv_dir:
        hdr = ["source"] + years + ["total"]
        save_csv(f"{csv_dir}/source_contribution_by_year.csv", csv_rows, hdr)


def analysis_double_extortion_doc(db_path: str, csv_dir: str | None):
    """Sección 6 (revisada): doble extorsión a nivel de documento usando el article_id real."""
    _header("6. DOBLE EXTORSIÓN A NIVEL DE DOCUMENTO (T1486 ∩ TA0010)")

    EXFIL_TECHS = {"T1020", "T1030", "T1041", "T1048", "T1537", "T1567", "T1567.002"}
    ENCRYPT_TECH = "T1486"

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT v.article_id,
               substr(a.published_utc, 1, 4) AS yr,
               GROUP_CONCAT(v.technique_id) AS techs
        FROM ttp_verdicts_v2 v
        JOIN articles a ON a.id = v.article_id
        WHERE v.verdict = 'accept'
          AND a.source != 'crowdstrike_blog'
          AND substr(a.published_utc, 1, 4) <= '2025'
        GROUP BY v.article_id
    """)
    rows = cur.fetchall()
    con.close()

    docs_by_year: dict[str, int] = defaultdict(int)
    encrypt_by_year: dict[str, int] = defaultdict(int)
    exfil_by_year: dict[str, int] = defaultdict(int)
    both_by_year: dict[str, int] = defaultdict(int)

    for _, yr, techs_str in rows:
        techs = set(techs_str.split(","))
        docs_by_year[yr] += 1
        has_enc = ENCRYPT_TECH in techs
        has_exf = bool(techs & EXFIL_TECHS)
        if has_enc:
            encrypt_by_year[yr] += 1
        if has_exf:
            exfil_by_year[yr] += 1
        if has_enc and has_exf:
            both_by_year[yr] += 1

    years = sorted(docs_by_year)
    print(f"\n  {'Año':<6} {'Docs':>6} {'Encrypt':>8} {'Exfil':>7} {'Ambas':>6}  {'Ratio':>7}")
    print("  " + "-" * 46)
    csv_rows = []
    for yr in years:
        t = docs_by_year[yr]
        both = both_by_year[yr]
        pct = _pct(both, t)
        print(f"  {yr:<6} {t:>6} {encrypt_by_year[yr]:>8} {exfil_by_year[yr]:>7} {both:>6}  {pct:>7}")
        csv_rows.append([yr, t, encrypt_by_year[yr], exfil_by_year[yr], both, pct])

    print("\n  Nota: cota inferior. Las menciones genéricas a exfiltración sin evidencia")
    print("  explícita de ATT&CK no cuentan. La dirección de la tendencia es fiable; el")
    print("  ratio absoluto va por lo bajo.")

    if csv_dir:
        save_csv(f"{csv_dir}/double_extortion_doc_level.csv", csv_rows,
                 ["year", "docs_with_ttps", "has_encrypt", "has_exfil", "has_both", "rate"])


def analysis_source_normalized(
    corpus: list[dict],
    article_counts: dict[str, dict[str, int]],
    tech_names: dict[str, str],
    csv_dir: str | None,
):
    """Sección 7: normalización estilo SNIP para corregir el sesgo de volumen de bc_site."""
    _header("7. EMERGENCIA NORMALIZADA POR FUENTE (corregido el sesgo)")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    early_years = {"2021", "2022", "2023"}
    late_years = {"2024", "2025"}

    # Conteo bruto por técnica, fuente y año
    counts: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    for r in tc:
        counts[r["tech_id"]][r["source"]][r["year"]] += 1

    # Todas las fuentes del corpus temporal
    sources = sorted(set(r["source"] for r in tc))

    def normalized_period(tech: str, period_years: set) -> float:
        """Suma sobre todas las fuentes de (count(T,S,Y) / articles(S,Y)) para
        los años del periodo."""
        total = 0.0
        for src in sources:
            arts = article_counts.get(src, {})
            for yr in period_years:
                n_arts = arts.get(yr, 0)
                if n_arts > 0:
                    total += counts[tech][src][yr] / n_arts
        return total

    all_techs = set(r["tech_id"] for r in tc)
    results = []
    for tech in all_techs:
        norm_early = normalized_period(tech, early_years)
        norm_late = normalized_period(tech, late_years)
        total = norm_early + norm_late
        if total < 0.05:  # demasiado rara incluso ya normalizada
            continue
        growth = norm_late / norm_early if norm_early > 0.001 else float("inf")
        results.append({
            "tech": tech,
            "norm_early": norm_early,
            "norm_late": norm_late,
            "growth": growth,
        })

    # Desempate por technique_id: hace el orden determinista entre ejecuciones
    # (sin él, las técnicas con el mismo growth heredaban el orden de un set).
    emerging_norm = sorted(
        [r for r in results if r["growth"] >= 1.5 and r["norm_late"] >= 0.1],
        key=lambda x: (-x["growth"], x["tech"]),
    )
    declining_norm = sorted(
        [r for r in results if r["growth"] <= 0.5 and r["norm_early"] >= 0.1],
        key=lambda x: (x["growth"], x["tech"]),
    )

    def print_norm_table(rows: list, label: str):
        print(f"\n  {label}")
        print(f"  {'ID':<14} {'Nombre':<36} {'Inicial':>7} {'Final':>7} {'Crec.':>8}")
        print("  " + "-" * 75)
        for r in rows[:15]:
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:35]
            g = f"{r['growth']:.1f}×" if r["growth"] != float("inf") else "new"
            print(
                f"  {r['tech']:<14} {name:<36} "
                f"{r['norm_early']:>7.3f} {r['norm_late']:>7.3f} {g:>8}"
            )

    print("\n  Conteo normalizado = Σ_fuente[ count(T,fuente,Y) / articles(fuente,Y) ]")
    print("  Corrige el pico de volumen de bc_site (392 artículos en 2023 frente a 15 en 2021).")
    print_norm_table(emerging_norm, "EMERGENTES tras normalizar (crecimiento ≥1.5×, norm_late≥0.10):")
    print_norm_table(declining_norm, "EN DECLIVE tras normalizar (crecimiento ≤0.5×, norm_early≥0.10):")

    # Comparativa: técnicas que figuran como emergentes en bruto pero NO en el normalizado
    raw_emerging_ids = {
        r["tech"]
        for r in results
        if r["growth"] >= 1.5
    }
    norm_emerging_ids = {r["tech"] for r in emerging_norm}
    artifacts = raw_emerging_ids - norm_emerging_ids
    if artifacts:
        print("\n  Técnicas que la normalización descarta (probables artefactos por volumen de fuente):")
        for t in sorted(artifacts):
            name = tech_names.get(t, tech_names.get(t.split(".")[0], ""))[:40]
            print(f"    {t:<14} {name}")

    if csv_dir:
        csv_rows = []
        for r in sorted(results, key=lambda x: (-x["norm_late"], x["tech"])):
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:60]
            g = f"{r['growth']:.3f}" if r["growth"] != float("inf") else "inf"
            csv_rows.append([r["tech"], name, f"{r['norm_early']:.4f}", f"{r['norm_late']:.4f}", g])
        save_csv(
            f"{csv_dir}/normalized_emergence.csv",
            csv_rows,
            ["technique_id", "name", "norm_early_2021_23", "norm_late_2024_25", "growth_ratio"],
        )


def analysis_shannon_entropy(corpus: list[dict], csv_dir: str | None):
    """Sección 8: entropía de Shannon de la distribución de fuentes por año."""
    _header("8. DIVERSIDAD DE FUENTES POR ENTROPÍA DE SHANNON")

    import math

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    years = sorted(set(r["year"] for r in tc))

    by_year_src: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in tc:
        by_year_src[r["year"]][r["source"]] += 1

    max_entropy = math.log2(len(set(r["source"] for r in tc)))  # H_max

    print(f"\n  H_max (distribución uniforme sobre {len(set(r['source'] for r in tc))} fuentes) = {max_entropy:.3f} bits")
    print(f"\n  {'Año':<6} {'H (bits)':>10} {'H/H_max':>9}  Distribución de fuentes (top 3)")
    print("  " + "-" * 70)

    csv_rows = []
    for yr in years:
        src_counts = by_year_src[yr]
        total = sum(src_counts.values())
        H = -sum((n / total) * math.log2(n / total) for n in src_counts.values() if n > 0)
        H_norm = H / max_entropy
        top3 = sorted(src_counts.items(), key=lambda x: -x[1])[:3]
        top3_str = ", ".join(f"{s}({n})" for s, n in top3)
        print(f"  {yr:<6} {H:>10.3f} {H_norm:>9.1%}  {top3_str}")
        csv_rows.append([yr, f"{H:.4f}", f"{H_norm:.4f}", top3_str])

    print(
        "\n  Una caída brusca de la entropía indica sesgo por volumen de fuente. "
        "Un H_norm bajo en un año significa que el corpus de ese año lo "
        "dominan unos pocos publishers."
    )

    if csv_dir:
        save_csv(
            f"{csv_dir}/shannon_entropy.csv",
            csv_rows,
            ["year", "entropy_bits", "entropy_normalized", "top3_sources"],
        )


def analysis_mann_kendall(
    corpus: list[dict],
    tech_names: dict[str, str],
    csv_dir: str | None,
):
    """Sección 9: test de tendencia de Mann-Kendall + matriz Prevalencia-Tendencia."""
    _header("9. TEST DE TENDENCIA MANN-KENDALL + MATRIZ PREVALENCIA-TENDENCIA")

    tc = [r for r in corpus if r["temporal_ok"] and r["year"] <= "2025"]
    years = sorted(set(r["year"] for r in tc))

    by_tech_year: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    total_per_year: dict[str, int] = defaultdict(int)
    for r in tc:
        by_tech_year[r["tech_id"]][r["year"]] += 1
        total_per_year[r["year"]] += 1

    # Construye la serie temporal de cada técnica (rellena con 0 los años sin datos)
    results = []
    for tech, yr_counts in by_tech_year.items():
        series = [yr_counts.get(yr, 0) for yr in years]
        total = sum(series)
        if total < 4:
            continue  # demasiado rara como para ver tendencia

        tau, p, direction = mann_kendall(series)

        # Categoría de prevalencia (según la media anual)
        mean_count = total / len(years)
        if mean_count >= 10:
            prevalence = "High"
        elif mean_count >= 3:
            prevalence = "Medium"
        else:
            prevalence = "Infrequent"

        # Umbral de significación: p < 0.10 con n=5 (la potencia estadística es baja)
        significant = p < 0.10

        # Categoría dentro de la matriz Prevalencia-Tendencia
        if significant and direction == "increasing" and prevalence == "Infrequent":
            category = "EMERGING"
        elif significant and direction == "increasing":
            category = "RISING"
        elif significant and direction == "decreasing":
            category = "OBSOLESCENT"
        elif prevalence == "High" and not significant:
            category = "CORE"
        else:
            category = "STABLE"

        results.append({
            "tech": tech,
            "series": series,
            "total": total,
            "mean": mean_count,
            "tau": tau,
            "p": p,
            "direction": direction,
            "significant": significant,
            "prevalence": prevalence,
            "category": category,
        })

    # Imprime por categoría
    for cat in ["EMERGING", "RISING", "CORE", "OBSOLESCENT", "STABLE"]:
        cat_rows = sorted(
            [r for r in results if r["category"] == cat],
            key=lambda x: -abs(x["tau"]),
        )
        if not cat_rows:
            continue
        print(f"\n  [{cat}]  n={len(cat_rows)}")
        if cat == "STABLE":
            print("  (se omite el listado individual de STABLE)")
            continue
        print(f"  {'ID':<14} {'Nombre':<34} {'τ':>6} {'p':>7}  {'Serie (2021-2025)'}")
        print("  " + "-" * 80)
        for r in cat_rows[:12]:
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:33]
            series_str = " ".join(str(v) for v in r["series"])
            sig = "*" if r["significant"] else " "
            print(
                f"  {r['tech']:<14} {name:<34} "
                f"{r['tau']:>+6.2f}{sig} {r['p']:>7.4f}  {series_str}"
            )

    print("\n  * p < 0.10  (n=5: valores críticos exactos a dos colas |τ|=0.8 p=0.083, |τ|=1.0 p=0.017)")
    print("  Prevalencia: High = media ≥10/año, Medium = 3-9/año, Infrequent = <3/año")
    print("  EMERGING = Infrequent + subida significativa  |  RISING = High/Med + subida significativa")
    print("  CORE = High + estable  |  OBSOLESCENT = bajada significativa")

    # Resumen de la matriz
    from collections import Counter as _C
    cat_counts = _C(r["category"] for r in results)
    print("\n  Resumen de la matriz Prevalencia-Tendencia:")
    for cat in ["EMERGING", "RISING", "CORE", "OBSOLESCENT", "STABLE"]:
        print(f"    {cat:<12}: {cat_counts.get(cat, 0)} técnicas")

    if csv_dir:
        csv_rows = []
        for r in sorted(results, key=lambda x: x["category"] + str(-x["total"])):
            name = tech_names.get(r["tech"], tech_names.get(r["tech"].split(".")[0], ""))[:60]
            series_str = "|".join(str(v) for v in r["series"])
            csv_rows.append([
                r["tech"], name, r["total"], f"{r['mean']:.1f}",
                f"{r['tau']:+.3f}", f"{r['p']:.4f}",
                r["direction"], r["significant"], r["prevalence"], r["category"],
                series_str,
            ])
        save_csv(
            f"{csv_dir}/mann_kendall_prevalence_matrix.csv",
            csv_rows,
            ["technique_id", "name", "total", "mean_per_year", "tau", "p_value",
             "direction", "significant", "prevalence", "category", "series_2021_2025"],
        )


# --- main ---
def main():
    parser = argparse.ArgumentParser(description="Análisis longitudinal del corpus de TTPs de ransomware")
    parser.add_argument("--db", default=DB_DEFAULT, help="Ruta a ransomware_intel.db")
    parser.add_argument("--csv-dir", default=None, help="Directorio donde guardar las salidas CSV")
    args = parser.parse_args()

    print(f"Cargando corpus desde {args.db} ...")
    corpus = load_corpus(args.db)
    print(f"Cargados {len(corpus)} TTPs aceptados")

    tech_names = load_technique_names(MITRE_CACHE)
    print(f"Cargados {len(tech_names)} nombres de técnica desde la caché de MITRE")

    article_counts = load_article_counts(args.db)
    print(f"Cargados conteos de artículos para {len(article_counts)} fuentes (denominador de la normalización)")

    analysis_volume(corpus, args.csv_dir)
    analysis_tactics(corpus, args.csv_dir)
    analysis_top_techniques(corpus, tech_names, args.csv_dir)
    analysis_emergence(corpus, tech_names, args.csv_dir)
    analysis_sources(corpus, args.csv_dir)
    analysis_double_extortion_doc(args.db, args.csv_dir)
    analysis_source_normalized(corpus, article_counts, tech_names, args.csv_dir)
    analysis_shannon_entropy(corpus, args.csv_dir)
    analysis_mann_kendall(corpus, tech_names, args.csv_dir)

    print()
    print("=" * 72)
    print("  Análisis terminado.")
    print("=" * 72)


if __name__ == "__main__":
    main()
