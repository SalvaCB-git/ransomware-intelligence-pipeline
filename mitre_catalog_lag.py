#!/usr/bin/env python3
"""
Análisis del retardo de catalogación en MITRE ATT&CK.

Cruza el corpus limpio (TTPs aceptados por el juez v2, sin crowdstrike_blog
porque su fecha de crawl contamina el dato) con el historial público de
versiones de MITRE ATT&CK Enterprise para medir la LATENCIA entre la
primera evidencia textual de una técnica en la literatura CTI y la fecha
en la que MITRE la cataloga formalmente.

Por cada técnica se reportan dos fuentes de fecha de MITRE:
  (A) mitre_first_release_date: fecha de la primera release pública .0
      mayor de ATT&CK Enterprise donde la técnica aparece como objeto
      attack-pattern. Basada en release; conservadora; corresponde al
      momento en que el conocimiento estuvo disponible en
      attack.mitre.org.
  (B) mitre_stix_created: campo `created` del objeto STIX attack-pattern
      en el bundle más reciente. Basada en commit; suele ir unos 30 días
      por delante de la release pública.

catalog_lag = mitre_date - first_seen_corpus
  Positivo: MITRE catalogó la técnica DESPUÉS de la primera evidencia
  textual del corpus (latencia institucional).
  Negativo: MITRE catalogó antes de cualquier mención en el corpus (el
  corpus refleja uso posterior a la catalogación).

Los bundles se descargan una vez desde los tags ATT&CK-v{N}.0 de
github.com/mitre/cti para N en 8..19 (12 mayores, ~570 MB) y se cachean
en outputs/catalog_lag/mitre_bundles/. Las ejecuciones siguientes ya son
offline.

# AVISO METODOLÓGICO IMPORTANTE (fuga de datos en el extractor)
# ---
# Este análisis mide *latencia de catalogación*, no *alerta temprana
# predictiva*. El extractor (Qwen 2.5 14B + RAG sobre una ChromaDB
# construida a partir del bundle STIX de MITRE el 2026-03-15, ATT&CK
# Enterprise ~v18.0) tenía acceso en el momento de la extracción a las
# descripciones de todas las técnicas marcadas aquí como "anticipadas",
# incluidas las que MITRE introdujo *después* de la fecha de publicación
# del artículo. La hipótesis "el corpus mencionó T_x N días antes de que
# MITRE la catalogara" se reformula mejor como "la fenomenología textual
# necesaria para aplicar la descripción T_x de MITRE-2026 ya está
# presente en artículos CTI N días antes de que MITRE publicara T_x". La
# demora institucional de MITRE es un fenómeno real y cuantificable; el
# valor predictivo de ejecutar este pipeline de forma contemporánea a
# cada artículo (es decir, con una ChromaDB congelada en el tiempo) NO
# queda establecido por este script y requeriría reextraer una muestra
# con una ChromaDB truncada por versión (tarea de seguimiento, documentada en
# la memoria del TFG).

Uso:
    python3 mitre_catalog_lag.py [--db PATH] [--csv-dir DIR]
                                  [--bundle-dir DIR] [--no-download]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import sqlite3
import urllib.request

DB_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "ransomware_intel.db")
CSV_DIR_DEFAULT = os.path.join(os.path.dirname(__file__), "outputs", "catalog_lag")
BUNDLE_DIR_DEFAULT = os.path.join(
    os.path.dirname(__file__), "outputs", "catalog_lag", "mitre_bundles"
)

# Los artículos de crowdstrike_blog llevan todos la fecha de crawl en
# published_utc; el sitemap del spider no traía campos lastmod. Se excluyen
# de los análisis temporales, en línea con longitudinal_analysis.py.
TEMPORAL_EXCLUDED = {"crowdstrike_blog"}

# Releases mayores de ATT&CK Enterprise. Las fechas son los timestamps del
# commit del tag en GitHub (repo mitre/cti): coinciden con la fecha de
# release publicada en attack.mitre.org/resources/versions/ o quedan a 1-3
# días de ella.
ATTACK_RELEASES = [
    ("8.0",  "2020-10-27"),
    ("9.0",  "2021-06-16"),
    ("10.0", "2021-10-21"),
    ("11.0", "2022-04-24"),
    ("12.0", "2022-10-25"),
    ("13.0", "2023-04-25"),
    ("14.0", "2023-10-31"),
    ("15.0", "2024-04-23"),
    ("16.0", "2024-10-30"),
    ("17.0", "2025-04-22"),
    ("18.0", "2025-10-28"),
    ("19.0", "2026-04-27"),
]

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    "ATT%26CK-v{version}/enterprise-attack/enterprise-attack.json"
)


# ----------------------------- gestión de bundles -----------------------------


def bundle_path_for(version: str, bundle_dir: str) -> str:
    return os.path.join(bundle_dir, f"enterprise-attack-{version}.json")


def download_bundle(version: str, bundle_dir: str) -> str:
    path = bundle_path_for(version, bundle_dir)
    if os.path.exists(path) and os.path.getsize(path) > 1_000_000:
        return path
    os.makedirs(bundle_dir, exist_ok=True)
    url = BUNDLE_URL.format(version=version)
    print(f"  downloading v{version} -> {path}")
    tmp = path + ".part"
    urllib.request.urlretrieve(url, tmp)
    os.rename(tmp, path)
    return path


def parse_bundle(path: str) -> dict:
    """Devuelve un dict external_id -> {name, created, modified, revoked,
    x_mitre_version, kill_chain_phases}."""
    with open(path) as f:
        bundle = json.load(f)
    out = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        kill_chain_phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])]
        out[ext_id] = {
            "name": obj.get("name"),
            "created": obj.get("created"),
            "modified": obj.get("modified"),
            "revoked": obj.get("revoked", False),
            "x_mitre_version": obj.get("x_mitre_version"),
            "kill_chain_phases": kill_chain_phases,
        }
    return out


def build_mitre_index(bundle_dir: str, allow_download: bool) -> dict:
    """Para cada external_id, registra la primera release de ATT&CK donde
    aparece, junto con sus últimos metadatos STIX.

    Devuelve un dict ext_id -> {
        first_version, first_release_date,
        ever_non_revoked_version, ever_non_revoked_date,
        latest_name, latest_created, latest_revoked,
        latest_x_mitre_version, latest_kill_chain_phases
    }
    """
    idx = {}
    for version, release_date in ATTACK_RELEASES:
        path = bundle_path_for(version, bundle_dir)
        if not os.path.exists(path):
            if not allow_download:
                print(f"  skipping v{version} (not cached, --no-download)")
                continue
            download_bundle(version, bundle_dir)
        techs = parse_bundle(path)
        for ext_id, meta in techs.items():
            entry = idx.get(ext_id)
            if entry is None:
                entry = {
                    "first_version": version,
                    "first_release_date": release_date,
                    "ever_non_revoked_version": None,
                    "ever_non_revoked_date": None,
                }
                idx[ext_id] = entry
            if (
                not meta["revoked"]
                and entry["ever_non_revoked_version"] is None
            ):
                entry["ever_non_revoked_version"] = version
                entry["ever_non_revoked_date"] = release_date
            # Siempre sobrescribimos con los metadatos más recientes vistos.
            entry["latest_name"] = meta["name"]
            entry["latest_created"] = meta["created"]
            entry["latest_revoked"] = meta["revoked"]
            entry["latest_x_mitre_version"] = meta["x_mitre_version"]
            entry["latest_kill_chain_phases"] = meta["kill_chain_phases"]
    return idx


# ------------------------------ carga del corpus ------------------------------


def load_corpus(db_path: str) -> dict:
    """Carga los TTPs accept v2 excluyendo crowdstrike_blog. Devuelve un
    dict technique_id -> {first_seen, accept_count, article_ids, sources,
    first_seen_source, first_seen_article_id, first_seen_title,
    first_seen_url}."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        """
        SELECT v.technique_id, a.published_utc, a.source, a.id,
               a.title, a.url
        FROM ttp_verdicts_v2 v
        JOIN articles a ON a.id = v.article_id
        WHERE v.verdict = 'accept'
          AND a.published_utc IS NOT NULL
          AND a.published_utc != ''
        """
    )
    rows = cur.fetchall()
    con.close()

    by_tech = {}
    for tech_id, pub_utc, source, art_id, title, url in rows:
        if source in TEMPORAL_EXCLUDED:
            continue
        pub_date = pub_utc[:10]
        tech_agg = by_tech.get(tech_id)
        if tech_agg is None:
            tech_agg = {
                "first_seen": pub_date,
                "all_dates": [],
                "accept_count": 0,
                "article_ids": set(),
                "sources": set(),
                "first_seen_source": source,
                "first_seen_article_id": art_id,
                "first_seen_title": title or "",
                "first_seen_url": url or "",
            }
            by_tech[tech_id] = tech_agg
        elif pub_date < tech_agg["first_seen"]:
            tech_agg["first_seen"] = pub_date
            tech_agg["first_seen_source"] = source
            tech_agg["first_seen_article_id"] = art_id
            tech_agg["first_seen_title"] = title or ""
            tech_agg["first_seen_url"] = url or ""
        tech_agg["all_dates"].append(pub_date)
        tech_agg["accept_count"] += 1
        tech_agg["article_ids"].add(art_id)
        tech_agg["sources"].add(source)
    return by_tech


def median_date(dates: list[str]) -> str:
    """Devuelve la fecha ISO mediana (yyyy-mm-dd) a partir de una lista de
    fechas. Con un número par de elementos devuelve el menor de los dos
    centrales (es determinista y evita inventar una fecha intermedia)."""
    if not dates:
        return ""
    s = sorted(dates)
    return s[(len(s) - 1) // 2]


# ------------------------------ núcleo del análisis ------------------------------


def days_between(d_from: str, d_to: str) -> int | None:
    if not d_from or not d_to:
        return None
    try:
        a = dt.date.fromisoformat(d_from[:10])
        b = dt.date.fromisoformat(d_to[:10])
    except ValueError:
        return None
    return (b - a).days


def parent_of(tech_id: str) -> str:
    return tech_id.split(".")[0] if "." in tech_id else tech_id


def cross(corpus: dict, mitre: dict, corpus_start: str) -> list[dict]:
    """Cruza los índices de corpus y MITRE. corpus_start es la fecha
    YYYY-MM-DD que delimita las técnicas "post-corpus-start" (las que MITRE
    introdujo después de esa fecha son candidatas para el análisis de
    retardo de catalogación). Se usa para marcar is_post_corpus_start y
    para calcular la tasa base."""
    rows = []
    for tech_id, agg in sorted(corpus.items()):
        mitre_meta = mitre.get(tech_id, {})
        first_release_date = mitre_meta.get("first_release_date") or ""
        first_version = mitre_meta.get("first_version") or ""
        ever_nr_date = mitre_meta.get("ever_non_revoked_date") or first_release_date
        ever_nr_version = mitre_meta.get("ever_non_revoked_version") or first_version
        stix_created = (mitre_meta.get("latest_created") or "")[:10]

        first_seen = agg["first_seen"]
        median_seen = median_date(agg["all_dates"])

        # Lags basados en el mínimo (se conservan por compatibilidad).
        lag_release = days_between(first_seen, first_release_date)
        lag_release_nr = days_between(first_seen, ever_nr_date)
        lag_created = days_between(first_seen, stix_created)

        # Lags basados en la mediana (más robustos frente a outliers).
        lag_release_med = days_between(median_seen, first_release_date)
        lag_release_nr_med = days_between(median_seen, ever_nr_date)
        lag_created_med = days_between(median_seen, stix_created)

        # Flag post-corpus-start: vale 1 sólo si MITRE introdujo la técnica
        # DESPUÉS de la fecha de inicio del corpus (es decir, es candidata
        # real al análisis de retardo; las preexistentes no lo son).
        is_post_start = (
            "1" if first_release_date and first_release_date > corpus_start else "0"
        )

        rows.append(
            {
                "technique_id": tech_id,
                "is_subtechnique": "1" if "." in tech_id else "0",
                "parent_id": parent_of(tech_id),
                "name": mitre_meta.get("latest_name") or "",
                "first_seen_corpus": first_seen,
                "median_seen_corpus": median_seen,
                "first_seen_source": agg["first_seen_source"],
                "first_seen_article_id": agg["first_seen_article_id"],
                "first_seen_title": agg["first_seen_title"][:140],
                "first_seen_url": agg["first_seen_url"],
                "mitre_first_version": first_version,
                "mitre_first_release_date": first_release_date,
                "mitre_first_nonrevoked_version": ever_nr_version,
                "mitre_first_nonrevoked_date": ever_nr_date,
                "mitre_stix_created": stix_created,
                "mitre_latest_revoked": "1" if mitre_meta.get("latest_revoked") else "0",
                "mitre_latest_x_version": mitre_meta.get("latest_x_mitre_version") or "",
                "catalog_lag_release_days": "" if lag_release is None else lag_release,
                "catalog_lag_nonrevoked_days": "" if lag_release_nr is None else lag_release_nr,
                "catalog_lag_created_days": "" if lag_created is None else lag_created,
                "catalog_lag_release_median_days": "" if lag_release_med is None else lag_release_med,
                "catalog_lag_nonrevoked_median_days": "" if lag_release_nr_med is None else lag_release_nr_med,
                "catalog_lag_created_median_days": "" if lag_created_med is None else lag_created_med,
                "accept_count": agg["accept_count"],
                "n_articles": len(agg["article_ids"]),
                "n_sources": len(agg["sources"]),
                "sources": ",".join(sorted(agg["sources"])),
                "in_mitre_enterprise": "1" if first_release_date else "0",
                "is_post_corpus_start": is_post_start,
            }
        )
    return rows


def write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        with open(path, "w", newline="") as f:
            f.write("")
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def has_positive_lag(row: dict, field: str) -> bool:
    """True si el campo serializado `field` de `row` contiene un lag
    positivo, es decir no está vacío y, parseado como entero, es > 0.
    Encapsula el predicado repetido row[field] != "" and int(row[field]) > 0."""
    return row[field] != "" and int(row[field]) > 0


def binomial_pvalue(k: int, n: int, p: float = 0.5) -> float:
    """Test binomial exacto unilateral: P(X >= k | X ~ Bin(n, p))."""
    if n <= 0 or k < 0:
        return 1.0
    if k > n:
        return 0.0
    total = 0.0
    for i in range(k, n + 1):
        total += math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
    return total


# ------------------------------ reporting por consola ------------------------------


def print_summary(
    corpus: dict,
    rows: list[dict],
    not_in_mitre: list[dict],
    revoked: list[dict],
    positive_lag: list[dict],
    positive_lag_robust: list[dict],
    positive_lag_multisource: list[dict],
    positive_lag_strict: list[dict],
    mitre: dict,
    corpus_start: str,
    post_start: list[dict],
) -> None:
    """Imprime por consola el resumen completo del análisis de catalog-lag
    (tablas, distribución de percentiles, test binomial y sanity-check)."""
    print("\n" + "!" * 78)
    print("CAVEAT: catalog_lag is institutional latency of MITRE, not predictive")
    print("early warning. The extractor's ChromaDB (built 2026-03-15, ~v18) had")
    print("access to descriptions of every technique flagged here, including")
    print("those introduced AFTER the article date. See docstring D1 caveat.")
    print("!" * 78)

    print("\n=== MITRE catalog-lag summary ===")
    print(
        f"Corpus accept v2 (excl. crowdstrike_blog): {len(corpus)} technique_ids"
    )
    print(
        f"  in MITRE Enterprise (any version):       "
        f"{sum(1 for r in rows if r['in_mitre_enterprise'] == '1')}"
    )
    print(
        f"  not in MITRE Enterprise:                 {len(not_in_mitre)}"
    )
    print(
        f"  revoked in latest bundle (v19.0):        {len(revoked)}"
    )
    print(
        f"  with positive catalog lag (>0):          {len(positive_lag)}"
    )

    # ---------- tasa base (post-corpus-start) ----------
    n_post_total = sum(
        1
        for ext_id, m in mitre.items()
        if (m.get("first_release_date") or "") > corpus_start
    )
    n_post_corpus = len(post_start)
    n_post_positive = sum(
        1
        for r in post_start
        if has_positive_lag(r, "catalog_lag_nonrevoked_days")
    )
    n_post_robust = sum(
        1
        for r in post_start
        if has_positive_lag(r, "catalog_lag_nonrevoked_days")
        and r["accept_count"] >= 3
    )
    n_post_multisource = sum(
        1
        for r in post_start
        if has_positive_lag(r, "catalog_lag_nonrevoked_days")
        and r["n_sources"] >= 2
    )
    print("\n--- Base rate (techniques introduced AFTER corpus start) ---")
    print(f"  MITRE introduced post-{corpus_start} (any release):  {n_post_total}")
    print(
        f"  ... captured by corpus accept v2:            "
        f"{n_post_corpus} ({100 * n_post_corpus / n_post_total:.1f}% of total)"
    )
    print(
        f"  ... with positive catalog lag (>0):          "
        f"{n_post_positive} "
        f"({100 * n_post_positive / max(n_post_corpus, 1):.1f}% of captured)"
    )
    print(
        f"  ... robust subset (lag>0, accept_count>=3):  {n_post_robust}"
    )
    print(
        f"  ... multisource subset (lag>0, n_sources>=2):{n_post_multisource}"
    )

    lags = [
        int(r["catalog_lag_nonrevoked_days"])
        for r in rows
        if r["catalog_lag_nonrevoked_days"] != ""
    ]
    if lags:
        lags_sorted = sorted(lags)
        n = len(lags_sorted)

        def pct(p):
            return lags_sorted[min(n - 1, int(p * n))]

        print("\nRelease-based catalog lag distribution (days, all techniques):")
        print(f"  n        : {n}")
        print(f"  min      : {lags_sorted[0]}")
        print(f"  p10      : {pct(0.10)}")
        print(f"  p50      : {pct(0.50)}")
        print(f"  p90      : {pct(0.90)}")
        print(f"  max      : {lags_sorted[-1]}")
        positives = [d for d in lags if d > 0]
        print(f"  positives: {len(positives)} ({100 * len(positives) / n:.1f}%)")
        if positives:
            ps = sorted(positives)
            print(
                f"  positive lag p50/p90/max: "
                f"{ps[len(ps) // 2]} / {ps[int(len(ps) * 0.9)]} / {ps[-1]} d"
            )

    print(
        "\nTop 20 techniques by positive catalog lag (release-based, non-revoked):"
    )
    print(
        f"  {'Tech':<11} {'Lag(d)':>7} {'FirstSeen':>11} {'1stRel':>11} "
        f"{'Ver':>5} {'Acc':>4} Name"
    )
    for r in positive_lag[:20]:
        print(
            f"  {r['technique_id']:<11} {r['catalog_lag_nonrevoked_days']:>7} "
            f"{r['first_seen_corpus']:>11} "
            f"{r['mitre_first_nonrevoked_date']:>11} "
            f"{r['mitre_first_nonrevoked_version']:>5} "
            f"{r['accept_count']:>4} {r['name'][:55]}"
        )

    print(
        f"\nRobust subset (lag > 0 AND accept_count >= 3): "
        f"{len(positive_lag_robust)} techniques"
    )
    print(
        f"  {'Tech':<11} {'Lag(d)':>7} {'FirstSeen':>11} {'MedSeen':>11} "
        f"{'1stRel':>11} {'Ver':>5} {'Acc':>4} {'Src':>3} Name"
    )
    for r in positive_lag_robust:
        print(
            f"  {r['technique_id']:<11} {r['catalog_lag_nonrevoked_days']:>7} "
            f"{r['first_seen_corpus']:>11} {r['median_seen_corpus']:>11} "
            f"{r['mitre_first_nonrevoked_date']:>11} "
            f"{r['mitre_first_nonrevoked_version']:>5} "
            f"{r['accept_count']:>4} {r['n_sources']:>3} {r['name'][:55]}"
        )

    print(
        f"\nMultisource subset (lag > 0 AND n_sources >= 2): "
        f"{len(positive_lag_multisource)} techniques"
    )
    print(
        f"  {'Tech':<11} {'Lag(d)':>7} {'MedLag(d)':>9} {'Acc':>4} {'Src':>3} Name"
    )
    for r in positive_lag_multisource:
        med = r["catalog_lag_nonrevoked_median_days"]
        print(
            f"  {r['technique_id']:<11} {r['catalog_lag_nonrevoked_days']:>7} "
            f"{med:>9} {r['accept_count']:>4} {r['n_sources']:>3} "
            f"{r['name'][:60]}"
        )

    print(
        f"\nSTRICT subset (min lag > 0 AND median lag > 0 AND "
        f"accept_count >= 3 AND n_sources >= 2): "
        f"{len(positive_lag_strict)} techniques"
    )
    print(
        f"  {'Tech':<11} {'Lag(d)':>7} {'MedLag(d)':>9} {'Acc':>4} {'Src':>3} Name"
    )
    for r in positive_lag_strict:
        med = r["catalog_lag_nonrevoked_median_days"]
        print(
            f"  {r['technique_id']:<11} {r['catalog_lag_nonrevoked_days']:>7} "
            f"{med:>9} {r['accept_count']:>4} {r['n_sources']:>3} "
            f"{r['name'][:60]}"
        )

    # ---------- test estadístico ----------
    # H0: entre las técnicas que MITRE introdujo después del inicio del
    # corpus y que además fueron capturadas por el corpus, éste es
    # agnóstico al timing de MITRE; P(catalog_lag > 0) = 0.5 (Bernoulli).
    # H1: P(catalog_lag > 0) > 0.5 (el corpus observa de forma sistemática
    # la fenomenología antes de que MITRE la catalogue).
    # Test: binomial exacto unilateral.
    if n_post_corpus > 0:
        p_value = binomial_pvalue(n_post_positive, n_post_corpus, 0.5)
        print(
            "\n--- Binomial test: H0 P(lag>0)=0.5 on post-corpus-start "
            "techniques ---"
        )
        print(
            f"  observed: {n_post_positive}/{n_post_corpus} positive "
            f"({100 * n_post_positive / n_post_corpus:.1f}%)"
        )
        print(f"  one-sided exact p-value (X >= k | Bin(n, 0.5)): {p_value:.4g}")
        if p_value < 0.001:
            verdict = "highly significant (p<0.001) reject H0"
        elif p_value < 0.01:
            verdict = "significant (p<0.01) reject H0"
        elif p_value < 0.05:
            verdict = "significant (p<0.05) reject H0"
        else:
            verdict = "NOT significant (p>=0.05) fail to reject H0"
        print(f"  verdict: {verdict}")

    print("\n=== Sanity check vs documented cases ===")
    for tid, label in [
        ("T1204.004", "ClickFix"),
        ("T1656", "Impersonation (revoked in v19)"),
        ("T1486", "Data Encrypted for Impact (pre-corpus)"),
    ]:
        r = next((x for x in rows if x["technique_id"] == tid), None)
        if r is None:
            print(f"  {tid}: not in corpus accept v2")
            continue
        print(f"  {tid} {label}")
        print(
            f"    first_seen_corpus  = {r['first_seen_corpus']} "
            f"({r['first_seen_source']}, art {r['first_seen_article_id']})"
        )
        print(
            f"    mitre_first        = v{r['mitre_first_nonrevoked_version']} "
            f"on {r['mitre_first_nonrevoked_date']}"
        )
        print(f"    mitre_stix_created = {r['mitre_stix_created']}")
        print(f"    catalog_lag_nr     = {r['catalog_lag_nonrevoked_days']} d")
        print(f"    catalog_lag_stix   = {r['catalog_lag_created_days']} d")
        print(
            f"    accept_count       = {r['accept_count']}, "
            f"revoked_now={r['mitre_latest_revoked']}"
        )

    print("\nDone.")


# --------------------------------- main -----------------------------------


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_DEFAULT)
    ap.add_argument("--csv-dir", default=CSV_DIR_DEFAULT)
    ap.add_argument("--bundle-dir", default=BUNDLE_DIR_DEFAULT)
    ap.add_argument(
        "--no-download",
        action="store_true",
        help="No descargar bundles que falten; usar sólo los cacheados.",
    )
    args = ap.parse_args()

    os.makedirs(args.csv_dir, exist_ok=True)

    print(f"BD: {args.db}")
    print(f"Bundle cache: {args.bundle_dir}")
    print(f"CSV out: {args.csv_dir}")

    print("\n[1/3] Construyendo índice de versiones de MITRE ATT&CK ...")
    mitre = build_mitre_index(args.bundle_dir, allow_download=not args.no_download)
    print(f"  indexed {len(mitre)} unique attack-pattern external_ids")

    print("\n[2/3] Cargando corpus accept v2 ...")
    corpus = load_corpus(args.db)
    print(
        f"  {len(corpus)} distinct technique_ids in corpus accept v2 "
        f"(crowdstrike_blog excluded)"
    )

    print("\n[3/3] Cruzando fuentes ...")

    # corpus_start: fecha de publicación más temprana de cualquier TTP
    # aceptado. Sirve para marcar is_post_corpus_start y calcular la tasa
    # base del análisis de retardo (las técnicas introducidas antes de esa
    # fecha no son candidatas por construcción).
    corpus_start = min((agg["first_seen"] for agg in corpus.values()), default="")
    print(f"  corpus_start = {corpus_start}")

    rows = cross(corpus, mitre, corpus_start)

    write_csv(os.path.join(args.csv_dir, "all_techniques.csv"), rows)

    positive_lag = [
        r
        for r in rows
        if has_positive_lag(r, "catalog_lag_nonrevoked_days")
    ]
    positive_lag.sort(key=lambda r: -int(r["catalog_lag_nonrevoked_days"]))
    write_csv(os.path.join(args.csv_dir, "catalog_lag.csv"), positive_lag)

    # Subconjunto robusto: lag positivo Y accept_count >= 3 para descartar
    # accepts aislados (un único artículo + un único TTP) que podrían ser
    # artefactos del juez v2.
    positive_lag_robust = [r for r in positive_lag if r["accept_count"] >= 3]
    write_csv(
        os.path.join(args.csv_dir, "catalog_lag_robust.csv"),
        positive_lag_robust,
    )

    # Subconjunto multi-fuente: lag positivo Y n_sources >= 2; un filtro
    # alternativo de robustez que exige que la técnica aparezca en
    # artículos de al menos 2 fuentes distintas (reduce el sesgo de
    # amplificación por un único vendor).
    positive_lag_multisource = [r for r in positive_lag if r["n_sources"] >= 2]
    write_csv(
        os.path.join(args.csv_dir, "catalog_lag_multisource.csv"),
        positive_lag_multisource,
    )

    # Subconjunto estricto: lag positivo tanto en el mínimo como en la
    # mediana, Y accept_count >= 3, Y n_sources >= 2. Sobrevive a todos
    # los filtros de robustez; son las únicas técnicas en las que el
    # grueso de las menciones del corpus (y no un outlier aislado) precede
    # a la catalogación en MITRE.
    positive_lag_strict = [
        r
        for r in positive_lag
        if r["catalog_lag_nonrevoked_median_days"] != ""
        and int(r["catalog_lag_nonrevoked_median_days"]) > 0
        and r["accept_count"] >= 3
        and r["n_sources"] >= 2
    ]
    write_csv(
        os.path.join(args.csv_dir, "catalog_lag_strict.csv"),
        positive_lag_strict,
    )

    not_in_mitre = [r for r in rows if r["in_mitre_enterprise"] == "0"]
    write_csv(os.path.join(args.csv_dir, "not_in_mitre.csv"), not_in_mitre)

    revoked = [r for r in rows if r["mitre_latest_revoked"] == "1"]
    write_csv(os.path.join(args.csv_dir, "revoked.csv"), revoked)

    # Subconjunto post-corpus-start: técnicas que MITRE introdujo después
    # del artículo más temprano del corpus. Son las candidatas reales al
    # análisis de retardo (las preexistentes no pueden tener lag positivo
    # por construcción).
    post_start = [r for r in rows if r["is_post_corpus_start"] == "1"]
    write_csv(
        os.path.join(args.csv_dir, "post_corpus_start.csv"),
        sorted(
            post_start,
            key=lambda r: (
                -(int(r["catalog_lag_nonrevoked_days"])
                  if r["catalog_lag_nonrevoked_days"] != "" else 0)
            ),
        ),
    )

    # ---------- resumen por consola ----------
    print_summary(
        corpus,
        rows,
        not_in_mitre,
        revoked,
        positive_lag,
        positive_lag_robust,
        positive_lag_multisource,
        positive_lag_strict,
        mitre,
        corpus_start,
        post_start,
    )


if __name__ == "__main__":
    main()
