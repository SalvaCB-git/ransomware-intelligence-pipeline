#!/usr/bin/env python3
"""
migrate_calibration.py: crea la tabla calibration_sample y la rellena con
una muestra estratificada (N=384 sacados de ttp_verdicts) más un grupo
de control (N=100 con conf=1.0).

Uso:
    docker exec scraper python3 /app/scrapy_project/migrate_calibration.py --dry-run
    docker exec scraper python3 /app/scrapy_project/migrate_calibration.py
"""

import sqlite3
import json
import random
import sys
from collections import defaultdict

DB_PATH = "/app/data/ransomware_intel.db"
MAIN_SAMPLE_SIZE = 384    # TTPs sacados de ttp_verdicts (conf=0.75)
CONTROL_SAMPLE_SIZE = 100  # TTPs sacados de extractions (conf=1.0, sin juzgar)
RANDOM_SEED = 42

DRY_RUN = "--dry-run" in sys.argv


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def create_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS calibration_sample (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_type TEXT CHECK(sample_type IN ('stratified','control')),
            ttp_verdict_id INTEGER,
            extraction_id INTEGER NOT NULL,
            article_id INTEGER NOT NULL,
            ttp_index INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            quote TEXT,
            llm_verdict TEXT,
            llm_reasoning TEXT,
            source TEXT,
            human_blind_verdict TEXT CHECK(human_blind_verdict IN ('accept','reject','uncertain')),
            human_reconciled_verdict TEXT,
            error_taxonomy_code TEXT,
            annotation_notes TEXT,
            annotated_at TEXT,
            session_id INTEGER DEFAULT 0
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_calib_annotated "
        "ON calibration_sample(human_blind_verdict)"
    )
    conn.commit()


def extract_quote(ttps_json, idx):
    try:
        ttps = json.loads(ttps_json or "[]")
        if idx < len(ttps):
            return ttps[idx].get("evidence_quote", "")
    except Exception:
        pass
    return ""


def build_stratified_sample(conn):
    """
    Coge N=384 TTPs de ttp_verdicts estratificando por (verdict x source).
    Reparto objetivo: accept 74,1% (285), reject 16,2% (62), uncertain 9,7% (37).
    """
    rows = conn.execute("""
        SELECT
            tv.id       AS verdict_id,
            tv.extraction_id,
            tv.article_id,
            tv.ttp_index,
            tv.technique_id,
            tv.verdict  AS llm_verdict,
            tv.reasoning AS llm_reasoning,
            a.source,
            e.ttps
        FROM ttp_verdicts tv
        JOIN extractions e ON tv.extraction_id = e.id
        JOIN articles   a ON tv.article_id    = a.id
    """).fetchall()

    print(f"Total en ttp_verdicts: {len(rows)}")

    verdict_targets = {
        "accept":    round(MAIN_SAMPLE_SIZE * 0.741),   # 285
        "reject":    round(MAIN_SAMPLE_SIZE * 0.162),   # 62
        "uncertain": MAIN_SAMPLE_SIZE
                     - round(MAIN_SAMPLE_SIZE * 0.741)
                     - round(MAIN_SAMPLE_SIZE * 0.162), # 37
    }
    print(f"Targets: {verdict_targets}")

    random.seed(RANDOM_SEED)
    selected = []

    for verdict, target_n in verdict_targets.items():
        verdict_pool = [r for r in rows if r["llm_verdict"] == verdict]
        total = len(verdict_pool)
        print(f"\n  verdict='{verdict}': pool={total}, target={target_n}")

        if total == 0:
            print(f"  Sin registros para '{verdict}' saltando")
            continue

        # Reparto por fuente dentro del veredicto.
        source_counts = defaultdict(int)
        for r in verdict_pool:
            source_counts[r["source"]] += 1

        stratum = []
        remaining = target_n

        for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            source_pool = [r for r in verdict_pool if r["source"] == source]
            n = round(target_n * count / total)
            n = min(n, len(source_pool), remaining)
            if n > 0:
                sampled = random.sample(source_pool, n)
                stratum.extend(sampled)
                remaining -= n
                print(f"    {source}: {n}/{count}")

        # Si queda hueco por los redondeos, lo rellena con extras al azar.
        if remaining > 0:
            used_ids = {r["verdict_id"] for r in stratum}
            pool_left = [r for r in verdict_pool if r["verdict_id"] not in used_ids]
            extra = random.sample(pool_left, min(remaining, len(pool_left)))
            stratum.extend(extra)
            if extra:
                print(f"    (+{len(extra)} extra para cubrir redondeo)")

        selected.extend(stratum)

    print(f"\nTotal muestra estratificada: {len(selected)}")
    return selected


def build_control_sample(conn):
    """
    Coge N=100 TTPs con confidence=1.0 de la tabla extractions
    que todavía no aparezcan en ttp_verdicts.
    """
    judged = set(
        (r[0], r[1])
        for r in conn.execute("SELECT extraction_id, ttp_index FROM ttp_verdicts")
    )

    rows = conn.execute("""
        SELECT e.id AS extraction_id, e.article_id, e.ttps, a.source
        FROM extractions e
        JOIN articles a ON e.article_id = a.id
        WHERE e.ttps IS NOT NULL AND e.ttps != '[]'
    """).fetchall()

    candidates = []
    for row in rows:
        try:
            ttps = json.loads(row["ttps"] or "[]")
        except Exception:
            continue
        for idx, ttp in enumerate(ttps):
            if ttp.get("confidence") == 1.0 and (row["extraction_id"], idx) not in judged:
                candidates.append({
                    "extraction_id": row["extraction_id"],
                    "article_id":    row["article_id"],
                    "ttp_index":     idx,
                    "technique_id":  ttp.get("technique_id", ""),
                    "quote":         ttp.get("evidence_quote", ""),
                    "source":        row["source"],
                })

    random.seed(RANDOM_SEED + 1)
    n = min(CONTROL_SAMPLE_SIZE, len(candidates))
    selected = random.sample(candidates, n)
    print(f"\nMuestra control (conf=1.0): {n}/{len(candidates)} candidatos")
    return selected


def insert_samples(conn, stratified, control):
    conn.execute("BEGIN")

    for row in stratified:
        quote = extract_quote(row["ttps"], row["ttp_index"])
        conn.execute("""
            INSERT INTO calibration_sample
                (sample_type, ttp_verdict_id, extraction_id, article_id,
                 ttp_index, technique_id, quote, llm_verdict, llm_reasoning, source)
            VALUES ('stratified', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["verdict_id"], row["extraction_id"], row["article_id"],
            row["ttp_index"], row["technique_id"], quote,
            row["llm_verdict"], row["llm_reasoning"], row["source"],
        ))

    for item in control:
        conn.execute("""
            INSERT INTO calibration_sample
                (sample_type, ttp_verdict_id, extraction_id, article_id,
                 ttp_index, technique_id, quote, llm_verdict, llm_reasoning, source)
            VALUES ('control', NULL, ?, ?, ?, ?, ?, NULL, NULL, ?)
        """, (
            item["extraction_id"], item["article_id"], item["ttp_index"],
            item["technique_id"], item["quote"], item["source"],
        ))

    conn.execute("COMMIT")
    return len(stratified) + len(control)


def print_distribution(conn):
    print("\n" + "=" * 60)
    print("DISTRIBUCIÓN calibration_sample:")
    print("=" * 60)
    for row in conn.execute("""
        SELECT sample_type, llm_verdict, COUNT(*) AS n
        FROM calibration_sample
        GROUP BY 1, 2 ORDER BY 1, 2
    """):
        print(f"  {row[0]:12s} | {str(row[1]):10s} | {row[2]}")
    total = conn.execute("SELECT COUNT(*) FROM calibration_sample").fetchone()[0]
    print(f"\n  TOTAL: {total}")

    print("\nDistribución estratificada por fuente:")
    for row in conn.execute("""
        SELECT source, llm_verdict, COUNT(*) AS n
        FROM calibration_sample
        WHERE sample_type = 'stratified'
        GROUP BY 1, 2 ORDER BY 1, 2
    """):
        print(f"  {row[0]:30s} | {str(row[1]):10s} | {row[2]}")


def main():
    print(f"{'[DRY Run] ' if DRY_RUN else ''}migrate_calibration.py")
    print(f"DB: {DB_PATH}")
    print(f"Target: {MAIN_SAMPLE_SIZE} estratificados + {CONTROL_SAMPLE_SIZE} control\n")

    conn = get_db()
    create_table(conn)

    # Si ya hay datos, pregunta antes de borrarlos.
    existing = conn.execute("SELECT COUNT(*) FROM calibration_sample").fetchone()[0]
    if existing > 0 and not DRY_RUN:
        print(f"calibration_sample ya tiene {existing} filas.")
        resp = input("¿Limpiar y regenerar? [y/N]: ").strip().lower()
        if resp != "y":
            print("Abortado.")
            conn.close()
            return
        conn.execute("DELETE FROM calibration_sample")
        conn.commit()
        print("Tabla limpiada.\n")

    stratified = build_stratified_sample(conn)
    control = build_control_sample(conn)

    if DRY_RUN:
        print("\n[DRY RUN] No se escribe nada.")
        print(f"  Estratificados: {len(stratified)}")
        print(f"  Control: {len(control)}")
        conn.close()
        return

    total = insert_samples(conn, stratified, control)
    print(f"\n{total} registros insertados en calibration_sample")
    print_distribution(conn)
    conn.close()
    print("\nListo. Ahora despliega app.py con los nuevos endpoints.")


if __name__ == "__main__":
    main()
