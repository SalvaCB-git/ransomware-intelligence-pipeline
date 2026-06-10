#!/usr/bin/env python3
"""
migrate_judge_v2_mode.py: añade la columna source_mode a ttp_verdicts_v2.

Clasifica los registros que ya estaban en la tabla:
  'rejudge'       TTPs que venían de mode_rejudge (conf=0.75, pasaron por ttp_verdicts v1).
  'rejudge_conf1' TTPs que venían de mode_rejudge_conf1 (conf=1.0, sin juez v1).

Regla: si (extraction_id, ttp_index) ya está en ttp_verdicts -> 'rejudge';
si no -> 'rejudge_conf1'.

Uso:
  docker cp scrapy_project/migrations/migrate_judge_v2_mode.py scraper:/app/scrapy_project/migrations/
  docker exec scraper python3 /app/scrapy_project/migrations/migrate_judge_v2_mode.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "ransomware_intel.db"


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    # --- Estado actual de la tabla ---
    cols = [r[1] for r in conn.execute("PRAGMA table_info(ttp_verdicts_v2)").fetchall()]
    total = conn.execute("SELECT COUNT(*) FROM ttp_verdicts_v2").fetchone()[0]
    print(f"Filas en ttp_verdicts_v2: {total}")
    print(f"Columnas actuales: {cols}")

    # --- Paso 1: añadir la columna si todavía no está ---
    if "source_mode" in cols:
        print("\nsource_mode ya existe: nos saltamos el ALTER TABLE")
    else:
        conn.execute("ALTER TABLE ttp_verdicts_v2 ADD COLUMN source_mode TEXT")
        conn.commit()
        print("\nColumna source_mode añadida.")

    # --- Paso 2: clasificar las filas que ya estaban ---
    null_before = conn.execute(
        "SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE source_mode IS NULL"
    ).fetchone()[0]
    print(f"Filas sin source_mode antes de clasificar: {null_before}")

    if null_before == 0:
        print("No hay nada que clasificar: todas las filas ya tienen source_mode.")
        _print_stats(conn)
        conn.close()
        return

    # Marca como 'rejudge' las que ya estaban en ttp_verdicts (pasaron por el juez v1).
    conn.execute("""
        UPDATE ttp_verdicts_v2
        SET source_mode = 'rejudge'
        WHERE source_mode IS NULL
          AND EXISTS (
              SELECT 1 FROM ttp_verdicts tv
               WHERE tv.extraction_id = ttp_verdicts_v2.extraction_id
                 AND tv.ttp_index     = ttp_verdicts_v2.ttp_index
          )
    """)
    rejudge_count = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]

    # Las que quedan son conf=1.0 (rejudge_conf1).
    conn.execute("""
        UPDATE ttp_verdicts_v2
        SET source_mode = 'rejudge_conf1'
        WHERE source_mode IS NULL
    """)
    conf1_count = conn.execute(
        "SELECT changes()"
    ).fetchone()[0]

    conn.commit()
    print(f"  'rejudge'       : {rejudge_count}")
    print(f"  'rejudge_conf1' : {conf1_count}")

    null_after = conn.execute(
        "SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE source_mode IS NULL"
    ).fetchone()[0]
    print(f"Filas sin source_mode tras clasificar: {null_after}")
    if null_after > 0:
        print("  Quedan filas sin clasificar: revisar a mano.")

    _print_stats(conn)
    conn.close()
    print("\nMigración completada.")


def _print_stats(conn):
    print("\n--- Reparto de source_mode ---")
    for row in conn.execute("""
        SELECT source_mode, verdict, COUNT(*) AS n
        FROM ttp_verdicts_v2
        GROUP BY source_mode, verdict
        ORDER BY source_mode, verdict
    """).fetchall():
        print(f"  {str(row[0]):<18} {row[1]:<10} {row[2]}")
    total = conn.execute("SELECT COUNT(*) FROM ttp_verdicts_v2").fetchone()[0]
    print(f"  {'TOTAL':<18} {'':10} {total}")


if __name__ == "__main__":
    run()
