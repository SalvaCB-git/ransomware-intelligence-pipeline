"""
migrate_judge.py: crea la tabla ttp_verdicts que usa el pipeline LLM-as-a-Judge.

Es idempotente: se puede lanzar varias veces sin riesgo.
Uso: python /app/scrapy_project/migrate_judge.py
"""

import sqlite3
import sys

DB_PATH = "/app/data/ransomware_intel.db"


def main():
    print(f"Conectando a {DB_PATH} ...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # --- 1. CREATE TABLE ttp_verdicts ---
    # Usamos UNIQUE(extraction_id, ttp_index) y NO (extraction_id, technique_id):
    # un mismo technique_id puede aparecer varias veces dentro del array JSON
    # de un extraction (lo hemos visto en el corpus real).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ttp_verdicts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            extraction_id INTEGER NOT NULL REFERENCES extractions(id),
            article_id    INTEGER NOT NULL REFERENCES articles(id),
            ttp_index     INTEGER NOT NULL,
            technique_id  TEXT NOT NULL,
            verdict       TEXT NOT NULL CHECK(verdict IN ('accept', 'reject', 'uncertain')),
            reasoning     TEXT,
            model         TEXT NOT NULL,
            judged_at     TEXT DEFAULT (datetime('now')),
            UNIQUE(extraction_id, ttp_index)
        )
    """)
    conn.commit()
    print("Tabla ttp_verdicts creada (o ya existía)")

    # --- 2. CREATE INDEX ---
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ttp_verdicts_extraction_id"
        " ON ttp_verdicts(extraction_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ttp_verdicts_verdict"
        " ON ttp_verdicts(verdict)"
    )
    conn.commit()
    print("Índices creados (o ya existían)")

    # --- 3. Conteos finales ---
    total_075 = conn.execute("""
        SELECT COUNT(*)
          FROM extractions e, json_each(e.ttps) t
         WHERE json_extract(t.value, '$.confidence') = 0.75
    """).fetchone()[0]

    already_judged = conn.execute("SELECT COUNT(*) FROM ttp_verdicts").fetchone()[0]

    print()
    print("=== Migración completada ===")
    print(f"  TTPs con confidence=0.75 (por juzgar): {total_075}")
    print(f"  Ya juzgados en ttp_verdicts:           {already_judged}")
    print(f"  Pendientes:                            {total_075 - already_judged}")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
