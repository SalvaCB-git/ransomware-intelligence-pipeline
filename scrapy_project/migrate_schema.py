"""
migrate_schema.py: migración del schema SQLite para el pipeline de extracción
de TTPs.

Sobre la tabla 'articles' añade:
  - processing_state TEXT DEFAULT 'pending'
  - processing_lock_time TEXT

Y crea la tabla 'extractions' junto con sus índices.

Es idempotente: se puede lanzar varias veces sin que falle.

Uso:
  python /app/scrapy_project/migrate_schema.py
"""

import sqlite3
import sys

DB_PATH = "/app/data/ransomware_intel.db"


def get_columns(conn, table):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cur.fetchall()}


def main():
    print(f"Conectando a {DB_PATH} ...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # --- 1. ALTER TABLE articles ---
    existing_cols = get_columns(conn, "articles")

    if "processing_state" not in existing_cols:
        conn.execute(
            "ALTER TABLE articles ADD COLUMN processing_state TEXT DEFAULT 'pending'"
        )
        conn.commit()
        print("Columna processing_state añadida a articles")
    else:
        print("· processing_state ya existía: nos saltamos el ALTER TABLE")

    if "processing_lock_time" not in existing_cols:
        conn.execute(
            "ALTER TABLE articles ADD COLUMN processing_lock_time TEXT"
        )
        conn.commit()
        print("Columna processing_lock_time añadida a articles")
    else:
        print("· processing_lock_time ya existía: nos saltamos el ALTER TABLE")

    # --- 2. CREATE TABLE extractions ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS extractions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id          INTEGER NOT NULL REFERENCES articles(id),
            model               TEXT NOT NULL,
            ttps                TEXT NOT NULL,
            reasoning           TEXT,
            valid_ttp_count     INTEGER,
            validation_issues   TEXT,
            prefilter_reason    TEXT,
            max_similarity_score REAL,
            elapsed_seconds     REAL,
            created_at          TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    print("Tabla extractions creada (o ya existía)")

    # --- 3. CREATE INDEX ---
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_extractions_article_id ON extractions(article_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_articles_processing_state ON articles(processing_state)"
    )
    conn.commit()
    print("Índices creados (o ya existían)")

    # --- 4. Conteos finales ---
    total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    pending = conn.execute(
        "SELECT COUNT(*) FROM articles WHERE processing_state = 'pending'"
    ).fetchone()[0]

    print()
    print("=== Migración completada ===")
    print(f"  Total artículos:            {total}")
    print(f"  Con processing_state=pending: {pending}")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
