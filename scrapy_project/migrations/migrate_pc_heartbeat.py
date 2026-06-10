#!/usr/bin/env python3
"""
migrate_pc_heartbeat.py: crea la tabla pc_heartbeat para la UI de la demo.

La tabla guarda el último heartbeat del PC con GPU (el worker remoto del
extractor RAG) y así la UI puede mostrar si está online u offline.

Schema pensado para una única fila (id=1, se actualiza con UPSERT):
  id INTEGER PRIMARY KEY
  hostname TEXT
  last_seen_utc TEXT  (ISO 8601)
  client_version TEXT
  meta_json TEXT      (JSON con gpu, ollama_status, etc.)

Uso:
  docker cp scrapy_project/migrations/migrate_pc_heartbeat.py scraper:/app/scrapy_project/migrations/
  docker exec scraper python3 /app/scrapy_project/migrations/migrate_pc_heartbeat.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "ransomware_intel.db"


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cols = conn.execute("PRAGMA table_info(pc_heartbeat)").fetchall()
    if cols:
        print(f"Tabla pc_heartbeat ya existe ({len(cols)} columnas). Sin cambios.")
        conn.close()
        return

    conn.execute(
        """
        CREATE TABLE pc_heartbeat (
            id INTEGER PRIMARY KEY,
            hostname TEXT,
            last_seen_utc TEXT NOT NULL,
            client_version TEXT,
            meta_json TEXT
        )
        """
    )
    conn.commit()
    print("Tabla pc_heartbeat creada.")
    conn.close()


if __name__ == "__main__":
    run()
