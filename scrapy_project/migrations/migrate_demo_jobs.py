#!/usr/bin/env python3
"""
migrate_demo_jobs.py: crea las tablas demo_jobs y demo_events que usa la
página /pipeline.

demo_jobs: cola de jobs que la UI envía al PC remoto (una fila por demo).
demo_events: stream de eventos (start/end/error de cada etapa) que el PC
manda mientras ejecuta el pipeline.

El PC recoge los jobs en estado 'queued' desde el endpoint
POST /api/demo/heartbeat (el mismo patrón que usa run_extraction.py).

Uso:
  docker cp scrapy_project/migrations/migrate_demo_jobs.py scraper:/app/scrapy_project/migrations/
  docker exec scraper python3 /app/scrapy_project/migrations/migrate_demo_jobs.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "ransomware_intel.db"


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    existing = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('demo_jobs','demo_events')"
        ).fetchall()
    }

    if "demo_jobs" in existing:
        print("Tabla demo_jobs ya existe.")
    else:
        conn.execute(
            """
            CREATE TABLE demo_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK(status IN ('queued','running','completed','filtered','failed','aborted')),
                input_type TEXT NOT NULL CHECK(input_type IN ('corpus','paste')),
                article_id INTEGER,
                title TEXT,
                body TEXT,
                published_utc TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                started_at TEXT,
                finished_at TEXT
            )
            """
        )
        conn.execute("CREATE INDEX idx_demo_jobs_status ON demo_jobs(status)")
        print("Tabla demo_jobs creada.")

    if "demo_events" in existing:
        print("Tabla demo_events ya existe.")
    else:
        conn.execute(
            """
            CREATE TABLE demo_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL REFERENCES demo_jobs(id),
                stage TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                ts TEXT NOT NULL,
                received_at TEXT DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute("CREATE INDEX idx_demo_events_job ON demo_events(job_id)")
        print("Tabla demo_events creada.")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    run()
