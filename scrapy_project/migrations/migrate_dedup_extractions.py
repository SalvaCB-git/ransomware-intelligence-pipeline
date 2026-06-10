#!/usr/bin/env python3
"""
migrate_dedup_extractions.py: borra extractions duplicadas (mismo artículo
con varias filas en la tabla).

Para elegir la fila que se conserva se ordena por: MAX(v2_accept),
MAX(valid_ttp_count), MAX(id).
Limpia en cascada los ttp_verdicts y ttp_verdicts_v2 que apuntaban a las
filas eliminadas.
"""
import sqlite3, sys

DB = "/app/data/ransomware_intel.db"
DRY_RUN = "--dry-run" in sys.argv

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA journal_mode=WAL")

# --- 1. Estado inicial de la BD ---
total_before   = conn.execute("SELECT COUNT(*) FROM extractions").fetchone()[0]
accepts_before = conn.execute("SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE verdict='accept'").fetchone()[0]
dup_articles   = conn.execute(
    "SELECT article_id FROM extractions GROUP BY article_id HAVING COUNT(*) > 1"
).fetchall()
dup_ids = [r["article_id"] for r in dup_articles]
print(f"Filas en extractions:           {total_before}")
print(f"Accepts en ttp_verdicts_v2:     {accepts_before}")
print(f"Artículos con duplicados:       {len(dup_ids)}")
print(f"Modo: {'DRY-RUN' if DRY_RUN else 'ESCRITURA REAL'}\n")

# --- 2. Decidir la extracción que se queda por cada artículo ---
# Criterio: MAX(v2_accept), MAX(valid_ttp_count), MAX(id).
rows = conn.execute(f"""
    SELECT e.id, e.article_id, e.valid_ttp_count,
           COUNT(v2.id)                                          AS v2_total,
           SUM(CASE WHEN v2.verdict='accept' THEN 1 ELSE 0 END) AS v2_accept
    FROM extractions e
    LEFT JOIN ttp_verdicts_v2 v2 ON v2.extraction_id = e.id
    WHERE e.article_id IN ({','.join('?'*len(dup_ids))})
    GROUP BY e.id
    ORDER BY e.article_id, e.id
""", dup_ids).fetchall()  # nosec B608 -- placeholders generados; ids por parámetros

from collections import defaultdict
by_article = defaultdict(list)
for r in rows:
    by_article[r["article_id"]].append(dict(r))

canonical_ids = []
to_delete_ids = []

for art_id, filas in by_article.items():
    # Ordena por: más v2_accept, más valid_ttp_count, mayor id.
    best = sorted(filas,
                  key=lambda f: (f["v2_accept"] or 0, f["valid_ttp_count"] or 0, f["id"]),
                  reverse=True)[0]
    canonical_ids.append(best["id"])
    for f in filas:
        if f["id"] != best["id"]:
            to_delete_ids.append(f["id"])

print(f"Extractions a conservar (canónicas): {len(canonical_ids)}")
print(f"Extractions a borrar:                {len(to_delete_ids)}")

# --- 3. Cuánto afecta esto a los veredictos ---
v1_orphans = conn.execute(
    f"SELECT COUNT(*) FROM ttp_verdicts WHERE extraction_id IN ({','.join('?'*len(to_delete_ids))})",  # nosec B608 -- placeholders generados; ids por parámetros
    to_delete_ids
).fetchone()[0]
v2_orphans = conn.execute(
    f"SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE extraction_id IN ({','.join('?'*len(to_delete_ids))})",  # nosec B608 -- placeholders generados; ids por parámetros
    to_delete_ids
).fetchone()[0]
v2_accept_loss = conn.execute(
    f"SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE extraction_id IN ({','.join('?'*len(to_delete_ids))}) AND verdict='accept'",  # nosec B608 -- placeholders generados; ids por parámetros
    to_delete_ids
).fetchone()[0]

print(f"\nVeredictos v1 huérfanos a eliminar:  {v1_orphans}")
print(f"Veredictos v2 huérfanos a eliminar:  {v2_orphans}")
print(f"  de los cuales accept:              {v2_accept_loss}")
print(f"\nAccepts tras limpieza (estimado):    {accepts_before - v2_accept_loss}")

if DRY_RUN:
    print("\n[dry-run] Sin cambios.")
    conn.close()
    sys.exit(0)

# --- 4. Ejecutar el borrado ---
print("\nEjecutando...")
placeholders = ','.join('?' * len(to_delete_ids))

conn.execute("BEGIN EXCLUSIVE")
conn.execute(f"DELETE FROM ttp_verdicts    WHERE extraction_id IN ({placeholders})", to_delete_ids)  # nosec B608 -- placeholders generados; ids por parámetros
conn.execute(f"DELETE FROM ttp_verdicts_v2 WHERE extraction_id IN ({placeholders})", to_delete_ids)  # nosec B608 -- placeholders generados; ids por parámetros
conn.execute(f"DELETE FROM extractions      WHERE id            IN ({placeholders})", to_delete_ids)  # nosec B608 -- placeholders generados; ids por parámetros
conn.commit()

# --- 5. Comprobación final ---
total_after   = conn.execute("SELECT COUNT(*) FROM extractions").fetchone()[0]
accepts_after = conn.execute("SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE verdict='accept'").fetchone()[0]
remaining_dups = conn.execute(
    "SELECT COUNT(*) FROM (SELECT article_id FROM extractions GROUP BY article_id HAVING COUNT(*) > 1)"
).fetchone()[0]

print("\n--- Resultado ---")
print(f"Filas extractions:  {total_before} {total_after}  (-{total_before - total_after})")
print(f"Accepts corpus:     {accepts_before} {accepts_after}  (-{accepts_before - accepts_after})")
print(f"Artículos con dups: {len(dup_ids)} {remaining_dups}")
if remaining_dups == 0:
    print("No quedan duplicados: tabla limpia.")
conn.close()
print("\nMigración completada.")
