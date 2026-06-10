#!/usr/bin/env python3
"""
explore_corpus.py Exploración del corpus de ransomware.
Uso: python3 pc/explore_corpus.py (la BD se resuelve relativa al repo)
"""

import os
import sqlite3
import json
import re
from collections import Counter

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ransomware_intel.db")

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

# Lista de familias conocidas. El orden importa: van primero las más largas o específicas.
FAMILIES = [
    "black basta", "black suit", "blacksuit", "blackcat", "black cat",
    "ransomhub", "ransomware hub", "lockbit", "lock bit",
    "scattered spider", "vice society", "avos locker", "avoslocker",
    "mount locker", "mountlocker", "ranzy locker",
    "conti", "ryuk", "revil", "sodinokibi", "alphv",
    "clop", "cl0p", "hive", "akira", "play", "royal", "medusa",
    "cuba", "noberus", "maze", "egregor", "darkside", "dark side",
    "blackmatter", "black matter", "ragnar", "ragnarlocker",
    "grief", "avaddon", "phobos", "dharma", "stop/djvu", "djvu",
    "wannacry", "wanna cry", "notpetya", "petya", "babuk",
    "karma", "lorenz", "pysa", "mespinoza", "makop", "snatch",
    "yanluowang", "onyx", "quantum", "rhysida", "hunters",
    "meow", "fog", "eldorado", "cactus", "dragonforce",
    "cicada", "helldown", "lynx", "interlock", "nitrogen",
    "bianlian", "bian lian", "trigona", "monti", "nokoyawa",
    "3am", "3 am", "werewolves", "knight", "idk",
]


def normalize_family(name: str) -> str:
    """Normaliza el nombre de una familia para agrupar sus variantes."""
    name = name.strip().lower()
    aliases = {
        "cl0p": "clop", "sodinokibi": "revil", "alphv": "blackcat",
        "black cat": "blackcat", "black suit": "blacksuit",
        "black basta": "blackbasta", "dark side": "darkside",
        "black matter": "blackmatter", "lock bit": "lockbit",
        "wanna cry": "wannacry", "bian lian": "bianlian",
        "stop/djvu": "djvu", "ranzy locker": "ranzy",
        "avos locker": "avoslocker", "mount locker": "mountlocker",
        "ransomware hub": "ransomhub", "ragnarlocker": "ragnar",
        "3 am": "3am",
    }
    return aliases.get(name, name).replace(" ", "")


def find_family(text: str):
    if not text:
        return None
    text_lower = text.lower()
    for family in FAMILIES:
        if family in text_lower:
            return normalize_family(family)
    return None


def extract_year(date_str: str) -> str:
    if not date_str:
        return "unknown"
    m = re.match(r"(\d{4})", date_str.strip())
    return m.group(1) if m else "unknown"


def hr(title: str, width: int = 64) -> None:
    print(f"\n{'---' * width}")
    print(f"  {title}")
    print(f"{'---' * width}")


def bar(label: str, count: int, total: int, width: int = 28) -> None:
    pct = count / total * 100 if total else 0
    filled = round(pct / 100 * width)
    b = "" * filled + "" * (width - filled)
    print(f"  {label:<32} {b} {count:>6,} ({pct:5.1f}%)")


# ---
con = sqlite3.connect(DB_PATH)
cur = con.cursor()

# Vista sin duplicados: una fila por artículo, la que tenga el mayor valid_ttp_count.
# Hace falta porque unos 120 artículos tienen filas duplicadas tras volver a procesarse
# durante la recuperación (sesiones 13-14). De esos, 9 tienen TTPs repartidos en dos
# filas, lo que infla el recuento en 40 TTPs. Nos quedamos siempre con la extracción
# de valor máximo.
con.execute("""
    CREATE TEMP VIEW extractions_dedup AS
    SELECT * FROM (
        SELECT *, ROW_NUMBER() OVER (
            PARTITION BY article_id ORDER BY valid_ttp_count DESC, id ASC
        ) AS _rn
        FROM extractions
    ) WHERE _rn = 1
""")
# Alias para que el resto del script use la vista sin renombrar nada.
EXTR = "extractions_dedup"

# ---
# 1. RESUMEN DEL CORPUS
# ---
hr("1. RESUMEN DEL CORPUS")

state_rows = cur.execute(
    "SELECT processing_state, COUNT(*) FROM articles GROUP BY processing_state ORDER BY 2 DESC"
).fetchall()
total_articles = sum(r[1] for r in state_rows)
print(f"\n  Total artículos en BD: {total_articles:,}")
for state, cnt in state_rows:
    bar(state or "(null)", cnt, total_articles)

total_extractions_raw = cur.execute("SELECT COUNT(*) FROM extractions").fetchone()[0]
total_extractions = cur.execute("SELECT COUNT(*) FROM extractions_dedup").fetchone()[0]
print(f"\n  Filas en extractions (sin filtrar): {total_extractions_raw:,}")
print(f"  Artículos únicos (sin duplicados):  {total_extractions:,}")

# ---
# 2. RECUENTO EXACTO DE TTPs
# ---
hr("2. RECUENTO EXACTO DE TTPs")

total_ttps = cur.execute(
    "SELECT COALESCE(SUM(valid_ttp_count), 0) FROM extractions_dedup"
).fetchone()[0]

arts_with_ttps = cur.execute(
    "SELECT COUNT(*) FROM extractions_dedup WHERE valid_ttp_count > 0"
).fetchone()[0]
arts_zero_ttps = cur.execute(
    "SELECT COUNT(*) FROM extractions_dedup WHERE valid_ttp_count = 0"
).fetchone()[0]

print(f"\n  --- TOTAL TTPs VÁLIDOS: {total_ttps:,} ---")
print(f"    Artículos con TTPs > 0:     {arts_with_ttps:>6,}  ({arts_with_ttps/total_extractions*100:.1f}%)")
print(f"    Artículos con 0 TTPs:       {arts_zero_ttps:>6,}  ({arts_zero_ttps/total_extractions*100:.1f}%)")
avg_all = total_ttps / total_extractions if total_extractions else 0
avg_pos = total_ttps / arts_with_ttps if arts_with_ttps else 0
print(f"    Media TTPs/artículo (todos): {avg_all:.2f}")
print(f"  --- Media TTPs/artículo (>0):   {avg_pos:.2f}")

# Reparto de TTPs por artículo
dist_rows = cur.execute(
    "SELECT valid_ttp_count, COUNT(*) FROM extractions_dedup WHERE valid_ttp_count > 0 GROUP BY 1 ORDER BY 1"
).fetchall()
buckets = {"1": 0, "2-3": 0, "4-6": 0, "7-10": 0, "11-15": 0, "16+": 0}
for cnt, freq in dist_rows:
    if cnt == 1:
        buckets["1"] += freq
    elif cnt <= 3:
        buckets["2-3"] += freq
    elif cnt <= 6:
        buckets["4-6"] += freq
    elif cnt <= 10:
        buckets["7-10"] += freq
    elif cnt <= 15:
        buckets["11-15"] += freq
    else:
        buckets["16+"] += freq

print(f"\n  Reparto de TTPs por artículo (base: {arts_with_ttps:,} artículos con >0):")
for bucket, freq in buckets.items():
    bar(f"  {bucket} TTP(s)", freq, arts_with_ttps)

max_ttps = cur.execute("SELECT MAX(valid_ttp_count) FROM extractions_dedup").fetchone()[0]
print(f"\n  Máximo TTPs en un artículo: {max_ttps}")

# ---
# 3. REPARTO POR TÁCTICA ATT&CK
# ---
hr("3. REPARTO POR TÁCTICA ATT&CK")
print("  (solo se cuentan TTPs sin errores bloqueantes, es decir _issues vacío)\n")

tactic_ttp_count = Counter()   # TTPs totales por táctica
tactic_art_count = Counter()   # artículos en los que aparece cada táctica

for (ttps_json,) in cur.execute(
    "SELECT ttps FROM extractions_dedup WHERE valid_ttp_count > 0"
):
    try:
        ttps = json.loads(ttps_json) if ttps_json else []
    except (json.JSONDecodeError, TypeError):
        continue

    article_tactics = set()
    for ttp in ttps:
        if ttp.get("_issues"):  # Si el TTP tiene un error bloqueante, lo saltamos.
            continue
        tactic_id = ttp.get("tactic_id", "unknown")
        tactic_ttp_count[tactic_id] += 1
        article_tactics.add(tactic_id)

    for tactic_id in article_tactics:
        tactic_art_count[tactic_id] += 1

total_valid_ttps = sum(tactic_ttp_count.values())
print(f"  TTPs válidos leídos del JSON: {total_valid_ttps:,}")
print(f"  (frente a la suma de valid_ttp_count: {total_ttps:,})\n")

print(f"  {'Táctica':<40} {'TTPs':>6}  {'Arts':>6}  {'TTPs%':>6}")
print(f"  {'---'*40} {'---'*6}  {'---'*6}  {'---'*6}")
for tactic_id, cnt in sorted(tactic_ttp_count.items(), key=lambda x: -x[1]):
    name = TACTIC_NAMES.get(tactic_id, tactic_id)
    label = f"{tactic_id} {name}"
    arts = tactic_art_count[tactic_id]
    pct = cnt / total_valid_ttps * 100 if total_valid_ttps else 0
    print(f"  {label:<40} {cnt:>6,}  {arts:>6,}  {pct:>5.1f}%")

# ---
# 4. TOP 25 TÉCNICAS ATT&CK
# ---
hr("4. TOP 25 TÉCNICAS ATT&CK")

tech_counter = Counter()
for (ttps_json,) in cur.execute(
    "SELECT ttps FROM extractions_dedup WHERE valid_ttp_count > 0"
):
    try:
        ttps = json.loads(ttps_json) if ttps_json else []
    except (json.JSONDecodeError, TypeError):
        continue
    for ttp in ttps:
        if ttp.get("_issues"):
            continue
        tid = ttp.get("subtechnique_id") or ttp.get("technique_id")
        if tid:
            tech_counter[tid] += 1

total_tech = sum(tech_counter.values())
print(f"\n  {'ID':<15} {'Count':>7}  {'%':>6}")
print(f"  {'---'*15} {'---'*7}  {'---'*6}")
for tid, cnt in tech_counter.most_common(25):
    pct = cnt / total_tech * 100
    print(f"  {tid:<15} {cnt:>7,}  {pct:>5.1f}%")

# ---
# 5. REPARTO POR FUENTE
# ---
hr("5. REPARTO POR FUENTE")

source_rows = cur.execute("""
    SELECT
        a.source,
        COUNT(DISTINCT e.article_id)               AS arts_extracted,
        SUM(CASE WHEN e.valid_ttp_count > 0 THEN 1 ELSE 0 END) AS arts_with_ttps,
        COALESCE(SUM(e.valid_ttp_count), 0)        AS total_ttps
    FROM extractions_dedup e
    JOIN articles a ON e.article_id = a.id
    GROUP BY a.source
    ORDER BY total_ttps DESC
""").fetchall()

total_src_arts = sum(r[1] for r in source_rows)
total_src_ttps = sum(r[3] for r in source_rows)

print(f"\n  {'Fuente':<32} {'Extr.':>6} {'Con TTPs':>9} {'TTPs':>7} {'TTPs/art':>9}")
print(f"  {'---'*32} {'---'*6} {'---'*9} {'---'*7} {'---'*9}")
for src, arts_ext, arts_pos, ttps in source_rows:
    avg = ttps / arts_pos if arts_pos else 0
    pct_pos = arts_pos / arts_ext * 100 if arts_ext else 0
    print(f"  {str(src):<32} {arts_ext:>6,} {arts_pos:>8,} {ttps:>7,} {avg:>9.2f}")
print(f"  {'---'*32} {'---'*6} {'---'*9} {'---'*7} {'---'*9}")
print(f"  {'TOTAL':<32} {total_src_arts:>6,} {'':>9} {total_src_ttps:>7,}")

# ---
# 6. EVOLUCIÓN EN EL TIEMPO (por año)
# ---
hr("6. EVOLUCIÓN EN EL TIEMPO")

year_rows = cur.execute("""
    SELECT a.published_utc, e.valid_ttp_count
    FROM extractions_dedup e
    JOIN articles a ON e.article_id = a.id
""").fetchall()

year_arts = Counter()
year_ttps = Counter()
year_arts_pos = Counter()
for date_str, ttp_cnt in year_rows:
    y = extract_year(date_str)
    year_arts[y] += 1
    year_ttps[y] += ttp_cnt or 0
    if ttp_cnt and ttp_cnt > 0:
        year_arts_pos[y] += 1

all_years = sorted(y for y in year_arts if y != "unknown" and y >= "2018")

print(f"\n  {'Año':<8} {'Extr.':>7} {'Con TTPs':>9} {'TTPs':>7} {'Avg TTPs':>9}")
print(f"  {'---'*8} {'---'*7} {'---'*9} {'---'*7} {'---'*9}")
for y in all_years:
    arts = year_arts[y]
    pos = year_arts_pos[y]
    ttps = year_ttps[y]
    avg = ttps / pos if pos else 0
    print(f"  {y:<8} {arts:>7,} {pos:>9,} {ttps:>7,} {avg:>9.2f}")
if "unknown" in year_arts:
    y = "unknown"
    arts = year_arts[y]
    pos = year_arts_pos[y]
    ttps = year_ttps[y]
    avg = ttps / pos if pos else 0
    print(f"  {'unknown':<8} {arts:>7,} {pos:>9,} {ttps:>7,} {avg:>9.2f}")

# ---
# 7. FAMILIAS DE RANSOMWARE
# ---
hr("7. FAMILIAS DE RANSOMWARE (a partir del título del artículo)")
print(
    "  LIMITACIÓN: la familia de ransomware no se guardó en la BD.\n"
    "     Sacarla del título es una aproximación y deja fuera muchos casos.\n"
)

family_rows = cur.execute("""
    SELECT a.title, e.valid_ttp_count
    FROM extractions_dedup e
    JOIN articles a ON e.article_id = a.id
    WHERE e.valid_ttp_count > 0
""").fetchall()

family_arts = Counter()
family_ttps = Counter()
unidentified = 0
for title, ttp_cnt in family_rows:
    fam = find_family(title)
    if fam:
        family_arts[fam] += 1
        family_ttps[fam] += ttp_cnt or 0
    else:
        unidentified += 1

identified = sum(family_arts.values())
print(f"  Artículos con familia identificada: {identified:,} / {arts_with_ttps:,} ({identified/arts_with_ttps*100:.1f}%)")
print(f"  Artículos sin familia identificada: {unidentified:,} ({unidentified/arts_with_ttps*100:.1f}%)\n")

print(f"  {'Familia':<22} {'Arts':>6} {'TTPs':>7} {'TTPs/art':>9}")
print(f"  {'---'*22} {'---'*6} {'---'*7} {'---'*9}")
for fam, arts in family_arts.most_common(25):
    ttps = family_ttps[fam]
    avg = ttps / arts
    print(f"  {fam:<22} {arts:>6,} {ttps:>7,} {avg:>9.2f}")

# ---
# 8. REPARTO POR CONFIANZA
# ---
hr("8. REPARTO POR CONFIANZA (TTPs válidos)")

conf_counter = Counter()
for (ttps_json,) in cur.execute(
    "SELECT ttps FROM extractions_dedup WHERE valid_ttp_count > 0"
):
    try:
        ttps = json.loads(ttps_json) if ttps_json else []
    except (json.JSONDecodeError, TypeError):
        continue
    for ttp in ttps:
        if ttp.get("_issues"):
            continue
        conf = ttp.get("confidence")
        if conf is not None:
            conf_counter[str(conf)] += 1

total_conf = sum(conf_counter.values())
print(f"\n  {'Confianza':<12} {'TTPs':>7}  {'%':>6}")
print(f"  {'---'*12} {'---'*7}  {'---'*6}")
for conf in ["1.0", "0.75", "0.5", "0.25", "1", "0.7", "0.5", "other"]:
    pass  # se reconstruye más abajo

for conf_val, cnt in sorted(conf_counter.items(), key=lambda x: -float(x[0]) if x[0].replace('.','',1).isdigit() else 0):
    pct = cnt / total_conf * 100 if total_conf else 0
    print(f"  {conf_val:<12} {cnt:>7,}  {pct:>5.1f}%")

con.close()
print(f"\n{'---' * 64}")
print("  FIN DE LA EXPLORACIÓN")
print(f"{'---' * 64}\n")
