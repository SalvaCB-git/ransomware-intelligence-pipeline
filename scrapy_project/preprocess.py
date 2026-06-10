#!/usr/bin/env python3
"""
preprocess.py Módulo de preprocesamiento e ingesta SQLite
============================================================
Convierte los CSVs de /app/outputs en una base de datos SQLite normalizada
en /app/data/ransomware_intel.db.

USO:
    python preprocess.py [--dry-run] [--db /ruta/custom.db]

OPCIONES:
    --dry-run   Muestra estadísticas sin escribir en la base de datos.
    --db PATH   Ruta al fichero SQLite (defecto: /app/data/ransomware_intel.db).

ESQUEMAS CSV SOPORTADOS:
    Grupo A: source, published_utc, headline, url, body
             (bc_site, cisco_talos, dfir_report, crowdstrike_blog,
              microsoft_security, talos_blog, cisa, kaspersky_securelist,
              sophos_news, elastic_security, huntress)
    Grupo B: source, url, title, date, body
             (unit42, welivesecurity, trendmicro_research, red_canary,
              sentinelone_blog)
"""

import argparse
import csv
import hashlib
import logging
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Sube el límite de tamaño de campo del CSV para aceptar bodies muy largos.
csv.field_size_limit(sys.maxsize)

try:
    from dateutil import parser as dateutil_parser
    HAS_DATEUTIL = True
except ImportError:
    HAS_DATEUTIL = False

# --- Configuración ---
OUTPUTS_DIR = Path(os.environ.get("OUTPUTS_DIR", "/app/outputs"))
DEFAULT_DB   = Path(os.environ.get("DB_PATH",     "/app/data/ransomware_intel.db"))

# CSVs que se ignoran siempre (pruebas o temporales).
IGNORE_FILES: set[str] = {"test_sentinelone.csv"}

# Tabla de equivalencias para el campo 'source':
# pasa los valores distintos que llegan del scraping a un nombre único.
SOURCE_MAP: dict[str, str] = {
    "Cisco Talos Blog":        "cisco_talos",
    "cisco talos blog":        "cisco_talos",
    "talos":                   "cisco_talos",
    "Talos® Intelligence":    "cisco_talos",
    "sentinelone":             "sentinelone_blog",
    "SentinelOne Blog":        "sentinelone_blog",
    "crowdstrike":             "crowdstrike_blog",
    "CrowdStrike Blog":        "crowdstrike_blog",
    "elastic":                 "elastic_security",
    "Elastic Security Labs":   "elastic_security",
    "welivesecurity":          "welivesecurity",
    "WeLiveSecurity":          "welivesecurity",
    "trendmicro":              "trendmicro_research",
    "Trend Micro Research":    "trendmicro_research",
    "cisa":                    "cisa",
    "CISA":                    "cisa",
}

# Columnas que define el Grupo A.
SCHEMA_A_COLS = {"source", "published_utc", "headline", "url", "body"}
# Columnas que define el Grupo B.
SCHEMA_B_COLS = {"source", "url", "title", "date", "body"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# --- SimHash (dedup por contenido parecido) ---
def _simhash(text: str, bits: int = 64) -> int:
    """
    Calcula un SimHash de 64 bits sobre los trigramas del texto normalizado.
    Devuelve un entero con signo de 64 bits para que encaje en SQLite INTEGER.
    Si dos documentos tienen distancia de Hamming ≤ 3 se tratan como duplicados.
    """
    text = re.sub(r"\s+", " ", text.lower().strip())
    tokens = [text[i:i+3] for i in range(len(text) - 2)] or [text]
    v = [0] * bits
    for token in tokens:
        h = int(hashlib.md5(token.encode(), usedforsecurity=False).hexdigest(), 16)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    unsigned = sum(1 << i for i in range(bits) if v[i] > 0)
    # Pasa de uint64 a int64 con signo para que SQLite lo acepte.
    return unsigned if unsigned < (1 << 63) else unsigned - (1 << 64)


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# --- Normalización de fechas ---
# Cada directiva strptime consume un nº fijo de dígitos; el resto del patrón son
# caracteres literales. _expanded_len mide cuántos caracteres ocupa el patrón ya
# expandido, para recortar `raw` a esa longitud e ignorar sufijos sobrantes.
_FMT_DIRECTIVE_WIDTH = {"%Y": 4, "%m": 2, "%d": 2, "%H": 2, "%M": 2, "%S": 2}


def _expanded_len(fmt: str) -> int:
    expanded = fmt
    for directive, width in _FMT_DIRECTIVE_WIDTH.items():
        expanded = expanded.replace(directive, "0" * width)
    return len(expanded)


def normalize_date(raw: str) -> str | None:
    """
    Pasa cualquier formato de fecha a ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ).
    Devuelve None si el campo viene vacío o no se puede interpretar.
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    if HAS_DATEUTIL:
        try:
            dt = dateutil_parser.parse(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    # Plan B: probar formatos ISO 8601 a mano.
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw[:_expanded_len(fmt)], fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    log.warning("No se pudo parsear la fecha: %r", raw)
    return None


# --- Limpieza de texto ---
_HTML_TAG  = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s{3,}")

def clean_text(text: str) -> str:
    """
    Limpieza ligera del body:
    - Quita etiquetas HTML que hayan quedado sueltas.
    - Reduce secuencias de 3 o más espacios o saltos de línea.
    - Aplica un strip final.
    El body ya llega casi limpio desde readability-lxml; esto es una red
    de seguridad por si acaso.
    """
    if not text:
        return ""
    text = _HTML_TAG.sub(" ", text)
    text = _WHITESPACE.sub(" ", text)
    return text.strip()


# --- SQLite: schema ---
DDL = """
CREATE TABLE IF NOT EXISTS articles (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT    NOT NULL,
    url           TEXT    NOT NULL UNIQUE,   -- dedup principal por URL
    title         TEXT,
    published_utc TEXT,
    body          TEXT,
    body_hash     TEXT,                       -- SHA-256 del body ya limpio
    simhash       INTEGER,                    -- SimHash de 64 bits
    ingested_at   TEXT    NOT NULL            -- marca de tiempo de ingesta
);

CREATE INDEX IF NOT EXISTS ix_articles_source        ON articles(source);
CREATE INDEX IF NOT EXISTS ix_articles_published_utc ON articles(published_utc);
CREATE INDEX IF NOT EXISTS ix_articles_simhash       ON articles(simhash);
"""

INSERT_SQL = """
INSERT OR IGNORE INTO articles
    (source, url, title, published_utc, body, body_hash, simhash, ingested_at)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    conn.commit()


# --- Lectura de CSVs ---
def detect_schema(fieldnames: list[str]) -> str:
    """Devuelve 'A', 'B' o 'UNKNOWN'."""
    cols = set(f.strip().lower() for f in fieldnames)
    if "published_utc" in cols and "headline" in cols:
        return "A"
    if "date" in cols and "title" in cols:
        return "B"
    return "UNKNOWN"


def _normalize_source(raw: str, csv_stem: str) -> str:
    """
    Devuelve el nombre canónico de la fuente:
    1. Si está en SOURCE_MAP, usa ese.
    2. Si el campo viene vacío, deduce la fuente del nombre del CSV
       (por ejemplo, 'bc_site_ransomware_20260223_093926' -> 'bc_site').
    """
    val = raw.strip()
    if val in SOURCE_MAP:
        return SOURCE_MAP[val]
    if val:
        return val
    # Plan B: coger el prefijo del nombre del fichero hasta '_ransomware'.
    parts = csv_stem.split("_ransomware")
    return parts[0] if parts else csv_stem


def iter_csv_rows(csv_path: Path):
    """
    Lee un CSV (Grupo A o B) y va emitiendo dicts normalizados con la forma
    {source, url, title, published_utc, body}. Las filas inválidas se saltan.
    """
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return
        schema = detect_schema(reader.fieldnames)
        if schema == "UNKNOWN":
            log.warning("Esquema desconocido en %s: %s", csv_path.name, reader.fieldnames)
            return
        stem = csv_path.stem  # nombre del fichero sin extensión
        for row in reader:
            try:
                raw_source = (row.get("source") or "").strip()
                # Descarta cabeceras repetidas dentro del propio CSV (source="source").
                if raw_source.lower() == "source":
                    continue
                source = _normalize_source(raw_source, stem)
                if schema == "A":
                    yield {
                        "source":        source,
                        "url":           (row.get("url")    or "").strip(),
                        "title":         (row.get("headline") or "").strip(),
                        "published_utc": (row.get("published_utc") or "").strip(),
                        "body":          (row.get("body") or "").strip(),
                    }
                else:  # B
                    yield {
                        "source":        source,
                        "url":           (row.get("url")    or "").strip(),
                        "title":         (row.get("title")  or "").strip(),
                        "published_utc": (row.get("date")   or "").strip(),
                        "body":          (row.get("body") or "").strip(),
                    }
            except Exception as exc:
                log.debug("Fila mal formada en %s: %s", csv_path.name, exc)


# --- Dedup por SimHash ---
SIMHASH_THRESHOLD = 3  # distancia de Hamming máxima para tratar como duplicado

def is_near_duplicate(conn: sqlite3.Connection, simhash: int) -> bool:
    """
    Mira si en la BD ya hay un artículo con un SimHash parecido.
    Con menos de 100k artículos recorrer toda la tabla sale gratis.
    """
    rows = conn.execute("SELECT simhash FROM articles").fetchall()
    return any(_hamming(simhash, r[0]) <= SIMHASH_THRESHOLD for r in rows)


# --- Ingesta principal ---
def ingest(db_path: Path, dry_run: bool = False) -> dict:
    """
    Recorre todos los CSVs de OUTPUTS_DIR y los carga en SQLite.
    Devuelve un dict con estadísticas de la ejecución.
    """
    stats = {
        "csvs_found":     0,
        "csvs_empty":     0,
        "rows_read":      0,
        "rows_inserted":  0,
        "rows_dup_url":   0,
        "rows_dup_sim":   0,
        "rows_no_url":    0,
        "rows_no_body":   0,
    }

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = None
    if not dry_run:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        init_db(conn)

    csv_files = sorted(OUTPUTS_DIR.glob("*.csv"))
    stats["csvs_found"] = len(csv_files)

    for csv_path in csv_files:
        # Saltar los ficheros marcados como prueba.
        if csv_path.name in IGNORE_FILES:
            log.info("Ignorando fichero de prueba: %s", csv_path.name)
            continue

        if csv_path.stat().st_size == 0:
            stats["csvs_empty"] += 1
            log.debug("Vacío (0 bytes): %s", csv_path.name)
            continue

        log.info("Procesando: %s", csv_path.name)
        file_inserted = 0

        for row in iter_csv_rows(csv_path):
            stats["rows_read"] += 1

            # Filtros mínimos.
            if not row["url"]:
                stats["rows_no_url"] += 1
                continue
            if not row["body"]:
                stats["rows_no_body"] += 1
                continue

            # Limpieza del contenido.
            body_clean    = clean_text(row["body"])
            title_clean   = clean_text(row["title"])
            date_norm     = normalize_date(row["published_utc"])
            body_hash     = hashlib.sha256(body_clean.encode()).hexdigest()
            simhash       = _simhash(body_clean[:2000])  # con 2000 caracteres ya sobra

            if dry_run:
                stats["rows_inserted"] += 1
                file_inserted += 1
                continue

            # La dedup por URL se hace en el INSERT OR IGNORE (UNIQUE en el schema).
            # La dedup por SimHash solo aplica si la URL es nueva.
            if is_near_duplicate(conn, simhash):
                stats["rows_dup_sim"] += 1
                continue

            result = conn.execute(
                INSERT_SQL,
                (row["source"], row["url"], title_clean,
                 date_norm, body_clean, body_hash, simhash, now_utc),
            )
            if result.rowcount == 1:
                stats["rows_inserted"] += 1
                file_inserted += 1
            else:
                stats["rows_dup_url"] += 1

        if not dry_run:
            conn.commit()
        log.info("  %d artículos insertados desde %s", file_inserted, csv_path.name)

    if conn:
        conn.close()

    return stats


# --- Comprobación posterior a la ingesta ---
def validate_db(db_path: Path) -> None:
    """Muestra un resumen rápido de la BD justo después de la ingesta."""
    conn = sqlite3.connect(db_path)
    total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    sources = conn.execute(
        "SELECT source, COUNT(*) AS n FROM articles GROUP BY source ORDER BY n DESC"
    ).fetchall()
    conn.close()

    log.info("---" * 60)
    log.info("VALIDACIÓN BD: %s", db_path)
    log.info("  Total artículos: %d", total)
    log.info("  Por fuente:")
    for src, cnt in sources:
        log.info("    %-35s %d", src, cnt)
    log.info("---" * 60)


# --- CLI ---
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Procesa los CSVs de ransomware intelligence y los carga en SQLite."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Solo muestra estadísticas, no escribe en la base de datos."
    )
    parser.add_argument(
        "--db", type=Path, default=DEFAULT_DB,
        help=f"Ruta al fichero SQLite (por defecto: {DEFAULT_DB})."
    )
    args = parser.parse_args()

    if not OUTPUTS_DIR.exists():
        log.error("El directorio de outputs no existe: %s", OUTPUTS_DIR)
        sys.exit(1)

    mode = "DRY-RUN" if args.dry_run else "REAL"
    log.info("=" * 60)
    log.info("preprocess.py modo %s", mode)
    log.info("outputs_dir : %s", OUTPUTS_DIR)
    log.info("db_path     : %s", args.db)
    log.info("=" * 60)

    stats = ingest(db_path=args.db, dry_run=args.dry_run)

    log.info("---" * 60)
    log.info("RESUMEN FINAL")
    log.info("  CSVs encontrados : %d", stats["csvs_found"])
    log.info("  CSVs vacíos      : %d", stats["csvs_empty"])
    log.info("  Filas leídas     : %d", stats["rows_read"])
    log.info("  Insertadas       : %d", stats["rows_inserted"])
    log.info("  Dup URL          : %d", stats["rows_dup_url"])
    log.info("  Dup SimHash      : %d", stats["rows_dup_sim"])
    log.info("  Sin URL          : %d", stats["rows_no_url"])
    log.info("  Sin body         : %d", stats["rows_no_body"])
    log.info("---" * 60)

    if not args.dry_run:
        validate_db(args.db)

    log.info("Completado en modo %s.", mode)


if __name__ == "__main__":
    main()
