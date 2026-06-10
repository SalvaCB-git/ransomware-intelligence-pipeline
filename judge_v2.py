#!/usr/bin/env python3
"""
judge_v2.py: LLM-as-a-Judge v2 con la API de Gemini (Google AI Studio).

Modos:
  python judge_v2.py --mode validate          # Evalúa sobre calibration_sample anotada
  python judge_v2.py --mode rejudge           # Vuelve a juzgar los TTPs aceptados por el juez v1
  python judge_v2.py --mode validate --limit 20  # Prueba rápida con N muestras

Requisitos:
  .env con GOOGLE_API_KEY=...
  pip install python-dotenv requests
"""

import argparse
import json
import os
import sqlite3
import time
from pathlib import Path

from dotenv import load_dotenv

import judge_core
from judge_core import (
    DEFAULT_DELAY_S as DELAY_SECONDS,
    call_gemini as _call_gemini_core,
    load_mitre_definitions as _load_mitre,
    lookup_technique,
)

load_dotenv()

# --- Configuración ---
DB_PATH        = Path(__file__).parent / "data" / "ransomware_intel.db"
MITRE_CACHE    = Path(__file__).parent / "data" / "mitre_attack_cache.json"
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
MODEL          = os.environ.get("GEMINI_MODEL", judge_core.DEFAULT_MODEL)
BATCH_SIZE     = 200   # paginación al desempaquetar TTPs en mode_rejudge_conf1


def load_mitre_definitions() -> dict:
    return _load_mitre(MITRE_CACHE)


def call_gemini(technique_id: str, technique_info: dict, quote: str,
                retries: int = 3) -> dict:
    """Wrapper de compatibilidad: misma firma que la versión antigua,
    delegando en judge_core.

    Lanza `JudgeError` en lugar de `RuntimeError` cuando se agotan los
    reintentos (los modos rejudge/rejudge_conf1 lo capturan con
    `except Exception` igualmente).
    """
    return _call_gemini_core(
        api_key=GOOGLE_API_KEY,
        technique_id=technique_id,
        technique_info=technique_info,
        quote=quote,
        model=MODEL,
        retries=retries,
    )


# --- utilidades de BD ---
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_v2_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ttp_verdicts_v2 (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            extraction_id INTEGER NOT NULL,
            article_id    INTEGER NOT NULL,
            ttp_index     INTEGER NOT NULL,
            technique_id  TEXT NOT NULL,
            verdict       TEXT NOT NULL CHECK(verdict IN ('accept','reject','uncertain')),
            reasoning     TEXT,
            model         TEXT NOT NULL,
            source_mode   TEXT,
            judged_at     TEXT DEFAULT (datetime('now')),
            UNIQUE(extraction_id, ttp_index)
        )
    """)
    conn.commit()


# --- Modo: validate ---
def mode_validate(limit):
    """Ejecuta el juez v2 sobre la calibration_sample ya anotada y compara
    los veredictos con la anotación humana."""
    mitre = load_mitre_definitions()
    conn  = get_conn()

    sql = """
        SELECT id, technique_id, quote, llm_verdict, human_blind_verdict
        FROM calibration_sample
        WHERE human_blind_verdict IS NOT NULL
          AND quote IS NOT NULL AND quote != ''
        ORDER BY id
    """
    if limit:
        sql += f" LIMIT {limit}"

    rows = conn.execute(sql).fetchall()
    print(f"\n{'='*60}")
    print(f"VALIDACIÓN: {len(rows)} muestras anotadas{f' (límite={limit})' if limit else ''}")
    print(f"Modelo: {MODEL}")
    print(f"{'='*60}\n")

    results = []
    for i, row in enumerate(rows, 1):
        tid   = row["technique_id"]
        quote = row["quote"]
        human = row["human_blind_verdict"]
        old   = row["llm_verdict"]

        print(f"[{i:3}/{len(rows)}] {tid}  human={human}  juez_v1={old}", flush=True)

        tech_info = lookup_technique(mitre, tid)
        try:
            result = call_gemini(tid, tech_info, quote)
            v2 = result["verdict"]
        except Exception as e:
            print(f"  ERROR: {e}")
            v2 = "error"

        agree_v2    = (v2 == human)
        agree_v1    = (old == human)
        status_v2   = "✓" if agree_v2 else "✗"
        status_v1   = "✓" if agree_v1 else "✗"
        print(f"       juez_v2={v2} {status_v2}  (juez_v1 {status_v1})", flush=True)

        results.append({
            "human": human, "v1": old, "v2": v2,
            "agree_v2": agree_v2, "agree_v1": agree_v1,
        })
        time.sleep(DELAY_SECONDS)

    # --- Métricas finales ---

    valid = [r for r in results if r["v2"] != "error"]
    n = len(valid)
    if n == 0:
        print("\nSin resultados válidos.")
        return

    acc_v1 = sum(r["agree_v1"] for r in valid) / n * 100
    acc_v2 = sum(r["agree_v2"] for r in valid) / n * 100

    # Falsos positivos: el juez dice accept y el humano dice reject.
    fp_v1 = sum(1 for r in valid if r["v1"] == "accept" and r["human"] == "reject")
    fp_v2 = sum(1 for r in valid if r["v2"] == "accept" and r["human"] == "reject")
    total_judged_accept_v1 = sum(1 for r in valid if r["v1"] == "accept")
    total_judged_accept_v2 = sum(1 for r in valid if r["v2"] == "accept")

    print(f"\n{'='*60}")
    print(f"RESULTADOS FINALES ({n} muestras válidas)")
    print(f"{'='*60}")
    print(f"  Acuerdo con humano Juez v1 (Qwen): {acc_v1:.1f}%")
    print(f"  Acuerdo con humano Juez v2 (Gemini): {acc_v2:.1f}%")
    print()
    if total_judged_accept_v1 > 0:
        fpr_v1 = fp_v1 / total_judged_accept_v1 * 100
        print(f"  Tasa FP Juez v1: {fp_v1}/{total_judged_accept_v1} = {fpr_v1:.1f}%")
    if total_judged_accept_v2 > 0:
        fpr_v2 = fp_v2 / total_judged_accept_v2 * 100
        print(f"  Tasa FP Juez v2: {fp_v2}/{total_judged_accept_v2} = {fpr_v2:.1f}%")

    # Distribución de veredictos de v2.
    for verdict in ("accept", "reject", "uncertain"):
        count = sum(1 for r in valid if r["v2"] == verdict)
        print(f"  v2 {verdict}: {count} ({count/n*100:.1f}%)")

    conn.close()


def _judge_and_store(conn, mitre, items, source_mode, skip_message=False):
    """Bucle de juicio compartido por mode_rejudge y mode_rejudge_conf1.

    Para cada `item` (dict con technique_id, quote, extraction_id, article_id,
    ttp_index) consulta a Gemma, inserta el veredicto en ttp_verdicts_v2 con el
    `source_mode` indicado y cuenta los resultados. Devuelve la tupla
    (accepted, rejected, uncertain, errors).

    `skip_message=True` imprime una línea al saltar un quote vacío (comportamiento
    de mode_rejudge); mode_rejudge_conf1 los salta en silencio.
    """
    accepted = rejected = uncertain = errors = 0
    n = len(items)

    for i, item in enumerate(items, 1):
        tid    = item["technique_id"]
        quote  = item["quote"] or ""
        ext_id = item["extraction_id"]
        art_id = item["article_id"]
        idx    = item["ttp_index"]

        if not quote.strip():
            if skip_message:
                print(f"[{i:4}/{n}] {tid} ext={ext_id} idx={idx} sin quote, skip")
            errors += 1
            continue

        print(f"[{i:4}/{n}] {tid} ext={ext_id} idx={idx} ", end="", flush=True)

        tech_info = lookup_technique(mitre, tid)
        try:
            judgement = call_gemini(tid, tech_info, quote)
            verdict = judgement["verdict"]
            reasoning = judgement.get("reasoning", "")
        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1
            time.sleep(DELAY_SECONDS)
            continue

        print(f" {verdict}")

        conn.execute("""
            INSERT OR IGNORE INTO ttp_verdicts_v2
                (extraction_id, article_id, ttp_index, technique_id, verdict, reasoning, model, source_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ext_id, art_id, idx, tid, verdict, reasoning, MODEL, source_mode))
        conn.commit()

        if verdict == "accept":      accepted  += 1
        elif verdict == "reject":    rejected  += 1
        else:                        uncertain += 1

        time.sleep(DELAY_SECONDS)

    return accepted, rejected, uncertain, errors


# --- Modo: rejudge ---
def mode_rejudge(limit):
    """Vuelve a juzgar todos los TTPs que aceptó el juez v1 y guarda los
    nuevos veredictos en ttp_verdicts_v2."""
    mitre = load_mitre_definitions()
    conn  = get_conn()
    ensure_v2_table(conn)

    # TTPs aceptados por v1 que todavía no ha juzgado v2.
    sql = """
        SELECT tv.extraction_id, tv.article_id, tv.ttp_index, tv.technique_id,
               json_extract(e.ttps, '$[' || tv.ttp_index || '].evidence_quote') AS quote
        FROM ttp_verdicts tv
        JOIN extractions e ON e.id = tv.extraction_id
        WHERE tv.verdict = 'accept'
          AND NOT EXISTS (
              SELECT 1 FROM ttp_verdicts_v2 v2
               WHERE v2.extraction_id = tv.extraction_id
                 AND v2.ttp_index = tv.ttp_index
          )
        ORDER BY tv.extraction_id
    """
    if limit:
        sql += f" LIMIT {limit}"

    rows = conn.execute(sql).fetchall()
    print(f"\n{'='*60}")
    print(f"RE-JUZGANDO: {len(rows)} TTPs aceptados por juez v1")
    print(f"Modelo: {MODEL}")
    print(f"{'='*60}\n")

    items = [
        {
            "technique_id":  row["technique_id"],
            "quote":         row["quote"],
            "extraction_id": row["extraction_id"],
            "article_id":    row["article_id"],
            "ttp_index":     row["ttp_index"],
        }
        for row in rows
    ]
    accepted, rejected, uncertain, errors = _judge_and_store(
        conn, mitre, items, "rejudge", skip_message=True
    )

    total = accepted + rejected + uncertain
    print(f"\n{'='*60}")
    print("COMPLETADO")
    print(f"  accept:    {accepted}  ({accepted/total*100:.1f}% de los procesados)" if total else "")
    print(f"  reject:    {rejected}  ({rejected/total*100:.1f}%)" if total else "")
    print(f"  uncertain: {uncertain}  ({uncertain/total*100:.1f}%)" if total else "")
    print(f"  errores:   {errors}")
    print("  Guardados en tabla ttp_verdicts_v2")
    conn.close()


# --- Modo: rejudge_conf1 ---
def mode_rejudge_conf1(limit):
    """Juzga los TTPs con confidence=1.0 (que no pasaron por el juez en el
    pipeline original)."""
    mitre = load_mitre_definitions()
    conn  = get_conn()
    ensure_v2_table(conn)

    # Cargamos los pares ya juzgados en un set para consultarlos en O(1).
    already_judged = set(
        (r[0], r[1]) for r in
        conn.execute("SELECT extraction_id, ttp_index FROM ttp_verdicts_v2").fetchall()
    )
    print(f"Ya juzgados en v2: {len(already_judged)} (se omitirán)")

    # Desempaquetamos los TTPs en Python paginando para no cargar todo en
    # memoria.
    offset = 0
    pending = []

    while True:
        rows = conn.execute(
            "SELECT id, article_id, ttps FROM extractions "
            "WHERE ttps IS NOT NULL LIMIT ? OFFSET ?",
            (BATCH_SIZE, offset)
        ).fetchall()
        if not rows:
            break
        for row in rows:
            ext_id = row["id"]
            art_id = row["article_id"]
            try:
                ttps = json.loads(row["ttps"]) if isinstance(row["ttps"], str) else row["ttps"]
                if not isinstance(ttps, list):
                    continue
            except (json.JSONDecodeError, TypeError):
                continue
            for idx, ttp in enumerate(ttps):
                try:
                    conf = float(ttp.get("confidence", 0))
                except (TypeError, ValueError):
                    continue
                if conf < 0.99:          # quedarse sólo con conf=1.0
                    continue
                if (ext_id, idx) in already_judged:
                    continue
                tid   = ttp.get("technique_id") or ttp.get("id", "")
                quote = ttp.get("evidence_quote", "")
                if not tid or not quote:
                    continue
                pending.append({
                    "extraction_id": ext_id,
                    "article_id":    art_id,
                    "ttp_index":     idx,
                    "technique_id":  tid,
                    "quote":         quote,
                })
        offset += BATCH_SIZE

    if limit:
        pending = pending[:limit]

    print(f"\n{'='*60}")
    print(f"RE-JUZGANDO conf=1.0: {len(pending)} TTPs pendientes")
    print(f"Modelo: {MODEL}")
    tiempo_est = len(pending) * DELAY_SECONDS / 3600
    print(f"Tiempo estimado: {tiempo_est:.1f}h (a {DELAY_SECONDS}s/TTP)")
    print(f"{'='*60}\n")

    accepted, rejected, uncertain, errors = _judge_and_store(
        conn, mitre, pending, "rejudge_conf1"
    )

    total = accepted + rejected + uncertain
    print(f"\n{'='*60}")
    print("COMPLETADO conf=1.0")
    if total:
        print(f"  accept:    {accepted}  ({accepted/total*100:.1f}%)")
        print(f"  reject:    {rejected}  ({rejected/total*100:.1f}%)")
        print(f"  uncertain: {uncertain}  ({uncertain/total*100:.1f}%)")
    print(f"  errores/sin quote: {errors}")
    print("  Guardados en tabla ttp_verdicts_v2")
    conn.close()


# --- Entry point ---
if __name__ == "__main__":
    if not GOOGLE_API_KEY:
        raise SystemExit("ERROR: GOOGLE_API_KEY no encontrada. Crea un .env con la clave.")

    parser = argparse.ArgumentParser(description="LLM-as-a-Judge v2 con Gemini")
    parser.add_argument("--mode",  choices=["validate", "rejudge", "rejudge_conf1"], required=True)
    parser.add_argument("--limit", type=int, default=None,
                        help="Limitar a N muestras (útil para pruebas rápidas)")
    args = parser.parse_args()

    if args.mode == "validate":
        mode_validate(args.limit)
    elif args.mode == "rejudge":
        mode_rejudge(args.limit)
    elif args.mode == "rejudge_conf1":
        mode_rejudge_conf1(args.limit)
