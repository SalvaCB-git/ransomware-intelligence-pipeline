#!/usr/bin/env python3
"""
run_extraction.py Orquestador local del pipeline de extracción de TTPs.

Pide lotes de artículos al servidor OCI, les aplica el prefilter de dos
niveles y usa RagExtractor (RAG + Qwen 2.5 14B) para extraer TTPs.
Después envía los resultados al endpoint commit_batch del servidor.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from prefilter import COSINE_THRESHOLD, filter_article
import rag_extractor
from rag_extractor import RagExtractor

# ---
# Configuración
# ---
SERVER_URL = "https://scraper.143.47.55.55.sslip.io"
OLLAMA_URL = "http://localhost:11434"
OLLAMA_TIMEOUT = 600        # 600 s (10 min): unas 3 veces el tiempo esperado con el body recortado a 20K
MAX_RETRIES = 3
BATCH_SIZE = 50             # se puede cambiar con --batch-size
MAX_BODY_CHARS = 20_000     # ~5K tokens; suficiente para la parte técnica de cualquier artículo
RETRY_BACKOFF = [5, 15, 30] # segundos de espera entre reintentos
AUTH_USER = os.environ.get("BASIC_AUTH_USER", "").strip() or None
AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "").strip() or None

_session = requests.Session()
if AUTH_USER and AUTH_PASS:
    _session.auth = HTTPBasicAuth(AUTH_USER, AUTH_PASS)
else:
    print("[pc] WARNING: BASIC_AUTH_USER/BASIC_AUTH_PASS no definidos peticiones sin auth", flush=True)

_stop_requested = False


# ---
# Señales
# ---
def signal_handler(signum: int, frame: Any) -> None:
    global _stop_requested
    if not _stop_requested:
        print("Interrupción recibida. Termino el artículo actual y hago commit...", file=sys.stderr)
    _stop_requested = True


# ---
# Comprobación de dependencias
# ---
def check_dependencies() -> None:
    """Comprueba que Ollama y el servidor Flask responden; aborta si algo falla."""
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        available = ", ".join(models) if models else "sin modelos"
        print(f"Ollama OK modelos: {available}")
    except Exception as exc:  # noqa: BLE001
        print(f"Error al verificar Ollama: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        resp = _session.get(f"{SERVER_URL}/api/status", timeout=10)
        resp.raise_for_status()
        print("Servidor Flask OK")
    except Exception as exc:  # noqa: BLE001
        print(f"Error al verificar el servidor: {exc}", file=sys.stderr)
        sys.exit(1)


# ---
# Helpers HTTP
# ---
def _get_backoff(attempt: int) -> int:
    idx = min(attempt, len(RETRY_BACKOFF) - 1)
    return RETRY_BACKOFF[idx]


def acquire_batch(limit: int) -> List[Dict[str, Any]]:
    url = f"{SERVER_URL}/api/ttps/acquire_batch"
    params = {"limit": limit}
    for attempt in range(MAX_RETRIES):
        try:
            resp = _session.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return data.get("articles", [])
        except Exception as exc:  # noqa: BLE001
            print(
                f"Acquire falló (intento {attempt+1}/{MAX_RETRIES}): {exc}",
                file=sys.stderr,
            )
            if attempt + 1 == MAX_RETRIES:
                break
            time.sleep(_get_backoff(attempt))
    return []


def commit_batch(results: List[Dict[str, Any]]) -> bool:
    if not results:
        return True

    url = f"{SERVER_URL}/api/ttps/commit_batch"
    payload = {"results": results}

    for attempt in range(MAX_RETRIES):
        try:
            resp = _session.post(url, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok", True) is False:
                print(f"commit_batch respondió ok=false: {data}", file=sys.stderr)
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            print(
                f"Commit falló (intento {attempt+1}/{MAX_RETRIES}): {exc}",
                file=sys.stderr,
            )
            if attempt + 1 == MAX_RETRIES:
                break
            time.sleep(_get_backoff(attempt))

    return False


# ---
# Procesamiento de cada artículo
# ---
def _serialize(obj: Any) -> str:
    return json.dumps(obj if obj is not None else [], ensure_ascii=False)


def process_article(
    article: Dict[str, Any],
    extractor: RagExtractor,
    collection: Any,
    embed_model: Any,
    use_prefilter: bool,
    dry_run: bool,
) -> Dict[str, Any]:
    start = time.time()
    article_id = article.get("id")
    body = article.get("body") or ""
    body = body[:MAX_BODY_CHARS]

    if not body.strip():
        elapsed = time.time() - start
        return {
            "article_id": article_id,
            "status": "failed",
            "model": "prefilter",
            "ttps": "[]",
            "reasoning": None,
            "valid_ttp_count": 0,
            "validation_issues": "[]",
            "prefilter_reason": "empty_body",
            "max_similarity_score": None,
            "elapsed_seconds": round(elapsed, 1),
        }

    prefilter_reason: Optional[str] = None
    max_similarity: Optional[float] = None

    if use_prefilter:
        try:
            pf = filter_article(body, collection=collection, model=embed_model,
                                cosine_threshold=COSINE_THRESHOLD)
            prefilter_reason = pf.get("reason")
            max_similarity = pf.get("max_similarity")
            if not pf.get("pass", False):
                elapsed = time.time() - start
                return {
                    "article_id": article_id,
                    "status": "filtered",
                    "model": "prefilter",
                    "ttps": "[]",
                    "reasoning": None,
                    "valid_ttp_count": 0,
                    "validation_issues": "[]",
                    "prefilter_reason": prefilter_reason,
                    "max_similarity_score": max_similarity,
                    "elapsed_seconds": round(elapsed, 1),
                }
        except Exception as exc:  # noqa: BLE001
            prefilter_reason = f"prefilter_error:{exc}"
            max_similarity = None
            elapsed = time.time() - start
            return {
                "article_id": article_id,
                "status": "failed",
                "model": "prefilter",
                "ttps": "[]",
                "reasoning": None,
                "valid_ttp_count": 0,
                "validation_issues": "[]",
                "prefilter_reason": prefilter_reason,
                "max_similarity_score": max_similarity,
                "elapsed_seconds": round(elapsed, 1),
            }
    else:
        prefilter_reason = "prefilter_skipped"

    if dry_run:
        elapsed = time.time() - start
        return {
            "article_id": article_id,
            "status": "dry-run",
            "model": rag_extractor.OLLAMA_MODEL,
            "ttps": "[]",
            "reasoning": None,
            "valid_ttp_count": 0,
            "validation_issues": "[]",
            "prefilter_reason": prefilter_reason,
            "max_similarity_score": max_similarity,
            "elapsed_seconds": round(elapsed, 1),
        }

    last_error: Optional[str] = None
    for attempt in range(MAX_RETRIES):
        try:
            result = extractor.extract(body)
        except Exception as exc:  # noqa: BLE001
            last_error = f"extractor_exception:{exc}"
            print(
                f"Extractor lanzó excepción (intento {attempt+1}/{MAX_RETRIES}): {last_error}",
                file=sys.stderr,
            )
            if attempt + 1 < MAX_RETRIES:
                time.sleep(_get_backoff(attempt))
            continue
        if result.get("error"):
            last_error = result["error"]
            print(
                f"Extractor falló (intento {attempt+1}/{MAX_RETRIES}): {last_error}",
                file=sys.stderr,
            )
            if attempt + 1 < MAX_RETRIES:
                time.sleep(_get_backoff(attempt))
            continue

        elapsed = time.time() - start
        ttps = result.get("ttps", [])
        issues = result.get("validation_issues", [])
        return {
            "article_id": article_id,
            "status": "completed",
            "model": rag_extractor.OLLAMA_MODEL,
            "ttps": _serialize(ttps),
            "reasoning": result.get("reasoning"),
            "valid_ttp_count": result.get("valid_ttp_count", 0),
            "validation_issues": _serialize(issues),
            "prefilter_reason": prefilter_reason,
            "max_similarity_score": max_similarity,
            "elapsed_seconds": round(elapsed, 1),
        }

    elapsed = time.time() - start
    return {
        "article_id": article_id,
        "status": "failed",
        "model": rag_extractor.OLLAMA_MODEL,
        "ttps": "[]",
        "reasoning": last_error,
        "valid_ttp_count": 0,
        "validation_issues": "[]",
        "prefilter_reason": prefilter_reason,
        "max_similarity_score": max_similarity,
        "elapsed_seconds": round(elapsed, 1),
    }


# ---
# Salida por consola
# ---
def print_summary(stats: Dict[str, int], elapsed_seconds: float, title: str = "Lote completado") -> None:
    mins, secs = divmod(int(elapsed_seconds), 60)
    speed = (stats["processed"] / (elapsed_seconds / 60)) if elapsed_seconds > 0 else 0
    print("" + "---" * 33 + "")
    print(f" {title:<29} ")
    print(f" Procesados:  {stats['processed']:<14}")
    print(f" Completados: {stats['completed']:<14}")
    print(f" Filtrados:   {stats['filtered']:<14}")
    print(f" Fallidos:    {stats['failed']:<14}")
    print(f" Tiempo:      {mins}m {secs:02d}s{' ' * (11 - len(str(mins)) - 2)}")
    print(f" Velocidad:   {speed:.1f} art/min    ")
    print("" + "---" * 33 + "")


# ---
# CLI
# ---
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Orquesta la extracción de TTPs con RAG y prefilter")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                        help="Tamaño del lote que se pide al servidor")
    parser.add_argument("--limit", type=int, default=0,
                        help="Número máximo de artículos a procesar (0 = todos)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo ejecuta el prefilter: no llama a Qwen ni hace commit")
    parser.add_argument("--no-prefilter", action="store_true",
                        help="Saltar el prefilter (modo debug)")
    return parser.parse_args()


def main() -> None:
    global _stop_requested

    args = parse_args()

    # Por seguridad: en dry-run sin límite, lo limitamos al tamaño del lote
    if args.dry_run and args.limit == 0:
        args.limit = args.batch_size
        print(f"Dry-run sin límite: fijo limit={args.limit} para no adquirir todo el corpus.")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Ajustar el OLLAMA_URL que usa rag_extractor para que apunte al endpoint configurado aquí
    rag_extractor.OLLAMA_URL = f"{OLLAMA_URL.rstrip('/')}/api/generate"

    check_dependencies()

    extractor = RagExtractor(index_dir=rag_extractor.INDEX_DIR)
    # Forzar el timeout de las llamadas a Ollama al valor configurado
    extractor.call_ollama = lambda user_prompt: RagExtractor.call_ollama(extractor, user_prompt, timeout=OLLAMA_TIMEOUT)

    collection = extractor.collection
    embed_model = extractor.embed_model

    stats = {"processed": 0, "completed": 0, "filtered": 0, "failed": 0}
    start_total = time.time()

    while not _stop_requested:
        if args.limit and stats["processed"] >= args.limit:
            break

        remaining = args.limit - stats["processed"] if args.limit else None
        batch_size = min(args.batch_size, remaining) if remaining else args.batch_size

        articles = acquire_batch(batch_size)
        if not articles:
            print("No hay artículos pendientes.")
            break

        results: List[Dict[str, Any]] = []
        batch_start = time.time()

        for idx, article in enumerate(articles, 1):
            if _stop_requested:
                print("Interrupción solicitada. Hago commit parcial del lote...", file=sys.stderr)
                break

            result = process_article(
                article,
                extractor=extractor,
                collection=collection,
                embed_model=embed_model,
                use_prefilter=not args.no_prefilter,
                dry_run=args.dry_run,
            )
            results.append(result)

            stats["processed"] += 1
            if result["status"] == "completed":
                stats["completed"] += 1
            elif result["status"] == "filtered":
                stats["filtered"] += 1
            elif result["status"] == "failed":
                stats["failed"] += 1

            elapsed = result.get("elapsed_seconds", 0)
            print(f"[{idx}/{len(articles)}] ID:{article.get('id')} | {result['status']} | {elapsed:.1f}s")

            if args.limit and stats["processed"] >= args.limit:
                _stop_requested = True
                break

        if args.dry_run:
            print("Dry-run: los resultados NO se envían al servidor.")
        else:
            if results:
                ok = commit_batch(results)
                if not ok:
                    print(
                        "Aviso: commit_batch falló; los artículos volverán a pending en unas 3 horas.",
                        file=sys.stderr,
                    )

        elapsed_batch = time.time() - batch_start
        print_summary(stats, elapsed_batch, title="Lote completado")

        if _stop_requested:
            break

    elapsed_total = time.time() - start_total
    print_summary(stats, elapsed_total, title="Sesión finalizada")
    sys.exit(0)


if __name__ == "__main__":
    main()
