#!/usr/bin/env python3
"""
demo_worker.py Daemon que mantiene este PC marcado como "online" en la UI
del servidor y, cuando se le pide, ejecuta el prefilter y la extracción RAG
sobre los artículos que llegan desde la UI, emitiendo eventos en tiempo real.
El juez v2 (Gemma 4) lo ejecuta el servidor al recibir el evento
rag_extract.end.

Uso:
    python demo_worker.py          # en primer plano (Ctrl+C para parar)
    systemctl --user start demo_worker   # como servicio systemd
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# ---
# .env
# ---
load_dotenv(Path(__file__).parent / ".env")

# ---
# Configuración
# ---
SCRAPER_URL = os.environ.get("SCRAPER_URL", "https://scraper.143.47.55.55.sslip.io")
AUTH_USER = os.environ.get("BASIC_AUTH_USER", "").strip() or None
AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "").strip() or None
POLL_INTERVAL_S = 2
HEARTBEAT_TIMEOUT_S = 10
EVENT_TIMEOUT_S = 30
OLLAMA_URL = "http://localhost:11434"
CLIENT_VERSION = "demo-worker-0.2"
MAX_BODY_CHARS = 20_000
OLLAMA_TIMEOUT = 600
EVENT_RETRY_BACKOFF = [2, 5, 10]
EVENT_MAX_RETRIES = 3

# ---
# Variables globales
# ---
_stop_requested = False
_current_job_id = None
_session = requests.Session()
if AUTH_USER and AUTH_PASS:
    _session.auth = HTTPBasicAuth(AUTH_USER, AUTH_PASS)
else:
    print("[pc] WARNING: BASIC_AUTH_USER/BASIC_AUTH_PASS no definidos peticiones sin auth", flush=True)

# Objetos pesados con carga perezosa (solo se crean al recibir el primer job)
_extractor = None          # instancia de RagExtractor
_chroma_collection = None  # colección ChromaDB usada por el prefilter
_embed_model = None        # SentenceTransformer usado por el prefilter


# ---
# Logging
# ---
def log(level: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {level} {msg}", flush=True)


# ---
# Señales
# ---
def _signal_handler(signum, frame):
    global _stop_requested
    sig_name = signal.Signals(signum).name
    log("INFO", f"Señal {sig_name} recibida, solicitando parada...")
    _stop_requested = True


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


# ---
# Helper de fecha en UTC
# ---
def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---
# Sondas de GPU y Ollama
# ---
def _gpu_mem_used_mb() -> int:
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            timeout=5,
        )
        return int(out.decode().strip().split("\n")[0])
    except Exception:
        return -1


def _check_ollama() -> tuple[bool, list[str]]:
    """Devuelve (ok, lista_de_nombres_de_modelos)."""
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        return True, models
    except Exception:
        return False, []


# ---
# Helpers HTTP
# ---
def _post_heartbeat(payload: dict) -> dict | None:
    """Envía el heartbeat por POST y devuelve el JSON de respuesta (o None si falla)."""
    try:
        resp = _session.post(
            f"{SCRAPER_URL}/api/demo/heartbeat",
            json=payload,
            timeout=HEARTBEAT_TIMEOUT_S,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log("WARN", f"Heartbeat fallido: {exc}")
        return None


def _post_event(event: dict) -> bool:
    """Envía un evento de job por POST con reintentos. Devuelve True si se entregó."""
    for attempt in range(EVENT_MAX_RETRIES):
        try:
            resp = _session.post(
                f"{SCRAPER_URL}/api/demo/job/event",
                json=event,
                timeout=EVENT_TIMEOUT_S,
            )
            if resp.status_code == 404:
                log("WARN", "El endpoint de eventos devolvió 404 (puede que aún no esté desplegado), lo salto")
                return False
            if 400 <= resp.status_code < 500:
                log("WARN", f"Evento rechazado con {resp.status_code}: {resp.text[:200]}")
                return False
            resp.raise_for_status()
            return True
        except Exception as exc:
            if attempt + 1 < EVENT_MAX_RETRIES:
                delay = EVENT_RETRY_BACKOFF[min(attempt, len(EVENT_RETRY_BACKOFF) - 1)]
                log("WARN", f"POST de evento fallido (intento {attempt+1}): {exc}, reintento en {delay}s")
                time.sleep(delay)
            else:
                log("ERROR", f"POST de evento fallido tras {EVENT_MAX_RETRIES} reintentos: {exc}")
    return False


def emit(job_id: int, stage: str, event_type: str, payload: dict) -> None:
    event = {
        "job_id": job_id,
        "stage": stage,
        "event_type": event_type,
        "payload": payload,
        "ts": utcnow_iso(),
    }
    _post_event(event)


# ---
# Carga perezosa de los componentes pesados
# ---
def _ensure_pipeline_loaded():
    """Carga RagExtractor y ChromaDB al recibir el primer job, para mantener
    el consumo bajo mientras el worker está en reposo."""
    global _extractor, _chroma_collection, _embed_model

    if _extractor is not None:
        return

    log("INFO", "Cargando componentes del pipeline (primer job)...")

    import rag_extractor
    from rag_extractor import RagExtractor
    rag_extractor.OLLAMA_URL = f"{OLLAMA_URL}/api/generate"

    _extractor = RagExtractor()
    # Sobrescribir el timeout de call_ollama
    _orig_call = _extractor.call_ollama
    _extractor.call_ollama = lambda prompt: RagExtractor.call_ollama(
        _extractor, prompt, timeout=OLLAMA_TIMEOUT
    )
    _chroma_collection = _extractor.collection
    _embed_model = _extractor.embed_model
    log("INFO", "Componentes del pipeline cargados")


# ---
# Etapas del pipeline
# ---
REASON_MAP = {
    "short": "below_min_words",
    "no_heuristic": "no_iocs_no_attck_vocab",
    "low_similarity": "low_cosine_similarity",
    "passed": None,
    "level1_ok": None,
}


def run_prefilter(body: str) -> dict:
    """Ejecuta el prefilter y devuelve un dict listo para meter en el payload del evento."""
    from prefilter import filter_article, COSINE_THRESHOLD

    _ensure_pipeline_loaded()

    t0 = time.time()
    pf = filter_article(
        body,
        collection=_chroma_collection,
        model=_embed_model,
        cosine_threshold=COSINE_THRESHOLD,
    )
    elapsed = round(time.time() - t0, 2)

    return {
        "passed": pf["pass"],
        "reason": REASON_MAP.get(pf.get("reason"), pf.get("reason")),
        "word_count": pf.get("word_count", 0),
        "ioc_hits": pf.get("ioc_hits", []),
        "attack_terms_hit": pf.get("attck_terms_hit", []),
        "max_cosine_similarity": pf.get("max_similarity"),
        "elapsed_seconds": elapsed,
    }


def run_rag_extract(body: str) -> dict:
    """Ejecuta la extracción RAG y devuelve un dict con prompts y respuesta cruda."""
    import rag_extractor
    from rag_extractor import SYSTEM_PROMPT

    _ensure_pipeline_loaded()

    t0 = time.time()

    # Paso 1: recuperar candidatos
    candidates = _extractor.retrieve_candidates(body)

    # Paso 2: construir el prompt
    user_prompt = _extractor.build_user_prompt(body, candidates)

    # Resumen de candidatos para el evento
    retrieved = []
    for c in candidates:
        retrieved.append({
            "technique_id": c["id"],
            "name": c["name"],
            "similarity": c["similarity"],
            "source": c["source"],
        })

    start_payload = {
        "model": rag_extractor.OLLAMA_MODEL,
        "num_ctx": 12288,
        "num_predict": 6144,
        "repeat_penalty": 1.02,
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": user_prompt,
        "retrieved_candidates": retrieved,
    }

    # Paso 3: llamar a Ollama
    response = _extractor.call_ollama(user_prompt)
    raw_text = response.get("raw", "")

    if response.get("error"):
        raise RuntimeError(f"Error de Ollama: {response['error']}")

    # Paso 4: parsear el JSON
    parsed = json.loads(raw_text)

    # Paso 5: validar
    validation = _extractor.validate(parsed, body, candidates)

    elapsed = round(time.time() - t0, 1)

    # Lista de TTPs ya parseados para el evento
    parsed_ttps = []
    for ttp in validation["ttps"]:
        parsed_ttps.append({
            "technique_id": ttp.get("technique_id", ""),
            "confidence": ttp.get("confidence", 0),
            "evidence_quote": ttp.get("evidence_quote", ""),
            "tactic_id": ttp.get("tactic_id", ""),
        })

    end_payload = {
        "raw_response": raw_text,
        "parsed_ttps": parsed_ttps,
        "reasoning": parsed.get("reasoning", ""),
        "validation_issues": validation["issues"],
        "valid_ttp_count": validation["valid_count"],
        "elapsed_seconds": elapsed,
    }

    return {
        "start_payload": start_payload,
        "end_payload": end_payload,
        "ttps": validation["ttps"],
        "candidates": candidates,
    }


# ---
# Ejecución de un job
# ---
def execute_job(job: dict) -> None:
    """Ejecuta prefilter + extracción RAG sobre un job y emite eventos en cada etapa.

    El juez v2 (Gemma 4) corre en el servidor en cuanto recibe rag_extract.end.
    Si se han encontrado TTPs, el worker NO emite pipeline.end: el servidor
    cierra el job después de juzgar.
    """
    global _current_job_id

    job_id = job["id"]
    body = (job.get("body") or "")[:MAX_BODY_CHARS]
    title = job.get("title", "untitled")
    _current_job_id = job_id

    log("INFO", f"Job {job_id} arrancado: {title[:60]}")
    emit(job_id, "pipeline", "start", {})

    try:
        # --- Etapa 1: Prefilter ---
        if _stop_requested:
            emit(job_id, "pipeline", "end", {"final_state": "aborted"})
            return

        emit(job_id, "prefilter", "start", {})
        try:
            pf_result = run_prefilter(body)
            emit(job_id, "prefilter", "end", pf_result)
        except Exception as exc:
            emit(job_id, "prefilter", "error", {
                "message": str(exc),
                "traceback": traceback.format_exc(),
                "elapsed_seconds": 0,
            })
            emit(job_id, "pipeline", "end", {"final_state": "failed"})
            return

        if not pf_result["passed"]:
            emit(job_id, "pipeline", "end", {"final_state": "filtered"})
            log("INFO", f"Job {job_id} descartado por el filtro: {pf_result['reason']}")
            return

        # --- Etapa 2: Extracción RAG ---
        if _stop_requested:
            emit(job_id, "pipeline", "end", {"final_state": "aborted"})
            return

        try:
            rag_result = run_rag_extract(body)
            emit(job_id, "rag_extract", "start", rag_result["start_payload"])
            emit(job_id, "rag_extract", "end", rag_result["end_payload"])
        except Exception as exc:
            emit(job_id, "rag_extract", "error", {
                "message": str(exc),
                "traceback": traceback.format_exc(),
                "elapsed_seconds": 0,
            })
            emit(job_id, "pipeline", "end", {"final_state": "failed"})
            return

        if rag_result["end_payload"]["valid_ttp_count"] == 0:
            emit(job_id, "pipeline", "end", {
                "final_state": "completed",
                "summary": {
                    "prefilter_passed": True,
                    "extracted": 0,
                    "accepted": 0,
                },
            })
            log("INFO", f"Job {job_id} completado: 0 TTPs válidos")
            return

        # Hay TTPs: el servidor ejecuta el juez v2 y se encarga de cerrar el job
        log("INFO",
            f"Job {job_id} entregado al servidor: "
            f"{rag_result['end_payload']['valid_ttp_count']} TTPs extraídos, "
            f"esperando al juez v2 en el servidor")

    except Exception as exc:
        log("ERROR", f"Job {job_id} error no controlado: {exc}\n{traceback.format_exc()}")
        try:
            emit(job_id, "pipeline", "end", {"final_state": "failed"})
        except Exception:
            pass
    finally:
        _current_job_id = None


# ---
# Bucle principal
# ---
def main() -> None:
    global _stop_requested, _current_job_id

    log("INFO", f"demo_worker {CLIENT_VERSION} arrancando")
    log("INFO", f"Servidor: {SCRAPER_URL}")
    log("INFO", f"Ollama: {OLLAMA_URL}")

    while not _stop_requested:
        # Construir el payload del heartbeat
        ollama_ok, ollama_models = _check_ollama()
        gpu_mem = _gpu_mem_used_mb()

        hb_payload = {
            "hostname": socket.gethostname(),
            "client_version": CLIENT_VERSION,
            "meta": {
                "ollama_ok": ollama_ok,
                "ollama_models": ollama_models,
                "gpu_mem_used_mb": gpu_mem,
                "current_job_id": _current_job_id,
            },
        }

        resp_data = _post_heartbeat(hb_payload)

        # Comprobar si el servidor nos asigna un job nuevo
        if resp_data and resp_data.get("next_job") and _current_job_id is None:
            job = resp_data["next_job"]
            execute_job(job)
        else:
            time.sleep(POLL_INTERVAL_S)

    # --- Apagado controlado ---
    if _current_job_id is not None:
        log("INFO", f"Abortando el job {_current_job_id} por apagado")
        try:
            emit(_current_job_id, "pipeline", "end", {"final_state": "aborted"})
        except Exception:
            pass

    log("INFO", "demo_worker detenido")
    sys.exit(0)


if __name__ == "__main__":
    main()
