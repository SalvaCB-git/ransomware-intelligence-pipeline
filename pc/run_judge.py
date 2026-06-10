"""
run_judge.py LLM-as-a-judge para los TTPs con confidence=0.75.

Cómo funciona:
  1. Pide un batch de TTPs pendientes al servidor
     (GET /api/judge/acquire_batch).
  2. Por cada TTP: construye el prompt, llama a Ollama (T=0) y parsea el JSON con el veredicto.
  3. Envía los veredictos de vuelta al servidor (POST /api/judge/commit_batch).
  4. Repite hasta que no queden TTPs pendientes.

Cómo se usa:
  python run_judge.py
  python run_judge.py --dry-run --max-batches 1 --limit 5
  python run_judge.py --limit 50 --model qwen2.5:14b-instruct-q4_K_M
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Optional

import requests  # pip install requests
from requests.auth import HTTPBasicAuth

# --- Configuración ---
SERVER_URL     = "https://scraper.143.47.55.55.sslip.io"
OLLAMA_URL     = "http://localhost:11434"
JUDGE_MODEL    = "qwen2.5:14b-instruct-q4_K_M"

BATCH_SIZE     = 20
OLLAMA_TIMEOUT = 120

AUTH_USER = os.environ.get("BASIC_AUTH_USER", "").strip() or None
AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "").strip() or None

_session = requests.Session()
if AUTH_USER and AUTH_PASS:
    _session.auth = HTTPBasicAuth(AUTH_USER, AUTH_PASS)
else:
    print("[pc] AVISO: BASIC_AUTH_USER/BASIC_AUTH_PASS no están definidos; las peticiones irán sin auth.", flush=True)

# --- Prompt del juez ---
JUDGE_SYSTEM = """\
Eres un experto en Cyber Threat Intelligence (CTI) especializado en ransomware.
Tu tarea es evaluar si una extracción de TTP de MITRE ATT&CK está justificada
basándote en el texto del artículo y la quote de evidencia proporcionada.

Criterios:
- ACCEPT  La técnica fue EJECUTADA por el atacante según el artículo.
            La quote de evidencia describe una acción ofensiva real.
- REJECT  La técnica es mencionada de forma hipotética, como recomendación
            defensiva, en contexto genérico, o sin evidencia de uso real.
            Ejemplos: "Para protegerse contra T1078...", "Los atacantes podrían..."
- UNCERTAIN La evidencia es ambigua o insuficiente para decidir con certeza.

Responde ÚNICAMENTE con JSON válido, sin texto adicional antes ni después.\
"""

JUDGE_TEMPLATE = """\
Artículo (extracto):
\"\"\"
{article_body}
\"\"\"

Técnica extraída: {technique_id} {technique_name}
Táctica: {tactic} ({tactic_id})
Quote de evidencia: "{evidence_quote}"
Confidence del extractor: {confidence}

¿La acción descrita fue EJECUTADA por el atacante, o es mencionada \
hipotéticamente/defensivamente?

Responde SOLO con este JSON:
{{"verdict": "accept|reject|uncertain", "reasoning": "una frase concisa"}}\
"""

# --- Comunicación con el servidor ---
def acquire_batch(limit: int) -> list[dict]:
    try:
        r = _session.get(
            f"{SERVER_URL}/api/judge/acquire_batch",
            params={"limit": limit},
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("items", [])
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] acquire_batch ha fallado: {e}", file=sys.stderr)
        return []


def commit_batch(verdicts: list[dict]) -> bool:
    if not verdicts:
        return True
    try:
        r = _session.post(
            f"{SERVER_URL}/api/judge/commit_batch",
            json={"verdicts": verdicts},
            timeout=30,
        )
        r.raise_for_status()
        result = r.json()
        if result.get("errors"):
            for err in result["errors"]:
                print(f"  [AVISO] error al hacer commit: {err}", file=sys.stderr)
        return result.get("ok", False)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] commit_batch ha fallado: {e}", file=sys.stderr)
        return False

# --- Ollama ---
def call_ollama(system_prompt: str, user_prompt: str, model: str) -> Optional[str]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 200,
        },
    }
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()["message"]["content"].strip()
    except requests.exceptions.Timeout:
        print(f"  [AVISO] Ollama ha hecho timeout ({OLLAMA_TIMEOUT}s)", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [AVISO] Error de Ollama: {e}", file=sys.stderr)
        return None

# --- Parseo del veredicto ---
_JSON_RE = re.compile(r'\{[^{}]*"verdict"[^{}]*\}', re.DOTALL)
_VALID_VERDICTS = {"accept", "reject", "uncertain"}


def parse_verdict(raw: Optional[str]) -> dict:
    if not raw:
        return {"verdict": "uncertain", "reasoning": "parse_failure: la respuesta llegó vacía"}

    try:
        parsed = json.loads(raw)
        v = parsed.get("verdict", "").lower().strip()
        if v in _VALID_VERDICTS:
            return {"verdict": v, "reasoning": parsed.get("reasoning", "")}
    except (json.JSONDecodeError, AttributeError):
        pass

    match = _JSON_RE.search(raw)
    if match:
        try:
            parsed = json.loads(match.group(0))
            v = parsed.get("verdict", "").lower().strip()
            if v in _VALID_VERDICTS:
                return {"verdict": v, "reasoning": parsed.get("reasoning", "")}
        except (json.JSONDecodeError, AttributeError):
            pass

    snippet = repr(raw[:120]) if raw else "None"
    return {"verdict": "uncertain", "reasoning": f"parse_failure: {snippet}"}

# --- Lógica por TTP ---
def judge_ttp(item: dict, model: str, dry_run: bool) -> dict:
    if dry_run:
        verdict_data = {"verdict": "accept", "reasoning": "dry_run"}
    else:
        user_prompt = JUDGE_TEMPLATE.format(
            article_body   = item.get("article_body", ""),
            technique_id   = item.get("technique_id", ""),
            technique_name = item.get("technique_name", ""),
            tactic         = item.get("tactic", ""),
            tactic_id      = item.get("tactic_id", ""),
            evidence_quote = item.get("evidence_quote", ""),
            confidence     = item.get("confidence", 0.75),
        )
        raw = call_ollama(JUDGE_SYSTEM, user_prompt, model)
        verdict_data = parse_verdict(raw)

    return {
        "extraction_id": item["extraction_id"],
        "article_id":    item["article_id"],
        "ttp_index":     item["ttp_index"],
        "technique_id":  item.get("technique_id", ""),
        "verdict":       verdict_data["verdict"],
        "reasoning":     verdict_data["reasoning"],
        "model":         model if not dry_run else "dry_run",
    }

# --- Bucle principal ---
def run(batch_size: int, model: str, dry_run: bool, max_batches: Optional[int]) -> None:
    total_judged    = 0
    total_accepted  = 0
    total_rejected  = 0
    total_uncertain = 0
    batch_count     = 0

    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Arrancando el juez")
    print(f"  model={model}  batch_size={batch_size}  dry_run={dry_run}")
    if max_batches:
        print(f"  max_batches={max_batches}")
    print()

    while True:
        if max_batches is not None and batch_count >= max_batches:
            print(f"Se ha llegado al límite de batches ({max_batches}). Parando.")
            break

        items = acquire_batch(batch_size)
        if not items:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] No quedan TTPs pendientes. Hemos terminado.")
            break

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] Batch {batch_count + 1}: {len(items)} TTPs recibidos")
        batch_verdicts = []

        for i, item in enumerate(items):
            tech    = item.get("technique_id", "?")
            ext_id  = item.get("extraction_id", "?")
            ttp_idx = item.get("ttp_index", "?")

            print(f"  [{i + 1:2d}/{len(items)}] ext={ext_id} idx={ttp_idx} {tech} ... ",
                  end="", flush=True)
            t0 = time.time()

            result = judge_ttp(item, model, dry_run)
            elapsed = time.time() - t0

            verdict = result["verdict"]
            print(f"{verdict.upper()} ({elapsed:.1f}s)")

            batch_verdicts.append(result)

            if verdict == "accept":
                total_accepted  += 1
            elif verdict == "reject":
                total_rejected  += 1
            else:
                total_uncertain += 1
            total_judged += 1

        ok = commit_batch(batch_verdicts)
        status = "ok" if ok else "ERROR"
        print(f"  Commit: {status} ({len(batch_verdicts)} verdicts)\n")
        batch_count += 1

    denom = max(total_judged, 1)
    print("=" * 60)
    print("RESUMEN FINAL")
    print(f"  Total juzgados : {total_judged}")
    print(f"  Accept         : {total_accepted:4d}  ({total_accepted / denom:.1%})")
    print(f"  Reject         : {total_rejected:4d}  ({total_rejected / denom:.1%})")
    print(f"  Uncertain      : {total_uncertain:4d}  ({total_uncertain / denom:.1%})")
    print("=" * 60)

# --- Punto de entrada ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LLM-as-a-judge para los TTPs con confidence=0.75"
    )
    parser.add_argument("--limit",       type=int, default=BATCH_SIZE,  help=f"TTPs por batch (por defecto {BATCH_SIZE})")
    parser.add_argument("--model",       type=str, default=JUDGE_MODEL, help=f"Modelo de Ollama (por defecto {JUDGE_MODEL})")
    parser.add_argument("--dry-run",     action="store_true",           help="No llama a Ollama; simula los veredictos")
    parser.add_argument("--max-batches", type=int, default=None,        help="Limita el número de batches (para debug)")
    args = parser.parse_args()

    run(
        batch_size  = args.limit,
        model       = args.model,
        dry_run     = args.dry_run,
        max_batches = args.max_batches,
    )
