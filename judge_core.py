"""judge_core: fuente única de verdad para el LLM-as-a-judge v2 (Gemma 4).

Lo usan en común:
  - `judge_v2.py` (script offline, modos validate / rejudge / rejudge_conf1).
  - `app.py` (`_run_judge_v2_for_job` y `/api/demo/job/event`, demo en vivo).

Antes había DOS implementaciones idénticas en paralelo (SYSTEM_PROMPT
copiado a mano, mismo schema, misma lógica de reintentos). Cualquier cambio
futuro al prompt o a los parámetros del modelo se hace SÓLO aquí.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Optional

import requests


# --- Modelo y endpoint ---
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemma-4-26b-a4b-it")
DEFAULT_DELAY_S = float(os.environ.get("JUDGE_DELAY_S", "7.0"))
DEFAULT_TIMEOUT_S = int(os.environ.get("JUDGE_TIMEOUT_S", "300"))
DEFAULT_RETRIES = 3


def gemini_url(model: str) -> str:
    # La API key NO va en la URL (antes ?key=... se filtraba al persistir str(e)
    # en demo_events, servido sin auth). Se manda en el header x-goog-api-key.
    return (
        f"https://generativelanguage.googleapis.com/v1beta/models"
        f"/{model}:generateContent"
    )


def _redact(text) -> str:
    """Cinturón anti-fuga: enmascara cualquier 'key=...' que pudiera colarse en un
    mensaje de error antes de loggear/persistir (defensa en profundidad)."""
    return re.sub(r"key=[\w-]+", "key=***", str(text))


# --- Prompt del sistema ---
#
# REGLA: este string es la fuente de verdad. Lo importan judge_v2.py y
# app.py. Si se modifica, hay que actualizar también el documento
# `outputs/krippendorff_segmented/argumentacion.md` y los textos de la
# memoria del TFG que lo citen literalmente.

SYSTEM_PROMPT = """You are a strict validator for MITRE ATT&CK technique annotations in cybersecurity threat intelligence (CTI) reports.

Your task: determine if a provided quote from a CTI article EXPLICITLY demonstrates a specific MITRE ATT&CK technique.

CRITICAL RULES apply all of them before accepting:
1. The quote must describe the SPECIFIC TECHNICAL PROCEDURE of the technique, not just its effects or context.
2. REJECT if the quote only describes impact, consequences, or organizational disruption without naming the technical mechanism.
3. REJECT if you are inferring the technique "must have been used" because the article is about ransomware.
4. REJECT if the technique belongs to the Reconnaissance phase (TA0043) but the quote describes post-compromise actions.
5. REJECT if the quote is a generic statement about the malware family without describing the specific technique execution.
6. DO NOT accept based on topic relevance alone require explicit, direct technical evidence.

Your reasoning process (MANDATORY):
Step 1 State what evidence the technique REQUIRES to be confirmed.
Step 2 Identify exactly what the quote says (verbatim analysis).
Step 3 Compare: does the quote satisfy step 1? Yes or No.
Step 4 Emit your verdict.

Only emit "accept" when the quote provides unambiguous, explicit evidence of the technique's specific mechanism."""


# --- Caché de definiciones de MITRE ATT&CK ---
_DEFAULT_CACHE_PATH = Path(__file__).parent / "data" / "mitre_attack_cache.json"


def load_mitre_definitions(cache_path: Optional[Path] = None) -> dict:
    """Carga la caché de MITRE desde JSON. Si no existe, la descarga y la
    guarda.

    Cada entrada: {technique_id: {"name": str, "description": str (<=600
    caracteres)}}.
    """
    path = Path(cache_path) if cache_path else _DEFAULT_CACHE_PATH
    if path.exists():
        with open(path) as f:
            return json.load(f)

    print(f"[judge_core] Descargando MITRE ATT&CK STIX bundle (~15 MB) {path}")
    url = ("https://raw.githubusercontent.com/mitre/cti/master/"
           "enterprise-attack/enterprise-attack.json")
    response = requests.get(url, timeout=90)
    response.raise_for_status()
    stix = response.json()

    techniques = {}
    for obj in stix["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        tid = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if not tid:
            continue
        desc = obj.get("description", "")
        if len(desc) > 600:
            desc = desc[:600].rsplit(" ", 1)[0] + "..."
        techniques[tid] = {"name": obj.get("name", ""), "description": desc}

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(techniques, f, indent=2)
    print(f"[judge_core] cache guardado: {len(techniques)} técnicas")
    return techniques


def lookup_technique(mitre: dict, technique_id: str) -> dict:
    """Devuelve la entrada de MITRE para `technique_id`.

    Fallback: si la sub-técnica (p. ej. T1059.001) no está, prueba con la
    padre (T1059). Si tampoco está, devuelve un placeholder estable.
    """
    if technique_id in mitre:
        return mitre[technique_id]
    parent = technique_id.split(".")[0]
    if parent in mitre:
        return mitre[parent]
    return {"name": technique_id, "description": "(definición no disponible)"}


# --- Constructor del prompt ---
def build_user_prompt(technique_id: str, name: str, desc: str, quote: str) -> str:
    return (
        "Evaluate this TTP annotation:\n\n"
        f"TECHNIQUE: {technique_id} {name}\n"
        f"MITRE DEFINITION: {desc}\n\n"
        "QUOTE FROM ARTICLE:\n"
        f'"""{quote}"""\n\n'
        f"Does this quote EXPLICITLY demonstrate {technique_id} ({name})?\n"
        "Follow the mandatory 4-step reasoning process from your instructions, "
        "then emit your verdict."
    )


# --- Llamada al modelo (con reintentos inteligentes) ---
_RETRYABLE_HTTP = (
    requests.ConnectionError,
    requests.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


class JudgeError(Exception):
    """Error definitivo del juez (después de agotar reintentos)."""


def call_gemini(
    api_key: str,
    technique_id: str,
    technique_info: dict,
    quote: str,
    model: str = DEFAULT_MODEL,
    retries: int = DEFAULT_RETRIES,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> dict:
    """Hace una llamada a Gemma 4 vía Google AI Studio. Devuelve
    {verdict, reasoning}.

    Política de reintentos (fix N17: antes era un `except Exception`
    indiscriminado):
      - HTTP 429: backoff de 30s x (attempt+1) y reintenta.
      - ConnectionError / Timeout: reintenta enseguida tras un sleep de 5s.
      - JSONDecodeError, KeyError (respuesta malformada): NO reintenta, es
        un error determinista de la respuesta del modelo, no de la red.
      - Otros `requests.HTTPError` (5xx, 4xx != 429): reintenta con sleep
        de 5s.
    """
    name = technique_info.get("name", technique_id)
    desc = technique_info.get("description", "(definición no disponible)")
    user_prompt = build_user_prompt(technique_id, name, desc, quote)
    url = gemini_url(model)
    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents":           [{"parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0,  # determinista: misma entrada -> mismo veredicto (reproducibilidad)
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "OBJECT",
                "properties": {
                    "verdict":   {"type": "STRING"},
                    "reasoning": {"type": "STRING"},
                },
                "required": ["verdict", "reasoning"],
            },
        },
    }

    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            response = requests.post(
                url, json=payload, timeout=timeout_s,
                headers={"x-goog-api-key": api_key},
            )
            if response.status_code == 429:
                wait = 30 * (attempt + 1)
                print(f"[judge_core] rate limit (429) esperando {wait}s")
                time.sleep(wait)
                last_err = JudgeError(f"HTTP 429 (attempt {attempt+1})")
                continue
            response.raise_for_status()
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
            # Gemma a veces añade texto detrás del JSON: usamos raw_decode.
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data, _ = json.JSONDecoder().raw_decode(text.strip())
            verdict = (data.get("verdict") or "uncertain").lower().strip()
            if verdict not in ("accept", "reject", "uncertain"):
                verdict = "uncertain"
            return {"verdict": verdict, "reasoning": data.get("reasoning", "")}

        except _RETRYABLE_HTTP as e:
            last_err = e
            print(f"[judge_core] red (intento {attempt+1}): {_redact(e)} reintentando")
            time.sleep(5)
        except requests.HTTPError as e:
            last_err = e
            print(f"[judge_core] HTTP (intento {attempt+1}): {_redact(e)} reintentando")
            time.sleep(5)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Determinista: la respuesta del modelo viene malformada. No reintentamos.
            raise JudgeError(f"respuesta inválida del modelo: {_redact(e)}") from e

    raise JudgeError(f"Gemma no respondió tras {retries} reintentos: {_redact(last_err)}")
