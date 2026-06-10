"""
benchmark.py Compara Qwen 2.5 14B y Llama 3.1 8B
extrayendo TTPs MITRE ATT&CK a partir de artículos de ransomware.

Cómo se usa:
    python3 benchmark.py

Requisitos:
    pip install requests
    Tener Ollama escuchando en localhost:11434 con los dos modelos descargados.

Salidas:
    benchmark_results.json  respuestas en crudo de cada modelo
    benchmark_summary.txt   resumen pensado para el TFG
"""

import json
import time
import requests
from pathlib import Path

# ---
# CONFIGURACIÓN
# ---
OLLAMA_URL = "http://localhost:11434/api/generate"

MODELS = {
    "qwen": "qwen2.5:14b-instruct-q4_K_M",
    "llama": "llama3.1:8b-instruct-q4_K_M",
}

# Artículo de prueba sobre BlackSuit ransomware (de DFIR Report, sacado de la BD)
TEST_ARTICLE = """
Title: Fake Zoom Ends in BlackSuit Ransomware

The threat actor gained initial access by a fake Zoom installer that used d3f@ckloader and 
IDAT loader to drop SectopRAT. After nine days of dwell time, the SectopRAT malware dropped 
Cobalt Strike and Brute Ratel. Lateral movement was achieved using various remote services 
and later RDP. To facilitate RDP lateral movement the threat actor employed a malware with 
proxy capabilities known as QDoor. The threat actor used WinRAR to archive various files and 
then upload them to a cloud SaaS application named Bublup. Finally, the threat actor deployed 
and executed BlackSuit ransomware across all Windows systems, using PsExec.

Additional details:
- Initial infection vector: trojanized Zoom installer downloaded from malicious website
- SectopRAT used for reconnaissance and credential harvesting
- Cobalt Strike beacons deployed for C2 communication
- Brute Ratel used as secondary C2 framework
- QDoor malware enabled RDP tunneling across network segments
- WinRAR used to compress sensitive files before exfiltration
- Data exfiltrated to Bublup cloud storage
- BlackSuit ransomware deployed via PsExec to all Windows hosts
- Nine days elapsed between initial access and ransomware deployment
"""

# ---
# DICCIONARIO MITRE ATT&CK REDUCIDO (subset de v15)
# Formato "ID: Nombre" sin descripciones para evitar el efecto lost-in-the-middle.
# Solo se incluyen las tácticas y técnicas más usadas en ransomware.
# ---
MITRE_DICT = """
TACTICS:
TA0001: Initial Access | TA0002: Execution | TA0003: Persistence
TA0004: Privilege Escalation | TA0005: Defense Evasion | TA0006: Credential Access
TA0007: Discovery | TA0008: Lateral Movement | TA0009: Collection
TA0010: Exfiltration | TA0011: Command and Control | TA0040: Impact

TECHNIQUES (selection relevant to ransomware):
T1566: Phishing | T1566.001: Spearphishing Attachment | T1566.002: Spearphishing Link
T1190: Exploit Public-Facing Application | T1195: Supply Chain Compromise
T1078: Valid Accounts | T1133: External Remote Services
T1059: Command and Scripting Interpreter | T1059.001: PowerShell | T1059.003: Windows Command Shell
T1204: User Execution | T1204.001: Malicious Link | T1204.002: Malicious File
T1047: Windows Management Instrumentation | T1053: Scheduled Task/Job
T1543: Create or Modify System Process | T1547: Boot or Logon Autostart Execution
T1548: Abuse Elevation Control Mechanism | T1055: Process Injection
T1027: Obfuscated Files or Information | T1036: Masquerading
T1112: Modify Registry | T1562: Impair Defenses | T1070: Indicator Removal
T1003: OS Credential Dumping | T1003.001: LSASS Memory | T1110: Brute Force
T1555: Credentials from Password Stores | T1552: Unsecured Credentials
T1057: Process Discovery | T1082: System Information Discovery
T1083: File and Directory Discovery | T1135: Network Share Discovery
T1018: Remote System Discovery | T1016: System Network Configuration Discovery
T1021: Remote Services | T1021.001: Remote Desktop Protocol | T1021.002: SMB/Windows Admin Shares
T1021.004: SSH | T1072: Software Deployment Tools | T1080: Taint Shared Content
T1560: Archive Collected Data | T1560.001: Archive via Utility
T1074: Data Staged | T1114: Email Collection | T1056: Input Capture
T1041: Exfiltration Over C2 Channel | T1048: Exfiltration Over Alternative Protocol
T1567: Exfiltration Over Web Service | T1567.002: Exfiltration to Cloud Storage
T1071: Application Layer Protocol | T1071.001: Web Protocols
T1090: Proxy | T1090.001: Internal Proxy | T1095: Non-Application Layer Protocol
T1572: Protocol Tunneling | T1105: Ingress Tool Transfer
T1486: Data Encrypted for Impact | T1489: Service Stop | T1490: Inhibit System Recovery
T1491: Defacement | T1485: Data Destruction | T1657: Financial Theft
"""

# ---
# PROMPT
# ---
def build_prompt(article: str) -> str:
    return f"""You are a cybersecurity analyst specializing in threat intelligence.
Your task is to extract MITRE ATT&CK TTPs from the ransomware incident report below.

RULES:
1. Return ONLY a valid JSON object. No explanation, no markdown, no text before or after.
2. Use ONLY technique IDs from the dictionary provided. Never invent IDs.
3. For each TTP, include: tactic_id, technique_id, subtechnique_id (null if none), confidence (0.0-1.0), evidence_quote (exact phrase from article supporting this TTP, max 20 words).
4. If you observe behaviors not yet in ATT&CK, add them to unmapped_behaviors as plain text.
5. confidence must reflect how explicitly the technique is stated (1.0 = explicitly named, 0.7 = strongly implied, 0.5 = inferred).

MITRE ATT&CK DICTIONARY:
{MITRE_DICT}

JSON SCHEMA (return exactly this structure):
{{
  "ransomware_family": "string",
  "ttps": [
    {{
      "tactic_id": "TA0001",
      "technique_id": "T1566",
      "subtechnique_id": null,
      "confidence": 0.95,
      "evidence_quote": "exact short quote from article"
    }}
  ],
  "unmapped_behaviors": ["description of behavior not in ATT&CK"]
}}

FEW-SHOT EXAMPLE:
Article snippet: "The attacker sent a phishing email with a malicious Excel attachment containing macros."
Expected output:
{{
  "ransomware_family": "unknown",
  "ttps": [
    {{
      "tactic_id": "TA0001",
      "technique_id": "T1566",
      "subtechnique_id": "T1566.001",
      "confidence": 1.0,
      "evidence_quote": "phishing email with a malicious Excel attachment"
    }},
    {{
      "tactic_id": "TA0002",
      "technique_id": "T1059",
      "subtechnique_id": null,
      "confidence": 0.8,
      "evidence_quote": "Excel attachment containing macros"
    }}
  ],
  "unmapped_behaviors": []
}}

NOW EXTRACT FROM THIS ARTICLE:
{article}

Return ONLY the JSON object:"""


# ---
# OLLAMA CLIENT
# ---
def query_ollama(model: str, prompt: str, timeout: int = 300) -> dict:
    """Lanza una consulta a Ollama y devuelve la respuesta junto a las métricas."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,   # Temperatura baja para que la extracción sea determinista.
            "top_p": 0.9,
            "num_predict": 2048,
        }
    }

    start = time.time()
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        elapsed = time.time() - start

        raw_response = data.get("response", "")
        tokens_eval = data.get("eval_count", 0)
        tokens_per_sec = tokens_eval / elapsed if elapsed > 0 else 0

        return {
            "model": model,
            "raw_response": raw_response,
            "elapsed_seconds": round(elapsed, 1),
            "tokens_generated": tokens_eval,
            "tokens_per_second": round(tokens_per_sec, 1),
            "error": None,
        }
    except Exception as e:
        return {
            "model": model,
            "raw_response": "",
            "elapsed_seconds": round(time.time() - start, 1),
            "tokens_generated": 0,
            "tokens_per_second": 0,
            "error": str(e),
        }


# ---
# VALIDACIÓN JSON
# ---
def validate_response(raw: str) -> dict:
    """Intenta parsear el JSON de la respuesta y devuelve un resumen de la validación."""
    result = {
        "valid_json": False,
        "has_ttps": False,
        "ttp_count": 0,
        "has_ransomware_family": False,
        "has_unmapped_behaviors": False,
        "invented_ids": [],
        "parsed": None,
        "parse_error": None,
    }

    # Si el JSON viene envuelto en markdown, lo recortamos.
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    # Intentamos parsear
    try:
        parsed = json.loads(text)
        result["valid_json"] = True
        result["parsed"] = parsed

        # Comprobar que están los campos esperados
        result["has_ransomware_family"] = "ransomware_family" in parsed
        result["has_unmapped_behaviors"] = "unmapped_behaviors" in parsed

        if "ttps" in parsed and isinstance(parsed["ttps"], list):
            result["has_ttps"] = True
            result["ttp_count"] = len(parsed["ttps"])

            # Detectar IDs inventados (chequeo básico de formato)
            import re
            for ttp in parsed["ttps"]:
                tid = ttp.get("technique_id", "")
                tactic = ttp.get("tactic_id", "")
                if tid and not re.match(r'^T\d{4}(\.\d{3})?$', tid):
                    result["invented_ids"].append(f"technique: {tid}")
                if tactic and not re.match(r'^TA\d{4}$', tactic):
                    result["invented_ids"].append(f"tactic: {tactic}")

    except json.JSONDecodeError as e:
        result["parse_error"] = str(e)

    return result


# ---
# MAIN
# ---
def main():
    print("=" * 60)
    print("BENCHMARK: Qwen 2.5 14B vs Llama 3.1 8B")
    print("Tarea: extracción de TTPs MITRE ATT&CK sobre un caso de BlackSuit ransomware")
    print("=" * 60)

    prompt = build_prompt(TEST_ARTICLE)
    print(f"\nPrompt listo ({len(prompt)} caracteres, ~{len(prompt)//4} tokens)\n")

    results = {}

    for name, model_id in MODELS.items():
        print(f"\n{'---'*40}")
        print(f"Ejecutando: {name.upper()} ({model_id})")
        print(f"{'---'*40}")
        print("Generando la respuesta... (puede tardar entre 30 y 120 s)")

        result = query_ollama(model_id, prompt)
        validation = validate_response(result["raw_response"])

        results[name] = {**result, "validation": validation}

        # Mostramos un resumen breve por consola
        if result["error"]:
            print(f"  ERROR: {result['error']}")
        else:
            print(f"   Tiempo: {result['elapsed_seconds']}s")
            print(f"  Tokens generados: {result['tokens_generated']} ({result['tokens_per_second']} tok/s)")
            print(f"  JSON válido: {validation['valid_json']}")
            if validation['valid_json']:
                print(f"   TTPs extraídos: {validation['ttp_count']}")
                print(f"   Familia de ransomware detectada: {validation['has_ransomware_family']}")
                print(f"   IDs inventados: {validation['invented_ids'] or 'ninguno'}")
                if validation['parsed']:
                    fam = validation['parsed'].get('ransomware_family', 'N/A')
                    print(f"   Familia identificada: {fam}")
            else:
                print(f"  Error al parsear: {validation['parse_error']}")
                print("   Primeros 300 caracteres de la respuesta:")
                print(f"     {result['raw_response'][:300]}")

    # --- Guardar las respuestas en crudo
    out_path = Path("benchmark_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n\nRespuestas en crudo guardadas en: {out_path.absolute()}")

    # --- Generar el resumen comparativo
    summary_path = Path("benchmark_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("BENCHMARK SUMMARY Qwen 2.5 14B vs Llama 3.1 8B\n")
        f.write("Artículo: Fake Zoom Ends in BlackSuit Ransomware (DFIR Report)\n")
        f.write("=" * 60 + "\n\n")

        for name, data in results.items():
            f.write(f"MODELO: {name.upper()} ({data['model']})\n")
            f.write(f"  Tiempo de inferencia: {data['elapsed_seconds']}s\n")
            f.write(f"  Velocidad: {data['tokens_per_second']} tokens/s\n")
            v = data["validation"]
            f.write(f"  JSON válido: {v['valid_json']}\n")
            f.write(f"  TTPs extraídos: {v['ttp_count']}\n")
            f.write(f"  IDs inventados: {v['invented_ids'] or 'ninguno'}\n")
            if v["parsed"]:
                f.write(f"  Familia de ransomware: {v['parsed'].get('ransomware_family', 'N/A')}\n")
                f.write("  TTPs en detalle:\n")
                for ttp in v["parsed"].get("ttps", []):
                    sub = ttp.get("subtechnique_id") or ""
                    conf = ttp.get("confidence", "?")
                    quote = ttp.get("evidence_quote", "")[:60]
                    f.write(f"    [{ttp.get('tactic_id')}] {ttp.get('technique_id')}"
                            f"{f'.{sub}' if sub else ''} (conf={conf}) \"{quote}\"\n")
                unmapped = v["parsed"].get("unmapped_behaviors", [])
                if unmapped:
                    f.write("  Comportamientos sin mapear:\n")
                    for b in unmapped:
                        f.write(f"    - {b}\n")
            f.write("\n")

    print(f" Resumen legible guardado en: {summary_path.absolute()}\n")

    # --- Veredicto rápido
    print("=" * 60)
    print("VEREDICTO RÁPIDO")
    print("=" * 60)
    for name, data in results.items():
        v = data["validation"]
        status = "" if v["valid_json"] and v["ttp_count"] > 0 and not v["invented_ids"] else ""
        print(f"{status} {name.upper()}: {v['ttp_count']} TTPs, "
              f"{data['elapsed_seconds']}s, "
              f"IDs inventados: {len(v['invented_ids'])}")


if __name__ == "__main__":
    main()
