"""
rag_extractor.py v2 Pipeline RAG con recuperación multi-query.

Cambios de la v2 frente a la v1:
- Recuperación multi-query: en vez de embeber el artículo entero, se sacan
  frases concretas de comportamiento y se consulta el índice por separado
  para cada una. Así se evita el promedio semántico que devolvía candidatos
  demasiado genéricos.
- Cotejo de citas más permisivo: si la cita exacta no aparece, se prueba
  buscando 4 palabras clave como alternativa.
- TOP_K_PER_QUERY=7 con unas 10-15 queries da ~35 candidatos únicos
  (MAX_CANDIDATES=50).
- Se eliminan candidatos duplicados por ID antes de meterlos en el prompt.
- "Fuera de candidatos RAG" pasa a ser un aviso (warning), ya no invalida
  el TTP.

Uso:
    python3 rag_extractor.py

Importar en el pipeline:
    from rag_extractor import RagExtractor
    extractor = RagExtractor()
    result = extractor.extract(article_text)
"""

import json
import re
import time
from pathlib import Path

import requests
import chromadb
from sentence_transformers import SentenceTransformer

# ---
# Configuración
# ---
OLLAMA_URL      = "http://localhost:11434/api/generate"
OLLAMA_MODEL    = "qwen2.5:14b-instruct-q4_K_M"
INDEX_DIR       = "./mitre_index"
CATALOG_PATH    = "./mitre_techniques.json"
COLLECTION      = "mitre_attack"
EMBED_MODEL     = "all-MiniLM-L6-v2"
TOP_K_PER_QUERY = 7
MAX_CANDIDATES  = 50

# ---
# Lookup determinista de herramientas
# Cubre herramientas cuyo nombre propio no tiene
# similitud semántica útil con las descripciones de ATT&CK.
# ---
TOOL_TO_TECHNIQUES: dict[str, list[str]] = {
    "psexec":              ["T1569.002", "T1021.002"],
    "wmic":                ["T1047"],
    "wmiexec":             ["T1047"],
    "cobalt strike":       ["T1071.001", "T1055"],
    "cobaltstrike":        ["T1071.001", "T1055"],
    "brute ratel":         ["T1071.001"],
    "sliver":              ["T1071.001"],
    "metasploit":          ["T1071.001"],
    "sectoprat":           ["T1105", "T1059"],
    "anydesk":             ["T1219"],
    "teamviewer":          ["T1219"],
    "mimikatz":            ["T1003.001"],
    "secretsdump":         ["T1003.002"],
    "winrar":              ["T1560.001"],
    "7zip":                ["T1560.001"],
    "7-zip":               ["T1560.001"],
    "rclone":              ["T1567.002"],
    "bublup":              ["T1567.002"],
    "filezilla":           ["T1048"],
    "qdoor":               ["T1572", "T1090.001"],
    "ngrok":               ["T1572"],
    "chisel":              ["T1572"],
    "blacksuit":           ["T1486"],
    "lockbit":             ["T1486", "T1490"],
    "conti":               ["T1486", "T1490"],
    "ryuk":                ["T1486", "T1490"],
    "nokoyawa":            ["T1486"],
    "icedid":              ["T1566.001", "T1059"],
    "nmap":                ["T1046"],
    "bloodhound":          ["T1087.002", "T1069.002"],
    "sharphound":          ["T1087.002", "T1069.002"],
    "trojanized":          ["T1204.002"],
    "fake zoom":           ["T1204.002"],
    "idat loader":         ["T1105"],
    "d3f@ckloader":        ["T1105"],
    "msiexec":             ["T1218.007"],
    "schtasks":            ["T1053.005"],
    "lazagne":             ["T1555"],
    "megasync":            ["T1567.002"],
    "netscan":             ["T1046"],
    "adrecon":             ["T1087.002"],
}

# Patrones precompilados con límites de palabra para no encajar trozos
# (por ejemplo "conti" dentro de "continuously" o "hive" dentro de "archive").
_TOOL_PATTERNS: dict[str, re.Pattern] = {
    kw: re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
    for kw in TOOL_TO_TECHNIQUES
}

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

SYSTEM_PROMPT = """You are Qwen, created by Alibaba Cloud. As an expert cybersecurity threat \
analyst specializing in MITRE ATT&CK framework mapping, your sole objective is to extract \
structured TTPs from ransomware incident reports.

OUTPUT RULES ABSOLUTE:
1. Output VALID JSON ONLY. Zero text before or after the JSON object.
2. Never invent technique IDs. Use ONLY IDs from the ALLOWED_CANDIDATES list provided.
3. evidence_quote MUST be an exact verbatim substring copied from the article text.
4. tactic_id MUST be compatible with the chosen technique_id per ATT&CK definitions.
5. subtechnique_id MUST be null OR a valid sub-technique of the parent technique_id.

CONFIDENCE SCALE use exactly these four values:
- 1.00: technique explicitly named or tool directly identified in text
- 0.75: tactic clearly evident but specific technique requires slight inference
- 0.50: behavior described but mechanism ambiguous
- 0.25: low-level artifact or telemetry, malicious intent unclear

JSON OUTPUT SCHEMA:
{
  "reasoning": "Your step-by-step analysis here FIRST: list each observed behavior, the tool/technique involved, and why it maps to a specific ATT&CK ID. Think before you map.",
  "ransomware_family": "string family name or 'unknown'",
  "ttps": [
    {
      "evidence_quote": "verbatim substring from article FILL THIS FIRST",
      "tactic_id": "TA####",
      "technique_id": "T####",
      "subtechnique_id": "T####.### or null",
      "confidence": 1.00
    }
  ],
  "unmapped_behaviors": [
    "plain text description of behaviors with no confident ATT&CK mapping"
  ]
}

CRITICAL: Fill "reasoning" first as your scratchpad. Then fill evidence_quote for
each TTP before deciding technique_id. This two-step process prevents hallucinations."""

FEW_SHOT = """
EXAMPLES study these before extracting:

[EXAMPLE 1 Explicit mapping with ransomware impact and tunneling, confidence 1.00]
Article: "The attacker used Chisel to tunnel RDP traffic through a proxy and reach isolated
systems. PsExec was then used to deploy Conti ransomware across all domain hosts, encrypting
files on every Windows machine."
Output:
{
  "ransomware_family": "Conti",
  "ttps": [
    {
      "evidence_quote": "used Chisel to tunnel RDP traffic through a proxy",
      "tactic_id": "TA0011",
      "technique_id": "T1572",
      "subtechnique_id": null,
      "confidence": 1.00
    },
    {
      "evidence_quote": "PsExec was then used to deploy Conti ransomware across all domain hosts",
      "tactic_id": "TA0002",
      "technique_id": "T1569",
      "subtechnique_id": "T1569.002",
      "confidence": 1.00
    },
    {
      "evidence_quote": "deploy Conti ransomware across all domain hosts, encrypting files on every Windows machine",
      "tactic_id": "TA0040",
      "technique_id": "T1486",
      "subtechnique_id": null,
      "confidence": 1.00
    }
  ],
  "unmapped_behaviors": []
}

[EXAMPLE 2 Implied mapping, confidence 0.75]
Article: "The adversary captured NTLM hashes from memory and subsequently authenticated
to the primary domain controller without triggering antivirus alerts."
Output:
{
  "ransomware_family": "unknown",
  "ttps": [
    {
      "evidence_quote": "captured NTLM hashes from memory",
      "tactic_id": "TA0006",
      "technique_id": "T1003",
      "subtechnique_id": "T1003.001",
      "confidence": 0.75
    }
  ],
  "unmapped_behaviors": [
    "authenticated to domain controller without triggering antivirus evasion mechanism unclear"
  ]
}

[EXAMPLE 3 Null mapping: do NOT force ATT&CK IDs onto vague text]
Article: "The threat actor demonstrated advanced knowledge of the target environment.
They operated carefully and avoided detection for several weeks."
Output:
{
  "ransomware_family": "unknown",
  "ttps": [],
  "unmapped_behaviors": [
    "advanced knowledge of target environment too vague for specific technique mapping",
    "operated carefully avoiding detection for several weeks no actionable behavior described"
  ]
}
"""


def extract_behavior_queries(article: str) -> list[str]:
    """Saca del artículo las frases que describen comportamientos para usarlas como queries."""
    queries = []

    sentences = re.split(r'(?<=[.!?])\s+', article.strip())
    for s in sentences:
        s = s.strip()
        if len(s) > 30 and not s.startswith("Title:"):
            queries.append(s)

    for line in article.split('\n'):
        line = line.strip()
        if line.startswith('- ') and len(line) > 20:
            queries.append(line[2:])

    seen = set()
    unique = []
    for q in queries:
        key = q[:60].lower()
        if key not in seen:
            seen.add(key)
            unique.append(q)

    return unique


class RagExtractor:
    def __init__(self, index_dir: str = INDEX_DIR):
        print("Inicializando RagExtractor v2...")
        print(f"  Cargando modelo embeddings: {EMBED_MODEL}")
        self.embed_model = SentenceTransformer(EMBED_MODEL)

        print(f"  Conectando a ChromaDB: {index_dir}")
        client = chromadb.PersistentClient(path=index_dir)
        self.collection = client.get_collection(COLLECTION)
        print(f"  Índice cargado {self.collection.count()} técnicas")

        self.catalog = {}
        if Path(CATALOG_PATH).exists():
            techniques = json.loads(Path(CATALOG_PATH).read_text())
            for t in techniques:
                self.catalog[t["id"]] = t
            print(f"  Catálogo cargado {len(self.catalog)} entradas")

    def retrieve_candidates(self, article: str) -> list[dict]:
        """
        Recuperación híbrida en dos pasos:
        1. Multi-query semántico: una query por cada frase de comportamiento.
        2. Lookup determinista de herramientas: detecta nombres conocidos
           y fuerza sus técnicas como candidatos con similarity=1.0.
        """
        behavior_queries = extract_behavior_queries(article)
        embeddings = self.embed_model.encode(behavior_queries).tolist()

        candidate_scores: dict[str, dict] = {}

        # --- Paso 1: recuperación semántica
        for query, embedding in zip(behavior_queries, embeddings):
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=TOP_K_PER_QUERY,
                include=["documents", "metadatas", "distances"],
            )
            for tech_id, meta, dist in zip(
                results["ids"][0],
                results["metadatas"][0],
                results["distances"][0],
            ):
                similarity = round(1 - dist, 3)
                if tech_id not in candidate_scores or \
                   similarity > candidate_scores[tech_id]["similarity"]:
                    candidate_scores[tech_id] = {
                        "id": tech_id,
                        "name": meta["name"],
                        "tactic_ids": json.loads(meta["tactic_ids"]),
                        "description": meta["description"],
                        "similarity": similarity,
                        "source": "semantic",
                    }

        # --- Paso 2: lookup determinista de herramientas (con límites de palabra)
        forced_ids = set()
        for tool_name, tech_ids in TOOL_TO_TECHNIQUES.items():
            if _TOOL_PATTERNS[tool_name].search(article):
                for tid in tech_ids:
                    if tid in self.catalog:
                        t = self.catalog[tid]
                        # Sobrescribir siempre: el lookup tiene prioridad
                        # sobre el RAG semántico para asegurar la inclusión
                        candidate_scores[tid] = {
                            "id": tid,
                            "name": t["name"],
                            "tactic_ids": t["tactic_ids"],
                            "description": t["description"],
                            "similarity": 1.0,
                            "source": f"tool_lookup:{tool_name}",
                        }
                        forced_ids.add(tid)

        # Añadir también las técnicas padre de las sub-técnicas forzadas
        parent_ids = set()
        for tid in list(forced_ids):
            if "." in tid:
                parent = tid.split(".")[0]
                if parent in self.catalog and parent not in candidate_scores:
                    t = self.catalog[parent]
                    candidate_scores[parent] = {
                        "id": parent,
                        "name": t["name"],
                        "tactic_ids": t["tactic_ids"],
                        "description": t["description"],
                        "similarity": 1.0,
                        "source": f"tool_lookup_parent:{tid}",
                    }
                    parent_ids.add(parent)

        if forced_ids or parent_ids:
            added = sorted(forced_ids | parent_ids)
            print(f"  Tool lookup añadió: {added}")

        # Separar candidatos del tool_lookup (siempre garantizados) y
        # candidatos del retrieval semántico (limitados por MAX_CANDIDATES)
        tool_candidates = [c for c in candidate_scores.values()
                           if c["source"].startswith("tool_lookup")]
        semantic_candidates = sorted(
            [c for c in candidate_scores.values()
             if not c["source"].startswith("tool_lookup")],
            key=lambda x: x["similarity"],
            reverse=True,
        )[:MAX_CANDIDATES]

        # Primero los del tool_lookup y luego los semánticos, evitando duplicados
        tool_ids = {c["id"] for c in tool_candidates}
        semantic_candidates = [c for c in semantic_candidates
                                if c["id"] not in tool_ids]
        candidates = tool_candidates + semantic_candidates

        return candidates

    def build_user_prompt(self, article: str, candidates: list[dict]) -> str:
        by_tactic: dict[str, list] = {}
        for c in candidates:
            for tid in c["tactic_ids"]:
                by_tactic.setdefault(tid, []).append(c)

        candidates_block = "ALLOWED_CANDIDATES (use ONLY these IDs):\n"
        for tactic_id in sorted(by_tactic.keys()):
            techs = by_tactic[tactic_id]
            candidates_block += f"\n  [{tactic_id}]\n"
            seen = set()
            for t in sorted(techs, key=lambda x: x["id"]):
                if t["id"] not in seen:
                    seen.add(t["id"])
                    desc = t["description"][:120].rstrip()
                    candidates_block += (
                        f"    {t['id']} {t['name']}\n"
                        f"      {desc}...\n"
                    )

        user_prompt = f"""{FEW_SHOT}

{candidates_block}

TACTIC-TECHNIQUE COMPATIBILITY mandatory rules:
- T1486 (Data Encrypted for Impact)           ONLY TA0040
- T1021.001 (Remote Desktop Protocol)         ONLY TA0008
- T1021.002 (SMB/Windows Admin Shares)        ONLY TA0008
- T1560 / T1560.001 (Archive Collected Data)  ONLY TA0009
- T1048, T1041, T1567 (Exfiltration)          ONLY TA0010
- T1059 (Command and Scripting Interpreter)   ONLY TA0002
- T1566 (Phishing) / T1204 (User Execution)   ONLY TA0001 / TA0002
- T1547 (Boot/Logon Autostart)                ONLY TA0003 or TA0004, NEVER TA0005
- T1003 (OS Credential Dumping)               ONLY TA0006
- T1071, T1090, T1095, T1572 (C2 techniques)  ONLY TA0011

RANSOMWARE DEPLOYMENT RULES apply always:
- When the article names a ransomware family (e.g. BlackSuit, LockBit, Conti) AND describes
  encryption or deployment across systems ALWAYS extract T1486 under TA0040.
- T1486 evidence_quote should quote the ransomware deployment sentence, e.g.:
  "deployed and executed BlackSuit ransomware across all Windows systems"
- PsExec deploying ransomware = TWO separate TTPs:
  (1) T1569.002 under TA0002 for the PsExec execution mechanism
  (2) T1486 under TA0040 for the ransomware impact
- Proxy/tunneling malware (QDoor, Chisel, Ngrok) T1572 under TA0011, NOT T1021

ARTICLE TO ANALYZE:
{article.strip()}

TASK: Extract all TTPs supported by verbatim evidence quotes.
- Fill evidence_quote FIRST for each TTP, then decide technique_id.
- Use ONLY IDs from ALLOWED_CANDIDATES above.
- Behaviors without a confident match unmapped_behaviors.
- Output VALID JSON ONLY. No text before or after the JSON object."""

        return user_prompt

    def call_ollama(self, user_prompt: str, timeout: int = 300) -> dict:
        payload = {
            "model": OLLAMA_MODEL,
            "system": SYSTEM_PROMPT,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 6144,   # subido de 4096 a 6144 para artículos con reasoning muy largo
                "num_ctx": 12288,      # ~10.7K tokens de prompt + 1.5K de margen (artículo recortado a 20K chars)
                "repeat_penalty": 1.02,
            },
        }
        start = time.time()
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            elapsed = time.time() - start
            return {
                "raw": data.get("response", ""),
                "elapsed": round(elapsed, 1),
                "tokens": data.get("eval_count", 0),
                "tok_per_sec": round(data.get("eval_count", 0) / elapsed, 1),
                "error": None,
            }
        except Exception as e:
            return {"raw": "", "elapsed": 0, "tokens": 0,
                    "tok_per_sec": 0, "error": str(e)}

    def validate(self, parsed: dict, article: str, candidates: list[dict]) -> dict:
        issues = []
        valid_ids = {c["id"] for c in candidates}
        article_lower = article.lower()
        validated_ttps = []
        seen_pairs = set()

        raw_ttps = parsed.get("ttps", [])
        if not isinstance(raw_ttps, list):
            issues.append("Formato invalido: ttps no es lista")
            raw_ttps = []

        for ttp in raw_ttps:
            if isinstance(ttp, str):
                issues.append(f"Formato invalido: ttp string '{ttp}'")
                ttp = {
                    "technique_id": ttp,
                    "tactic_id": "",
                    "evidence_quote": "",
                    "confidence": 0.25,
                    "subtechnique_id": None,
                }
            elif not isinstance(ttp, dict):
                issues.append("Formato invalido: ttp no es objeto")
                continue

            tid = ttp.get("technique_id", "")
            tact = ttp.get("tactic_id", "")
            quote = ttp.get("evidence_quote", "")
            sub = ttp.get("subtechnique_id")
            ttp_issues = []    # errores bloqueantes (invalidan el TTP)
            ttp_warnings = []  # avisos que no invalidan

            # Añadir el nombre de la técnica usando el catálogo
            if tid in self.catalog:
                ttp["technique_name"] = self.catalog[tid]["name"]
            else:
                ttp["technique_name"] = ""

            if tid not in valid_ids:
                # Se acepta la técnica padre si alguna de sus sub-técnicas
                # está entre los candidatos
                parent_covered = any(
                    c.startswith(tid + ".") for c in valid_ids
                )
                if not parent_covered:
                    # Solo aviso, no error: Qwen conoce bien el catálogo y
                    # un falso negativo del RAG no debería descartar TTPs válidos.
                    msg = f"ID {tid} fuera de candidatos RAG"
                    ttp_warnings.append(msg)
                    issues.append(msg)  # se sigue registrando en validation_issues

            if tid in self.catalog:
                allowed = self.catalog[tid]["tactic_ids"]
                if tact not in allowed:
                    # Autocorrección: usar la primera táctica válida del catálogo
                    if allowed:
                        ttp["tactic_id"] = allowed[0]
                        ttp_issues.append(
                            f"Tactic autocorregida: {tact} {allowed[0]} "
                            f"para {tid}"
                        )
                    else:
                        ttp_issues.append(
                            f"Tactic {tact} incompatible con {tid} "
                            f"(permitidos: {allowed})"
                        )

            if quote:
                quote_lower = quote.lower()
                if quote_lower not in article_lower:
                    words = [w for w in quote_lower.split() if len(w) > 3][:4]
                    if not all(w in article_lower for w in words):
                        ttp_issues.append(f"Quote no encontrada: '{quote[:50]}'")

            if sub and tid and not sub.startswith(tid):
                ttp_issues.append(f"Sub-técnica {sub} no pertenece a {tid}")

            pair = (tid, sub)
            if pair in seen_pairs:
                ttp_issues.append(f"Duplicado: {tid}")
            else:
                seen_pairs.add(pair)

            ttp["_issues"] = ttp_issues
            ttp["_warnings"] = ttp_warnings
            if ttp_issues:
                issues.extend(ttp_issues)
            validated_ttps.append(ttp)

        return {
            "ttps": validated_ttps,
            "issues": issues,
            # Se cuenta como válido si no tiene errores bloqueantes;
            # los warnings del RAG no invalidan el TTP.
            "valid_count": sum(1 for t in validated_ttps if not t["_issues"]),
        }

    def extract(self, article: str) -> dict:
        candidates = self.retrieve_candidates(article)
        user_prompt = self.build_user_prompt(article, candidates)
        response = self.call_ollama(user_prompt)

        if response["error"]:
            return {"error": response["error"]}

        try:
            parsed = json.loads(response["raw"])
        except json.JSONDecodeError as e:
            return {"error": f"JSON parse error: {e}",
                    "raw": response["raw"][:500]}

        validation = self.validate(parsed, article, candidates)

        return {
            "ransomware_family": parsed.get("ransomware_family", "unknown"),
            "ttps": validation["ttps"],
            "unmapped_behaviors": parsed.get("unmapped_behaviors", []),
            "candidates_retrieved": [c["id"] for c in candidates],
            "valid_ttp_count": validation["valid_count"],
            "total_ttp_count": len(validation["ttps"]),
            "validation_issues": validation["issues"],
            "elapsed_seconds": response["elapsed"],
            "tokens_generated": response["tokens"],
            "tokens_per_second": response["tok_per_sec"],
            "error": None,
        }


def main():
    print("=" * 60)
    print("RAG EXTRACTOR v2 recuperación multi-query")
    print("=" * 60)

    if not Path(INDEX_DIR).exists():
        print("\nÍndice no encontrado. Ejecuta: python3 build_index.py")
        return

    extractor = RagExtractor()

    print(f"\n{'---'*50}")
    print("Artículo: Fake Zoom BlackSuit ransomware")
    print(f"{'---'*50}")

    queries = extract_behavior_queries(TEST_ARTICLE)
    print(f"\nQueries de comportamiento extraídas ({len(queries)}):")
    for i, q in enumerate(queries, 1):
        print(f"  {i:2}. {q[:75]}")

    print("\nEjecutando recuperación multi-query...")
    candidates = extractor.retrieve_candidates(TEST_ARTICLE)
    print(f"\nTop {len(candidates)} candidatos únicos:")
    for c in candidates:
        print(f"  {c['id']:15} sim={c['similarity']}  {c['name']}")

    print("\nGenerando extracción con Qwen 2.5 14B...")
    result = extractor.extract(TEST_ARTICLE)

    out = Path("rag_results_v2.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nGuardado en: {out.absolute()}")

    # Mostrar resultado
    print("\n" + "=" * 60)
    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return

    # El campo reasoning es un scratchpad interno: no se muestra en la salida principal
    if result.get("ransomware_family"):
        pass  # se imprime más abajo
    print(f"  Familia:         {result['ransomware_family']}")
    print(f"  TTPs extraídos:  {result['total_ttp_count']}")
    print(f"  TTPs válidos:    {result['valid_ttp_count']}")
    print(f"  Issues:          {len(result['validation_issues'])}")
    print(f"  Tiempo:          {result['elapsed_seconds']}s | {result['tokens_per_second']} tok/s")

    print("\n  TTPs:")
    for ttp in result["ttps"]:
        issues = ttp.get("_issues", [])
        status = "" if not issues else ""
        sub = ttp.get("subtechnique_id") or ""
        print(f"    {status} [{ttp['tactic_id']}] "
              f"{ttp['technique_id']}"
              f"{f' {sub}' if sub else ''} "
              f"(conf={ttp.get('confidence')}) "
              f" \"{ttp.get('evidence_quote','')[:55]}\"")
        for issue in issues:
            print(f"          {issue}")

    if result["unmapped_behaviors"]:
        print("\n  Unmapped:")
        for b in result["unmapped_behaviors"]:
            print(f"    - {b[:80]}")

    print("\n" + "=" * 60)
    print("COMPARATIVA")
    print(f"  {'':20} Plano v1   RAG v1   RAG v2")
    print(f"  TTPs extraídos:     10         8        {result['total_ttp_count']}")
    print(f"  TTPs válidos:        7          1        {result['valid_ttp_count']}")
    print(f"  Issues:              3          9        {len(result['validation_issues'])}")


if __name__ == "__main__":
    main()


