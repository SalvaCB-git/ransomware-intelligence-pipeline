"""
prefilter.py Prefiltro de artículos antes de que el LLM extraiga TTPs.

Estructura en dos niveles encadenados:
  Nivel 1: Heurísticas deterministas (coste casi cero, O(n)).
  Nivel 2: Similitud coseno contra el índice ChromaDB de MITRE ATT&CK.

Uso como módulo:
    from prefilter import filter_article, filter_batch

Uso directo (prueba con una muestra de 50 artículos):
    python prefilter.py [--db PATH] [--threshold 0.40] [--sample 50] [--no-level2]

Diseño: prima el recall sobre la precisión. Es mejor un falso positivo
que perder un TTP.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sqlite3
import sys
import textwrap
from pathlib import Path

# ---
# Constantes configurables
# ---
MIN_WORDS: int = 200                # Mínimo de palabras para no descartar el artículo de entrada
COSINE_THRESHOLD: float = 0.55      # Umbral calibrado sobre una muestra de 300 artículos
                                    # (2026-03-20): con 0.40 no descartaba nada (mín. observado 0.44).
                                    # Con 0.55 descarta ~22% (marketing, notas de prensa sin TTPs).
CHUNK_SIZE_WORDS: int = 187         # Aproximadamente 250 tokens con all-MiniLM-L6-v2

# Directorio del proyecto (donde están mitre_index/ y mitre_techniques.json)
PROJECT_DIR = Path(__file__).parent

# ---
# Vocabulario base de ATT&CK más términos extraídos del catálogo MITRE
# ---
_ATTACK_BASE_TERMS: list[str] = [
    # Verbos de acción
    "execute", "inject", "exfiltrate", "encrypt", "persist", "escalate",
    "lateral", "credential", "dump", "spawn", "payload", "backdoor",
    # Herramientas y binarios comunes
    "powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32",
    "rundll32", "certutil", "bitsadmin", "wmic", "schtasks", "at.exe",
    "net.exe", "nltest", "whoami", "ipconfig", "arp", "nmap", "netstat",
    # Componentes del sistema
    "registry", "scheduled task", "scheduled tasks", "windows service",
    "lsass", "sam database", "ntds", "active directory", "domain controller",
    "group policy", "startup folder", "autorun", "run key",
    # Técnicas MITRE frecuentes
    "process injection", "dll injection", "dll sideloading", "dll hijacking",
    "process hollowing", "token impersonation", "pass the hash", "pass the ticket",
    "kerberoasting", "golden ticket", "silver ticket", "dcsync",
    "living off the land", "lolbas", "fileless", "reflective loading",
    "lateral movement", "remote service", "smb", "rdp", "winrm", "wmi",
    "command and control", "c2", "c&c", "beaconing", "cobalt strike",
    "metasploit", "empire", "meterpreter", "sliver", "brute ratel",
    # Herramientas de exfiltración/compresión
    "psexec", "winrar", "7zip", "7-zip", "rclone", "robocopy",
    "mimikatz", "procdump", "lsadump", "secretsdump", "impacket",
    # Familias ransomware / actores
    "ransomware", "lockbit", "blacksuit", "conti", "ryuk", "revil",
    "alphv", "blackcat", "cl0p", "clop", "akira", "play", "royal",
    "darkside", "maze", "ragnar", "hive", "cuba", "vice society",
    "nokoyawa", "medusa", "hunters international", "rhysida",
    # Fases kill chain
    "initial access", "execution", "persistence", "privilege escalation",
    "defense evasion", "credential access", "discovery", "collection",
    "exfiltration", "impact", "reconnaissance", "resource development",
    # Conceptos técnicos de TTP
    "vulnerability", "exploit", "cve", "zero day", "zero-day", "rce",
    "remote code execution", "arbitrary code", "buffer overflow",
    "phishing", "spearphishing", "vishing", "smishing", "malicious attachment",
    "malicious link", "drive-by", "watering hole",
    "command line", "obfuscation", "base64", "encoded command",
    "anti-forensics", "log clearing", "event log", "vss", "shadow copy",
    "double extortion", "data theft", "leak site", "name and shame",
    "bitcoin", "monero", "cryptocurrency", "ransom note", "decryptor",
    "backup deletion", "volume shadow", "wbadmin", "bcdedit",
    # IoC-adjacent (sin ser IoC puros)
    "indicator of compromise", "ioc", "ttps", "mitre att&ck",
    "tactic", "technique", "sub-technique",
]


def _load_attck_vocab_from_json() -> set[str]:
    """
    Carga los nombres de técnicas MITRE de mitre_techniques.json que tengan
    al menos dos palabras (frases específicas como "command and scripting
    interpreter"). Antes se añadían palabras sueltas sacadas de nombres y
    descripciones, lo que colaba términos genéricos como "tool", "file",
    "page" o "increase" en el vocabulario y disparaba falsos hits en el
    contador attck_terms_hit del prefilter.
    """
    json_path = PROJECT_DIR / "mitre_techniques.json"
    if not json_path.exists():
        return set()

    try:
        techniques = json.loads(json_path.read_text(encoding="utf-8"))
        extra: set[str] = set()
        for tech in techniques:
            name = (tech.get("name") or "").strip()
            if name and len(name.split()) >= 2:
                extra.add(name.lower())
        return extra
    except (json.JSONDecodeError, KeyError, TypeError):
        return set()


# Vocabulario final consolidado (se carga al importar, coste único)
_ATTACK_VOCAB: set[str] = set(_ATTACK_BASE_TERMS) | _load_attck_vocab_from_json()

# ---
# TOOL_MAP reutilizado desde rag_extractor.py.
# Para la regla de herramientas solo hacen falta las claves (los nombres).
# ---
_TOOL_NAMES: set[str] = {
    # RATs y frameworks C2
    "cobalt strike", "cobaltstrike", "metasploit", "meterpreter",
    "empire", "sliver", "brute ratel", "havoc", "nimplant",
    "nighthawk", "poshc2", "covenant", "mythic", "merlin",
    # Credential dumping
    "mimikatz", "rubeus", "kekeo", "safetykatz", "pypykatz",
    "lazagne", "procdump", "nanodump",
    # Lateral movement / execution
    "psexec", "impacket", "wmiexec", "smbexec", "atexec",
    "crackmapexec", "cme", "evil-winrm", "evil winrm",
    # Recon / discovery
    "bloodhound", "sharphound", "adrecon", "powerview", "sharpview",
    "nmap", "masscan", "zmap", "shodan", "censys",
    # Exfiltración / compresión
    "rclone", "winrar", "7zip", "7-zip", "winscp", "filezilla",
    "megasync", "robocopy", "xcopy",
    # Cifrado / ransomware payloads
    "lockbit", "blacksuit", "conti", "ryuk", "revil", "sodinokibi",
    "alphv", "blackcat", "cl0p", "clop", "akira", "play", "royal",
    "darkside", "maze", "ragnar", "hive", "cuba", "vice society",
    "nokoyawa", "medusa", "rhysida",
    # Loaders / droppers
    "qbot", "qakbot", "emotet", "icedid", "bumblebee", "gootkit",
    "dridex", "trickbot", "bazarloader", "bazarbackdoor",
    "systembc", "anydesk", "atera", "screenconnect",
    # VSS / defensa
    "vssadmin", "wbadmin", "bcdedit", "powertool", "gmer",
    "processguard", "defender exclusion",
}

# ---
# Regex precompilados para la regla de IoCs del Nivel 1
# ---
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Hashes: MD5 (32), SHA1 (40) y SHA256 (64); solo secuencias hexadecimales puras
_RE_HASH = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")

# IPv4: cuatro octetos en el rango 0-255
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Dominios "defanged": hxxp://, hxxps://, [.]com, [.]net, [.]org, [.]io...
_RE_DEFANGED = re.compile(
    r"hxxps?://|"                        # hxxp:// y hxxps://
    r"\[\.\](?:com|net|org|io|gov|edu|co|uk|ru|cn|de)\b|"  # [.]tld
    r"(?:com|net|org|io|gov)\[at\]|"    # dominio[at]tld (raro pero documentado)
    r"\[dot\](?:com|net|org|io|gov)",    # [dot]tld
    re.IGNORECASE,
)


# ---
# Nivel 1: heurísticas deterministas
# ---
def _check_ioc_rule(body: str) -> bool:
    """Devuelve True si el cuerpo del artículo contiene al menos un IoC."""
    if _RE_CVE.search(body):
        return True
    if _RE_HASH.search(body):
        return True
    if _RE_IPV4.search(body):
        return True
    if _RE_DEFANGED.search(body):
        return True
    return False


def _find_ioc_hits(body: str) -> list[str]:
    """Devuelve la lista de IoCs detectados (CVEs, hashes, IPs, dominios defanged)."""
    hits: list[str] = []
    hits.extend(_RE_CVE.findall(body))
    hits.extend(_RE_HASH.findall(body))
    hits.extend(_RE_IPV4.findall(body))
    hits.extend(_RE_DEFANGED.findall(body))
    return list(dict.fromkeys(hits))  # dedup conservando el orden


def _check_attck_vocab_rule(body_lower: str) -> bool:
    """
    Devuelve True si el cuerpo contiene al menos 2 términos del vocabulario ATT&CK.
    El umbral es 2 (no 1) porque términos muy cortos como 'cmd' aparecen en
    cualquier texto y darían demasiados falsos positivos.
    """
    count = 0
    for term in _ATTACK_VOCAB:
        if term in body_lower:
            count += 1
            if count >= 2:
                return True
    return False


def _find_attck_term_hits(body_lower: str) -> list[str]:
    """Devuelve la lista de términos ATT&CK y herramientas detectados."""
    hits: list[str] = []
    for term in _ATTACK_VOCAB:
        if term in body_lower:
            hits.append(term)
    for tool in _TOOL_NAMES:
        if tool in body_lower and tool not in hits:
            hits.append(tool)
    return hits


def _check_tools_rule(body_lower: str) -> bool:
    """Devuelve True si el cuerpo menciona al menos una herramienta de _TOOL_NAMES."""
    for tool in _TOOL_NAMES:
        if tool in body_lower:
            return True
    return False


def _run_level1(body: str) -> dict:
    """
    Aplica las heurísticas del Nivel 1.

    Devuelve un dict con:
      - passed: bool
      - reason: str ("short" | "no_heuristic" | "level1_ok")
      - triggered: list[str]  reglas que han disparado
      - word_count: int
    """
    words = body.split()
    word_count = len(words)

    if word_count < MIN_WORDS:
        return {
            "passed": False,
            "reason": "short",
            "triggered": [],
            "word_count": word_count,
            "ioc_hits": [],
            "attck_terms_hit": [],
        }

    body_lower = body.lower()
    triggered: list[str] = []

    if _check_ioc_rule(body):
        triggered.append("ioc")
    if _check_attck_vocab_rule(body_lower):
        triggered.append("attck_vocab")
    if _check_tools_rule(body_lower):
        triggered.append("tools")

    ioc_hits = _find_ioc_hits(body)
    attck_terms_hit = _find_attck_term_hits(body_lower)

    if triggered:
        return {
            "passed": True,
            "reason": "level1_ok",
            "triggered": triggered,
            "word_count": word_count,
            "ioc_hits": ioc_hits,
            "attck_terms_hit": attck_terms_hit,
        }
    else:
        return {
            "passed": False,
            "reason": "no_heuristic",
            "triggered": [],
            "word_count": word_count,
            "ioc_hits": ioc_hits,
            "attck_terms_hit": attck_terms_hit,
        }


# ---
# Nivel 2: similitud coseno contra ChromaDB
# ---
def _chunk_body(body: str, chunk_size: int = CHUNK_SIZE_WORDS) -> list[str]:
    """
    Trocea el cuerpo en chunks de aproximadamente chunk_size palabras,
    con solapamiento mínimo. Siempre devuelve al menos un chunk, incluso
    si el body está vacío.
    """
    words = body.split()
    if not words:
        return [body]

    chunks: list[str] = []
    for i in range(0, len(words), chunk_size):
        chunk = " ".join(words[i : i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
    return chunks if chunks else [body]


def _run_level2(
    body: str,
    collection,
    threshold: float = COSINE_THRESHOLD,
    model=None,
) -> dict:
    """
    Calcula la similitud coseno del artículo contra ChromaDB.

    Usa query_embeddings (embeddings precalculados) en lugar de query_texts
    para no chocar con la función de embedding guardada en la colección.

    Devuelve un dict con:
      - passed: bool
      - reason: str ("low_similarity" | "passed")
      - max_similarity: float
    """
    chunks = _chunk_body(body)
    max_sim = 0.0

    for chunk in chunks:
        try:
            if model is not None:
                # Embebemos el chunk a mano y usamos query_embeddings
                embedding = model.encode(chunk, normalize_embeddings=True).tolist()
                results = collection.query(
                    query_embeddings=[embedding],
                    n_results=1,
                    include=["distances"],
                )
            else:
                # Plan B: dejar que ChromaDB calcule el embedding
                # (puede fallar si hay conflicto con la función almacenada)
                results = collection.query(
                    query_texts=[chunk],
                    n_results=1,
                    include=["distances"],
                )

            # En ChromaDB con métrica coseno: distance = 1 - cosine_similarity.
            # Recortamos al rango [0, 1] para evitar desvíos por coma flotante.
            if results and results.get("distances") and results["distances"][0]:
                distance = results["distances"][0][0]
                similarity = max(0.0, min(1.0, 1.0 - distance))
                if similarity > max_sim:
                    max_sim = similarity
        except Exception:
            # Si falla la query de un chunk, seguimos con el siguiente
            continue

    if max_sim >= threshold:
        return {"passed": True, "reason": "passed", "max_similarity": max_sim}
    else:
        return {"passed": False, "reason": "low_similarity", "max_similarity": max_sim}


# ---
# API pública
# ---
def filter_article(
    body: str,
    chroma_client=None,
    collection=None,
    cosine_threshold: float = COSINE_THRESHOLD,
    model=None,
) -> dict:
    """
    Filtra un artículo aplicando los dos niveles.

    Args:
        body: Texto completo del artículo.
        chroma_client: Modelo SentenceTransformer (mantenido por compatibilidad de API).
        collection: Colección ChromaDB ya abierta. Si es None, se salta el Nivel 2.
        cosine_threshold: Umbral de similitud coseno. Por defecto COSINE_THRESHOLD.
        model: Alias de chroma_client. Vale en cualquiera de las dos posiciones.

    Returns:
        {
            "pass": bool,
            "reason": str,           # "short" | "no_heuristic" | "low_similarity" | "passed"
            "level1_triggered": list[str],
            "max_similarity": float | None,
            "word_count": int,
        }
    """
    # chroma_client es en realidad el modelo SentenceTransformer (compatibilidad de API)
    embed_model = model or chroma_client

    # Nivel 1
    l1 = _run_level1(body)

    if not l1["passed"]:
        return {
            "pass": False,
            "reason": l1["reason"],
            "level1_triggered": l1["triggered"],
            "max_similarity": None,
            "word_count": l1["word_count"],
            "ioc_hits": l1.get("ioc_hits", []),
            "attck_terms_hit": l1.get("attck_terms_hit", []),
        }

    # Nivel 2 solo si hay una colección disponible
    if collection is None:
        # Sin Nivel 2, el artículo pasa con que supere el Nivel 1
        return {
            "pass": True,
            "reason": "passed",
            "level1_triggered": l1["triggered"],
            "max_similarity": None,
            "word_count": l1["word_count"],
            "ioc_hits": l1.get("ioc_hits", []),
            "attck_terms_hit": l1.get("attck_terms_hit", []),
        }

    l2 = _run_level2(body, collection, threshold=cosine_threshold, model=embed_model)

    return {
        "pass": l2["passed"],
        "reason": l2["reason"],
        "level1_triggered": l1["triggered"],
        "max_similarity": l2["max_similarity"],
        "word_count": l1["word_count"],
        "ioc_hits": l1.get("ioc_hits", []),
        "attck_terms_hit": l1.get("attck_terms_hit", []),
    }


def filter_batch(
    article_ids: list[int],
    db_path: str,
    chroma_client=None,
    collection=None,
    cosine_threshold: float = COSINE_THRESHOLD,
    model=None,
) -> dict:
    """
    Filtra un batch de artículos leídos directamente de la BD SQLite.

    Args:
        article_ids: Lista de IDs de la tabla articles.
        db_path: Ruta al fichero SQLite (ransomware_intel.db).
        chroma_client: Modelo SentenceTransformer (compatibilidad de API).
        collection: Colección ChromaDB ya abierta.
        cosine_threshold: Umbral de similitud coseno.
        model: Alias de chroma_client.

    Returns:
        {
            "passed_ids": list[int],
            "rejected_ids": list[int],
            "results": dict[int, dict],   # ID resultado de filter_article
            "stats": {
                "total": int,
                "passed": int,
                "rejected": int,
                "rejected_short": int,
                "rejected_no_heuristic": int,
                "rejected_low_similarity": int,
                "pass_rate": float,
            }
        }
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    passed_ids: list[int] = []
    rejected_ids: list[int] = []
    results: dict[int, dict] = {}

    stats = {
        "total": 0,
        "passed": 0,
        "rejected": 0,
        "rejected_short": 0,
        "rejected_no_heuristic": 0,
        "rejected_low_similarity": 0,
        "pass_rate": 0.0,
    }

    try:
        for article_id in article_ids:
            row = conn.execute(
                "SELECT id, body FROM articles WHERE id = ?", (article_id,)
            ).fetchone()

            if row is None:
                continue

            body = row["body"] or ""
            result = filter_article(
                body,
                chroma_client=chroma_client,
                collection=collection,
                cosine_threshold=cosine_threshold,
                model=model,
            )
            results[article_id] = result
            stats["total"] += 1

            if result["pass"]:
                passed_ids.append(article_id)
                stats["passed"] += 1
            else:
                rejected_ids.append(article_id)
                stats["rejected"] += 1
                reason = result["reason"]
                if reason == "short":
                    stats["rejected_short"] += 1
                elif reason == "no_heuristic":
                    stats["rejected_no_heuristic"] += 1
                elif reason == "low_similarity":
                    stats["rejected_low_similarity"] += 1

    finally:
        conn.close()

    if stats["total"] > 0:
        stats["pass_rate"] = round(stats["passed"] / stats["total"], 3)

    return {
        "passed_ids": passed_ids,
        "rejected_ids": rejected_ids,
        "results": results,
        "stats": stats,
    }


# ---
# Helpers para __main__
# ---
def _load_chroma_collection():
    """
    Crea el cliente de ChromaDB y devuelve (modelo, colección).

    El índice se construyó con build_index.py usando la función de embedding
    'default' de ChromaDB. Por eso abrimos la colección SIN pasar
    embedding_function (para evitar el conflicto) y usamos SentenceTransformer
    a mano para generar los query_embeddings que pasamos a collection.query().

    Devuelve (modelo_sentence_transformer, colección) o (None, None) si falla.
    """
    try:
        import chromadb
        from sentence_transformers import SentenceTransformer

        index_path = str(PROJECT_DIR / "mitre_index")
        client = chromadb.PersistentClient(path=index_path)

        # Sin embedding_function se evita el conflicto con la función 'default'
        # que quedó registrada cuando build_index.py creó la colección.
        collection = client.get_collection(name="mitre_attack")

        # Cargamos el modelo a mano para usarlo en las queries
        model = SentenceTransformer("all-MiniLM-L6-v2")
        return model, collection
    except Exception as exc:
        print(f"[WARN] No se pudo cargar ChromaDB: {exc}", file=sys.stderr)
        print("[WARN] El filtro funcionará solo con Nivel 1 (heurísticas).", file=sys.stderr)
        return None, None


def _print_separator(char: str = "---", width: int = 70) -> None:
    print(char * width)


def _first_n_words(text: str, n: int = 100) -> str:
    return " ".join(text.split()[:n])


# ---
# __main__: prueba directa sobre una muestra aleatoria de la BD
# ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prueba prefilter.py sobre muestra aleatoria de la BD."
    )
    parser.add_argument(
        "--db",
        default=str(PROJECT_DIR / "data" / "ransomware_intel.db"),
        help="Ruta a la BD SQLite (default: ./data/ransomware_intel.db)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=COSINE_THRESHOLD,
        help=f"Umbral de similitud coseno del Nivel 2 (default: {COSINE_THRESHOLD})",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=50,
        help="Número de artículos a muestrear (default: 50)",
    )
    parser.add_argument(
        "--no-level2",
        action="store_true",
        help="Salta el Nivel 2 (ChromaDB). Útil para probar solo las heurísticas.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Semilla para hacerlo reproducible (default: aleatorio)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[ERROR] BD no encontrada: {db_path}", file=sys.stderr)
        sys.exit(1)

    # --- Cargar ChromaDB ---
    # _load_chroma_collection devuelve (modelo SentenceTransformer, colección)
    embed_model, collection = (None, None)
    if not args.no_level2:
        print("Cargando índice ChromaDB...")
        embed_model, collection = _load_chroma_collection()

    if collection is None and not args.no_level2:
        print("[INFO] Sigo solo con el Nivel 1.\n")

    # --- Muestreo de artículos ---
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    all_ids = [row[0] for row in conn.execute("SELECT id FROM articles").fetchall()]
    conn.close()

    if args.seed is not None:
        random.seed(args.seed)

    sample_size = min(args.sample, len(all_ids))
    sample_ids = random.sample(all_ids, sample_size)

    _print_separator("---")
    print("PREFILTER prueba sobre muestra aleatoria")
    print(f"BD:         {db_path}")
    print(f"Total IDs:  {len(all_ids):,}")
    print(f"Muestra:    {sample_size}")
    print(f"Threshold:  {args.threshold}")
    print(f"Nivel 2:    {'activo' if collection else 'desactivado'}")
    if embed_model is not None:
        print("Modelo:     all-MiniLM-L6-v2 (query_embeddings)")
    _print_separator("---")

    # --- Ejecutar el filtro ---
    print(f"\nProcesando {sample_size} artículos...\n")

    batch_result = filter_batch(
        article_ids=sample_ids,
        db_path=str(db_path),
        chroma_client=embed_model,
        collection=collection,
        cosine_threshold=args.threshold,
        model=embed_model,
    )

    stats = batch_result["stats"]
    results = batch_result["results"]

    # --- Estadísticas globales ---
    _print_separator()
    print("ESTADÍSTICAS GENERALES")
    _print_separator()
    print(f"  Total procesados:            {stats['total']}")
    print(f"  PASAN al extractor:        {stats['passed']} ({stats['pass_rate']:.1%})")
    print(f"  DESCARTADOS total:         {stats['rejected']}")
    print(f"     Demasiado cortos:        {stats['rejected_short']}")
    print(f"     Sin heurísticas Nivel 1: {stats['rejected_no_heuristic']}")
    print(f"     Baja similitud Nivel 2:  {stats['rejected_low_similarity']}")

    # --- Reparto de las similitudes coseno ---
    sims = [r["max_similarity"] for r in results.values() if r["max_similarity"] is not None]
    if sims:
        sims.sort()
        _print_separator()
        print("DISTRIBUCIÓN DE SIMILITUDES COSENO (Nivel 2)")
        _print_separator()
        buckets = [(0.0, 0.2), (0.2, 0.3), (0.3, 0.4), (0.4, 0.5), (0.5, 0.7), (0.7, 1.01)]
        for lo, hi in buckets:
            count = sum(1 for s in sims if lo <= s < hi)
            bar = "" * count
            print(f"  [{lo:.1f}{hi:.1f}): {count:3d}  {bar}")
        print(f"\n  Mínima:  {min(sims):.4f}")
        print(f"  Máxima:  {max(sims):.4f}")
        avg = sum(sims) / len(sims)
        print(f"  Media:   {avg:.4f}")
        sims_sorted = sorted(sims)
        median = sims_sorted[len(sims_sorted) // 2]
        print(f"  Mediana: {median:.4f}")
    else:
        print("\n[INFO] No hay datos de similitud (Nivel 2 desactivado o ningún artículo llegó hasta él).")

    # --- Desglose de reglas del Nivel 1 ---
    _print_separator()
    print("REGLAS NIVEL 1 FRECUENCIA DE DISPARO (artículos que superan longitud mínima)")
    _print_separator()
    rule_counts: dict[str, int] = {"ioc": 0, "attck_vocab": 0, "tools": 0}
    for r in results.values():
        for rule in r.get("level1_triggered", []):
            if rule in rule_counts:
                rule_counts[rule] += 1
    for rule, count in rule_counts.items():
        print(f"  {rule:20s}: {count}")

    # --- Ejemplos de artículos descartados ---
    # (se muestran como máximo 3 para revisión manual)
    _print_separator()
    print("EJEMPLOS DE ARTÍCULOS DESCARTADOS (máx. 3)")
    _print_separator()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    examples_shown = 0
    for article_id in batch_result["rejected_ids"]:
        if examples_shown >= 3:
            break
        result = results[article_id]
        row = conn.execute(
            "SELECT id, source, title, published_utc, body FROM articles WHERE id = ?",
            (article_id,),
        ).fetchone()
        if row is None:
            continue

        reason_label = {
            "short": "Demasiado corto",
            "no_heuristic": "Sin heurísticas Nivel 1",
            "low_similarity": "Baja similitud Nivel 2",
        }.get(result["reason"], result["reason"])

        print(f"\n  ID:      {row['id']}")
        print(f"  Fuente:  {row['source']}")
        print(f"  Título:  {row['title']}")
        print(f"  Fecha:   {row['published_utc']}")
        print(f"  Razón:   {reason_label}")
        print(f"  Palabras: {result['word_count']}")
        if result["max_similarity"] is not None:
            print(f"  Max sim: {result['max_similarity']:.4f}")

        preview = _first_n_words(row["body"] or "", 100)
        print("\n  Primeras 100 palabras:")
        for line in textwrap.wrap(preview, width=66, initial_indent="    ", subsequent_indent="    "):
            print(line)
        examples_shown += 1

    conn.close()

    # --- Estimación sobre el corpus completo ---
    _print_separator()
    total_in_db = len(all_ids)
    estimated_pass = int(total_in_db * stats["pass_rate"])
    print(f"ESTIMACIÓN SOBRE TODO EL CORPUS ({total_in_db:,} artículos)")
    print(f"  Artículos que pasarían el filtro: ~{estimated_pass:,} ({stats['pass_rate']:.1%})")
    print(f"  Artículos descartados:            ~{total_in_db - estimated_pass:,} ({1-stats['pass_rate']:.1%})")
    _print_separator("---")
    print("Fin del análisis. Ajusta COSINE_THRESHOLD o MIN_WORDS si hace falta.")

