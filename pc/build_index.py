"""
build_index.py v2 Construye el índice de MITRE ATT&CK usando las descripciones completas.
CAMBIO en v2: embed_text usa la descripción completa en vez de las tres primeras frases.
Apoyo empírico: IntelEX e IEEE Access muestran que las descripciones completas
mejoran el retrieval frente a los títulos o las descripciones truncadas.

build_index.py Construye el índice RAG de MITRE ATT&CK en ChromaDB.

Se ejecuta una sola vez. Descarga el bundle STIX oficial de MITRE y genera
embeddings semánticos de cada técnica y sub-técnica para poder recuperarlas por similitud.

Cómo se usa:
    python3 build_index.py

Salidas:
    ./mitre_index/   directorio persistente de ChromaDB (~200 MB)
    ./mitre_techniques.json catálogo ya parseado (útil para inspeccionarlo)
"""

import json
import re
import time
from pathlib import Path

import requests
import chromadb
from sentence_transformers import SentenceTransformer

# ---
# CONFIGURACIÓN
# ---
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
INDEX_DIR = "./mitre_index"
CATALOG_PATH = "./mitre_techniques.json"
COLLECTION_NAME = "mitre_attack"

# Modelo de embeddings rápido, eficaz para similitud semántica en inglés.
# Se descarga solo la primera vez (~90 MB).
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ---
# DESCARGA DEL BUNDLE STIX
# ---
def download_stix(url: str) -> dict:
    print("Descargando el bundle STIX desde GitHub...")
    print(f"  URL: {url}")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    print(f"  Descargados {len(data.get('objects', []))} objetos STIX")
    return data


# ---
# PARSEO DEL BUNDLE STIX
# ---
def parse_techniques(stix_bundle: dict) -> list[dict]:
    """
    Extrae técnicas y sub-técnicas del bundle STIX.
    Incluye ID, nombre, descripción, tácticas y sub-técnicas relacionadas.
    Deja fuera las técnicas marcadas como deprecadas o revocadas.
    """
    objects = stix_bundle.get("objects", [])

    # Mapea los short_name de tactic a sus tactic_id (por ejemplo, "initial-access" "TA0001").
    tactic_id_map = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            ext = obj.get("external_references", [])
            for ref in ext:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id_map[short] = ref["external_id"]

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Saca el ID (formato T#### o T####.###)
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref["external_id"]
                break
        if not tech_id:
            continue

        # Tácticas que tiene asociadas la técnica.
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = []
        for phase in kill_chain:
            if phase.get("kill_chain_name") == "mitre-attack":
                tname = phase["phase_name"]
                tid = tactic_id_map.get(tname)
                if tid:
                    tactics.append({"tactic_id": tid, "tactic_name": tname})

        # Descripción corta: primera frase y la segunda si existe (versión truncada para embeddings).
        description = obj.get("description", "")
        # Limpia el markdown que viene en el STIX.
        description = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', description)
        description = re.sub(r'\n+', ' ', description).strip()
        short_desc = ". ".join(description.split(". ")[:3]).strip()
        if short_desc and not short_desc.endswith("."):
            short_desc += "."

        name = obj.get("name", "")
        is_subtechnique = "." in tech_id

        # Ejemplos procedurales: están en x_mitre_platforms y en la kill chain,
        # y usan lenguaje de incidente en vez del de taxonomía.
        # Nota: los ejemplos de procedimiento viven en los objetos "relationship"
        # del bundle, no dentro del propio attack-pattern. Por eso usamos aquí
        # la descripción completa, que ya suele incluirlos.
        full_desc = obj.get("description", "")
        full_desc = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', full_desc)
        full_desc = re.sub(r'\n+', ' ', full_desc).strip()


        # Texto que se pasará al embedding: nombre + descripción completa (sin recortar).
        # La literatura (IntelEX, IEEE Access) confirma que usar la descripción
        # entera mejora el retrieval frente a solo el título o la versión corta.
        embed_text = f"{name}: {full_desc}"

        techniques.append({
            "id": tech_id,
            "name": name,
            "is_subtechnique": is_subtechnique,
            "parent_id": tech_id.split(".")[0] if is_subtechnique else None,
            "tactics": tactics,
            "tactic_ids": [t["tactic_id"] for t in tactics],
            "description": short_desc,
            "full_description": full_desc,
            "embed_text": embed_text,
        })

    # Las ordenamos por ID.
    techniques.sort(key=lambda x: x["id"])
    print(f"  Técnicas parseadas: {len(techniques)}")
    print(f"  Sub-técnicas: {sum(1 for t in techniques if t['is_subtechnique'])}")
    print(f"  Técnicas padre: {sum(1 for t in techniques if not t['is_subtechnique'])}")
    return techniques


# ---
# CONSTRUCCIÓN DEL ÍNDICE CHROMADB
# ---
def build_chromadb_index(techniques: list[dict], index_dir: str) -> None:
    print(f"\nCargando el modelo de embeddings: {EMBEDDING_MODEL}")
    print("  (En la primera ejecución descarga ~90 MB; un poco de paciencia...)")
    model = SentenceTransformer(EMBEDDING_MODEL)
    print("  Modelo cargado")

    print(f"\nCreando el índice ChromaDB en: {index_dir}")
    client = chromadb.PersistentClient(path=index_dir)

    # Si ya existe la colección la borramos para reconstruirla limpia.
    try:
        client.delete_collection(COLLECTION_NAME)
        print("  Colección anterior eliminada")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},  # usamos similitud coseno
    )

    # Preparamos los datos que se pasan a ChromaDB.
    ids = []
    texts = []
    metadatas = []

    for tech in techniques:
        ids.append(tech["id"])
        texts.append(tech["embed_text"])
        metadatas.append({
            "name": tech["name"],
            "is_subtechnique": tech["is_subtechnique"],
            "parent_id": tech["parent_id"] or "",
            "tactic_ids": json.dumps(tech["tactic_ids"]),
            "description": tech["description"][:500],
            "full_description": tech["full_description"][:500],
        })

    # Calculamos los embeddings por batches.
    print(f"\nCalculando embeddings para {len(texts)} técnicas...")
    BATCH = 64
    all_embeddings = []
    for i in range(0, len(texts), BATCH):
        batch = texts[i:i + BATCH]
        embs = model.encode(batch, show_progress_bar=False).tolist()
        all_embeddings.extend(embs)
        print(f"  {min(i + BATCH, len(texts))}/{len(texts)} embeddings calculados")

    # Insertamos en ChromaDB también por batches.
    print("\nInsertando en ChromaDB...")
    CHROMA_BATCH = 500
    for i in range(0, len(ids), CHROMA_BATCH):
        collection.add(
            ids=ids[i:i + CHROMA_BATCH],
            embeddings=all_embeddings[i:i + CHROMA_BATCH],
            documents=texts[i:i + CHROMA_BATCH],
            metadatas=metadatas[i:i + CHROMA_BATCH],
        )
        print(f"  {min(i + CHROMA_BATCH, len(ids))}/{len(ids)} insertados")

    print(f"\nÍndice construido con {collection.count()} entradas")


# ---
# PRUEBA DE RECUPERACIÓN
# ---
def test_retrieval(index_dir: str) -> None:
    print("\n" + "=" * 50)
    print("PRUEBA DE RECUPERACIÓN")
    print("=" * 50)

    model = SentenceTransformer(EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=index_dir)
    collection = client.get_collection(COLLECTION_NAME)

    test_queries = [
        "fake installer trojanized software user executed malicious file",
        "lateral movement RDP remote desktop protocol",
        "data exfiltration cloud storage WinRAR archive",
        "ransomware encryption files impact",
        "Cobalt Strike command and control C2 beacon",
    ]

    for query in test_queries:
        emb = model.encode([query]).tolist()
        results = collection.query(
            query_embeddings=emb,
            n_results=3,
            include=["documents", "metadatas", "distances"],
        )
        print(f"\nQuery: \"{query[:60]}\"")
        for i, (doc, meta, dist) in enumerate(zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        )):
            sim = round(1 - dist, 3)  # pasamos de distancia coseno a similitud
            tactics = json.loads(meta["tactic_ids"])
            print(f"  {i+1}. [{meta['name'].split(':')[0] if ':' in meta['name'] else ''}] "
                  f"{results['ids'][0][i]} {meta['name']} "
                  f"(sim={sim}, tactics={tactics})")


# ---
# MAIN
# ---
def main():
    print("=" * 60)
    print("BUILD_INDEX índice RAG de MITRE ATT&CK")
    print("=" * 60)

    start = time.time()

    # 1. Descargar el STIX.
    stix = download_stix(STIX_URL)

    # 2. Parsear las técnicas.
    print("\nParseando las técnicas...")
    techniques = parse_techniques(stix)

    # 3. Guardar el catálogo en JSON (sirve para inspeccionarlo y validarlo).
    Path(CATALOG_PATH).write_text(
        json.dumps(techniques, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"  Catálogo guardado en: {CATALOG_PATH}")

    # 4. Construir el índice ChromaDB.
    build_chromadb_index(techniques, INDEX_DIR)

    # 5. Comprobar que el retrieval funciona.
    test_retrieval(INDEX_DIR)

    elapsed = round(time.time() - start, 1)
    print(f"\nBuild terminado en {elapsed}s")
    print(f"   Índice: {INDEX_DIR}/")
    print(f"   Catálogo: {CATALOG_PATH}")
    print("\nSiguiente paso: python3 rag_extractor.py")


if __name__ == "__main__":
    main()
