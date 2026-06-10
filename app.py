"""Panel web y API del pipeline de inteligencia de ransomware (Flask).

Único módulo de la capa web: sirve la UI del panel de scraping, la API que
consume el worker del PC, la calibración humana y los dashboards de la demo
del TFG. Corre dentro del contenedor `scraper` (rutas /app/*) detrás de
Nginx Proxy Manager. El import es casi puro: el arranque real (scheduler,
directorios) lo hace init_runtime() bajo __main__.

Índice de secciones (los marcadores `# --- ... ---` se pueden grepear):
  - Constantes y configuración: rutas /app/* y config del juez v2 (env vars).
  - Basic Auth: decorador require_basic_auth (defensa en profundidad tras NPM).
  - Historia persistente / Spiders disponibles / Estado global del job:
    estado compartido del panel de scraping (outputs/.history.json, job_state).
  - Preprocess / Scheduler: run_preprocess (subprocess) + APScheduler diario.
  - run_spiders: hilo que lanza `scrapy crawl` por subprocess, uno por spider.
  - Rutas (panel): /, /run, /upload_spider, /log/<f>, /stop,
    /trigger/preprocess, /api/status, /download/<f>.
  - API de extracción de TTPs: _get_db() (SQLite con PRAGMAs WAL/busy_timeout)
    y /api/ttps/acquire_batch + commit_batch (los consume el worker del PC).
  - API del juez v1: /api/judge/acquire_batch + commit_batch.
  - Calibración humana: /api/calibration/{stats,next,article,verdict,reconcile}
    + /calibration (UI de anotación ciega).
  - UI de demo (defensa del TFG): /demo, /api/demo/stats, /api/demo/pc_status y
    dashboards read-only (/corpus, /calibration-stats, /arm, /catalog-lag,
    /judge, /longitudinal con sus /api/*/data). No recalculan nada: leen los
    CSV de outputs/* generados por los scripts de análisis de la raíz.
  - Runner del judge v2: hilo en background que juzga los TTPs de un job de la
    demo con Gemma (Google AI Studio).
  - Demo jobs / heartbeats: /api/demo/* (jobs, eventos, heartbeats del PC).
  - /pipeline y /api/docs (OpenAPI) + init_runtime() al final.

Relación con otros módulos:
  - judge_core.py: fuente única del juez v2 (SYSTEM_PROMPT, build_user_prompt,
    call_gemini); este módulo solo orquesta (lotes, persistencia, hilos).
  - templates/<vista>/index.html: una carpeta Jinja2 por vista. Jinja cachea
    las plantillas: editarlas exige reiniciar el contenedor (static/ no).

Deliberadamente en un solo fichero para la entrega del TFG: la división en
blueprints (corpus / judge / demo / runner) queda como trabajo futuro.
"""
import atexit
import os
import re
import json
import subprocess
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, send_from_directory, render_template, request, redirect
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor as APThreadPoolExecutor
import csv
import sys
import base64
import hmac
from functools import wraps

# Imports aliasados (evitan choques con nombres de variable locales del módulo).
import sqlite3 as _sqlite3
import csv as _csv
import time as _time
from pathlib import Path as _Path
from judge_core import (
    DEFAULT_DELAY_S, DEFAULT_MODEL,
    SYSTEM_PROMPT as _JUDGE_SYSTEM_PROMPT,
    build_user_prompt as _build_judge_user_prompt,
    call_gemini as _call_gemini_impl,
)

csv.field_size_limit(sys.maxsize)

app = Flask(__name__)

_DB_PATH = "/app/data/ransomware_intel.db"
SCRAPY_DIR = "/app/scrapy_project/bcddg"
SPIDERS_DIR = "/app/scrapy_project/bcddg/bcddg/spiders"
OUTPUTS_DIR = "/app/outputs"
HISTORY_FILE = "/app/outputs/.history.json"

os.makedirs(OUTPUTS_DIR, exist_ok=True)
LOGS_DIR = "/app/outputs/logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Directorios de salida de los análisis (los leen las páginas de la demo).
_EVAL_F1_DIR = _Path("/app/outputs/evaluation_f1")
_LONGITUDINAL_DIR = _Path("/app/outputs/longitudinal")
_COOCCURRENCE_DIR = _Path("/app/outputs/cooccurrence")
_CATALOG_LAG_DIR = _Path("/app/outputs/catalog_lag")

# Configuración del juez v2 (la lógica vive en judge_core.py).
_JUDGE_MODEL = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
_JUDGE_DELAY_S = float(os.environ.get("JUDGE_DELAY_S", str(DEFAULT_DELAY_S)))
_JUDGE_TIMEOUT_S = int(os.environ.get("JUDGE_TIMEOUT_S", "300"))
_JUDGE_RETRIES = 3
_MITRE_CACHE_PATH = _Path("/app/data/mitre_attack_cache.json")

# --- Basic Auth ---
# Defensa en profundidad. NPM ya hace Basic Auth por delante, pero si NPM cae
# o se publica el puerto 7000, los endpoints de mutación quedan al descubierto.
# Compatibilidad: si BASIC_AUTH_USER/PASS no están en .env, se imprime un aviso
# al importar y los decoradores no hacen nada (modo despliegue progresivo).
_BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "").strip()
_BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "").strip()
_BASIC_AUTH_ENABLED = bool(_BASIC_AUTH_USER and _BASIC_AUTH_PASS)

if not _BASIC_AUTH_ENABLED:
    print("[auth] AVISO: Basic Auth DESACTIVADO. BASIC_AUTH_USER/PASS no "
          "definidos en .env. Los endpoints de mutación quedan abiertos.", flush=True)

def _check_basic_auth_header(header_value: str) -> bool:
    if not header_value or not header_value.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header_value[6:]).decode("utf-8")
        user, _, pwd = decoded.partition(":")
    except Exception:
        return False
    return (hmac.compare_digest(user, _BASIC_AUTH_USER)
            and hmac.compare_digest(pwd, _BASIC_AUTH_PASS))

def _basic_auth_or_401():
    """Devuelve None si la petición está autenticada (o si la auth está
    desactivada). Si no, devuelve una respuesta 401."""
    if not _BASIC_AUTH_ENABLED:
        return None
    if _check_basic_auth_header(request.headers.get("Authorization", "")):
        return None
    return ("Unauthorized", 401,
            {"WWW-Authenticate": 'Basic realm="scraper"'})

def require_basic_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        deny = _basic_auth_or_401()
        if deny is not None:
            return deny
        return fn(*args, **kwargs)
    return wrapper

# --- Historia persistente ---
def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

# --- Spiders disponibles ---
# Spiders cuyo `name = ...` lee bien get_available_spiders pero que NO funcionan
# en producción: o bien el proveedor bloquea las IPs de OCI, o hay un captcha
# que no se puede saltar. Se listan en el backend para que /run los acepte si
# alguien los invoca a propósito; la UI los pinta como chips deshabilitados vía
# blocked_spiders data-blocked="1" .chip-blocked.
BLOCKED_SPIDERS = frozenset({
    "sophos_news_ransomware",
    "kaspersky_securelist_ransomware",
})

def get_available_spiders():
    spiders = []
    for fname in sorted(os.listdir(SPIDERS_DIR)):
        if not fname.endswith(".py") or fname.startswith("__"):
            continue
        path = os.path.join(SPIDERS_DIR, fname)
        with open(path) as f:
            content = f.read()
        m = re.search(r'^\s+name\s*=\s*["\']([a-z][a-z0-9_]+)["\']', content, re.MULTILINE)
        if m:
            spiders.append(m.group(1))
    return spiders

# --- Estado global del job ---
job_state = {
    "running": False,
    "current_spider": None,
    "current_index": 0,
    "total": 0,
    "queue": [],
    "log": [],
    "started_at": None,
    "finished_at": None,
    "items_current": 0,
    "stop_requested": False,
    # --- Preprocess state ---
    "preprocess_running": False,
    "preprocess_last_run": None,    # timestamp ISO
    "preprocess_last_status": None, # "ok" | "error"
    "preprocess_triggered_by": None,
}

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    job_state["log"].append(line)
    # Mantener solo los últimos 200 mensajes
    if len(job_state["log"]) > 200:
        job_state["log"] = job_state["log"][-200:]
    print(line)

def count_csv_rows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return 0
    try:
        # errors='replace' evita que un carácter raro tire el conteo entero
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            return max(0, sum(1 for _ in csv.reader(f)) - 1)
    except Exception as e:
        print(f"Error contando filas en {path}: {e}")
        return 0

def repair_history():
    """Repasa el historial y recalcula los conteos de artículos cuando ve
    ceros que probablemente sean un error."""
    log("Verificando integridad del historial...")
    history = load_history()
    updated = False
    for spider, data in history.items():
        for run in data.get("runs", []):
            if run.get("articles") == 0:
                path = os.path.join(OUTPUTS_DIR, run["file"])
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    real_count = count_csv_rows(path)
                    if real_count > 0:
                        log(f"  Reparando {run['file']}: 0 -> {real_count}")
                        run["articles"] = real_count
                        updated = True
        if updated:
            data["total_articles"] = sum(r["articles"] for r in data["runs"])
    if updated:
        save_history(history)
        log("Historial reparado y guardado")
    else:
        log("Historial correcto")

# --- Preprocess ---
def run_preprocess(triggered_by: str = "manual") -> None:
    """
    Lanza preprocess.py como subproceso y actualiza job_state.
    El flag preprocess_running asegura que solo corra una instancia a la vez.
    """
    if job_state["preprocess_running"]:
        log("Preprocess ya en curso: se ignora el trigger")
        return

    job_state["preprocess_running"] = True
    job_state["preprocess_triggered_by"] = triggered_by
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOGS_DIR, f"preprocess_{ts}.log")

    log(f"Preprocess iniciado (trigger: {triggered_by})")

    try:
        with open(log_path, "w") as lf:
            lf.write(f"=== preprocess.py {datetime.now().isoformat()} trigger: {triggered_by} ===\n")
            lf.flush()
            result = subprocess.run(
                ["python", "/app/scrapy_project/preprocess.py"],
                stdout=lf,
                stderr=lf,
                text=True,
                timeout=600,  # como mucho 10 min
            )
        status = "ok" if result.returncode == 0 else "error"
        log(f"Preprocess {'OK' if status == 'ok' else 'ERROR'} (código {result.returncode}) log: preprocess_{ts}.log")
    except subprocess.TimeoutExpired:
        status = "error"
        log("Preprocess TIMEOUT (>10 min)")
    except Exception as exc:
        status = "error"
        log(f"Preprocess EXCEPCIÓN: {exc}")
    finally:
        job_state["preprocess_running"] = False
        job_state["preprocess_last_run"] = datetime.now().isoformat()
        job_state["preprocess_last_status"] = status
        job_state["preprocess_triggered_by"] = None


# --- Scheduler ---
#
# El scheduler arranca de forma perezosa desde init_runtime() (no al importar),
# para que importar `app` desde tests o scripts no dispare jobs en background.

_scheduler = None


def init_scheduler():
    """Crea y arranca el BackgroundScheduler con el job de preprocess cada 6h.
    Es idempotente: si ya está en marcha, no hace nada."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler(
        executors={"default": APThreadPoolExecutor(1)},
        job_defaults={"coalesce": True, "max_instances": 1},
        timezone="UTC",
    )
    _scheduler.add_job(
        func=lambda: run_preprocess("scheduler_6h"),
        trigger="interval",
        hours=6,
        id="preprocess_6h",
        replace_existing=True,
    )
    _scheduler.start()
    atexit.register(lambda: _scheduler.shutdown(wait=False))
    return _scheduler


def run_spiders(queue):
    job_state["running"] = True
    job_state["queue"] = queue
    job_state["log"] = []
    job_state["started_at"] = datetime.now().isoformat()
    job_state["finished_at"] = None
    job_state["total"] = len(queue)
    job_state["current_index"] = 0
    job_state["current_log_file"] = None
    job_state["stop_requested"] = False

    history = load_history()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    log(f"Iniciando {len(queue)} spiders en cola")

    for i, spider in enumerate(queue):
        if job_state.get("stop_requested"):
            log("Stop solicitado: se detiene la cola")
            break
        job_state["current_spider"] = spider
        job_state["current_index"] = i + 1
        job_state["items_current"] = 0
        out_file = f"{OUTPUTS_DIR}/{spider}_{timestamp}.csv"
        log_file = f"{LOGS_DIR}/{spider}_{timestamp}.log"
        job_state["current_log_file"] = f"{spider}_{timestamp}.log"

        log(f"[{i+1}/{len(queue)}] {spider}")

        try:
            with open(log_file, "w") as lf:
                lf.write(f"=== {spider} {datetime.now().isoformat()} ===\n")
                lf.flush()
                proc = subprocess.Popen(
                    ["scrapy", "crawl", spider, "-o", out_file, "-s", "LOG_LEVEL=INFO"],
                    cwd=SCRAPY_DIR,
                    stdout=lf,
                    stderr=lf,
                    text=True,
                )
                proc.wait()  # Sin timeout: el spider corre hasta terminar o hasta que se pida STOP

            count = count_csv_rows(out_file)
            job_state["items_current"] = count

            if spider not in history:
                history[spider] = {"runs": [], "total_articles": 0}
            history[spider]["runs"].append({
                "date": datetime.now().isoformat(),
                "articles": count,
                "file": os.path.basename(out_file),
                "log": os.path.basename(log_file),
            })
            history[spider]["total_articles"] = sum(r["articles"] for r in history[spider]["runs"])
            history[spider]["last_run"] = datetime.now().isoformat()
            save_history(history)

            log(f"[{i+1}/{len(queue)}] {spider} {count} artículos")
        except Exception as e:
            log(f"[{i+1}/{len(queue)}] {spider} ERROR: {e}")

    job_state["running"] = False
    job_state["current_spider"] = None
    job_state["current_log_file"] = None
    job_state["finished_at"] = datetime.now().isoformat()
    log("Completado")

    # Lanza preprocess automáticamente al terminar cada batch de scraping
    threading.Thread(
        target=run_preprocess, args=("post_scraping",), daemon=True
    ).start()

# --- Helpers ---
def human_size(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} GB"

def get_files():
    files = []
    for fname in sorted(os.listdir(OUTPUTS_DIR), reverse=True):
        if not fname.endswith((".csv", ".jsonl")) or fname.startswith("."):
            continue
        path = os.path.join(OUTPUTS_DIR, fname)
        stat = os.stat(path)
        base = fname.replace(".csv", "").replace(".jsonl", "")
        log_name = f"{base}.log"
        log_exists = os.path.exists(os.path.join(LOGS_DIR, log_name))
        # Spider: la parte previa al sufijo _YYYYMMDD_HHMMSS si existe; si no, el propio base.
        m = re.match(r"^(.+?)_\d{8}_\d{6}$", base)
        spider = m.group(1) if m else base
        files.append({
            "name": fname,
            "spider": spider,
            "size": human_size(stat.st_size),
            "size_bytes": stat.st_size,
            "rows": count_csv_rows(path),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "mtime": int(stat.st_mtime),
            "log": log_name if log_exists else None,
        })
    return files

# --- Rutas ---
@app.route("/")
def scraper_index():
    return render_template(
        "scraper/index.html",
        state=job_state,
        spiders=get_available_spiders(),
        blocked_spiders=BLOCKED_SPIDERS,
        history=load_history(),
        files=get_files(),
    )

@app.route("/run", methods=["POST"])
@require_basic_auth
def run():
    if job_state["running"]:
        return redirect("/")
    queue = request.form.getlist("spiders")
    if not queue:
        queue = get_available_spiders()
    t = threading.Thread(target=run_spiders, args=(queue,), daemon=True)
    t.start()
    return redirect("/")

@app.route("/upload_spider", methods=["POST"])
@require_basic_auth
def upload_spider():
    f = request.files.get("file")
    if not f or not f.filename.endswith(".py"):
        return jsonify({"status": "error", "message": "Solo ficheros .py"})
    content = f.read().decode("utf-8")
    # Comprueba que el fichero define un nombre de spider
    m = re.search(r'^\s+name\s*=\s*["\']([a-z][a-z0-9_]+)["\']', content, re.MULTILINE)
    if not m:
        return jsonify({"status": "error", "message": "El fichero no tiene 'name = ...' de Scrapy"})
    spider_name = m.group(1)
    from werkzeug.utils import secure_filename
    # No confiar en f.filename: '../../../../tmp/evil.py' escapaba SPIDERS_DIR vía
    # os.path.join y, al caer dentro del paquete de spiders, Scrapy lo importaba
    # (escritura arbitraria -> ejecución de código). Saneamos el nombre y, como
    # cinturón, confirmamos con realpath que dest queda dentro de SPIDERS_DIR
    # (mismo patrón que /log).
    safe_name = secure_filename(f.filename or "")
    if not safe_name.endswith(".py"):
        safe_name = spider_name + ".py"
    safe_root = os.path.realpath(SPIDERS_DIR)
    dest = os.path.realpath(os.path.join(safe_root, safe_name))
    if not (dest == safe_root or dest.startswith(safe_root + os.sep)):
        return jsonify({"status": "error", "message": "Destino no permitido"})
    with open(dest, "w") as out:
        out.write(content)
    return jsonify({"status": "ok", "name": spider_name, "file": os.path.basename(dest)})


@app.route("/log/<filename>")
def view_log(filename):
    from markupsafe import escape as _escape
    # Defensa en profundidad: Werkzeug ya bloquea '/' en el segmento <filename>,
    # pero aquí rechazamos también NULL bytes, backslashes (al estilo Windows)
    # y cualquier intento de salir del directorio una vez resueltos los symlinks
    # con realpath.
    if "\x00" in filename or "/" in filename or "\\" in filename:
        return "Acceso no permitido", 403
    safe_root = os.path.realpath(LOGS_DIR)
    safe_path = os.path.realpath(os.path.join(safe_root, filename))
    if not (safe_path == safe_root or safe_path.startswith(safe_root + os.sep)):
        return "Acceso no permitido", 403
    if not os.path.exists(safe_path):
        return "Log no encontrado", 404
    with open(safe_path, errors="replace") as f:
        raw = f.read()
    # Colorea las líneas relevantes (escapando antes el contenido para evitar XSS)
    lines = []
    for line in raw.split("\n"):
        safe = str(_escape(line))
        if "Scraped" in line or "scraped" in line:
            lines.append(f'<span class="text-emerald-300">{safe}</span>')
        elif "ERROR" in line:
            lines.append(f'<span class="text-rose-300">{safe}</span>')
        elif "WARNING" in line:
            lines.append(f'<span class="text-amber-300">{safe}</span>')
        elif "pages/min" in line or "items/min" in line or "Crawled" in line:
            lines.append(f'<span class="text-cyan-300">{safe}</span>')
        else:
            lines.append(safe)
    colored = "\n".join(lines)
    return render_template("scraper/log.html", name=filename, content=colored)

@app.route("/stop", methods=["POST"])
@require_basic_auth
def stop():
    if job_state["running"]:
        job_state["stop_requested"] = True
        log("Stop solicitado por el usuario")
    return redirect("/")


@app.route("/trigger/preprocess", methods=["POST"])
@require_basic_auth
def trigger_preprocess():
    """Lanza preprocess.py a mano, ya sea desde el panel web o por API."""
    if job_state["preprocess_running"]:
        return jsonify({"status": "already_running"})
    threading.Thread(
        target=run_preprocess, args=("manual",), daemon=True
    ).start()
    return jsonify({"status": "started"})

@app.route("/api/status")
def status():
    return jsonify(job_state)

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(OUTPUTS_DIR, filename, as_attachment=True)

# --- API de extracción de TTPs ---


def _get_db():
    """Abre conexión a la BD con row_factory, WAL y PRAGMAs de robustez."""
    conn = _sqlite3.connect(_DB_PATH)
    conn.row_factory = _sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")  # espera 5s ante un lock antes de fallar
    conn.execute("PRAGMA foreign_keys=ON")    # aplica las FKs declaradas (OFF por defecto en SQLite)
    return conn


@app.route("/api/ttps/acquire_batch", methods=["GET"])
@require_basic_auth
def acquire_batch():
    """
    GET /api/ttps/acquire_batch?limit=N  (por defecto 50, máximo 200)

    - Libera huérfanos (pasa de 'processing' a 'pending' si lock_time > 3h)
    - Selecciona hasta N artículos en estado 'pending'
    - Los marca como 'processing' de golpe (BEGIN EXCLUSIVE)
    - Devuelve JSON con la lista de artículos
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    conn = None  # se define antes del try para que el except no
                 # falle con UnboundLocalError si _get_db() lanza.
    try:
        conn = _get_db()
        conn.execute("BEGIN EXCLUSIVE")

        # 1. Liberar huérfanos
        conn.execute("""
            UPDATE articles
               SET processing_state = 'pending',
                   processing_lock_time = NULL
             WHERE processing_state = 'processing'
               AND processing_lock_time < datetime('now', '-3 hours')
        """)

        # 2. Seleccionar los pendientes
        rows = conn.execute("""
            SELECT id, source, url, title, published_utc, body
              FROM articles
             WHERE processing_state = 'pending'
             LIMIT ?
        """, (limit,)).fetchall()

        ids = [r["id"] for r in rows]

        # 3. Marcar como en proceso
        if ids:
            placeholders = ",".join("?" * len(ids))
            conn.execute(f"""
                UPDATE articles
                   SET processing_state = 'processing',
                       processing_lock_time = datetime('now')
                 WHERE id IN ({placeholders})
            """, ids)  # nosec B608 -- placeholders generados; datos de usuario por parámetros

        conn.execute("COMMIT")

        articles = [dict(r) for r in rows]
        conn.close()

        return jsonify({
            "articles": articles,
            "count": len(articles),
            "acquired_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    except Exception:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500


@app.route("/api/ttps/commit_batch", methods=["POST"])
@require_basic_auth
def commit_batch():
    """
    POST /api/ttps/commit_batch
    Body JSON: {"results": [{article_id, status, model, ttps, reasoning,
                             valid_ttp_count, validation_issues, prefilter_reason,
                             max_similarity_score, elapsed_seconds}]}

    - Inserta en la tabla extractions (si el status es 'completed' o 'failed')
    - Actualiza processing_state en articles
    - Todo dentro de una única transacción
    """
    data = request.get_json(silent=True)
    if not data or "results" not in data or not isinstance(data["results"], list):
        return jsonify({"ok": False, "error": "Body JSON inválido: falta 'results' (lista)"}), 400

    results = data["results"]
    # contadores separados en vez del antiguo "committed", que era ambiguo.
    inserted = 0          # filas insertadas en `extractions`
    state_updated = 0     # filas con UPDATE de processing_state OK
    skipped = 0           # items sin article_id (entrada inválida)
    errors = []
    insert_errors_by_id = []   # ids cuyo INSERT en extractions falló (aunque el UPDATE de estado sí se aplicó)

    conn = None  # se define antes para que el except sea seguro.
    try:
        conn = _get_db()
        conn.execute("BEGIN")

        for item in results:
            article_id = item.get("article_id")
            status = item.get("status", "failed")

            if article_id is None:
                skipped += 1
                errors.append("Resultado sin article_id: se ignora")
                continue

            # Insertar en extractions si hay datos de TTP
            if status in ("completed", "failed"):
                try:
                    import json as _json
                    ttps_val = item.get("ttps")
                    if isinstance(ttps_val, (list, dict)):
                        ttps_val = _json.dumps(ttps_val, ensure_ascii=False)
                    vi_val = item.get("validation_issues")
                    if isinstance(vi_val, (list, dict)):
                        vi_val = _json.dumps(vi_val, ensure_ascii=False)

                    conn.execute("""
                        INSERT INTO extractions
                            (article_id, model, ttps, reasoning, valid_ttp_count,
                             validation_issues, prefilter_reason, max_similarity_score,
                             elapsed_seconds)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        article_id,
                        item.get("model", ""),
                        ttps_val or "[]",
                        item.get("reasoning"),
                        item.get("valid_ttp_count"),
                        vi_val,
                        item.get("prefilter_reason"),
                        item.get("max_similarity_score"),
                        item.get("elapsed_seconds"),
                    ))
                    inserted += 1
                except Exception as e:
                    insert_errors_by_id.append(article_id)
                    errors.append(f"article_id={article_id}: INSERT extractions falló {e}")
                    # NO abortamos. El UPDATE de processing_state se hace
                    # igual para que el artículo no se quede colgado en
                    # 'processing' bloqueando reintentos. El cliente verá el id
                    # en `insert_errors`.

            # Actualiza el estado del artículo (siempre, salvo los ya descartados arriba)
            conn.execute("""
                UPDATE articles
                   SET processing_state = ?,
                       processing_lock_time = NULL
                 WHERE id = ?
            """, (status, article_id))
            state_updated += 1

        conn.execute("COMMIT")
        conn.close()

        return jsonify({
            "ok": True,
            "inserted": inserted,
            "state_updated": state_updated,
            "skipped": skipped,
            "insert_errors": insert_errors_by_id,
            "errors": errors,
            # Alias para no romper clientes antiguos: equivale a state_updated
            # (que es lo que espera run_extraction.py).
            "committed": state_updated,
        })

    except Exception:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500


@app.route("/api/judge/acquire_batch", methods=["GET"])
@require_basic_auth
def judge_acquire_batch():
    """
    GET /api/judge/acquire_batch?limit=N  (por defecto 20, máximo 100)

    Devuelve hasta N TTPs con confidence=0.75 que aún no estén en ttp_verdicts.
    El JSON se desempaqueta en Python (no con json_each en SQL) para no hacer
    full scans lentos sobre el campo ttps de miles de extracciones.
    """
    try:
        limit = min(int(request.args.get("limit", 20)), 100)
    except (ValueError, TypeError):
        limit = 20

    BODY_TRUNCATE = 12000
    PAGE_SIZE = 100  # extracciones por página al escanear

    import json as _json

    conn = None  # se define antes para evitar UnboundLocalError en el except.
    try:
        conn = _get_db()

        # 1. Cargar en un set los pares ya juzgados (unas 3000 entradas como mucho, muy rápido)
        judged = set(
            (r[0], r[1])
            for r in conn.execute("SELECT extraction_id, ttp_index FROM ttp_verdicts")
        )

        # 2. Recorrer las extracciones por páginas y desempaquetar el JSON en Python
        results = []
        offset = 0

        while len(results) < limit:
            rows = conn.execute("""
                SELECT e.id, e.article_id, e.ttps, substr(a.body, 1, ?)
                  FROM extractions e
                  JOIN articles a ON a.id = e.article_id
                 LIMIT ? OFFSET ?
            """, (BODY_TRUNCATE, PAGE_SIZE, offset)).fetchall()

            if not rows:
                break

            for ext_id, article_id, ttps_json, body in rows:
                try:
                    ttps = _json.loads(ttps_json or "[]")
                except Exception:
                    continue

                for idx, ttp in enumerate(ttps):
                    if ttp.get("confidence") != 0.75:
                        continue
                    if (ext_id, idx) in judged:
                        continue
                    results.append({
                        "extraction_id":  ext_id,
                        "article_id":     article_id,
                        "ttp_index":      idx,
                        "technique_id":   ttp.get("technique_id", ""),
                        "tactic_id":      ttp.get("tactic_id", ""),
                        "tactic":         ttp.get("tactic", ""),
                        "technique_name": ttp.get("technique_name", ""),
                        "confidence":     ttp.get("confidence"),
                        "evidence_quote": ttp.get("evidence_quote", ""),
                        "article_body":   body,
                    })
                    if len(results) >= limit:
                        break

                if len(results) >= limit:
                    break

            offset += PAGE_SIZE

        conn.close()

        return jsonify({
            "items": results,
            "count": len(results),
            "acquired_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500


@app.route("/api/judge/commit_batch", methods=["POST"])
@require_basic_auth
def judge_commit_batch():
    """
    POST /api/judge/commit_batch
    Body JSON:
    {
      "verdicts": [
        {
          "extraction_id": 42,
          "article_id": 6,
          "ttp_index": 0,
          "technique_id": "T1486",
          "verdict": "accept|reject|uncertain",
          "reasoning": "...",
          "model": "qwen2.5:14b-instruct-q4_K_M"
        }
      ]
    }
    INSERT OR IGNORE idempotente: si se reintenta un batch no se duplican veredictos.
    """
    data = request.get_json(silent=True)
    if not data or "verdicts" not in data or not isinstance(data["verdicts"], list):
        return jsonify({"ok": False, "error": "Body JSON inválido: falta 'verdicts' (lista)"}), 400

    VALID_VERDICTS = {"accept", "reject", "uncertain"}
    committed = 0
    errors = []

    conn = None  # se define antes para evitar UnboundLocalError en el except.
    try:
        conn = _get_db()
        conn.execute("BEGIN")

        for item in data["verdicts"]:
            ext_id  = item.get("extraction_id")
            ttp_idx = item.get("ttp_index")
            verdict = item.get("verdict")

            if ext_id is None or ttp_idx is None:
                errors.append(f"Item sin extraction_id/ttp_index: {item}")
                continue
            if verdict not in VALID_VERDICTS:
                errors.append(f"Veredicto inválido '{verdict}' ext={ext_id} idx={ttp_idx}")
                continue

            try:
                conn.execute("""
                    INSERT OR IGNORE INTO ttp_verdicts
                        (extraction_id, article_id, ttp_index, technique_id,
                         verdict, reasoning, model)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ext_id,
                    item.get("article_id"),
                    ttp_idx,
                    item.get("technique_id", ""),
                    verdict,
                    item.get("reasoning"),
                    item.get("model", ""),
                ))
                committed += 1
            except Exception as e:
                errors.append(f"ext={ext_id} idx={ttp_idx}: {e}")

        conn.execute("COMMIT")
        conn.close()

        return jsonify({"ok": True, "committed": committed, "errors": errors})

    except Exception:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500


# --- Calibración humana ---
def _mitre_url(technique_id):
    tid = (technique_id or "").upper()
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def _calib_stats(conn):
    """Devuelve un dict con el progreso de la calibración."""
    total = conn.execute("SELECT COUNT(*) FROM calibration_sample").fetchone()[0]
    done  = conn.execute(
        "SELECT COUNT(*) FROM calibration_sample WHERE human_blind_verdict IS NOT NULL"
    ).fetchone()[0]
    control_total = conn.execute(
        "SELECT COUNT(*) FROM calibration_sample WHERE sample_type='control'"
    ).fetchone()[0]
    control_done = conn.execute(
        "SELECT COUNT(*) FROM calibration_sample "
        "WHERE sample_type='control' AND human_blind_verdict IS NOT NULL"
    ).fetchone()[0]

    # Acuerdo crudo (solo sobre la muestra estratificada que tenga llm_verdict)
    compared = conn.execute("""
        SELECT COUNT(*) FROM calibration_sample
        WHERE sample_type='stratified'
          AND human_blind_verdict IS NOT NULL
          AND llm_verdict IS NOT NULL
    """).fetchone()[0]
    agree = conn.execute("""
        SELECT COUNT(*) FROM calibration_sample
        WHERE sample_type='stratified'
          AND human_blind_verdict IS NOT NULL
          AND llm_verdict IS NOT NULL
          AND human_blind_verdict = llm_verdict
    """).fetchone()[0]

    raw_pct = round(agree / compared * 100, 1) if compared > 0 else None

    return {
        "total": total,
        "done": done,
        "pct": round(done / total * 100, 1) if total > 0 else 0,
        "control_total": control_total,
        "control_done": control_done,
        "raw_agreement_pct": raw_pct,
        "compared": compared,
        "agree": agree,
    }


@app.route("/api/calibration/stats")
def calibration_stats():
    conn = None
    try:
        conn = _get_db()
        stats = _calib_stats(conn)
        return jsonify(stats)
    except Exception:
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/calibration/next")
def calibration_next():
    """Devuelve el siguiente TTP sin anotar, sin llm_verdict ni llm_reasoning (fase ciega)."""
    conn = None
    try:
        conn = _get_db()
        row = conn.execute("""
            SELECT id, sample_type, extraction_id, article_id, ttp_index,
                   technique_id, quote, source
            FROM calibration_sample
            WHERE human_blind_verdict IS NULL
            ORDER BY id ASC
            LIMIT 1
        """).fetchone()

        stats = _calib_stats(conn)

        if row is None:
            return jsonify({"done": True, "stats": stats})

        return jsonify({
            "done": False,
            "id": row["id"],
            "sample_type": row["sample_type"],
            "extraction_id": row["extraction_id"],
            "article_id": row["article_id"],
            "ttp_index": row["ttp_index"],
            "technique_id": row["technique_id"],
            "quote": row["quote"] or "",
            "source": row["source"] or "",
            "mitre_url": _mitre_url(row["technique_id"]),
            "stats": stats,
        })
    except Exception:
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/calibration/article/<int:article_id>")
def calibration_article(article_id):
    """Devuelve el body completo del artículo para el botón [V]."""
    conn = None
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT title, url, body, source, published_utc FROM articles WHERE id=?",
            (article_id,)
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "Artículo no encontrado"}), 404
        return jsonify(dict(row))
    except Exception:
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/calibration/verdict", methods=["POST"])
@require_basic_auth
def calibration_verdict():
    """
    Guarda el veredicto ciego del anotador humano y devuelve llm_verdict y llm_reasoning.
    Payload: {id, verdict}
    """
    data = request.get_json(silent=True) or {}
    sample_id = data.get("id")
    verdict = data.get("verdict")

    if sample_id is None or verdict not in ("accept", "reject", "uncertain"):
        return jsonify({"ok": False, "error": "Payload inválido"}), 400

    conn = None
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT sample_type, llm_verdict, llm_reasoning "
            "FROM calibration_sample WHERE id=?",
            (sample_id,)
        ).fetchone()

        if row is None:
            return jsonify({"ok": False, "error": "ID no encontrado"}), 404

        conn.execute("""
            UPDATE calibration_sample
               SET human_blind_verdict = ?,
                   annotated_at = datetime('now')
             WHERE id = ? AND human_blind_verdict IS NULL
        """, (verdict, sample_id))
        conn.commit()

        stats = _calib_stats(conn)

        return jsonify({
            "ok": True,
            "llm_verdict": row["llm_verdict"],
            "llm_reasoning": row["llm_reasoning"],
            "agreement": (row["llm_verdict"] == verdict) if row["llm_verdict"] else None,
            "is_control": row["sample_type"] == "control",
            "stats": stats,
        })
    except Exception:
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/calibration/reconcile", methods=["POST"])
@require_basic_auth
def calibration_reconcile():
    """
    Guarda el código de error y las notas cuando hay desacuerdo.
    Payload: {id, error_code, notes (opcional), reconciled_verdict (opcional)}
    """
    data = request.get_json(silent=True) or {}
    sample_id = data.get("id")
    error_code = data.get("error_code")

    if sample_id is None or not error_code:
        return jsonify({"ok": False, "error": "Payload inválido"}), 400

    conn = None
    try:
        conn = _get_db()
        conn.execute("""
            UPDATE calibration_sample
               SET error_taxonomy_code      = ?,
                   annotation_notes         = ?,
                   human_reconciled_verdict = ?
             WHERE id = ?
        """, (
            error_code,
            data.get("notes"),
            data.get("reconciled_verdict"),
            sample_id,
        ))
        conn.commit()
        return jsonify({"ok": True})
    except Exception:
        app.logger.exception("unhandled error in %s", request.path)
        return jsonify({"ok": False, "error": "internal_error"}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/calibration")
def calibration_ui():
    # UI mobile-first, migrada a templates/calibration/index.html en la auditoría del 19-05-2026.
    return render_template("calibration/index.html")


# --- UI de demo (defensa del TFG) ---
#
# UI demostrativa colgada de /demo. Las plantillas viven en /app/templates/ y los
# assets estáticos en /app/static/ (ambos montados como volumen desde el host).
#
# Endpoints:
# GET /demo dashboard principal
# GET /api/demo/stats JSON con los cuatro hallazgos estrella
# GET /api/demo/pc_status JSON con el estado del PC remoto (worker RAG)
# POST /api/demo/heartbeat recibe el heartbeat del PC (auth vía NPM)

def _read_csv_records(path):
    """Lee un CSV como lista de diccionarios. Devuelve [] si no existe."""
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(_csv.DictReader(f))


def _ensure_pc_heartbeat_table():
    """Idempotente. Crea la tabla si todavía no existe.

    La fuente de verdad es la migración
    `scrapy_project/migrations/migrate_pc_heartbeat.py` (ejecutada el
    09-05-2026). Esta función queda como red de seguridad, pero ya no se llama
    al importar; solo se invoca desde `init_runtime()` cuando el proceso es de
    verdad el servidor Flask.
    """
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pc_heartbeat (
                id INTEGER PRIMARY KEY,
                hostname TEXT,
                last_seen_utc TEXT NOT NULL,
                client_version TEXT,
                meta_json TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _read_primary_metrics_csv():
    """Devuelve un dict con la forma {scope: {metric: {point, ci_low, ci_high}}}."""
    path = _EVAL_F1_DIR / "primary_metrics.csv"
    if not path.exists():
        return {}
    metrics_by_scope = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in _csv.DictReader(f):
            scope = row["scope"]
            metric = row["metric"]
            metrics_by_scope.setdefault(scope, {})[metric] = {
                "point": float(row["point_estimate"]),
                "ci_low": float(row["ci_low_95"]),
                "ci_high": float(row["ci_high_95"]),
                "n": int(row["n"]),
            }
    return metrics_by_scope


def _read_error_taxonomy_csv():
    """Devuelve un dict {error_code: {n, v2_corrected, correction_rate}, _total: {...}}."""
    path = _EVAL_F1_DIR / "error_taxonomy_correction.csv"
    if not path.exists():
        return {}
    taxonomy_by_code = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in _csv.DictReader(f):
            taxonomy_by_code[row["error_code"]] = {
                "n": int(row["n"]),
                "v2_corrected": int(row["v2_corrected"]),
                "correction_rate": float(row["correction_rate"]),
            }
    return taxonomy_by_code


def _read_tost_csv():
    path = _EVAL_F1_DIR / "tost_equivalence.csv"
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(_csv.DictReader(f))
    if not rows:
        return {}
    r = rows[0]
    return {
        "p_human": float(r["p_human"]),
        "p_gemma": float(r["p_gemma"]),
        "delta_min": float(r["delta_min"]),
        "equivalence_proven": r["equivalence_proven"].lower() == "true",
    }


def _read_extractor_yield_csv():
    """F1 del extractor por su cuenta (sin juez), para luego calcular el delta
    frente al pipeline completo.

    Ojo: el CSV usa el scope literal 'combined' (no 'combined_weighted' como
    sí hace primary_metrics.csv).
    """
    path = _EVAL_F1_DIR / "extractor_only_yield.csv"
    if not path.exists():
        return None
    with open(path, newline="", encoding="utf-8") as f:
        for row in _csv.DictReader(f):
            if row.get("scope") == "combined":
                try:
                    return float(row["f1"])
                except (KeyError, ValueError, TypeError):
                    return None
    return None


@app.route("/demo")
def demo_index():
    return render_template("demo/index.html")


@app.route("/api/demo/stats")
def demo_stats():
    """
    Devuelve los cuatro números estrella del dashboard.

    Los datos de corpus y convergencia se sacan en vivo de la BD. Los CSVs de
    outputs/evaluation_f1/ aportan F1 y la taxonomía de errores.
    """
    conn = _get_db()
    try:
        # Corpus validado (accepts en ttp_verdicts_v2)
        corpus_validated = conn.execute(
            "SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE verdict='accept'"
        ).fetchone()[0]

        # Total de artículos
        total_articles = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]

        # Convergencia: humano (grupo de control)
        row = conn.execute(
            """
            SELECT
              COUNT(*) AS n,
              SUM(CASE WHEN human_blind_verdict='accept' THEN 1 ELSE 0 END) AS accepts
            FROM calibration_sample
            WHERE sample_type='control' AND human_blind_verdict IS NOT NULL
            """
        ).fetchone()
        n_human = row["n"] or 0
        accepts_human = row["accepts"] or 0
        rate_human = (accepts_human / n_human) if n_human else None

        # Convergencia: Gemma sobre los TTPs con conf=1.0
        row = conn.execute(
            """
            SELECT
              COUNT(*) AS n,
              SUM(CASE WHEN verdict='accept' THEN 1 ELSE 0 END) AS accepts
            FROM ttp_verdicts_v2
            WHERE source_mode='rejudge_conf1'
            """
        ).fetchone()
        n_gemma = row["n"] or 0
        accepts_gemma = row["accepts"] or 0
        rate_gemma = (accepts_gemma / n_gemma) if n_gemma else None

        # Fecha de la última actualización del corpus
        row = conn.execute(
            "SELECT MAX(ingested_at) AS last FROM articles"
        ).fetchone()
        last_update = row["last"] if row else None
    finally:
        conn.close()

    metrics = _read_primary_metrics_csv()
    combined = metrics.get("combined_weighted", {})
    f1_metric = combined.get("f1") or {}
    mcc_metric = combined.get("mcc") or {}
    alpha_metric = combined.get("krippendorff_alpha") or {}

    extractor_only_f1 = _read_extractor_yield_csv()
    f1_delta_pp = None
    if extractor_only_f1 is not None and f1_metric.get("point") is not None:
        f1_delta_pp = (f1_metric["point"] - extractor_only_f1) * 100

    tax = _read_error_taxonomy_csv()
    e1 = tax.get("E1") or {}
    total_tax = tax.get("_total") or {}

    tost = _read_tost_csv()

    delta_pp = None
    if rate_human is not None and rate_gemma is not None:
        delta_pp = (rate_gemma - rate_human) * 100

    return jsonify({
        "corpus_validated": corpus_validated,
        "total_articles": total_articles,
        "last_update_iso": last_update,
        "convergence": {
            "human": rate_human,
            "gemma": rate_gemma,
            "n_human": n_human,
            "n_gemma": n_gemma,
            "delta_pp": delta_pp,
            "tost_delta_min": tost.get("delta_min"),
            "tost_proven": tost.get("equivalence_proven"),
        },
        "f1": {
            "point": f1_metric.get("point"),
            "ci_low": f1_metric.get("ci_low"),
            "ci_high": f1_metric.get("ci_high"),
            "mcc": mcc_metric.get("point"),
            "alpha": alpha_metric.get("point"),
            "extractor_only": extractor_only_f1,
            "delta_pp": f1_delta_pp,
        },
        "e1": {
            "rate": e1.get("correction_rate"),
            "corrected": e1.get("v2_corrected"),
            "total": e1.get("n"),
            "total_correction_rate": total_tax.get("correction_rate"),
            "total_corrected": total_tax.get("v2_corrected"),
            "total_errors": total_tax.get("n"),
        },
    })


@app.route("/api/demo/pc_status")
def demo_pc_status():
    """
    Estado del PC con GPU. Se considera online si llegó un heartbeat hace
    menos de ONLINE_WINDOW_S segundos.
    """
    ONLINE_WINDOW_S = 15

    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT hostname, last_seen_utc, client_version, meta_json "
            "FROM pc_heartbeat WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({
            "online": False,
            "last_seen_iso": None,
            "seconds_since": None,
            "hostname": None,
            "meta": None,
        })

    last_seen_iso = row["last_seen_utc"]
    seconds_since = None
    online = False
    try:
        # ISO 8601 UTC, con formato 'YYYY-MM-DDTHH:MM:SS(.ffffff)?Z?'
        s = last_seen_iso.rstrip("Z")
        last_seen_dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        seconds_since = (datetime.now(timezone.utc) - last_seen_dt).total_seconds()
        online = seconds_since is not None and seconds_since <= ONLINE_WINDOW_S
    except (TypeError, ValueError):
        pass

    meta = None
    if row["meta_json"]:
        try:
            meta = json.loads(row["meta_json"])
        except (ValueError, TypeError):
            meta = None

    return jsonify({
        "online": online,
        "last_seen_iso": last_seen_iso,
        "seconds_since": seconds_since,
        "hostname": row["hostname"],
        "client_version": row["client_version"],
        "meta": meta,
    })


@app.route("/corpus")
def corpus_index():
    return render_template("corpus/index.html")


@app.route("/api/corpus/stats")
def corpus_stats():
    """Agregados calculados sobre el corpus completo."""
    conn = _get_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]

        by_source = [
            dict(row) for row in conn.execute(
                "SELECT source, COUNT(*) AS n FROM articles GROUP BY source ORDER BY n DESC"
            ).fetchall()
        ]
        by_state = {
            row[0]: row[1] for row in conn.execute(
                "SELECT processing_state, COUNT(*) FROM articles GROUP BY processing_state"
            ).fetchall()
        }
        by_year = [
            {"year": row[0], "n": row[1]}
            for row in conn.execute(
                "SELECT substr(published_utc, 1, 4) AS y, COUNT(*) "
                "FROM articles WHERE published_utc IS NOT NULL "
                "GROUP BY y ORDER BY y"
            ).fetchall() if row[0]
        ]

        # Artículos con al menos 1 TTP aceptado por v2
        with_ttps = conn.execute(
            """
            SELECT COUNT(DISTINCT a.id)
            FROM articles a
            JOIN extractions e ON e.article_id = a.id
            JOIN ttp_verdicts_v2 v ON v.extraction_id = e.id
            WHERE v.verdict = 'accept'
            """
        ).fetchone()[0]

        # Total de accepts en v2 (sanity check)
        accepts_v2 = conn.execute(
            "SELECT COUNT(*) FROM ttp_verdicts_v2 WHERE verdict='accept'"
        ).fetchone()[0]
    finally:
        conn.close()

    return jsonify({
        "total_articles":    total,
        "by_source":         by_source,
        "by_state":          by_state,
        "by_year":           by_year,
        "articles_with_ttps": with_ttps,
        "accepts_v2":        accepts_v2,
    })


@app.route("/api/corpus/articles")
def corpus_articles():
    """
    Listado paginado con filtros opcionales.
    Query params: source, state, year, has_ttps (0/1), q (substring en el título), page, per_page (máx. 50).
    """
    args = request.args
    source = args.get("source")
    state = args.get("state")
    year = args.get("year")
    has_ttps = args.get("has_ttps")
    q = args.get("q", "").strip()
    try:
        page = max(0, int(args.get("page", 0)))
    except ValueError:
        page = 0
    try:
        per_page = min(50, max(5, int(args.get("per_page", 20))))
    except ValueError:
        per_page = 20

    where = []
    params = []
    if source:
        where.append("a.source = ?"); params.append(source)
    if state:
        where.append("a.processing_state = ?"); params.append(state)
    if year:
        where.append("substr(a.published_utc, 1, 4) = ?"); params.append(year)
    if q:
        where.append("(a.title LIKE ? OR a.url LIKE ?)")
        params.append(f"%{q}%"); params.append(f"%{q}%")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    having_sql = ""
    if has_ttps == "1":
        having_sql = "HAVING v2_accepts > 0"
    elif has_ttps == "0":
        having_sql = "HAVING v2_accepts = 0 OR v2_accepts IS NULL"

    conn = _get_db()
    try:
        # Total tras aplicar filtros (sin paginar).
        # Para hacer COUNT con HAVING hace falta una subconsulta.
        count_sql = f"""
          SELECT COUNT(*) FROM (
            SELECT a.id,
                   SUM(CASE WHEN v.verdict='accept' THEN 1 ELSE 0 END) AS v2_accepts
            FROM articles a
            LEFT JOIN extractions e ON e.article_id = a.id
            LEFT JOIN ttp_verdicts_v2 v ON v.extraction_id = e.id
            {where_sql}
            GROUP BY a.id
            {having_sql}
          )
        """  # nosec B608 -- placeholders generados; datos de usuario por parámetros
        total_filtered = conn.execute(count_sql, params).fetchone()[0]

        list_sql = f"""
          SELECT a.id, a.source, a.title, a.url, a.published_utc, a.processing_state,
                 e.id AS extraction_id,
                 e.valid_ttp_count, e.max_similarity_score, e.prefilter_reason,
                 e.elapsed_seconds,
                 SUM(CASE WHEN v.verdict='accept' THEN 1 ELSE 0 END) AS v2_accepts,
                 COUNT(v.id) AS v2_judged
          FROM articles a
          LEFT JOIN extractions e ON e.article_id = a.id
          LEFT JOIN ttp_verdicts_v2 v ON v.extraction_id = e.id
          {where_sql}
          GROUP BY a.id
          {having_sql}
          ORDER BY a.published_utc DESC NULLS LAST
          LIMIT ? OFFSET ?
        """  # nosec B608 -- placeholders generados; datos de usuario por parámetros
        rows = conn.execute(list_sql, params + [per_page, page * per_page]).fetchall()
    finally:
        conn.close()

    return jsonify({
        "page": page,
        "per_page": per_page,
        "total": total_filtered,
        "articles": [dict(r) for r in rows],
    })


@app.route("/api/corpus/article/<int:article_id>")
def corpus_article_detail(article_id):
    """Detalle completo de un artículo: metadatos, body, extraction y verdicts v1/v2."""
    conn = _get_db()
    try:
        art_row = conn.execute(
            "SELECT id, source, url, title, published_utc, body, processing_state, ingested_at "
            "FROM articles WHERE id = ?",
            (article_id,)
        ).fetchone()
        if art_row is None:
            return jsonify({"error": "not_found"}), 404
        article = dict(art_row)

        ext_row = conn.execute(
            "SELECT id, model, ttps, reasoning, valid_ttp_count, validation_issues, "
            "       prefilter_reason, max_similarity_score, elapsed_seconds, created_at "
            "FROM extractions WHERE article_id = ? ORDER BY id DESC LIMIT 1",
            (article_id,)
        ).fetchone()
        extraction = None
        ttps_parsed = []
        if ext_row:
            extraction = dict(ext_row)
            try:
                ttps_parsed = json.loads(extraction["ttps"]) if extraction["ttps"] else []
            except (json.JSONDecodeError, TypeError):
                ttps_parsed = []

            # Veredictos v1 y v2 indexados por ttp_index
            v1_rows = conn.execute(
                "SELECT ttp_index, technique_id, verdict, reasoning, model "
                "FROM ttp_verdicts WHERE extraction_id = ?",
                (extraction["id"],)
            ).fetchall()
            v1_by_idx = {r["ttp_index"]: dict(r) for r in v1_rows}

            v2_rows = conn.execute(
                "SELECT ttp_index, technique_id, verdict, reasoning, model, source_mode "
                "FROM ttp_verdicts_v2 WHERE extraction_id = ?",
                (extraction["id"],)
            ).fetchall()
            v2_by_idx = {r["ttp_index"]: dict(r) for r in v2_rows}

            # Adjuntar a cada TTP su veredicto v1 y v2
            for i, ttp in enumerate(ttps_parsed):
                ttp["_index"] = i
                ttp["_v1"] = v1_by_idx.get(i)
                ttp["_v2"] = v2_by_idx.get(i)

            extraction["ttps_parsed"] = ttps_parsed
            # No mandamos el JSON crudo: ya va parseado
            extraction.pop("ttps", None)
    finally:
        conn.close()

    return jsonify({
        "article":    article,
        "extraction": extraction,
    })


@app.route("/calibration-stats")
def calibration_stats_index():
    return render_template("calibration_stats/index.html")


@app.route("/api/calibration-stats/data")
def calibration_stats_data():
    """
    Devuelve el bundle de datos de la calibración humana (sesión 19, 484 anotaciones).

    - sample_distribution: cuentas por sample_type × verdict
    - confusion_v1:        matriz 3×3 humano vs LLM v1 (sobre la muestra estratificada)
    - control_distribution: distribución del grupo de control (sin v1)
    - taxonomy:            cuentas por error_taxonomy_code (E1-E5)
    - alpha_by_source:     Krippendorff α por fuente (de la sesión 19)
    - quotes:              las 484 anotaciones completas (para el visor de quotes en el cliente)
    """
    conn = _get_db()
    try:
        # Distribución por tipo de muestra
        sample_distribution = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT sample_type, COUNT(*) FROM calibration_sample "
                "WHERE human_blind_verdict IS NOT NULL GROUP BY sample_type"
            ).fetchall()
        }

        # Matriz de confusión humano vs v1 sobre la muestra estratificada
        confusion_v1 = []
        for row in conn.execute(
            """
            SELECT human_blind_verdict, llm_verdict, COUNT(*) AS n
            FROM calibration_sample
            WHERE sample_type='stratified' AND human_blind_verdict IS NOT NULL
            GROUP BY human_blind_verdict, llm_verdict
            """
        ).fetchall():
            confusion_v1.append({
                "human": row[0],
                "v1": row[1],
                "count": row[2],
            })

        # Distribución del grupo de control
        control_distribution = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT human_blind_verdict, COUNT(*) FROM calibration_sample "
                "WHERE sample_type='control' AND human_blind_verdict IS NOT NULL "
                "GROUP BY human_blind_verdict"
            ).fetchall()
        }

        # Taxonomía
        taxonomy = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT error_taxonomy_code, COUNT(*) FROM calibration_sample "
                "WHERE error_taxonomy_code IS NOT NULL GROUP BY error_taxonomy_code"
            ).fetchall()
        }

        # Quotes completos para el visor
        quotes = []
        for row in conn.execute(
            """
            SELECT id, sample_type, technique_id, quote, source,
                   human_blind_verdict, human_reconciled_verdict,
                   llm_verdict, llm_reasoning, error_taxonomy_code,
                   annotation_notes, annotated_at, article_id
            FROM calibration_sample
            WHERE human_blind_verdict IS NOT NULL
            ORDER BY id
            """
        ).fetchall():
            quotes.append(dict(row))
    finally:
        conn.close()

    # Krippendorff α por fuente: snapshot de la sesión 19 (16-abr-2026).
    #
    # Calcularlo en caliente desde la BD actual daría valores distintos a los
    # que cita la memoria (§calibración), porque el corpus ha cambiado desde la sesión
    # 19 (más anotaciones humanas, dedup B1 aplicado, el juez v1 amplió
    # cobertura). Bajar `min_n` en krippendorff_segmented.py para incluir
    # Huntress/Trendmicro/Elastic/Welivesecurity tampoco arregla nada: sus α
    # se recalcularían sobre la BD evolucionada y no encajarían con los
    # números que aparecen en la memoria.
    #
    # La α del contrato (α=0,6461 sobre la estratificada, Objetivo 3) no
    # depende de este corte y se puede reproducir desde
    # outputs/krippendorff_segmented/headline.csv, que el script sí regenera
    # de forma consistente.
    #
    # Pasar a leer el CSV dinámicamente exigiría reescribir la narrativa de
    # la memoria (§calibración) para que cuadre con la BD actual. Trabajo a futuro,
    # post-defensa.
    alpha_by_source = [
        {"source": "huntress",            "alpha": 0.73,  "n": 5,   "verdict_h": "good"},
        {"source": "trendmicro_research", "alpha": 0.78,  "n": 6,   "verdict_h": "good"},
        {"source": "elastic_security_labs","alpha": 0.21,  "n": 9,   "verdict_h": "marginal"},
        {"source": "cisa",                "alpha": 0.16,  "n": 11,  "verdict_h": "marginal"},
        {"source": "dfir_report",         "alpha": 0.10,  "n": 17,  "verdict_h": "marginal"},
        {"source": "microsoft_security",  "alpha": -0.05, "n": 25,  "verdict_h": "poor"},
        {"source": "cisco_talos",         "alpha": -0.09, "n": 38,  "verdict_h": "poor"},
        {"source": "crowdstrike_blog",    "alpha": -0.10, "n": 31,  "verdict_h": "poor"},
        {"source": "bc_site",             "alpha": -0.18, "n": 163, "verdict_h": "poor"},
        {"source": "red_canary",          "alpha": -0.27, "n": 7,   "verdict_h": "poor"},
        {"source": "welivesecurity",      "alpha": -0.30, "n": 4,   "verdict_h": "poor"},
        {"source": "sentinelone_blog",    "alpha": -0.38, "n": 31,  "verdict_h": "poor"},
        {"source": "unit42",              "alpha": -0.60, "n": 29,  "verdict_h": "poor"},
    ]

    return jsonify({
        "sample_distribution":  sample_distribution,
        "confusion_v1":         confusion_v1,
        "control_distribution": control_distribution,
        "taxonomy":             taxonomy,
        "alpha_by_source":      alpha_by_source,
        "alpha_global_v1":      -0.1452,
        "alpha_global_v2":      0.5738,
        "quotes":               quotes,
    })


@app.route("/arm")
def arm_index():
    return render_template("arm/index.html")


@app.route("/api/arm/data")
def arm_data():
    """Bundle para la página de co-ocurrencia y ARM."""
    base = _COOCCURRENCE_DIR
    return jsonify({
        "centrality":   _read_csv_records(base / "graph_centrality.csv"),
        "edges":        _read_csv_records(base / "pairwise_cooccurrence.csv"),
        "rules":        _read_csv_records(base / "arm_rules.csv"),
        "rules_sig":    _read_csv_records(base / "arm_rules_significant.csv"),
        "tactic_pairs": _read_csv_records(base / "top_rules_by_tactic_pair.csv"),
    })


# --- Catalog lag (análisis de latencia de MITRE ATT&CK, sesión 27) ---
#
# Mide el desfase entre la primera evidencia textual de una técnica en el
# corpus y su catalogación oficial por MITRE. OJO: esto NO valida el valor
# predictivo del pipeline; ver el caveat D1 (data leakage retrospectivo del
# extractor) en la memoria del TFG (§resultados, catalog-lag).

@app.route("/catalog-lag")
def catalog_lag_index():
    return render_template("catalog_lag/index.html")


def _binomial_test_exact_one_sided(k, n, p):
    """P(X >= k) bajo X ~ Binomial(n, p). Solo stdlib (math.lgamma).
    Para el test 21/49 con H0=0.5 da p≈0.8736, igual que el script standalone.
    Devuelve el max(p_lower, p_upper) one-sided para no interpretar mal el signo.
    """
    if n == 0:
        return None
    import math
    def log_binom_pmf(k, n, p):
        if k < 0 or k > n:
            return float("-inf")
        if p in (0.0, 1.0):
            return 0.0 if (k == 0 and p == 0.0) or (k == n and p == 1.0) else float("-inf")
        return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
                + k * math.log(p) + (n - k) * math.log(1 - p))
    # Sumatorio en log-space para no desbordar.
    def sum_pmf_from(k_min):
        total = 0.0
        for kk in range(k_min, n + 1):
            total += math.exp(log_binom_pmf(kk, n, p))
        return total
    p_upper = sum_pmf_from(k)
    p_lower = 1.0 - sum_pmf_from(k + 1) if k < n else 0.0
    return max(min(p_upper, 1.0), min(p_lower, 1.0))


def _build_lag_histogram(rows):
    """Histograma con bins de 200 días sobre catalog_lag_release_days en el rango [-2000, 2000]."""
    bin_size = 200
    edges = list(range(-2000, 2001, bin_size))
    bins = [0] * (len(edges) - 1)
    for r in rows:
        try:
            v = int(r["catalog_lag_release_days"])
        except (KeyError, ValueError, TypeError):
            continue
        if v < edges[0] or v >= edges[-1]:
            continue
        idx = (v - edges[0]) // bin_size
        if 0 <= idx < len(bins):
            bins[idx] += 1
    return {
        "edges": edges,
        "counts": bins,
        "bin_size": bin_size,
    }


@app.route("/api/catalog-lag/data")
def catalog_lag_data():
    """Bundle para la página de catalog lag.

    Devuelve los CSVs principales que genera `mitre_catalog_lag.py`:
      - all_techniques: las 290 técnicas accept v2 (sin CrowdStrike), con todas
        las métricas de lag calculadas sobre tres fuentes de fechas MITRE.
      - strict: las 4 técnicas que sobreviven al filtro
        `lag_min > 0 AND lag_median > 0 AND accept_count >= 3 AND n_sources >= 2`.
        Hallazgo publicable.
      - robust: subconjunto con `lag_min > 0 AND accept_count >= 3`.
      - multisource: subconjunto con `lag_min > 0 AND n_sources >= 2`.
      - positive: técnicas con `lag_min > 0` (incluye outliers iniciales).
      - post_corpus_start: 49 técnicas que MITRE añadió después del inicio
        del corpus (denominador del test binomial).

    Además, calcula al vuelo el test binomial sobre `post_corpus_start` y
    devuelve el p-value (así no hace falta re-ejecutar scipy desde el
    contenedor).
    """
    base = _CATALOG_LAG_DIR
    all_t  = _read_csv_records(base / "all_techniques.csv")
    strict = _read_csv_records(base / "catalog_lag_strict.csv")
    robust = _read_csv_records(base / "catalog_lag_robust.csv")
    multi  = _read_csv_records(base / "catalog_lag_multisource.csv")
    positive = _read_csv_records(base / "catalog_lag.csv")
    post   = _read_csv_records(base / "post_corpus_start.csv")
    revoked = _read_csv_records(base / "revoked.csv")

    # --- Agregados rápidos que se muestran en la cabecera ---
    n_total = len(all_t)
    n_positive = len(positive)
    n_strict = len(strict)
    n_post = len(post)
    n_post_positive = sum(
        1 for r in post
        if (r.get("catalog_lag_release_days") or "").lstrip("-").isdigit()
        and int(r["catalog_lag_release_days"]) > 0
    )
    # Test binomial exacto (sumatorio binomial con H0=0.5) usando solo stdlib.
    binom_p = _binomial_test_exact_one_sided(n_post_positive, n_post, 0.5) \
              if n_post else None

    # --- Histograma de catalog_lag_release_days sobre todas las técnicas ---
    histogram = _build_lag_histogram(all_t)

    # --- Modo de fallo "outlier inicial": min > 0 pero median < 0 ---
    outliers = []
    for r in positive:
        try:
            lag_min = int(r["catalog_lag_release_days"])
            lag_median = int(r["catalog_lag_release_median_days"])
        except (KeyError, ValueError, TypeError):
            continue
        if lag_min > 0 and lag_median < 0:
            outliers.append({
                "technique_id": r["technique_id"],
                "name": r["name"],
                "lag_min": lag_min,
                "lag_median": lag_median,
                "accept_count": int(r.get("accept_count") or 0),
                "n_sources": int(r.get("n_sources") or 0),
                "sources": r.get("sources", ""),
            })
    outliers.sort(key=lambda x: -x["lag_min"])

    return jsonify({
        "summary": {
            "n_total_techniques": n_total,
            "n_positive_lag": n_positive,
            "n_strict": n_strict,
            "n_post_corpus_start": n_post,
            "n_post_positive": n_post_positive,
            "binomial_p_value": binom_p,
            "binomial_observed_rate": (n_post_positive / n_post) if n_post else None,
        },
        "strict": strict,
        "robust": robust,
        "multisource": multi,
        "positive": positive,
        "post_corpus_start": post,
        "revoked": revoked,
        "histogram": histogram,
        "outliers": outliers,
    })


@app.route("/judge")
def judge_compare_index():
    return render_template("judge/index.html")


@app.route("/api/judge/data")
def judge_compare_data():
    """Bundle para la página que compara el juez v1 contra el v2."""
    base = _EVAL_F1_DIR

    # Migración v1→v2: solo el modo 'rejudge' (los accepts de v1 que v2 ha vuelto a juzgar)
    conn = _get_db()
    try:
        mig_rows = conn.execute(
            """
            SELECT v1.verdict AS v1_v, v2.verdict AS v2_v, COUNT(*) AS n
            FROM ttp_verdicts v1
            JOIN ttp_verdicts_v2 v2
              ON v1.extraction_id = v2.extraction_id AND v1.ttp_index = v2.ttp_index
            WHERE v2.source_mode = 'rejudge'
            GROUP BY v1.verdict, v2.verdict
            """
        ).fetchall()
        migration = [{"v1": r[0], "v2": r[1], "count": r[2]} for r in mig_rows]

        v1_rows = conn.execute(
            "SELECT verdict, COUNT(*) FROM ttp_verdicts GROUP BY verdict"
        ).fetchall()
        v1_totals = {r[0]: r[1] for r in v1_rows}

        v2_rows = conn.execute(
            "SELECT source_mode, verdict, COUNT(*) "
            "FROM ttp_verdicts_v2 GROUP BY source_mode, verdict"
        ).fetchall()
        v2_totals = [{"source_mode": r[0], "verdict": r[1], "count": r[2]} for r in v2_rows]
    finally:
        conn.close()

    return jsonify({
        "primary_metrics":  _read_csv_records(base / "primary_metrics.csv"),
        "confusion_matrix": _read_csv_records(base / "confusion_matrix_3x3.csv"),
        "error_taxonomy":   _read_csv_records(base / "error_taxonomy_correction.csv"),
        "per_source":       _read_csv_records(base / "per_source_metrics.csv"),
        "per_technique":    _read_csv_records(base / "per_technique_metrics.csv"),
        "sensitivity":      _read_csv_records(base / "sensitivity_analysis.csv"),
        "tost":             _read_csv_records(base / "tost_equivalence.csv"),
        "extractor_yield":  _read_csv_records(base / "extractor_only_yield.csv"),
        "v1_totals":        v1_totals,
        "v2_totals":        v2_totals,
        "migration":        migration,
        # Alpha v1 (Krippendorff sobre la muestra estratificada, sesión 19). No
        # hay CSV asociado: es un valor histórico que dejamos hardcodeado.
        "alpha_v1":         -0.1452,
    })


@app.route("/longitudinal")
def longitudinal_index():
    return render_template("longitudinal/index.html")


@app.route("/api/longitudinal/data")
def longitudinal_data():
    """Devuelve, como JSON, el bundle de CSVs que viven en outputs/longitudinal/."""
    base = _LONGITUDINAL_DIR
    return jsonify({
        "volume_by_year":      _read_csv_records(base / "volume_by_year.csv"),
        "volume_by_quarter":   _read_csv_records(base / "volume_by_quarter.csv"),
        "tactic_distribution": _read_csv_records(base / "tactic_distribution_by_year.csv"),
        "top_techniques":      _read_csv_records(base / "top_techniques_by_year.csv"),
        "mann_kendall":        _read_csv_records(base / "mann_kendall_prevalence_matrix.csv"),
        "normalized_emergence": _read_csv_records(base / "normalized_emergence.csv"),
        "shannon_entropy":     _read_csv_records(base / "shannon_entropy.csv"),
        "source_contribution": _read_csv_records(base / "source_contribution_by_year.csv"),
        "double_extortion":    _read_csv_records(base / "double_extortion_doc_level.csv"),
    })


# --- Runner del judge v2 (Gemma 4 a través de Google AI Studio) ---
#
# Se dispara desde /api/demo/job/event cuando llega rag_extract.end con
# parsed_ttps. Corre en un thread daemon y va insertando los eventos
# judge_v2.start, judge_v2.end y pipeline.end directamente en demo_events.
#
# La LÓGICA del modelo (system prompt, call_gemini y lookup de MITRE) está
# movida a `judge_core.py` para no duplicarla con `judge_v2.py` (script
# standalone). Si hay que tocar el SYSTEM_PROMPT, hacerlo en `judge_core.py`.

# Cache en memoria del proceso Flask para no releer el JSON en cada job.
_mitre_defs_cache = None


def _load_mitre_definitions():
    """Carga perezosa y memoizada. Lee del JSON local (sin descargar nada: lo
    rellena judge_v2.py la primera vez que se ejecuta). Devuelve {} si el
    fichero no existe."""
    global _mitre_defs_cache
    if _mitre_defs_cache is not None:
        return _mitre_defs_cache
    try:
        with open(_MITRE_CACHE_PATH) as f:
            _mitre_defs_cache = json.load(f)
    except (OSError, json.JSONDecodeError):
        _mitre_defs_cache = {}
    return _mitre_defs_cache


def _call_gemini(api_key, technique_id, technique_info, quote):
    """Wrapper ligero: delega en judge_core.call_gemini usando los settings de la demo."""
    return _call_gemini_impl(
        api_key=api_key,
        technique_id=technique_id,
        technique_info=technique_info,
        quote=quote,
        model=_JUDGE_MODEL,
        retries=_JUDGE_RETRIES,
        timeout_s=_JUDGE_TIMEOUT_S,
    )


def _insert_demo_event(conn, job_id, stage, event_type, payload_dict):
    """Inserta un evento como si lo hubiese mandado el worker. ts = ahora."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO demo_events (job_id, stage, event_type, payload, ts) "
        "VALUES (?, ?, ?, ?, ?)",
        (job_id, stage, event_type, json.dumps(payload_dict, ensure_ascii=False), ts),
    )


def _run_judge_v2_for_job(job_id, parsed_ttps, prefilter_passed_summary=True):
    """Ejecuta el judge v2 sobre los TTPs extraídos y cierra el job.

    Inserta judge_v2.start, judge_v2.end y pipeline.end directamente en
    demo_events. Al terminar, pone demo_jobs.status='completed'.
    """
    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    started = _time.time()

    # Quedarse solo con los TTPs válidos para el juez (con technique_id y evidence_quote)
    judge_inputs = []
    for ttp in parsed_ttps or []:
        tid = (ttp.get("technique_id") or "").strip()
        quote = (ttp.get("evidence_quote") or "").strip()
        if tid and quote:
            judge_inputs.append({"technique_id": tid, "quote": quote})

    mitre = _load_mitre_definitions()
    per_ttp_prompts = []
    for inp in judge_inputs:
        info = mitre.get(inp["technique_id"], {})
        per_ttp_prompts.append(
            _build_judge_user_prompt(
                inp["technique_id"],
                info.get("name", inp["technique_id"]),
                info.get("description", "(definición no disponible)"),
                inp["quote"],
            )
        )

    conn = _get_db()
    try:
        _insert_demo_event(conn, job_id, "judge_v2", "start", {
            "model": _JUDGE_MODEL,
            "ttp_count": len(judge_inputs),
            "endpoint": (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{_JUDGE_MODEL}:generateContent"
            ),
            "system_prompt": _JUDGE_SYSTEM_PROMPT,
            "per_ttp_prompts": per_ttp_prompts,
        })
        conn.commit()
    finally:
        conn.close()

    verdicts = []
    if not api_key:
        # Sin API key: fallback que marca todos como uncertain explicando el motivo
        for inp in judge_inputs:
            verdicts.append({
                "technique_id": inp["technique_id"],
                "verdict": "uncertain",
                "reasoning": "GOOGLE_API_KEY no configurada en el servidor",
            })
    else:
        for i, inp in enumerate(judge_inputs):
            info = mitre.get(inp["technique_id"], {})
            try:
                res = _call_gemini(api_key, inp["technique_id"], info, inp["quote"])
                verdicts.append({
                    "technique_id": inp["technique_id"],
                    "verdict": res["verdict"],
                    "reasoning": res["reasoning"],
                })
            except Exception as e:
                verdicts.append({
                    "technique_id": inp["technique_id"],
                    "verdict": "uncertain",
                    "reasoning": f"error: {e}",
                })
            if i < len(judge_inputs) - 1:
                _time.sleep(_JUDGE_DELAY_S)

    accept = sum(1 for v in verdicts if v["verdict"] == "accept")
    reject = sum(1 for v in verdicts if v["verdict"] == "reject")
    elapsed = _time.time() - started

    conn = _get_db()
    try:
        _insert_demo_event(conn, job_id, "judge_v2", "end", {
            "verdicts": verdicts,
            "accept_count": accept,
            "reject_count": reject,
            "elapsed_seconds": round(elapsed, 2),
        })

        row = conn.execute(
            "SELECT status FROM demo_jobs WHERE id=?", (job_id,)
        ).fetchone()
        already_done = bool(row) and row["status"] in (
            "completed", "filtered", "failed", "aborted"
        )

        _insert_demo_event(conn, job_id, "pipeline", "end", {
            "final_state": "completed",
            "summary": {
                "prefilter_passed": prefilter_passed_summary,
                "extracted": len(parsed_ttps or []),
                "accepted": accept,
            },
        })

        if not already_done:
            conn.execute(
                "UPDATE demo_jobs SET status='completed', finished_at=datetime('now') "
                "WHERE id=?",
                (job_id,),
            )
        conn.commit()
    finally:
        conn.close()


def _judge_thread_wrapper(job_id, parsed_ttps):
    try:
        print(f"[judge-thread] start job_id={job_id} n_ttps={len(parsed_ttps)}", flush=True)
        _run_judge_v2_for_job(job_id, parsed_ttps)
        print(f"[judge-thread] done job_id={job_id}", flush=True)
    except Exception as e:
        import traceback
        print(f"[judge-thread] FAILED job_id={job_id}: {e}", flush=True)
        traceback.print_exc()


def _spawn_judge_thread(job_id, parsed_ttps):
    th = threading.Thread(
        target=_judge_thread_wrapper,
        args=(job_id, parsed_ttps),
        daemon=True,
    )
    th.start()
    print(f"[judge-thread] spawned thread for job_id={job_id}, alive={th.is_alive()}", flush=True)


@app.route("/api/demo/heartbeat", methods=["POST"])
@require_basic_auth
def demo_heartbeat():
    """
    Recibe el heartbeat del PC remoto y, si el PC está libre, le entrega el
    próximo job en estado 'queued'. La auth se hace con Basic Auth en NPM (el
    frontal).

    Payload JSON:
      { "hostname": str, "client_version": str,
        "meta": { "ollama_ok": bool, "ollama_models": [...], "gpu_mem_used_mb": int,
                  "current_job_id": int | null } }

    Respuesta:
      { "ok": True, "received_at_utc": iso, "next_job": {...} | null }
    """
    payload = request.get_json(silent=True) or {}
    hostname = (payload.get("hostname") or "").strip()[:120] or None
    client_version = (payload.get("client_version") or "").strip()[:60] or None
    meta = payload.get("meta") or {}
    meta_json = json.dumps(meta) if meta else None

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    next_job = None
    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO pc_heartbeat (id, hostname, last_seen_utc, client_version, meta_json)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              hostname = excluded.hostname,
              last_seen_utc = excluded.last_seen_utc,
              client_version = excluded.client_version,
              meta_json = excluded.meta_json
            """,
            (hostname, now_iso, client_version, meta_json),
        )

        if meta.get("current_job_id") is None:
            row = conn.execute(
                "SELECT id, input_type, article_id, title, body, published_utc "
                "FROM demo_jobs WHERE status='queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is not None:
                job_id = row["id"]
                body = row["body"]
                title = row["title"]
                published = row["published_utc"]

                if row["input_type"] == "corpus" and not body and row["article_id"] is not None:
                    art = conn.execute(
                        "SELECT title, body, published_utc FROM articles WHERE id=?",
                        (row["article_id"],),
                    ).fetchone()
                    if art is not None:
                        body = art["body"]
                        title = title or art["title"]
                        published = published or art["published_utc"]

                conn.execute(
                    "UPDATE demo_jobs SET status='running', started_at=datetime('now') "
                    "WHERE id=? AND status='queued'",
                    (job_id,),
                )
                next_job = {
                    "id": job_id,
                    "input_type": row["input_type"],
                    "article_id": row["article_id"],
                    "title": title,
                    "body": body,
                    "published_utc": published,
                }

        conn.commit()
    finally:
        conn.close()

    return jsonify({"ok": True, "received_at_utc": now_iso, "next_job": next_job})


@app.route("/api/demo/job/event", methods=["POST"])
@require_basic_auth
def demo_job_event():
    """
    Recibe un evento de pipeline que emite el worker del PC.

    Payload JSON:
      { "job_id": int, "stage": str, "event_type": str,
        "payload": {...}, "ts": iso }

    Cuando stage='pipeline' y event_type='end', actualiza demo_jobs.status
    según payload.final_state.
    """
    data = request.get_json(silent=True) or {}
    try:
        job_id = int(data["job_id"])
        stage = str(data["stage"])[:40]
        event_type = str(data["event_type"])[:20]
    except (KeyError, ValueError, TypeError):
        return jsonify({"ok": False, "error": "invalid_payload"}), 400

    payload_obj = data.get("payload") or {}
    payload_json = json.dumps(payload_obj, ensure_ascii=False)
    ts = (data.get("ts") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))[:40]

    conn = _get_db()
    spawn_judge_with = None
    try:
        conn.execute(
            "INSERT INTO demo_events (job_id, stage, event_type, payload, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (job_id, stage, event_type, payload_json, ts),
        )

        if stage == "pipeline" and event_type == "end":
            row = conn.execute(
                "SELECT status FROM demo_jobs WHERE id=?", (job_id,)
            ).fetchone()
            current_status = row["status"] if row else None
            # Idempotente: si el job ya quedó cerrado por el runner del judge
            # en el servidor, ignoramos el pipeline.end del worker para no
            # pisar 'completed' con otro estado distinto.
            if current_status not in ("completed", "filtered", "failed", "aborted"):
                final = payload_obj.get("final_state", "completed")
                if final not in ("completed", "filtered", "failed", "aborted"):
                    final = "completed"
                conn.execute(
                    "UPDATE demo_jobs SET status=?, finished_at=datetime('now') WHERE id=?",
                    (final, job_id),
                )

        # Dispatch del judge: si llega rag_extract.end con TTPs, se lanza en background
        if stage == "rag_extract" and event_type == "end":
            parsed = payload_obj.get("parsed_ttps") or []
            if parsed:
                spawn_judge_with = parsed

        conn.commit()
    finally:
        conn.close()

    if spawn_judge_with is not None:
        _spawn_judge_thread(job_id, spawn_judge_with)

    return jsonify({"ok": True})


@app.route("/api/demo/jobs", methods=["GET", "POST"])
def demo_jobs():
    """
    GET: lista de jobs (los más recientes primero, máximo 50).
    POST: crea un job nuevo. Payload JSON:
      { "input_type": "corpus"|"paste", "article_id": int?, "title": str?, "body": str? }
    """
    # La auth solo aplica al POST (mutación). El GET sigue siendo público (dashboard).
    if request.method == "POST":
        deny = _basic_auth_or_401()
        if deny is not None:
            return deny
    conn = _get_db()
    try:
        if request.method == "GET":
            limit = max(1, min(int(request.args.get("limit", 50) or 50), 200))
            rows = conn.execute(
                "SELECT id, status, input_type, article_id, title, published_utc, "
                "created_at, started_at, finished_at "
                "FROM demo_jobs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return jsonify({"jobs": [dict(r) for r in rows]})

        data = request.get_json(silent=True) or {}
        input_type = data.get("input_type")
        if input_type not in ("corpus", "paste"):
            return jsonify({"ok": False, "error": "invalid_input_type"}), 400

        article_id = data.get("article_id")
        title = (data.get("title") or "").strip() or None
        body = (data.get("body") or "").strip() or None
        published_utc = (data.get("published_utc") or "").strip() or None

        if input_type == "corpus":
            if not article_id:
                return jsonify({"ok": False, "error": "article_id_required"}), 400
            art = conn.execute(
                "SELECT title, published_utc FROM articles WHERE id=?",
                (article_id,),
            ).fetchone()
            if art is None:
                return jsonify({"ok": False, "error": "article_not_found"}), 404
            title = title or art["title"]
            published_utc = published_utc or art["published_utc"]
            # el body se resuelve cuando el heartbeat haga el dispatch
        else:
            if not body:
                return jsonify({"ok": False, "error": "body_required"}), 400
            article_id = None
            title = title or "(texto pegado)"

        cur = conn.execute(
            "INSERT INTO demo_jobs (status, input_type, article_id, title, body, published_utc) "
            "VALUES ('queued', ?, ?, ?, ?, ?)",
            (input_type, article_id, title, body, published_utc),
        )
        conn.commit()
        return jsonify({"ok": True, "job_id": cur.lastrowid})
    finally:
        conn.close()


@app.route("/api/demo/jobs/<int:job_id>", methods=["GET"])
def demo_job_detail(job_id):
    """Devuelve el job junto con su lista de eventos ordenada por id."""
    conn = _get_db()
    try:
        job = conn.execute(
            "SELECT id, status, input_type, article_id, title, body, published_utc, "
            "created_at, started_at, finished_at "
            "FROM demo_jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        if job is None:
            return jsonify({"ok": False, "error": "not_found"}), 404
        events = conn.execute(
            "SELECT id, stage, event_type, payload, ts, received_at "
            "FROM demo_events WHERE job_id=? ORDER BY id",
            (job_id,),
        ).fetchall()
        return jsonify({
            "job": dict(job),
            "events": [
                {**dict(ev), "payload": json.loads(ev["payload"]) if ev["payload"] else {}}
                for ev in events
            ],
        })
    finally:
        conn.close()


@app.route("/api/demo/jobs/<int:job_id>/events", methods=["GET"])
def demo_job_events(job_id):
    """Stream incremental de eventos. Parámetro: after_id=N (por defecto 0)."""
    after_id = max(0, int(request.args.get("after_id", 0) or 0))
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, stage, event_type, payload, ts, received_at "
            "FROM demo_events WHERE job_id=? AND id>? ORDER BY id",
            (job_id, after_id),
        ).fetchall()
        job = conn.execute(
            "SELECT status FROM demo_jobs WHERE id=?", (job_id,)
        ).fetchone()
        return jsonify({
            "status": job["status"] if job else None,
            "events": [
                {**dict(r), "payload": json.loads(r["payload"]) if r["payload"] else {}}
                for r in rows
            ],
        })
    finally:
        conn.close()


@app.route("/api/demo/articles/search", methods=["GET"])
def demo_articles_search():
    """Búsqueda de artículos del corpus para el desplegable de la UI /pipeline.

    Param q: substring sobre el title (sin distinguir mayúsculas).
    Devuelve los 30 más recientes ordenados por published_utc DESC.
    """
    q = (request.args.get("q") or "").strip()
    conn = _get_db()
    try:
        if q:
            rows = conn.execute(
                "SELECT id, source, title, published_utc "
                "FROM articles WHERE title LIKE ? "
                "ORDER BY published_utc DESC NULLS LAST LIMIT 30",
                (f"%{q}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, source, title, published_utc "
                "FROM articles ORDER BY published_utc DESC NULLS LAST LIMIT 30"
            ).fetchall()
        return jsonify({"articles": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/pipeline")
def pipeline_index():
    # ?replay=<job_id> reproduce estáticamente un demo_job ya completado desde
    # demo_events (sin requerir el PC ni el heartbeat). El front llama a
    # loadJob(REPLAY_JOB_ID) en el onload. None si no se pasa o no es entero.
    replay_job_id = request.args.get("replay", type=int)
    return render_template("pipeline/index.html", replay_job_id=replay_job_id)


@app.route("/api/docs")
def api_docs():
    # Documentación interactiva: Swagger UI (CDN) sobre /static/openapi.yaml.
    # Read-only y pública, como el resto de páginas de inspección.
    return render_template("apidocs.html")


def init_runtime():
    """Arranca el servidor siguiendo un orden controlado."""
    _ensure_pc_heartbeat_table()
    repair_history()
    init_scheduler()


if __name__ == "__main__":
    init_runtime()
    app.run(host="0.0.0.0", port=7000, debug=False)