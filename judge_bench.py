#!/usr/bin/env python3
"""Experimento: ¿`temperature=0` mejora o empeora el juez Gemma 4 frente al humano?

El pipeline está CERRADO: el corpus se juzgó a la temperatura por defecto de la
API y de ahí salen las cifras publicadas. Este script NO toca ese pipeline: es un
experimento aparte que, sobre las anotaciones humanas (`calibration_sample`),
compara el acuerdo con el humano de dos brazos:

  - DEFAULT : el veredicto v2 CONGELADO en la BD (el juez del pipeline, temp por
              defecto). Se reutiliza; 0 llamadas.
  - TEMP0   : un veredicto NUEVO a `temperature=0`, con el MISMO prompt y modelo.

Mide accuracy / precision / recall / F1 / kappa / accept-rate de cada brazo vs el
humano, y un test de McNemar pareado (exacto) para decir si temp=0 cambia el
acuerdo de forma significativa o es ruido.

El juez se llama con la temperatura EXPLÍCITA (no usa judge_core.call_gemini), así
que el experimento es independiente del código de producción (se puede revertir
`temperature=0` en judge_core sin afectar a esto).

Multi-día: la cuota diaria del tier gratuito limita a ~cientos de llamadas/día.
El script es REANUDABLE (cada veredicto se escribe a --out y se saltan los hechos)
y PARA LIMPIO al detectar cuota agotada (varios 429 seguidos), en vez de girar.
Pensado para correrse a diario (cron o a mano) hasta completar:

    python3 judge_bench.py --collect-only      # una tanda diaria (recolecta y para)
    python3 judge_bench.py --analyze-only       # informe final cuando estén los 377

Requiere GOOGLE_API_KEY en el entorno. Análisis con stdlib (sin numpy/scipy).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
import time

import requests

from judge_core import (
    DEFAULT_MODEL,
    SYSTEM_PROMPT,
    build_user_prompt,
    gemini_url,
    load_mitre_definitions,
    lookup_technique,
)

HERE = os.path.dirname(os.path.abspath(__file__))
# Ruta relativa al repo (override por env DB_PATH para correr dentro del contenedor).
DB_DEFAULT = os.environ.get("DB_PATH", os.path.join(HERE, "data", "ransomware_intel.db"))
OUT_DEFAULT = os.path.join(HERE, "outputs", "judge_bench_temp0.jsonl")

_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {"verdict": {"type": "STRING"}, "reasoning": {"type": "STRING"}},
    "required": ["verdict", "reasoning"],
}


class Quota429(Exception):
    """429 sostenido tras reintentos cortos: probablemente cuota diaria agotada."""


# --- datos ---
def load_items(db_path: str) -> list[dict]:
    """Anotaciones humanas con su veredicto v2 congelado (default temp). Una fila
    por (extraction_id, ttp_index)."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute("""
        SELECT cs.extraction_id, cs.ttp_index, cs.technique_id, cs.quote,
               cs.human_blind_verdict AS human, cs.sample_type,
               (SELECT v.verdict FROM ttp_verdicts_v2 v
                 WHERE v.extraction_id = cs.extraction_id
                   AND v.ttp_index = cs.ttp_index
                 LIMIT 1) AS default_verdict
        FROM calibration_sample cs
        WHERE cs.quote IS NOT NULL AND trim(cs.quote) != ''
          AND cs.human_blind_verdict IS NOT NULL AND cs.human_blind_verdict != ''
    """).fetchall()
    con.close()
    return [dict(r) for r in rows if r["default_verdict"]]


# --- juez con temperatura explícita (autónomo, distingue 429-cuota de errores) ---
def judge(api_key: str, model: str, tid: str, info: dict, quote: str,
          temperature: float, timeout: int = 120) -> dict:
    name = info.get("name", tid)
    desc = info.get("description", "(definición no disponible)")
    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": build_user_prompt(tid, name, desc, quote)}]}],
        "generationConfig": {
            "temperature": temperature,
            "response_mime_type": "application/json",
            "response_schema": _RESPONSE_SCHEMA,
        },
    }
    url = gemini_url(model)
    err = None
    for attempt in range(4):
        try:
            r = requests.post(url, json=payload, timeout=timeout,
                              headers={"x-goog-api-key": api_key})
        except (requests.ConnectionError, requests.Timeout) as e:
            err = f"net:{e}"
            time.sleep(5)
            continue
        if r.status_code == 429:
            err = "429"
            if attempt < 3:
                time.sleep(30)
                continue
            raise Quota429()
        try:
            r.raise_for_status()
            txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(txt)
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise RuntimeError(f"respuesta malformada: {e}")
        except requests.HTTPError as e:
            err = f"http:{e}"
            time.sleep(5)
            continue
    raise RuntimeError(f"agotados reintentos: {err}")


def collect(items: list[dict], out_path: str, delay: float, temperature: float,
            max_consec_quota: int = 3, quota_wait: float = 0.0) -> int:
    """Recolecta veredictos temp=0, reanudable.

    quota_wait=0  -> al agotar la cuota PARA limpio (modo tanda/cron).
    quota_wait>0  -> al agotar la cuota DUERME quota_wait s y reintenta, en un
                     bucle persistente hasta completar (modo 'dejar de fondo').
    """
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if not api_key:
        sys.exit("ERROR: falta GOOGLE_API_KEY en el entorno.")
    mitre = load_mitre_definitions()

    def load_done() -> set:
        d = set()
        if os.path.exists(out_path):
            with open(out_path) as fr:
                for line in fr:
                    try:
                        rec = json.loads(line)
                        d.add((rec["extraction_id"], rec["ttp_index"]))
                    except Exception:
                        pass
        return d

    done = load_done()
    total_new = 0
    while True:
        pending = [it for it in items if (it["extraction_id"], it["ttp_index"]) not in done]
        if not pending:
            break
        print(f"[{time.strftime('%Y-%m-%d %H:%M')}] modelo={DEFAULT_MODEL} temp={temperature} "
              f"hechos={len(done)}/{len(items)} pendientes={len(pending)}", flush=True)
        consec_quota = 0
        quota_hit = made_progress = False
        with open(out_path, "a") as f:
            for it in pending:
                tid = it["technique_id"]
                info = lookup_technique(mitre, tid)
                try:
                    v = judge(api_key, DEFAULT_MODEL, tid, info, it["quote"], temperature)
                except Quota429:
                    consec_quota += 1
                    if consec_quota >= max_consec_quota:
                        quota_hit = True
                        break
                    continue
                except Exception as e:
                    consec_quota = 0
                    print(f"  ERROR {tid} ext={it['extraction_id']}: {e}", flush=True)
                    time.sleep(delay)
                    continue
                consec_quota = 0
                rec = {"extraction_id": it["extraction_id"], "ttp_index": it["ttp_index"],
                       "verdict": v.get("verdict", ""), "reasoning": v.get("reasoning", "")}
                f.write(json.dumps(rec) + "\n")
                f.flush()
                done.add((it["extraction_id"], it["ttp_index"]))
                total_new += 1
                made_progress = True
                print(f"  [{len(done):3}/{len(items)}] {tid} -> {rec['verdict']}", flush=True)
                time.sleep(delay)
        remaining = len(items) - len(done)
        if remaining == 0:
            break
        if quota_hit:
            if quota_wait > 0:
                print(f"  >>> Cuota agotada. Durmiendo {quota_wait/3600:.1f}h y reintentando "
                      f"(faltan {remaining}).", flush=True)
                time.sleep(quota_wait)
                continue
            print(f"  >>> Cuota agotada: parada limpia (faltan {remaining}).", flush=True)
            break
        if not made_progress:
            print("  >>> Sin progreso ni 429: paro para no girar sobre errores persistentes.", flush=True)
            break
    print(f"\nTotal recogido: {len(done)}/{len(items)} (nuevos esta ejecución: {total_new})", flush=True)
    return len(done)


# --- análisis (stdlib) ---
def binarize(verdict: str) -> int:
    """accept -> 1; reject/uncertain/otro -> 0 (binarización operacional CTI)."""
    return 1 if (verdict or "").strip().lower() == "accept" else 0


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    n = len(y_true)
    acc = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    po = acc
    p_pred1, p_true1 = (tp + fp) / n, (tp + fn) / n
    pe = p_pred1 * p_true1 + (1 - p_pred1) * (1 - p_true1)
    kappa = (po - pe) / (1 - pe) if (1 - pe) else 0.0
    return {"n": n, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "kappa": kappa,
            "accept_rate": sum(y_pred) / n if n else 0.0}


def mcnemar_exact(b: int, c: int) -> float:
    """p-valor exacto (dos colas) de McNemar sobre los pares discordantes."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n))


def analyze(items: list[dict], out_path: str) -> None:
    if not os.path.exists(out_path):
        sys.exit(f"No existe {out_path}; corre primero la recolección.")
    temp0 = {}
    with open(out_path) as f:
        for line in f:
            try:
                d = json.loads(line)
                temp0[(d["extraction_id"], d["ttp_index"])] = d["verdict"]
            except Exception:
                pass
    rows = [it for it in items if (it["extraction_id"], it["ttp_index"]) in temp0]
    if not rows:
        sys.exit("Aún no hay veredictos temp=0 que analizar.")
    H = [binarize(it["human"]) for it in rows]
    D = [binarize(it["default_verdict"]) for it in rows]
    T = [binarize(temp0[(it["extraction_id"], it["ttp_index"])]) for it in rows]
    md, mt = metrics(H, D), metrics(H, T)
    d_ok = [int(d == h) for h, d in zip(H, D)]
    t_ok = [int(t == h) for h, t in zip(H, T)]
    b = sum(1 for do, to in zip(d_ok, t_ok) if do and not to)
    c = sum(1 for do, to in zip(d_ok, t_ok) if not do and to)
    p = mcnemar_exact(b, c)
    flips = sum(1 for d, t in zip(D, T) if d != t)

    def fmt(m):
        return (f"acc={m['acc']*100:5.1f}%  F1={m['f1']:.3f}  kappa={m['kappa']:+.3f}  "
                f"P={m['prec']:.3f} R={m['rec']:.3f}  accept={m['accept_rate']*100:.1f}%")

    parcial = "" if len(rows) == len(items) else f"  [PARCIAL: {len(rows)}/{len(items)}]"
    print("=" * 82)
    print(f"EXPERIMENTO temperature=0 vs default: N={len(rows)} ítems pareados{parcial}")
    print("=" * 82)
    print(f"  Humano accept-rate:            {sum(H)/len(H)*100:.1f}%")
    print(f"  DEFAULT (pipeline) vs humano:  {fmt(md)}")
    print(f"  TEMP=0  (nuevo)    vs humano:  {fmt(mt)}")
    print(f"\n  Veredictos que CAMBIAN con temp=0: {flips}/{len(rows)} ({flips/len(rows)*100:.1f}%)")
    print(f"  McNemar: default-solo-acierta b={b}, temp0-solo-acierta c={c}, p={p:.4f}")
    delta = (mt["acc"] - md["acc"]) * 100
    if p < 0.05:
        concl = (f"temp=0 MEJORA significativamente ({delta:+.1f} pp accuracy)" if c > b
                 else f"temp=0 EMPEORA significativamente ({delta:+.1f} pp accuracy)")
    else:
        concl = f"sin diferencia significativa (Δacc={delta:+.1f} pp, p={p:.3f})"
    print(f"\n  >>> CONCLUSIÓN: {concl}")
    print("\n  --- por sample_type ---")
    for st in ("control", "stratified"):
        sub = [it for it in rows if it["sample_type"] == st]
        if not sub:
            continue
        h = [binarize(it["human"]) for it in sub]
        d = [binarize(it["default_verdict"]) for it in sub]
        t = [binarize(temp0[(it["extraction_id"], it["ttp_index"])]) for it in sub]
        print(f"    {st:11} N={len(sub):3}  humano_accept={sum(h)/len(h)*100:4.1f}%  "
              f"default_acc={metrics(h,d)['acc']*100:4.1f}%  temp0_acc={metrics(h,t)['acc']*100:4.1f}%  "
              f"default_accept={sum(d)/len(d)*100:4.1f}% temp0_accept={sum(t)/len(t)*100:4.1f}%")
    print("=" * 82)


def main() -> None:
    ap = argparse.ArgumentParser(description="Experimento juez Gemma 4: temp=0 vs default")
    ap.add_argument("--db", default=DB_DEFAULT, help="ruta a la BD canónica (default: data/ del repo)")
    ap.add_argument("--out", default=OUT_DEFAULT, help="JSONL de veredictos temp=0 (reanudable)")
    ap.add_argument("--delay", type=float, default=6.0, help="segundos entre llamadas")
    ap.add_argument("--temperature", type=float, default=0.0, help="temperatura del brazo experimental")
    ap.add_argument("--max-consec-429", type=int, default=3, help="429 seguidos para declarar cuota agotada")
    ap.add_argument("--quota-wait", type=float, default=0.0,
                    help="s a dormir al agotar cuota antes de reintentar (0=parar limpio; >0=bucle persistente de fondo)")
    ap.add_argument("--collect-only", action="store_true", help="solo recolecta (no analiza)")
    ap.add_argument("--analyze-only", action="store_true", help="solo analiza el JSONL ya recogido")
    args = ap.parse_args()

    items = load_items(args.db)
    print(f"Ítems pareados (humano + default congelado): {len(items)}\n", flush=True)
    if not args.analyze_only:
        collect(items, args.out, args.delay, args.temperature, args.max_consec_429, args.quota_wait)
    if not args.collect_only:
        analyze(items, args.out)


if __name__ == "__main__":
    main()
