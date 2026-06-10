#!/usr/bin/env python3
"""
Análisis de co-ocurrencia y Association Rule Mining sobre el corpus limpio
(2.355 TTPs).

Uso:
    python3 cooccurrence_analysis.py [--db PATH] [--csv-dir DIR]

Salidas (en --csv-dir, por defecto outputs/cooccurrence/):
    1. pairwise_cooccurrence.csv: similitud de Jaccard para todos los pares
       que co-ocurren.
    2. arm_rules.csv: todas las reglas que pasan los umbrales de support,
       confidence y lift.
    3. arm_rules_significant.csv: filtrado a reglas significativas BH
       (FDR α=0.05).
    4. graph_centrality.csv: degree / PageRank / betweenness (grafo
       completo y con T1486 eliminado).
    5. top_rules_by_tactic_pair.csv: mejores reglas agrupadas por
       transiciones entre tácticas.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sqlite3
from collections import Counter, defaultdict, deque

DB_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "ransomware_intel.db")
MITRE_CACHE = os.path.join(os.path.dirname(__file__), "data", "mitre_attack_cache.json")
CSV_DEFAULT = os.path.join(os.path.dirname(__file__), "outputs", "cooccurrence")

# T1486 (Data Encrypted for Impact) aparece en la mayoría de artículos de
# ransomware y actúa como un pozo gravitatorio del grafo. Lo eliminamos en
# el segundo grafo para que se vea la subestructura.
RANSOMWARE_PAYLOAD = "T1486"

# Aristas con Jaccard por debajo de este umbral se podan del grafo (suelo
# de ruido).
MIN_JACCARD = 0.02

# Conteo mínimo de co-ocurrencias para aristas del grafo (filtra artefactos
# de un único caso). Pares con count_both=1 pueden dar Jaccard=1.0 si ambas
# técnicas son raras, lo que infla artificialmente su degree centrality.
MIN_COOCCURRENCE = 2

# Umbrales de ARM (calibrados para corpus CTI esparsos según la literatura).
MIN_SUPPORT = 0.01      # >=1% de los artículos (~12 documentos)
MIN_CONFIDENCE = 0.40   # >=40% de probabilidad condicional
MIN_LIFT = 1.2          # >1.2x por encima del baseline de independencia

TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Orden cronológico del kill-chain para inferir dirección temporal.
# A->B "forward" significa que la táctica de A precede a la de B en el
# kill-chain.
TACTIC_ORDER = {
    "TA0043": 0,   # Reconnaissance
    "TA0042": 1,   # Resource Development
    "TA0001": 2,   # Initial Access
    "TA0002": 3,   # Execution
    "TA0003": 4,   # Persistence
    "TA0004": 5,   # Privilege Escalation
    "TA0005": 6,   # Defense Evasion
    "TA0006": 7,   # Credential Access
    "TA0007": 8,   # Discovery
    "TA0008": 9,   # Lateral Movement
    "TA0009": 10,  # Collection
    "TA0011": 11,  # Command and Control
    "TA0010": 12,  # Exfiltration
    "TA0040": 13,  # Impact
}


# --- utilidades ---
def _header(title):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def _pct(n, total):
    return f"{100*n/total:.1f}%" if total else "0.0%"


def save_csv(path, rows, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  saved {path}")


# --- carga de datos ---
def load_technique_names(cache_path):
    """Carga los nombres de técnicas desde el JSON de caché de MITRE ATT&CK."""
    if not os.path.exists(cache_path):
        return {}
    with open(cache_path) as f:
        cache = json.load(f)
    return {k: v.get("name", k) for k, v in cache.items()}


def load_transactions(db_path, mitre_names):
    """
    Carga los TTPs aceptados agrupados por article_id (una transacción por
    artículo).

    Returns:
        transactions: lista de frozensets de technique_ids.
        tech_meta:    dict {technique_id: {tactic_id, name}}.
        tech_count:   dict {technique_id: nº de artículos que contienen la
                      técnica}.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        SELECT
            v.article_id,
            v.ttp_index,
            v.technique_id,
            e.ttps
        FROM ttp_verdicts_v2 v
        JOIN extractions e ON e.id = v.extraction_id
        WHERE v.verdict = 'accept'
        ORDER BY v.article_id, v.ttp_index
    """)
    rows = cur.fetchall()
    con.close()

    by_article = defaultdict(set)   # article_id -> set de technique_ids
    tech_meta = {}                  # technique_id -> {tactic_id, name}
    skipped = 0

    for article_id, ttp_index, tech_id, ttps_json in rows:
        try:
            ttps = json.loads(ttps_json)
        except (json.JSONDecodeError, TypeError):
            skipped += 1
            continue
        if ttp_index >= len(ttps):
            skipped += 1
            continue
        ttp = ttps[ttp_index]
        tactic_id = ttp.get("tactic_id") or "unknown"
        # El JSON de ttps no trae campo 'name': lo resolvemos desde la caché de MITRE.
        parent_id = tech_id.split(".")[0]
        name = (mitre_names.get(tech_id)
                or mitre_names.get(parent_id)
                or tech_id)
        by_article[article_id].add(tech_id)
        if tech_id not in tech_meta:
            tech_meta[tech_id] = {"tactic_id": tactic_id, "name": name}

    if skipped:
        print(f"[warn] skipped {skipped} TTPs (JSON parse error or out-of-bounds index)")

    transactions = [frozenset(techs) for techs in by_article.values() if techs]
    tech_count = defaultdict(int)
    for txn in transactions:
        for t in txn:
            tech_count[t] += 1

    print(f"Loaded {len(transactions)} articles with ≥1 accepted TTP "
          f"({len(tech_meta)} unique techniques, "
          f"{sum(len(t) for t in transactions)} technique-article pairs)")
    return transactions, tech_meta, dict(tech_count)


# --- utilidades estadísticas ---
def _log_hyper_pmf(k, N, K, n):
    """log P(X=k) para Hipergeométrica(población=N, éxitos=K, extracciones=n).

    Usa log-gamma para evitar overflow con factoriales grandes.
    """
    lo = max(0, n + K - N)
    hi = min(n, K)
    if k < lo or k > hi:
        return float("-inf")
    return (
        math.lgamma(K + 1) - math.lgamma(k + 1) - math.lgamma(K - k + 1)
        + math.lgamma(N - K + 1) - math.lgamma(n - k + 1) - math.lgamma(N - K - n + k + 1)
        - math.lgamma(N + 1) + math.lgamma(n + 1) + math.lgamma(N - n + 1)
    )


def fisher_exact_pvalue(n11, n12, n21, n22):
    """Test exacto de Fisher (bilateral) sobre una tabla de contingencia 2x2.

    Disposición:
        |  B=1  B=0
    A=1 | n11   n12
    A=0 | n21   n22

    Devuelve el p-value exacto. Usa lgamma para manejar conteos grandes sin
    overflow. Preferible a Chi-cuadrado cuando alguna frecuencia esperada
    es <5 (frecuente en corpus CTI esparsos).
    """
    N = n11 + n12 + n21 + n22
    K = n11 + n21   # total de la columna 1 (B presente)
    n = n11 + n12   # total de la fila 1 (A presente)

    if N == 0 or K == 0 or n == 0 or K == N or n == N:
        return 1.0

    log_p_obs = _log_hyper_pmf(n11, N, K, n)
    lo = max(0, n + K - N)
    hi = min(n, K)

    p_total = 0.0
    for k in range(lo, hi + 1):
        log_p_k = _log_hyper_pmf(k, N, K, n)
        if log_p_k <= log_p_obs + 1e-10:
            p_total += math.exp(log_p_k)

    return min(1.0, p_total)


def benjamini_hochberg(p_values, alpha=0.05):
    """Corrección FDR de Benjamini-Hochberg.

    Devuelve una lista de bool (True = se rechaza H0 = significativo).
    Aplica el procedimiento step-up: encuentra el mayor rank k tal que
    p(k) <= k*alpha/m y rechaza todas las hipótesis con rank <= k.
    """
    m = len(p_values)
    if m == 0:
        return []
    indexed = sorted(range(m), key=lambda i: p_values[i])
    last_rejected = -1
    for rank, i in enumerate(indexed, 1):
        if p_values[i] <= alpha * rank / m:
            last_rejected = rank
    result = [False] * m
    for rank, i in enumerate(indexed, 1):
        if rank <= last_rejected:
            result[i] = True
    return result


# --- ARM ---
def compute_pairwise(transactions):
    """Calcula los conteos de co-ocurrencia por pares y las similitudes de
    Jaccard.

    Devuelve un dict {(tech_a, tech_b): {count_both, count_a, count_b,
    jaccard, support}} donde tech_a < tech_b lexicográficamente (orden
    canónico).
    """
    n_docs = len(transactions)
    tech_count = defaultdict(int)
    pair_count = defaultdict(int)

    for txn in transactions:
        techs = sorted(txn)
        for t in techs:
            tech_count[t] += 1
        for i in range(len(techs)):
            for j in range(i + 1, len(techs)):
                pair_count[(techs[i], techs[j])] += 1

    pairwise = {}
    for (a, b), count_both in pair_count.items():
        count_a = tech_count[a]
        count_b = tech_count[b]
        union = count_a + count_b - count_both
        jaccard = count_both / union if union > 0 else 0.0
        support = count_both / n_docs
        pairwise[(a, b)] = {
            "count_both": count_both,
            "count_a": count_a,
            "count_b": count_b,
            "jaccard": jaccard,
            "support": support,
        }

    return pairwise, dict(tech_count), n_docs


def _tactic_direction(tac_a, tac_b):
    """Infiere la dirección temporal a partir del orden de tácticas ATT&CK.

    Las reglas ARM no tienen dirección (no hay orden temporal inherente).
    Usamos la secuencia canónica del kill-chain de ATT&CK para asignar una
    dirección probable a posteriori. Pares de la misma táctica son
    comportamientos paralelos, no secuenciales.
    """
    ord_a = TACTIC_ORDER.get(tac_a)
    ord_b = TACTIC_ORDER.get(tac_b)
    if ord_a is None or ord_b is None:
        return "unknown"
    if ord_a < ord_b:
        return "forward"
    elif ord_a > ord_b:
        return "backward"
    return "same_tactic"


def compute_arm_rules(pairwise, tech_meta, n_docs):
    """Genera reglas ARM a partir de las co-ocurrencias por pares.

    Para cada par genera ambas direcciones (A->B y B->A).
    Filtra por MIN_SUPPORT, MIN_CONFIDENCE y MIN_LIFT.
    Aplica test exacto de Fisher + corrección FDR de Benjamini-Hochberg.
    Devuelve la lista de reglas (dicts) ordenada por lift descendente.
    """
    rules = []
    for (a, b), pair_stats in pairwise.items():
        count_both = pair_stats["count_both"]
        count_a = pair_stats["count_a"]
        count_b = pair_stats["count_b"]
        support = pair_stats["support"]
        jaccard = pair_stats["jaccard"]

        if support < MIN_SUPPORT:
            continue

        for ant, consequent, count_ant, count_con in [
            (a, b, count_a, count_b),
            (b, a, count_b, count_a),
        ]:
            confidence = count_both / count_ant if count_ant > 0 else 0.0
            if confidence < MIN_CONFIDENCE:
                continue

            support_ant = count_ant / n_docs
            support_con = count_con / n_docs
            denom = support_ant * support_con
            lift = support / denom if denom > 0 else 0.0
            if lift <= MIN_LIFT:
                continue

            # Tabla 2x2 para Fisher exacto (disposición en el docstring de
            # fisher_exact_pvalue; ant=fila A, consecuente=columna B).
            n11 = count_both
            n12 = count_ant - count_both
            n21 = count_con - count_both
            n22 = n_docs - n11 - n12 - n21
            p_val = fisher_exact_pvalue(n11, n12, n21, n22)

            ant_meta = tech_meta.get(ant, {})
            con_meta = tech_meta.get(consequent, {})
            ant_tactic = ant_meta.get("tactic_id", "unknown")
            con_tactic = con_meta.get("tactic_id", "unknown")

            rules.append({
                "antecedent": ant,
                "consequent": consequent,
                "ant_name": ant_meta.get("name", ant),
                "con_name": con_meta.get("name", consequent),
                "ant_tactic": ant_tactic,
                "con_tactic": con_tactic,
                "temporal_direction": _tactic_direction(ant_tactic, con_tactic),
                "support": support,
                "confidence": confidence,
                "lift": lift,
                "jaccard": jaccard,
                "count_both": count_both,
                "count_ant": count_ant,
                "count_con": count_con,
                "n_docs": n_docs,
                "fisher_p": p_val,
                "bh_significant": False,
            })

    if rules:
        p_values = [r["fisher_p"] for r in rules]
        significant = benjamini_hochberg(p_values, alpha=0.05)
        for i, r in enumerate(rules):
            r["bh_significant"] = significant[i]

    rules.sort(key=lambda r: -r["lift"])
    return rules


# --- Grafo ---
def build_adj(pairwise, exclude=None):
    """Construye un dict de adyacencia no dirigido y ponderado
    {nodo: {vecino: peso_jaccard}}.

    Las aristas se podan cuando Jaccard < MIN_JACCARD o count_both <
    MIN_COOCCURRENCE. El filtro por conteo elimina pares que aparecen en
    un único artículo y que dan Jaccard alto sólo porque ambas técnicas
    son muy raras (artefacto de co-ocurrencia única que inflaría la
    degree centrality de técnicas raras). Los nodos sin aristas válidas
    quedan excluidos (los nodos aislados distorsionan PageRank).
    """
    adj = defaultdict(dict)
    for (a, b), pair_stats in pairwise.items():
        if exclude is not None and (a == exclude or b == exclude):
            continue
        if pair_stats["jaccard"] < MIN_JACCARD:
            continue
        if pair_stats["count_both"] < MIN_COOCCURRENCE:
            continue
        adj[a][b] = pair_stats["jaccard"]
        adj[b][a] = pair_stats["jaccard"]
    return dict(adj)


def degree_centrality(adj):
    """Degree ponderado = suma de los pesos Jaccard de las aristas de cada
    nodo.

    Degree alto = la técnica co-ocurre a menudo con muchas otras (es un
    enabler versátil).
    """
    return {n: sum(adj[n].values()) for n in adj}


def pagerank(adj, d=0.85, max_iter=100, tol=1e-6):
    """PageRank sobre el grafo no dirigido ponderado por Jaccard.

    Usa transiciones ponderadas por Jaccard: el nodo m reparte su rank
    entre sus vecinos en proporción al peso de la arista sobre el peso
    saliente total. PageRank alto = la técnica es el destino probable de
    muchos caminos del kill-chain (comportamiento de atractor/sumidero).
    """
    nodes = list(adj.keys())
    N = len(nodes)
    if N == 0:
        return {}

    out_weight = {n: sum(adj[n].values()) for n in nodes}
    pr = {n: 1.0 / N for n in nodes}

    for _ in range(max_iter):
        new_pr = {}
        for n in nodes:
            rank_sum = 0.0
            for m, w in adj.get(n, {}).items():
                ow = out_weight.get(m, 0.0)
                if ow > 0:
                    rank_sum += pr[m] * w / ow
            new_pr[n] = (1.0 - d) / N + d * rank_sum
        delta = sum(abs(new_pr[n] - pr[n]) for n in nodes)
        pr = new_pr
        if delta < tol:
            break

    return pr


def betweenness_centrality(adj):
    """Betweenness centrality sin pesos vía el algoritmo de Brandes (2001).

    Usa BFS (caminos mínimos no ponderados) sobre la topología de aristas.
    Betweenness alto = la técnica hace de puente entre clusters del
    kill-chain (eliminarla desconectaría partes del grafo de ataque).
    Se normaliza por (N-1)(N-2) para que sea comparable entre grafos de
    distinto tamaño.
    """
    nodes = list(adj.keys())
    betweenness = {n: 0.0 for n in nodes}

    for s in nodes:
        stack = []
        pred = {n: [] for n in nodes}
        sigma = {n: 0 for n in nodes}
        sigma[s] = 1
        dist = {n: -1 for n in nodes}
        dist[s] = 0
        queue = deque([s])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in adj.get(v, {}):
                if dist[w] < 0:
                    queue.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        delta = {n: 0.0 for n in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                betweenness[w] += delta[w]

    N = len(nodes)
    if N > 2:
        scale = 1.0 / ((N - 1) * (N - 2))
        for n in nodes:
            betweenness[n] *= scale

    return betweenness


# --- secciones de análisis ---
def resolve_name(tech_meta, tid, maxlen):
    """Resuelve el nombre de la técnica desde tech_meta y lo trunca a maxlen.

    Encapsula el patrón meta = tech_meta.get(tid); name = meta.get("name",
    tid)[:maxlen] reutilizado en analysis_graph.
    """
    meta = tech_meta.get(tid, {})
    return meta.get("name", tid)[:maxlen]


def analysis_pairwise(pairwise, n_docs, csv_dir):
    _header("1. PAIRWISE CO-OCCURRENCE MATRIX")

    total_pairs = len(pairwise)
    pairs_above_support = sum(1 for pair_stats in pairwise.values() if pair_stats["support"] >= MIN_SUPPORT)
    pairs_above_jaccard = sum(1 for pair_stats in pairwise.values() if pair_stats["jaccard"] >= MIN_JACCARD)

    print(f"\n  Total technique pairs co-occurring at least once: {total_pairs:,}")
    print(f"  Pairs with support ≥ {MIN_SUPPORT:.0%} (≥{int(MIN_SUPPORT*n_docs)} articles): {pairs_above_support:,}")
    print(f"  Pairs with Jaccard ≥ {MIN_JACCARD} (graph edges): {pairs_above_jaccard:,}")

    # Mejores pares por conteo bruto (co-ocurrencias más frecuentes, más
    # accionable que Jaccard).
    top20_count = sorted(
        ((k, v) for k, v in pairwise.items() if v["count_both"] >= MIN_COOCCURRENCE),
        key=lambda x: -x[1]["count_both"],
    )[:20]
    print(f"\n  Top 20 pairs by co-occurrence count (count_both ≥ {MIN_COOCCURRENCE}):")
    print(f"  {'Tech A':<14} {'Tech B':<14} {'Count':>7} {'Jaccard':>8} {'Supp':>7}")
    print("  " + "-" * 58)
    for (a, b), pair_stats in top20_count:
        print(
            f"  {a:<14} {b:<14} {pair_stats['count_both']:>7} "
            f"{pair_stats['jaccard']:>8.4f} {pair_stats['support']:>7.1%}"
        )

    if csv_dir:
        rows = []
        for (a, b), pair_stats in sorted(pairwise.items(), key=lambda x: -x[1]["jaccard"]):
            rows.append([
                a, b,
                pair_stats["count_both"], pair_stats["count_a"], pair_stats["count_b"], n_docs,
                f"{pair_stats['jaccard']:.4f}",
                f"{pair_stats['support']:.4f}",
            ])
        save_csv(
            f"{csv_dir}/pairwise_cooccurrence.csv",
            rows,
            ["tech_a", "tech_b", "count_both", "count_a", "count_b",
             "n_articles", "jaccard", "support"],
        )


def analysis_arm(rules, csv_dir):
    _header("2. ASSOCIATION RULE MINING")

    n_rules = len(rules)
    n_significant = sum(1 for r in rules if r["bh_significant"])
    print(f"\n  Configuration: support≥{MIN_SUPPORT:.0%}, confidence≥{MIN_CONFIDENCE:.0%}, lift>{MIN_LIFT}")
    print(f"  Total rules passing thresholds: {n_rules}")
    print(f"  BH-significant rules (FDR α=0.05): {n_significant}")

    # Validación de baseline: {T1059/T1059.001} -> {T1105} debe aparecer.
    t1059_variants = {"T1059", "T1059.001", "T1059.003", "T1059.005"}
    baseline_found = any(
        (r["antecedent"] in t1059_variants and r["consequent"] == "T1105") or
        (r["antecedent"] == "T1105" and r["consequent"] in t1059_variants)
        for r in rules
    )
    baseline_any = any(
        r["antecedent"] in t1059_variants or r["consequent"] in t1059_variants
        for r in rules
    )
    print(f"\n  Baseline check {{T1059*}} {{T1105}}: "
          f"{'FOUND' if baseline_found else 'NOT FOUND'}"
          + (" (T1059 appears in other rules)" if not baseline_found and baseline_any else ""))

    print("\n  Top 25 rules by lift:")
    print(f"  {'Antecedent':<14} {'Consequent':<14} {'Supp':>6} {'Conf':>6} "
          f"{'Lift':>6} {'p-val':>8}  {'BH':>4}  Direction")
    print("  " + "-" * 80)
    for r in rules[:25]:
        sig = "" if r["bh_significant"] else " "
        print(
            f"  {r['antecedent']:<14} {r['consequent']:<14} "
            f"{r['support']:>6.1%} {r['confidence']:>6.1%} {r['lift']:>6.2f} "
            f"{r['fisher_p']:>8.4f}  {sig:>4}  {r['temporal_direction']}"
        )

    # Distribución de direcciones entre las reglas significativas.
    dir_counts = Counter(r["temporal_direction"] for r in rules if r["bh_significant"])
    if dir_counts:
        print("\n  Temporal direction (BH-significant rules):")
        for direction, count in dir_counts.most_common():
            tac_name = direction.replace("_", " ")
            print(f"    {tac_name:<14}: {count:>4} rules  ({_pct(count, n_significant)})")

    if csv_dir:
        header = [
            "antecedent", "consequent", "ant_name", "con_name",
            "ant_tactic", "con_tactic",
            "support", "confidence", "lift", "jaccard",
            "count_both", "count_ant", "count_con", "n_articles",
            "fisher_p", "bh_significant", "temporal_direction",
        ]

        def rule_row(r):
            return [
                r["antecedent"], r["consequent"],
                r["ant_name"][:50], r["con_name"][:50],
                r["ant_tactic"], r["con_tactic"],
                f"{r['support']:.4f}", f"{r['confidence']:.4f}",
                f"{r['lift']:.4f}", f"{r['jaccard']:.4f}",
                r["count_both"], r["count_ant"], r["count_con"], r["n_docs"],
                f"{r['fisher_p']:.6f}", r["bh_significant"],
                r["temporal_direction"],
            ]

        save_csv(f"{csv_dir}/arm_rules.csv", [rule_row(r) for r in rules], header)
        save_csv(
            f"{csv_dir}/arm_rules_significant.csv",
            [rule_row(r) for r in rules if r["bh_significant"]],
            header,
        )


def analysis_tactic_pairs(rules, csv_dir):
    _header("3. TOP RULES BY TACTIC PAIR")

    by_pair = defaultdict(list)
    for r in rules:
        if r["bh_significant"]:
            by_pair[(r["ant_tactic"], r["con_tactic"])].append(r)

    sorted_pairs = sorted(by_pair.items(), key=lambda x: -len(x[1]))
    print(f"\n  Tactic pairs with ≥1 BH-significant rule: {len(sorted_pairs)}")

    csv_rows = []
    for (tac_a, tac_b), pair_rules in sorted_pairs[:20]:
        name_a = TACTIC_NAMES.get(tac_a, tac_a)
        name_b = TACTIC_NAMES.get(tac_b, tac_b)
        top5 = sorted(pair_rules, key=lambda r: -r["confidence"])[:5]
        print(f"\n  {tac_a} {name_a}   {tac_b} {name_b}  ({len(pair_rules)} rules)")
        for r in top5:
            print(
                f"    {r['antecedent']:<14} {r['consequent']:<14} "
                f"conf={r['confidence']:.0%}  lift={r['lift']:.2f}"
            )
            csv_rows.append([
                tac_a, name_a, tac_b, name_b,
                r["antecedent"], r["consequent"],
                f"{r['confidence']:.4f}", f"{r['lift']:.4f}",
                r["temporal_direction"],
            ])

    if csv_dir:
        save_csv(
            f"{csv_dir}/top_rules_by_tactic_pair.csv",
            csv_rows,
            ["tactic_from_id", "tactic_from_name", "tactic_to_id", "tactic_to_name",
             "antecedent", "consequent", "confidence", "lift", "temporal_direction"],
        )


def analysis_graph(pairwise, tech_meta, tech_count, csv_dir):
    _header("4. GRAPH CENTRALITY ANALYSIS")

    adj_full = build_adj(pairwise)
    adj_excised = build_adj(pairwise, exclude=RANSOMWARE_PAYLOAD)

    n_edges_full = sum(len(v) for v in adj_full.values()) // 2
    n_edges_excised = sum(len(v) for v in adj_excised.values()) // 2
    print(f"\n  Full graph:     {len(adj_full)} nodes,  {n_edges_full} edges  (Jaccard ≥ {MIN_JACCARD})")
    print(f"  Excised graph:  {len(adj_excised)} nodes,  {n_edges_excised} edges  ({RANSOMWARE_PAYLOAD} removed)")

    print("\n  Computing degree centrality ...")
    deg_full = degree_centrality(adj_full)
    deg_exc = degree_centrality(adj_excised)

    print("  Computing PageRank (d=0.85) ...")
    pr_full = pagerank(adj_full)
    pr_exc = pagerank(adj_excised)

    print("  Computing betweenness centrality (Brandes) ...")
    bt_full = betweenness_centrality(adj_full)
    bt_exc = betweenness_centrality(adj_excised)

    def top_n(metric_dict, n=10):
        return sorted(metric_dict.items(), key=lambda x: -x[1])[:n]

    print("\n  Top 10 by Weighted Degree full graph (most co-occurring with many techniques):")
    print(f"  {'ID':<14} {'Name':<36} {'Degree':>8} {'Count':>7}")
    print("  " + "-" * 68)
    for tid, deg in top_n(deg_full):
        name = resolve_name(tech_meta, tid, 35)
        count = tech_count.get(tid, 0)
        print(f"  {tid:<14} {name:<36} {deg:>8.4f} {count:>7}")

    print("\n  Top 10 by Betweenness excised graph (kill chain bottlenecks):")
    print(f"  {'ID':<14} {'Name':<36} {'Betweenness':>12}")
    print("  " + "-" * 65)
    for tid, bt in top_n(bt_exc):
        name = resolve_name(tech_meta, tid, 35)
        print(f"  {tid:<14} {name:<36} {bt:>12.6f}")

    print("\n  Top 10 by PageRank full graph (kill chain attractors):")
    print(f"  {'ID':<14} {'Name':<36} {'PageRank':>10}")
    print("  " + "-" * 63)
    for tid, pr_val in top_n(pr_full):
        name = resolve_name(tech_meta, tid, 35)
        print(f"  {tid:<14} {name:<36} {pr_val:>10.6f}")

    # Notas de interpretación.
    if deg_full and bt_exc:
        top_bt = max(bt_exc, key=bt_exc.get)
        t1486_deg_rank = sorted(deg_full, key=deg_full.get, reverse=True).index(RANSOMWARE_PAYLOAD) + 1 \
            if RANSOMWARE_PAYLOAD in deg_full else "N/A"
        print("\n  Interpretation notes:")
        print(f"    {RANSOMWARE_PAYLOAD} degree rank (full graph): #{t1486_deg_rank}")
        print("    Note: Jaccard-weighted degree is diluted for very frequent techniques.")
        print(f"    {RANSOMWARE_PAYLOAD} co-occurs with many techniques but its high marginal")
        print("    frequency (~27% of articles) makes each Jaccard edge weight small.")
        print("    Discovery techniques appear densely interconnected within single incidents.")
        print(f"    Highest betweenness (excised): {top_bt} bridges kill chain phases")

    if csv_dir:
        all_nodes = set(tech_count.keys())
        rows = []
        for tid in sorted(all_nodes):
            meta = tech_meta.get(tid, {})
            rows.append([
                tid,
                resolve_name(tech_meta, tid, 60),
                meta.get("tactic_id", "unknown"),
                tech_count.get(tid, 0),
                f"{deg_full.get(tid, 0.0):.4f}",
                f"{pr_full.get(tid, 0.0):.6f}",
                f"{bt_full.get(tid, 0.0):.6f}",
                f"{deg_exc.get(tid, 0.0):.4f}",
                f"{pr_exc.get(tid, 0.0):.6f}",
                f"{bt_exc.get(tid, 0.0):.6f}",
            ])
        save_csv(
            f"{csv_dir}/graph_centrality.csv",
            rows,
            ["technique_id", "name", "tactic_id", "count",
             "full_degree", "full_pagerank", "full_betweenness",
             "excised_degree", "excised_pagerank", "excised_betweenness"],
        )


# --- main ---
def main():
    parser = argparse.ArgumentParser(
        description="Análisis de co-ocurrencia y ARM sobre el corpus de TTPs de ransomware"
    )
    parser.add_argument("--db", default=DB_DEFAULT, help="Ruta a ransomware_intel.db")
    parser.add_argument(
        "--csv-dir",
        default=CSV_DEFAULT,
        help=f"Directorio donde guardar los CSV (por defecto: {CSV_DEFAULT})",
    )
    args = parser.parse_args()

    print(f"Database: {args.db}")
    print(f"CSV output: {args.csv_dir}")
    print()

    print("Loading MITRE ATT&CK technique names ...")
    mitre_names = load_technique_names(MITRE_CACHE)
    print(f"  {len(mitre_names)} technique names loaded")

    print("Loading corpus ...")
    transactions, tech_meta, tech_count = load_transactions(args.db, mitre_names)

    print("Computing pairwise co-occurrences ...")
    pairwise, tech_count, n_docs = compute_pairwise(transactions)
    print(f"  {len(pairwise):,} unique technique pairs found across {n_docs} articles")

    print("Computing ARM rules ...")
    rules = compute_arm_rules(pairwise, tech_meta, n_docs)

    analysis_pairwise(pairwise, n_docs, args.csv_dir)
    analysis_arm(rules, args.csv_dir)
    analysis_tactic_pairs(rules, args.csv_dir)
    analysis_graph(pairwise, tech_meta, tech_count, args.csv_dir)

    print()
    print("=" * 72)
    print("  Analysis complete.")
    if args.csv_dir:
        print(f"  CSVs saved to: {args.csv_dir}")
    print("=" * 72)


if __name__ == "__main__":
    main()
