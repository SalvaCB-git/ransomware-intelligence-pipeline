"""Validación de las implementaciones estadísticas propias contra implementaciones
de referencia (scikit-learn, scipy, statsmodels, networkx).

Estas pruebas NO forman parte del núcleo determinista (que corre con solo
`pytest`): requieren la pila científica, así que hacen `importorskip` y se
SALTAN si no está instalada (la suite core no se rompe). Para ejecutarlas:

    python3 -m venv .venv-validation
    .venv-validation/bin/pip install pytest -r requirements-validation.txt
    .venv-validation/bin/pytest tests/test_analysis_vs_reference.py -v

Respaldan la afirmación de §4.10.5 del TFG: cada técnica implementada en el
código del proyecto coincide numéricamente con su implementación de referencia.
Resultado esperado: 13 PASS (8 originales + 5 de métricas de clasificación: F1,
precision, recall, balanced accuracy y kappa de Cohen, todas contra scikit-learn).
Único matiz documentado: el bootstrap BCa coincide
con scipy sobre dato continuo (maquinaria correcta); sobre dato binario queda
una diferencia de convención en la interpolación del cuantil de una distribución
discreta, por eso aquí se valida la maquinaria con dato continuo.
"""
import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")
pytest.importorskip("sklearn")
pytest.importorskip("statsmodels")
pytest.importorskip("networkx")
pytest.importorskip("krippendorff")

import scipy.stats as sstats
from sklearn.metrics import (matthews_corrcoef, f1_score, precision_score,
                             recall_score, balanced_accuracy_score, cohen_kappa_score)
from statsmodels.stats.multitest import multipletests
# alias: el nombre empieza por "test_" y pytest lo recolectaría como prueba
from statsmodels.stats.proportion import test_proportions_2indep as sm_test_proportions_2indep
import networkx as nx

from evaluation_f1 import (m_mcc, m_f1, m_precision, m_recall, m_balanced_accuracy,
                           m_cohens_kappa, bootstrap_bca, tost_two_proportions)
from cooccurrence_analysis import (fisher_exact_pvalue, benjamini_hochberg,
                                   pagerank, betweenness_centrality)
from longitudinal_analysis import mann_kendall


def test_mcc_matches_sklearn():
    rng = np.random.default_rng(0)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        tp = int(((yt == 1) & (yp == 1)).sum()); fp = int(((yt == 0) & (yp == 1)).sum())
        fn = int(((yt == 1) & (yp == 0)).sum()); tn = int(((yt == 0) & (yp == 0)).sum())
        if (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn) == 0:
            # denominador 0: el custom devuelve nan (sklearn devolvería 0.0)
            assert np.isnan(m_mcc(yt, yp))
        else:
            assert abs(m_mcc(yt, yp) - matthews_corrcoef(yt, yp)) < 1e-9


def test_f1_matches_sklearn():
    # F1 es la métrica estrella del TFG: hasta ahora no se validaba contra sklearn.
    rng = np.random.default_rng(10)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        tp = int(((yt == 1) & (yp == 1)).sum()); fp = int(((yt == 0) & (yp == 1)).sum())
        fn = int(((yt == 1) & (yp == 0)).sum())
        if tp == 0 and fp == 0 and fn == 0:
            # sin positivos en ninguno: el custom devuelve nan (sklearn daría 0.0)
            assert np.isnan(m_f1(yt, yp))
        else:
            assert abs(m_f1(yt, yp) - f1_score(yt, yp, zero_division=0)) < 1e-9


def test_precision_matches_sklearn():
    rng = np.random.default_rng(11)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        tp = int(((yt == 1) & (yp == 1)).sum()); fp = int(((yt == 0) & (yp == 1)).sum())
        if tp + fp == 0:
            # sin positivos predichos: custom nan (sklearn 0.0)
            assert np.isnan(m_precision(yt, yp))
        else:
            assert abs(m_precision(yt, yp) - precision_score(yt, yp, zero_division=0)) < 1e-9


def test_recall_matches_sklearn():
    rng = np.random.default_rng(12)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        tp = int(((yt == 1) & (yp == 1)).sum()); fn = int(((yt == 1) & (yp == 0)).sum())
        if tp + fn == 0:
            # sin positivos reales: custom nan (sklearn 0.0)
            assert np.isnan(m_recall(yt, yp))
        else:
            assert abs(m_recall(yt, yp) - recall_score(yt, yp, zero_division=0)) < 1e-9


def test_balanced_accuracy_matches_sklearn():
    rng = np.random.default_rng(13)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        pos = int((yt == 1).sum()); neg = int((yt == 0).sum())
        if pos == 0 or neg == 0:
            # una sola clase en y_true: custom nan (sklearn promedia solo la presente)
            assert np.isnan(m_balanced_accuracy(yt, yp))
        else:
            assert abs(m_balanced_accuracy(yt, yp) - balanced_accuracy_score(yt, yp)) < 1e-9


def test_cohens_kappa_matches_sklearn():
    rng = np.random.default_rng(14)
    for _ in range(300):
        n = int(rng.integers(5, 150))
        yt = rng.integers(0, 2, n); yp = rng.integers(0, 2, n)
        p_t1 = float((yt == 1).mean()); p_p1 = float((yp == 1).mean())
        pe = p_t1 * p_p1 + (1 - p_t1) * (1 - p_p1)
        if pe == 1:
            # acuerdo esperado por azar = 1 (denominador 0): custom nan
            assert np.isnan(m_cohens_kappa(yt, yp))
        else:
            assert abs(m_cohens_kappa(yt, yp) - cohen_kappa_score(yt, yp)) < 1e-9


def test_fisher_matches_scipy():
    rng = np.random.default_rng(1)
    for _ in range(300):
        a, b, c, d = [int(x) for x in rng.integers(0, 30, 4)]
        if a + b + c + d == 0:
            continue
        _, ref = sstats.fisher_exact([[a, b], [c, d]], alternative="two-sided")
        assert abs(fisher_exact_pvalue(a, b, c, d) - ref) < 1e-9


def test_benjamini_hochberg_matches_statsmodels():
    rng = np.random.default_rng(2)
    for _ in range(300):
        m = int(rng.integers(1, 50))
        pv = rng.uniform(0, 1, m)
        cust = benjamini_hochberg(list(pv), alpha=0.05)
        ref = multipletests(pv, alpha=0.05, method="fdr_bh")[0]
        assert list(map(bool, cust)) == list(map(bool, ref))


def test_betweenness_matches_networkx():
    rng = np.random.default_rng(3)
    for _ in range(30):
        N = int(rng.integers(5, 20))
        G = nx.gnp_random_graph(N, 0.3, seed=int(rng.integers(0, 1_000_000)))
        if G.number_of_edges() == 0:
            continue
        adj = {n: {w: 1.0 for w in G.neighbors(n)} for n in G.nodes()}
        cust = betweenness_centrality(adj)
        ref = nx.betweenness_centrality(G, normalized=True)
        for n in ref:
            assert abs(cust[n] - ref[n]) < 1e-9


def test_pagerank_matches_networkx():
    rng = np.random.default_rng(4)
    done = 0
    while done < 30:
        N = int(rng.integers(5, 20))
        G = nx.gnp_random_graph(N, 0.4, seed=int(rng.integers(0, 1_000_000)))
        if G.number_of_edges() == 0 or min(dict(G.degree()).values()) == 0:
            continue  # el custom no redistribuye nodos colgantes
        for u, v in G.edges():
            G[u][v]["weight"] = float(rng.uniform(0.1, 1.0))
        adj = {n: {w: G[n][w]["weight"] for w in G.neighbors(n)} for n in G.nodes()}
        cust = pagerank(adj, d=0.85, max_iter=1000, tol=1e-12)
        ref = nx.pagerank(G, alpha=0.85, weight="weight", max_iter=1000, tol=1e-12)
        for n in ref:
            assert abs(cust[n] - ref[n]) < 1e-6
        done += 1


def test_mann_kendall_matches_scipy_n5():
    rng = np.random.default_rng(5)
    for _ in range(300):
        x = [int(v) for v in rng.permutation(5)]  # ints, sin empates (como en uso real)
        tau, p, _ = mann_kendall(x)
        r = sstats.kendalltau(list(range(5)), x, method="exact")
        assert abs(tau - r.statistic) < 1e-9
        assert abs(p - r.pvalue) < 1e-9


def test_tost_matches_statsmodels():
    rng = np.random.default_rng(6)
    for _ in range(300):
        n1 = int(rng.integers(20, 300)); n2 = int(rng.integers(20, 300))
        c1 = int(rng.integers(1, n1)); c2 = int(rng.integers(1, n2))
        delta = float(rng.uniform(0.03, 0.15))
        cust = tost_two_proportions(c1 / n1, n1, c2 / n2, n2, delta)
        rl = sm_test_proportions_2indep(c1, n1, c2, n2, value=-delta, method="wald",
                                        compare="diff", alternative="larger").pvalue
        rh = sm_test_proportions_2indep(c1, n1, c2, n2, value=delta, method="wald",
                                        compare="diff", alternative="smaller").pvalue
        assert abs(cust["p_low"] - rl) < 1e-9
        assert abs(cust["p_high"] - rh) < 1e-9


def test_bootstrap_bca_machinery_matches_scipy_continuous():
    """La maquinaria BCa (z0, aceleración, percentiles ajustados) coincide con
    scipy sobre dato CONTINUO dentro del error Monte Carlo (~0,002 con 20k
    iteraciones). La diferencia que se observa sobre dato binario es solo la
    convención de interpolación del cuantil de una distribución discreta."""
    rng = np.random.default_rng(7)
    def mean_metric(yt, yp):
        return float(np.mean(yt))
    for _ in range(4):
        data = rng.normal(0.5, 0.2, int(rng.integers(60, 140)))
        r = np.random.default_rng(11)
        _, lo_c, hi_c = bootstrap_bca(mean_metric, data, data.copy(),
                                      n_iter=20000, rng=r, alpha=0.05)
        res = sstats.bootstrap((data,), np.mean, method="BCa", n_resamples=20000,
                               confidence_level=0.95, random_state=12)
        assert abs(lo_c - res.confidence_interval.low) < 0.01
        assert abs(hi_c - res.confidence_interval.high) < 0.01
