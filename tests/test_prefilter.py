"""Tests del pre-filtrado determinista (Nivel 1) de `pc/prefilter.py`.

Importa limpio en el host (usa `from __future__ import annotations`; las
dependencias pesadas —chromadb, sentence-transformers— son lazy).
"""
import prefilter


def test_check_ioc_rule_positive():
    assert prefilter._check_ioc_rule("Exploited CVE-2024-1234 in the wild") is True
    assert prefilter._check_ioc_rule("beacon to 198.51.100.42 daily") is True
    assert prefilter._check_ioc_rule("hash d41d8cd98f00b204e9800998ecf8427e found") is True


def test_check_ioc_rule_negative():
    assert prefilter._check_ioc_rule("") is False
    assert prefilter._check_ioc_rule("the quarterly report shows revenue growth") is False
    # "10.0.0" son 3 octetos, no es una IPv4 válida -> no cuenta como IoC
    assert prefilter._check_ioc_rule("upgraded to version 10.0.0 today") is False


def test_find_ioc_hits_order_and_dedup():
    # CVE se recoge antes que la IP; orden preservado
    assert prefilter._find_ioc_hits("CVE-2024-1234 and 10.0.0.1") == ["CVE-2024-1234", "10.0.0.1"]
    # duplicados colapsados conservando el orden
    assert prefilter._find_ioc_hits("8.8.8.8 ... 8.8.8.8 again") == ["8.8.8.8"]
    assert prefilter._find_ioc_hits("clean text") == []


def test_check_attck_vocab_rule_threshold(monkeypatch):
    # Umbral = 2 términos distintos. Fijamos un vocabulario conocido para
    # que el test sea determinista e independiente de mitre_techniques.json.
    monkeypatch.setattr(prefilter, "_ATTACK_VOCAB",
                        {"lateral movement", "credential dumping", "persistence"})
    assert prefilter._check_attck_vocab_rule("lateral movement then persistence") is True
    assert prefilter._check_attck_vocab_rule("only persistence here") is False   # 1 término
    assert prefilter._check_attck_vocab_rule("") is False


def test_check_tools_rule():
    assert prefilter._check_tools_rule("the attacker ran mimikatz to dump creds") is True
    # 'play' (familia de ransomware del set) es substring de 'display' -> True.
    # Es un comportamiento conocido (matching por substring, sin word boundary).
    assert prefilter._check_tools_rule("adjust the display brightness") is True
    assert prefilter._check_tools_rule("the budget meeting was rescheduled") is False


def test_run_level1_short():
    out = prefilter._run_level1("hello world")
    assert out["passed"] is False
    assert out["reason"] == "short"
    assert out["word_count"] == 2
    assert out["triggered"] == []


def test_run_level1_signals(monkeypatch):
    monkeypatch.setattr(prefilter, "MIN_WORDS", 3)
    out = prefilter._run_level1("CVE-2024-1234 ran mimikatz")
    assert out["passed"] is True
    assert out["reason"] == "level1_ok"
    assert "ioc" in out["triggered"]
    assert "tools" in out["triggered"]


def test_run_level1_no_heuristic(monkeypatch):
    monkeypatch.setattr(prefilter, "MIN_WORDS", 3)
    monkeypatch.setattr(prefilter, "_ATTACK_VOCAB", {"zzz_nonexistent_term"})
    monkeypatch.setattr(prefilter, "_TOOL_NAMES", {"zzz_nonexistent_tool"})
    out = prefilter._run_level1("lorem ipsum dolor sit amet")
    assert out["passed"] is False
    assert out["reason"] == "no_heuristic"
    assert out["triggered"] == []


def test_chunk_body():
    assert prefilter._chunk_body("a b c d", chunk_size=2) == ["a b", "c d"]
    assert prefilter._chunk_body("a b c", chunk_size=10) == ["a b c"]
    # cuerpo vacío -> siempre devuelve al menos un chunk
    assert prefilter._chunk_body("") == [""]
