"""Tests de las funciones puras de `scrapy_project/preprocess.py`.

El módulo se carga vía el fixture `preprocess` (ver conftest.py), que sortea
la incompatibilidad de anotaciones con Python 3.8 sin modificar el fichero.
"""
import sys
import types
import hashlib as _hashlib

import pytest


@pytest.fixture
def preprocess_simhash(preprocess, monkeypatch):
    """Igual que `preprocess`, pero permite ejecutar `_simhash` en Python 3.8.

    `_simhash` llama a `hashlib.md5(token, usedforsecurity=False)`. El kwarg
    `usedforsecurity` existe desde Python 3.9; en 3.8 (el host) lanza
    TypeError. Es solo una anotación FIPS y NO altera el digest, así que
    inyectamos un `hashlib` shim que lo ignora. En producción (contenedor
    Python 3.14) y en 3.9+ no se toca nada.
    """
    if sys.version_info < (3, 9):
        shim = types.ModuleType("hashlib_compat")
        for _n in dir(_hashlib):
            setattr(shim, _n, getattr(_hashlib, _n))
        shim.md5 = lambda data=b"", **kwargs: _hashlib.md5(data)
        monkeypatch.setattr(preprocess, "hashlib", shim)
    return preprocess


def test_simhash_deterministic(preprocess_simhash):
    p = preprocess_simhash
    assert p._simhash("hello world") == p._simhash("hello world")


def test_simhash_normalization(preprocess_simhash):
    # minúsculas + colapso de espacios -> mismo hash
    p = preprocess_simhash
    assert p._simhash("Hello   World") == p._simhash("hello world")


def test_simhash_empty_is_signed_int64(preprocess_simhash):
    h = preprocess_simhash._simhash("")
    assert isinstance(h, int)
    assert -(2 ** 63) <= h < (2 ** 63)


def test_hamming(preprocess):
    assert preprocess._hamming(0, 0) == 0
    assert preprocess._hamming(0b1010, 0b0001) == 3   # 1010 ^ 0001 = 1011 -> 3 bits
    assert preprocess._hamming(255, 255) == 0


def test_normalize_date(preprocess):
    assert preprocess.normalize_date("") is None
    assert preprocess.normalize_date("   ") is None
    # rama de fallback manual (sin dateutil) e idéntico resultado con dateutil
    assert preprocess.normalize_date("2026-02-23") == "2026-02-23T00:00:00Z"
    assert preprocess.normalize_date("xyzzy not a date") is None


def test_clean_text(preprocess):
    assert preprocess.clean_text("") == ""
    assert preprocess.clean_text(None) == ""
    # las etiquetas pasan a espacio; los runs de 3+ espacios colapsan a 1; strip final
    assert preprocess.clean_text("<p>Hello</p>     world") == "Hello world"
    assert preprocess.clean_text("already clean") == "already clean"
    # runs de 2 espacios NO se colapsan (el umbral es 3+)
    assert preprocess.clean_text("a  b") == "a  b"


def test_detect_schema(preprocess):
    assert preprocess.detect_schema(["source", "published_utc", "headline", "url"]) == "A"
    assert preprocess.detect_schema(["Published_UTC", "HEADLINE"]) == "A"   # case-insensitive
    assert preprocess.detect_schema(["source", "url", "title", "date"]) == "B"
    assert preprocess.detect_schema([]) == "UNKNOWN"
    # 'date' sin 'title' no es B; sin 'published_utc' no es A -> UNKNOWN
    assert preprocess.detect_schema(["date", "headline"]) == "UNKNOWN"
