"""Tests de `judge_core.lookup_technique`.

`judge_core.py` importa limpio en el host (usa `from __future__ import
annotations`; su única dependencia de terceros a nivel de módulo es
`requests`, ya instalada). `lookup_technique` es pura.
"""
import judge_core


def test_lookup_direct_hit():
    mitre = {"T1486": {"name": "Data Encrypted for Impact", "description": "d"}}
    assert judge_core.lookup_technique(mitre, "T1486") == {
        "name": "Data Encrypted for Impact", "description": "d"
    }


def test_lookup_subtechnique_parent_fallback():
    mitre = {"T1059": {"name": "Command and Scripting Interpreter", "description": "d"}}
    # T1059.001 no está, pero el padre T1059 sí
    assert judge_core.lookup_technique(mitre, "T1059.001") == mitre["T1059"]


def test_lookup_placeholder():
    placeholder = {"name": "T9999", "description": "(definición no disponible)"}
    assert judge_core.lookup_technique({}, "T9999") == placeholder
    # sub-técnica cuyo padre tampoco existe -> placeholder con el id completo
    assert judge_core.lookup_technique({}, "T9999.001") == {
        "name": "T9999.001", "description": "(definición no disponible)"
    }
