"""Configuración compartida de la suite de tests unitarios.

- Pone la raíz del repo y `pc/` en `sys.path` para poder importar
  `judge_core` y `prefilter` directamente.
- Expone `preprocess` (cargado de forma tolerante a la versión de Python).
- Expone `get_available_spiders` importando la función REAL de `app.py`
  bajo un aislamiento que stubea flask/apscheduler.

Todo corre en el HOST, en un venv con solo `pytest` instalado. Nunca en el
contenedor (ver `tests/README.md`).
"""
import sys
import types
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PC = ROOT / "pc"
for _p in (str(ROOT), str(PC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="session")
def preprocess():
    """Carga `scrapy_project/preprocess.py`.

    El módulo usa anotaciones PEP585/604 (`set[str]`, `str | None`) sin
    `from __future__ import annotations`, así que NO importa tal cual en
    Python 3.8 (el host). Lo cargamos prefijando ese import: con PEP563 las
    anotaciones pasan a ser cadenas perezosas y nunca se evalúan, técnica
    válida en 3.7+. Así ejercitamos el fichero de producción SIN tocarlo y
    SIN exigir un intérprete más nuevo.
    """
    path = ROOT / "scrapy_project" / "preprocess.py"
    src = "from __future__ import annotations\n" + path.read_text(encoding="utf-8")
    mod = types.ModuleType("preprocess_under_test")
    mod.__file__ = str(path)
    exec(compile(src, str(path), "exec"), mod.__dict__)
    return mod


@pytest.fixture
def get_available_spiders(monkeypatch, tmp_path):
    """Devuelve la función REAL `app.get_available_spiders`.

    `app.py` importa flask + apscheduler (no instalados en el host) y hace
    `os.makedirs('/app/...')` a nivel de módulo. Stubeamos esos imports y
    parcheamos `os.makedirs`, de modo que el módulo importa y podemos llamar
    a la función real (su regex de detección de spiders), apuntando
    `SPIDERS_DIR` a un directorio temporal. `init_runtime()` y el scheduler
    solo se ejecutan bajo `if __name__ == "__main__"`, así que importar el
    módulo es seguro. Si el aislamiento fallara, se hace `skip` (la suite no
    se rompe por ello).
    """
    import os
    import importlib
    from unittest import mock

    flask_stub = types.ModuleType("flask")
    flask_stub.Flask = lambda *a, **k: mock.MagicMock()
    for _name in ("jsonify", "send_from_directory", "render_template",
                  "request", "redirect"):
        setattr(flask_stub, _name, mock.MagicMock())

    stubs = {"flask": flask_stub}
    for _mod in ("apscheduler", "apscheduler.schedulers",
                 "apscheduler.schedulers.background",
                 "apscheduler.executors", "apscheduler.executors.pool"):
        stubs[_mod] = types.ModuleType(_mod)
    stubs["apscheduler.schedulers.background"].BackgroundScheduler = mock.MagicMock
    stubs["apscheduler.executors.pool"].ThreadPoolExecutor = mock.MagicMock

    for _name, _stub in stubs.items():
        monkeypatch.setitem(sys.modules, _name, _stub)
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)
    sys.modules.pop("app", None)
    try:
        app_mod = importlib.import_module("app")
    except Exception as exc:  # pragma: no cover - entorno sin poder importar app
        pytest.skip(f"no se pudo importar app.py en aislamiento: {exc!r}")
    monkeypatch.setattr(app_mod, "SPIDERS_DIR", str(tmp_path))
    return app_mod.get_available_spiders
