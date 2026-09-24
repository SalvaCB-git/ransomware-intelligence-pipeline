"""Tests de utilidades aisladas de `app.py`.

Las funciones se importan desde `app.py` bajo aislamiento (ver el fixture
`get_available_spiders` en conftest.py). `SPIDERS_DIR` apunta a un directorio
temporal y las peticiones Flask se representan con un stub.
"""

import base64
import sys


def test_get_available_spiders_normal(get_available_spiders, tmp_path):
    (tmp_path / "foo.py").write_text('class Foo:\n    name = "foo_ransomware"\n')
    (tmp_path / "bar.py").write_text('class Bar:\n    name = "bar_blog"\n')
    # ordenado por NOMBRE DE FICHERO (bar.py antes que foo.py)
    assert get_available_spiders() == ["bar_blog", "foo_ransomware"]


def test_get_available_spiders_skips_non_spiders(get_available_spiders, tmp_path):
    (tmp_path / "__init__.py").write_text('    name = "should_skip"\n')  # dunder -> ignorado
    (tmp_path / "notes.txt").write_text('    name = "not_python"\n')      # no .py -> ignorado
    (tmp_path / "base.py").write_text("class Base:\n    pass\n")          # sin name=
    assert get_available_spiders() == []


def test_get_available_spiders_regex_boundary(get_available_spiders, tmp_path):
    (tmp_path / "good.py").write_text('class G:\n    name = "good_one"\n')
    (tmp_path / "upper.py").write_text('class U:\n    name = "BadName"\n')  # mayúscula -> no
    (tmp_path / "num.py").write_text('class N:\n    name = "123bad"\n')     # empieza por dígito -> no
    assert get_available_spiders() == ["good_one"]


def test_protected_endpoint_fails_closed_without_credentials(
        get_available_spiders, monkeypatch):
    app_module = sys.modules["app"]
    monkeypatch.setattr(app_module, "_BASIC_AUTH_ENABLED", False)
    calls = []

    @app_module.require_basic_auth
    def protected_endpoint():
        calls.append(True)
        return "ok"

    assert protected_endpoint() == ("Authentication is not configured", 503)
    assert calls == []


def test_protected_endpoint_rejects_missing_header(
        get_available_spiders, monkeypatch):
    app_module = sys.modules["app"]
    monkeypatch.setattr(app_module, "_BASIC_AUTH_ENABLED", True)
    app_module.request.headers.get.return_value = ""

    response = app_module._basic_auth_or_error()

    assert response[0] == "Unauthorized"
    assert response[1] == 401
    assert response[2]["WWW-Authenticate"] == 'Basic realm="scraper"'


def test_protected_endpoint_accepts_valid_credentials(
        get_available_spiders, monkeypatch):
    app_module = sys.modules["app"]
    monkeypatch.setattr(app_module, "_BASIC_AUTH_ENABLED", True)
    monkeypatch.setattr(app_module, "_BASIC_AUTH_USER", "analyst")
    monkeypatch.setattr(app_module, "_BASIC_AUTH_PASS", "secret")
    encoded = base64.b64encode(b"analyst:secret").decode("ascii")
    app_module.request.headers.get.return_value = f"Basic {encoded}"

    assert app_module._basic_auth_or_error() is None
