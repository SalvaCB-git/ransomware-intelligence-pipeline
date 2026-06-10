"""Tests de `app.get_available_spiders` (detección de spiders por regex).

La función se importa REAL desde `app.py` bajo aislamiento (ver el fixture
`get_available_spiders` en conftest.py), con `SPIDERS_DIR` apuntando a un
directorio temporal. La regex exige `name = "..."` indentado, en minúsculas.
"""


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
