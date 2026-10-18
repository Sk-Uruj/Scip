"""Distribution name != import name, and transitive dependencies are not 'dead'."""
import textwrap

import pytest

from core.finding import Finding
from core.pkg_alias import import_names, import_names_known, normalize_dist, parents_of
from core.risk_graph import RiskGraph


@pytest.mark.parametrize("dist,expected", [
    ("PyYAML", "yaml"), ("pyyaml", "yaml"), ("Pillow", "pil"), ("PyJWT", "jwt"),
    ("beautifulsoup4", "bs4"), ("scikit-learn", "sklearn"), ("python-dateutil", "dateutil"),
    ("django-allauth", "allauth"), ("djangorestframework", "rest_framework"), ("opencv-python", "cv2"),
])
def test_known_aliases(dist, expected):
    assert expected in import_names(dist)


def test_normalisation_follows_pep_503():
    assert normalize_dist("Py_YAML") == normalize_dist("py-yaml") == normalize_dist("PY.YAML") == "py-yaml"


def test_confidence_flag():
    assert import_names_known("pillow") and import_names_known("Django")
    assert not import_names_known("some-obscure-lib")


def test_transitive_relationships():
    assert "django" in parents_of("sqlparse") and "requests" in parents_of("urllib3")


def graph_for(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return RiskGraph(str(tmp_path)).build(force_rebuild=True)


def dep(package):
    return Finding(engine="dependency", title=f"{package} CVE", file="requirements.txt", extra={"package": package})


APP = '''
    import yaml, jwt
    from PIL import Image
    from flask import Flask, request
    app = Flask(__name__)

    @app.route("/thumb")
    def thumb():
        return str(Image.open(request.files["f"]).size)

    @app.route("/cfg")
    def cfg():
        return str(yaml.load(request.data, Loader=yaml.Loader))

    @app.route("/tok")
    def tok():
        return jwt.decode(request.args["t"], options={"verify_signature": False})
'''


def test_distribution_names_resolve_to_the_imported_module(tmp_path):
    """Regression: Pillow / PyYAML / PyJWT are imported and used inside HTTP routes but were all DEAD."""
    graph = graph_for(tmp_path, {"app.py": APP})
    findings = [dep("pillow"), dep("PyYAML"), dep("pyjwt")]
    graph.analyze_reachability(findings)
    for f in findings:
        assert f.exposure == "HTTP" and f.reachable is True, f.extra["package"]
        assert f.package_imported is True
        assert len(f.extra["attack_path"]) >= 2


def test_transitive_dependency_inherits_the_exposure_of_its_parent(tmp_path):
    graph = graph_for(tmp_path, {"app.py": '''
        from django.http import HttpResponse
        from django.urls import path
        def index(request):
            return HttpResponse("hi")
        urlpatterns = [path("", index)]
    '''})
    sqlparse, django = dep("sqlparse"), dep("django")
    graph.analyze_reachability([sqlparse, django])
    assert django.exposure == sqlparse.exposure
    assert sqlparse.extra["transitive_via"] == "django"
    assert sqlparse.package_imported is False           # not imported directly


def test_transitive_dependency_of_an_unused_parent_is_dead_too(tmp_path):
    graph = graph_for(tmp_path, {"app.py": "import os\n"})
    sqlparse, django = dep("sqlparse"), dep("django")
    graph.analyze_reachability([sqlparse, django])
    assert django.exposure == "DEAD" and sqlparse.exposure == "DEAD"


def test_unknown_package_is_unknown_not_dead(tmp_path):
    graph = graph_for(tmp_path, {"app.py": APP})
    f = dep("some-obscure-lib")
    graph.analyze_reachability([f])
    assert f.exposure == "UNKNOWN" and f.reachable is None
    assert "not treated as unused" in f.extra["exposure_detail"]


def test_known_package_that_is_really_unused_is_still_dead(tmp_path):
    graph = graph_for(tmp_path, {"app.py": APP})
    f = dep("celery")
    graph.analyze_reachability([f])
    assert f.exposure == "DEAD" and f.reachable is False
