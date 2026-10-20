"""Unit tests for Dependency Engine improvements (Phases 1-7)."""
import os
import tempfile
import pytest

from core.finding import Finding
from core.fp_detector import detect_false_positives, _get_repo_env_context, _REPO_ENV_CACHE
from core.risk_graph import RiskGraph
from engines.dependency_engine import VulnInfo, _combine, is_dev_requirement_file


def test_dead_unimported_dependency_tagged_high_fp(tmp_path):
    """When a package's import name is known but it is never imported in code,
    RiskGraph must set exposure='DEAD', reachable=False, and fp_likelihood='HIGH'."""
    app_code = """
from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/fetch")
def fetch():
    return requests.get("https://example.com").text
"""
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")
    rg = RiskGraph(str(tmp_path)).build(force_rebuild=True)

    # requests is imported
    f_req = Finding(
        engine="dependency",
        title="Requests CVE",
        file="requirements.txt",
        extra={"package": "requests"},
    )
    # cryptography is a known package but never imported
    f_crypto = Finding(
        engine="dependency",
        title="Cryptography CVE",
        file="requirements.txt",
        extra={"package": "cryptography"},
    )

    rg.analyze_reachability([f_req, f_crypto])

    assert f_req.reachable is True
    assert f_req.exposure == "HTTP"
    assert f_req.fp_likelihood is None

    assert f_crypto.reachable is False
    assert f_crypto.exposure == "DEAD"
    assert f_crypto.fp_likelihood == "HIGH"
    assert "not imported" in f_crypto.fp_reason
    assert f_crypto.extra["fp_likelihood"] == "HIGH"


def test_component_gating_uncalled_component_tagged_high_fp(tmp_path):
    """When an advisory targets an unused component/submodule (e.g. GeoDjango, strip_tags, ImageDraw),
    it must be flagged as a HIGH false positive."""
    (tmp_path / "app.py").write_text("import django\nfrom PIL import Image\n", encoding="utf-8")
    rg = RiskGraph(str(tmp_path)).build(force_rebuild=True)

    f_geo = Finding(
        engine="dependency",
        title="CVE-2026-15307: django==3.2.18 - GeoDjango spatial lookups",
        description="GeoDjango spatial lookups allow file writes",
        file="requirements.txt",
        extra={"package": "django"},
    )
    f_striptags = Finding(
        engine="dependency",
        title="CVE-2024-53907: django==4.2 - Denial-of-service in strip_tags()",
        description="Django denial-of-service in django.utils.html.strip_tags()",
        file="requirements.txt",
        extra={"package": "django"},
    )
    f_draw = Finding(
        engine="dependency",
        title="CVE-2023-44271: pillow==9.4.0 - ImageDraw text drawing DoS",
        description="DoS in ImageDraw text drawing",
        file="requirements.txt",
        extra={"package": "pillow"},
    )

    rg.analyze_reachability([f_geo, f_striptags, f_draw])

    for f in [f_geo, f_striptags, f_draw]:
        assert f.fp_likelihood == "HIGH"
        assert f.exposure == "DEAD"
        assert "affected component" in f.fp_reason
        assert f.extra["fp_likelihood"] == "HIGH"


def test_component_gating_allows_active_component(tmp_path):
    """When a gated component IS imported or used in the application,
    it must NOT be flagged as a false positive."""
    code = """
from PIL import Image, ImageDraw
from django.utils.html import strip_tags

def clean(text):
    return strip_tags(text)
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    rg = RiskGraph(str(tmp_path)).build(force_rebuild=True)

    f_striptags = Finding(
        engine="dependency",
        title="CVE-2024-53907: django==4.2 - Denial-of-service in strip_tags()",
        description="Django denial-of-service in django.utils.html.strip_tags()",
        file="requirements.txt",
        extra={"package": "django"},
    )
    f_draw = Finding(
        engine="dependency",
        title="CVE-2023-44271: pillow==9.4.0 - ImageDraw text drawing DoS",
        description="DoS in ImageDraw text drawing",
        file="requirements.txt",
        extra={"package": "pillow"},
    )

    rg.analyze_reachability([f_striptags, f_draw])

    assert f_striptags.fp_likelihood is None
    assert f_draw.fp_likelihood is None


def test_django_installed_apps_enables_component(tmp_path):
    """When a component (e.g. humanize) is in INSTALLED_APPS in settings.py,
    it must be recognized as active in the risk graph."""
    settings_code = """
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.humanize',
]
"""
    (tmp_path / "settings.py").write_text(settings_code, encoding="utf-8")
    rg = RiskGraph(str(tmp_path)).build(force_rebuild=True)

    f_humanize = Finding(
        engine="dependency",
        title="CVE-2024-24680: django==4.2 - intcomma filter DoS",
        description="DoS in the intcomma filter from django.contrib.humanize",
        file="requirements.txt",
        extra={"package": "django"},
    )

    rg.analyze_reachability([f_humanize])

    assert f_humanize.fp_likelihood is None


def test_platform_windows_on_linux_deployment_tagged_high_fp(tmp_path):
    """When Dockerfile indicates Linux deployment, Windows-only vulnerabilities
    must be flagged as HIGH false positives."""
    _REPO_ENV_CACHE.clear()
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    f_win = Finding(
        engine="dependency",
        title="CVE-2025-66221: werkzeug==3.0.1 - Werkzeug safe_join() allows Windows special device names",
        description="safe_join not safe on Windows. Only affects Werkzeug safe_join on Windows.",
        file="requirements.txt",
        extra={"package": "werkzeug"},
    )

    detect_false_positives([f_win], repo_path=str(tmp_path))

    assert f_win.fp_likelihood == "HIGH"
    assert "Windows environments" in f_win.fp_reason
    assert f_win.extra["fp_likelihood"] == "HIGH"


def test_asgi_on_wsgi_deployment_tagged_high_fp(tmp_path):
    """When project runs on WSGI via Gunicorn, ASGI request smuggling advisories
    must be flagged as HIGH false positives."""
    _REPO_ENV_CACHE.clear()
    (tmp_path / "Procfile").write_text("web: gunicorn pygoat.wsgi --workers 4\n", encoding="utf-8")

    f_asgi = Finding(
        engine="dependency",
        title="CVE-2026-33034: django==4.2 - SGI requests with a missing or understated Content-Length",
        description="Affects ASGI request handling. SGI requests with understated Content-Length.",
        file="requirements.txt",
        extra={"package": "django"},
    )

    detect_false_positives([f_asgi], repo_path=str(tmp_path))

    assert f_asgi.fp_likelihood == "HIGH"
    assert "ASGI request handling" in f_asgi.fp_reason
    assert f_asgi.extra["fp_likelihood"] == "HIGH"


def test_proxy_advisory_without_proxy_tagged_high_fp(tmp_path):
    """When no proxy is configured in the repository, proxy-specific vulnerabilities
    must be flagged as HIGH false positives."""
    _REPO_ENV_CACHE.clear()
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    f_proxy = Finding(
        engine="dependency",
        title="CVE-2024-37891: urllib3==1.26.9 - Proxy-Authorization header leak",
        description="Proxy-Authorization request header isn't stripped",
        file="requirements.txt",
        extra={"package": "urllib3"},
    )

    detect_false_positives([f_proxy], repo_path=str(tmp_path))

    assert f_proxy.fp_likelihood == "HIGH"
    assert "proxy configuration" in f_proxy.fp_reason
    assert f_proxy.extra["fp_likelihood"] == "HIGH"


def test_zip_archive_execution_tagged_high_fp(tmp_path):
    """extract_zipped_paths advisories require running from a zip archive."""
    f_zip = Finding(
        engine="dependency",
        title="CVE-2026-25645: requests==2.28.2 - Insecure Temp File Reuse in extract_zipped_paths",
        description="Only relevant when requests itself runs from a zip archive (extract_zipped_paths).",
        file="requirements.txt",
        extra={"package": "requests"},
    )

    detect_false_positives([f_zip], repo_path=str(tmp_path))

    assert f_zip.fp_likelihood == "HIGH"
    assert "zip archive" in f_zip.fp_reason
    assert f_zip.extra["fp_likelihood"] == "HIGH"


def test_combine_selects_richest_metadata():
    """_combine must select the most detailed summary and description."""
    stub = VulnInfo(
        id="GHSA-1",
        aliases={"CVE-2026-0001"},
        summary="Brief",
        details="Short text",
        cvss=7.5,
        severity_source="cvss3",
    )
    rich = VulnInfo(
        id="CVE-2026-0001",
        aliases={"GHSA-1"},
        summary="Comprehensive summary of arbitrary code execution",
        details="Very detailed explanation with remediation and impact analysis",
        cvss=7.5,
        severity_source="cvss3",
        fixed=["1.2.0"],
    )

    combined = _combine([stub, rich], {"GHSA-1", "CVE-2026-0001"})

    assert combined.id == "CVE-2026-0001"
    assert combined.summary == "Comprehensive summary of arbitrary code execution"
    assert combined.details == "Very detailed explanation with remediation and impact analysis"
    assert combined.fixed == ["1.2.0"]


def test_is_dev_requirement_file():
    assert is_dev_requirement_file("requirements-dev.txt") is True
    assert is_dev_requirement_file("test-requirements.txt") is True
    assert is_dev_requirement_file("tests/requirements.txt") is True
    assert is_dev_requirement_file("dockerized_labs/lab1/requirements.txt") is True
    assert is_dev_requirement_file("requirements.txt") is False
    assert is_dev_requirement_file("Pipfile.lock") is False
