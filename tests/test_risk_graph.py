import os
import tempfile
import pytest
from core.finding import Finding
from core.risk_graph import RiskGraph
from core.graph_store import SQLiteGraphStore


def test_entrypoint_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/login")
def login_route():
    return {"status": "ok"}

def internal_worker():
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)
        stats = rg.get_statistics()
        assert stats["entrypoints"] >= 1
        assert stats["functions"] >= 2

        # Check entrypoint node exists
        entrypoint_nodes = [n for n, d in rg.graph.nodes(data=True) if d.get("kind") == "ENTRYPOINT"]
        assert len(entrypoint_nodes) == 1
        data = rg.graph.nodes[entrypoint_nodes[0]]
        assert data["route"] == "/api/login"
        assert data["method"] == "GET"


def test_code_reachability_and_attack_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        # main.py has an entrypoint calling helper.py::vulnerable_func
        main_code = """
from fastapi import FastAPI
from helper import vulnerable_func

app = FastAPI()

@app.get("/vulnerable")
def public_endpoint():
    vulnerable_func()
"""
        helper_code = """
def vulnerable_func():
    # Vulnerable line
    pass

def dead_isolated_func():
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(helper_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        # Finding 1: in vulnerable_func
        f_reachable = Finding(
            engine="bandit",
            title="SQLi",
            file="helper.py",
            line=3,
            severity=8.0,
        )

        # Finding 2: in dead_isolated_func
        f_unreachable = Finding(
            engine="bandit",
            title="Dead Code Flaw",
            file="helper.py",
            line=6,
            severity=7.0,
        )

        rg.analyze_reachability([f_reachable, f_unreachable])

        # f_reachable must be True with an attack path
        assert f_reachable.reachable is True
        assert len(f_reachable.extra.get("attack_path", [])) >= 2
        assert "vulnerable_func" in f_reachable.extra["attack_path"][-1]

        # f_unreachable must be False (dead code)
        assert f_unreachable.reachable is False
        assert f_unreachable.extra.get("attack_path") == []


def test_dependency_reachability_used_vs_unused():
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
import requests
from flask import Flask

app = Flask(__name__)

@app.route("/check")
def check():
    requests.get("https://example.com")
"""
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write(main_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        # Finding on requests (actually imported and reached)
        f_requests = Finding(
            engine="dependency",
            title="Requests CVE",
            file="requirements.txt",
            extra={"package": "requests"},
        )

        # Finding on unused_lib (never imported)
        f_unused = Finding(
            engine="dependency",
            title="Unused CVE",
            file="requirements.txt",
            extra={"package": "unused_lib"},
        )

        rg.analyze_reachability([f_requests, f_unused])

        assert f_requests.reachable is True
        assert len(f_requests.extra.get("attack_path", [])) >= 2

        # Unused package in requirements.txt is marked False!
        assert f_unused.reachable is False
        assert f_unused.blast_radius == 0


def test_test_caller_exclusion_in_blast_radius():
    with tempfile.TemporaryDirectory() as tmpdir:
        # app code
        app_code = """
def service_func():
    pass
"""
        prod_caller = """
from app import service_func
def prod_worker():
    service_func()
"""
        test_dir = os.path.join(tmpdir, "tests")
        os.makedirs(test_dir, exist_ok=True)
        test_caller = """
from app import service_func
def test_case_one():
    service_func()
def test_case_two():
    service_func()
"""
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write(app_code)
        with open(os.path.join(tmpdir, "worker.py"), "w") as f:
            f.write(prod_caller)
        with open(os.path.join(test_dir, "test_app.py"), "w") as f:
            f.write(test_caller)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        finding = Finding(engine="bandit", title="Issue", file="app.py", line=2)
        rg.analyze_reachability([finding])

        # Blast radius must only count prod_worker (1), NOT the 2 test callers!
        assert finding.blast_radius == 1


def test_sqlite_persistence_and_cache_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = """
def alpha():
    beta()
def beta():
    pass
"""
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write(code)

        db_path = os.path.join(tmpdir, "graph.sqlite")
        store = SQLiteGraphStore(db_path=SQLiteGraphStore.for_repo(tmpdir).db_path)

        # Build and save
        rg1 = RiskGraph(tmpdir, store=store).build(force_rebuild=True)
        assert rg1.graph.number_of_nodes() >= 2

        # Load from cache
        rg2 = RiskGraph(tmpdir, store=store).build(force_rebuild=False)
        assert rg2.graph.number_of_nodes() == rg1.graph.number_of_nodes()
        assert rg2.graph.number_of_edges() == rg1.graph.number_of_edges()


def test_main_cli_and_worker_exposure_tiers():
    with tempfile.TemporaryDirectory() as tmpdir:
        cli_code = """
def run_cli():
    execute_migration()

def execute_migration():
    pass

if __name__ == "__main__":
    run_cli()
"""
        worker_code = """
def process_loop():
    do_work()

def do_work():
    pass

if __name__ == "__main__":
    process_loop()
"""
        with open(os.path.join(tmpdir, "migrate.py"), "w") as f:
            f.write(cli_code)
        with open(os.path.join(tmpdir, "tiering_engine.py"), "w") as f:
            f.write(worker_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_cli = Finding(engine="semgrep", title="SQL Migration", file="migrate.py", line=6)
        f_worker = Finding(engine="bandit", title="Worker Issue", file="tiering_engine.py", line=6)

        rg.analyze_reachability([f_cli, f_worker])

        assert f_cli.exposure == "CLI"
        assert f_cli.reachable is True
        assert len(f_cli.extra.get("attack_path", [])) >= 2
        # Verify path contains file and line info
        assert "migrate.py" in f_cli.extra["attack_path"][0]

        assert f_worker.exposure == "WORKER"
        assert f_worker.reachable is True
        assert len(f_worker.extra.get("attack_path", [])) >= 2
        assert "tiering_engine.py" in f_worker.extra["attack_path"][0]


def test_internal_only_and_unknown_reachability():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = """
def internal_parent():
    internal_child()

def internal_child():
    pass
"""
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        # 1. Analyzed function with internal caller but no entrypoint -> reachable: False, exposure: INTNL
        f_intnl = Finding(engine="bandit", title="Internal", file="helper.py", line=5)
        # 2. Unknown function in non-existent file -> reachable: None, exposure: UNKNOWN
        f_unknown = Finding(engine="bandit", title="Unknown", file="missing_file.py", line=10)

        rg.analyze_reachability([f_intnl, f_unknown])

        assert f_intnl.reachable is False
        assert f_intnl.exposure == "INTNL"
        assert f_intnl.blast_radius == 1

        assert f_unknown.reachable is None
        assert f_unknown.exposure == "UNKNOWN"


def test_route_calling_class_method():
    """Verify route calling a class method resolves Class.method reachability and returns reachable=True."""
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
from fastapi import FastAPI
from service import AuthService

app = FastAPI()

@app.post("/login")
def login_route():
    svc = AuthService()
    svc.authenticate()
"""
        service_code = """
class AuthService:
    def authenticate(self):
        # Line 4: inside AuthService.authenticate
        pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "service.py"), "w") as f:
            f.write(service_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_method = Finding(
            engine="bandit",
            title="WeakAuth",
            file="service.py",
            line=4,
            severity=7.5,
        )
        rg.analyze_reachability([f_method])

        assert f_method.reachable is True
        assert f_method.exposure == "HTTP"
        assert len(f_method.extra.get("attack_path", [])) >= 2
        assert "AuthService.authenticate" in f_method.extra["attack_path"][-1]


def test_route_calling_nested_calls():
    """Verify visit_Call recurses through nested calls like wrapper(inner()) or jsonify(process(data))."""
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
from fastapi import FastAPI
from helpers import wrapper, inner

app = FastAPI()

@app.get("/data")
def data_route():
    return wrapper(inner())
"""
        helpers_code = """
def wrapper(val):
    return val

def inner():
    # Vulnerable logic inside nested call
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "helpers.py"), "w") as f:
            f.write(helpers_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_inner = Finding(
            engine="bandit",
            title="InnerVulnerability",
            file="helpers.py",
            line=6,
            severity=8.0,
        )
        rg.analyze_reachability([f_inner])

        assert f_inner.reachable is True
        assert f_inner.exposure == "HTTP"
        assert len(f_inner.extra.get("attack_path", [])) >= 2
        assert "inner" in f_inner.extra["attack_path"][-1]


def test_annotated_depends_detection():
    """Verify Depends inside Annotated[Session, Depends(get_db)] creates a CALLS edge and reaches get_db."""
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
from fastapi import FastAPI, Depends
from typing import Annotated
from db import get_db

app = FastAPI()

@app.get("/users")
def get_users(db: Annotated[object, Depends(get_db)]):
    return []
"""
        db_code = """
def get_db():
    # Database connection logic
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "db.py"), "w") as f:
            f.write(db_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_db = Finding(
            engine="bandit",
            title="DBExposure",
            file="db.py",
            line=3,
            severity=7.0,
        )
        rg.analyze_reachability([f_db])

        assert f_db.reachable is True
        assert f_db.exposure == "HTTP"
        assert any("get_db" in p for p in f_db.extra.get("attack_path", []))


def test_startup_hook_exposure_tier():
    """Verify startup hooks (on_event, lifespan) produce STARTUP exposure tier and startup reach score."""
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
from fastapi import FastAPI
from worker import init_cache

app = FastAPI()

@app.on_event("startup")
def startup_hook():
    init_cache()
"""
        worker_code = """
def init_cache():
    # Cache initialization flaw
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "worker.py"), "w") as f:
            f.write(worker_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_cache = Finding(
            engine="bandit",
            title="InsecureCache",
            file="worker.py",
            line=3,
            severity=6.0,
        )
        rg.analyze_reachability([f_cache])

        assert f_cache.reachable is True
        assert f_cache.exposure == "STARTUP"
        assert len(f_cache.extra.get("attack_path", [])) >= 2
        assert "STARTUP" in f_cache.extra["attack_path"][0]


def test_heuristic_edge_tagged_and_formatted():
    """Verify method resolution on object instances tags edge confidence as heuristic and formats it in attack_path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
from fastapi import FastAPI
from service import ProcessService

app = FastAPI()

@app.post("/process")
def process_route():
    svc = ProcessService()
    svc.run()
"""
        service_code = """
class ProcessService:
    def run(self):
        pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        with open(os.path.join(tmpdir, "service.py"), "w") as f:
            f.write(service_code)

        rg = RiskGraph(tmpdir).build(force_rebuild=True)

        f_run = Finding(
            engine="bandit",
            title="Flaw",
            file="service.py",
            line=3,
            severity=7.0,
        )
        rg.analyze_reachability([f_run])

        assert f_run.reachable is True
        path = f_run.extra.get("attack_path", [])
        assert any("(heuristic)" in p for p in path)


def test_dependency_component_gating():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a repo that imports django but NOT django.contrib.gis
        code = """
import django.db.models
from django.conf import settings

def some_func():
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(code)
            
        rg = RiskGraph(tmpdir).build(force_rebuild=True)
        
        # Test CVE without the component imported
        finding1 = Finding(
            engine="dependency",
            title="CVE-2023-XXXX: SQL Injection in GeoDjango",
            description="A vulnerability in GeoDjango allows...",
            file="requirements.txt",
            extra={"package": "django"}
        )
        rg.analyze_reachability([finding1])
        
        assert getattr(finding1, "package_imported", False) is True
        assert getattr(finding1, "symbol_reachable", None) is False
        assert finding1.fp_likelihood == "HIGH"
        assert "affected component not used" in finding1.fp_reason
        
        # Now create code that DOES import it
        code_gis = """
import django.contrib.gis

def some_gis_func():
    pass
"""
        with open(os.path.join(tmpdir, "gis.py"), "w") as f:
            f.write(code_gis)
            
        rg2 = RiskGraph(tmpdir).build(force_rebuild=True)
        finding2 = Finding(
            engine="dependency",
            title="CVE-2023-XXXX: SQL Injection in GeoDjango",
            description="A vulnerability in GeoDjango allows...",
            file="requirements.txt",
            extra={"package": "django"}
        )
        rg2.analyze_reachability([finding2])
        
        assert getattr(finding2, "package_imported", False) is True
        assert getattr(finding2, "symbol_reachable", False) is None
        assert finding2.fp_likelihood is None
