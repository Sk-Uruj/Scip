import os
import tempfile
from core.finding import Finding
from engines.blast_radius_engine import calculate_blast_radius, find_enclosing_function


def test_find_enclosing_function():
    code = """
def foo():
    x = 1
    y = 2

def bar():
    z = 3
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        f_path = f.name

    try:
        assert find_enclosing_function(f_path, 3) == "foo"
        assert find_enclosing_function(f_path, 7) == "bar"
    finally:
        os.remove(f_path)


def test_calculate_blast_radius():
    with tempfile.TemporaryDirectory() as tmpdir:
        helper_code = """
def vulnerable_helper():
    pass
"""
        caller_code = """
from helper import vulnerable_helper

def caller_one():
    vulnerable_helper()

def caller_two():
    caller_one()
"""
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(helper_code)
        with open(os.path.join(tmpdir, "caller.py"), "w") as f:
            f.write(caller_code)

        finding = Finding(
            engine="bandit",
            title="Test Finding",
            file="helper.py",
            line=2,
        )

        calculate_blast_radius([finding], tmpdir)
        # caller_one calls vulnerable_helper, and caller_two calls caller_one (transitive)
        assert finding.blast_radius == 2


def test_blast_radius_skip_dirs():
    """Verify directories like .venv, node_modules, and .git are skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        helper_code = """
def target_func():
    pass
"""
        # A legitimate caller in the repo root
        real_caller = """
from helper import target_func
def legit_caller():
    target_func()
"""
        # Callers inside .venv and node_modules that should be ignored
        venv_dir = os.path.join(tmpdir, ".venv", "Lib", "site-packages")
        os.makedirs(venv_dir, exist_ok=True)
        venv_caller = """
from helper import target_func
def venv_caller():
    target_func()
"""
        node_dir = os.path.join(tmpdir, "node_modules", "package")
        os.makedirs(node_dir, exist_ok=True)
        node_caller = """
from helper import target_func
def node_caller():
    target_func()
"""
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(helper_code)
        with open(os.path.join(tmpdir, "real_caller.py"), "w") as f:
            f.write(real_caller)
        with open(os.path.join(venv_dir, "caller.py"), "w") as f:
            f.write(venv_caller)
        with open(os.path.join(node_dir, "caller.py"), "w") as f:
            f.write(node_caller)

        finding = Finding(
            engine="bandit",
            title="Test Finding",
            file="helper.py",
            line=2,
        )

        calculate_blast_radius([finding], tmpdir)
        # Only real_caller should be counted, ignoring .venv and node_modules
        assert finding.blast_radius == 1


def test_blast_radius_name_collision_isolation():
    """Ensure two unrelated files defining same function name are not merged in call graph."""
    with tempfile.TemporaryDirectory() as tmpdir:
        service_a = """
def process():
    pass
"""
        caller_a = """
from service_a import process

def run_a():
    process()
"""
        service_b = """
def process():
    pass
"""
        caller_b = """
from service_b import process

def run_b1():
    process()

def run_b2():
    run_b1()
"""
        with open(os.path.join(tmpdir, "service_a.py"), "w") as f:
            f.write(service_a)
        with open(os.path.join(tmpdir, "caller_a.py"), "w") as f:
            f.write(caller_a)
        with open(os.path.join(tmpdir, "service_b.py"), "w") as f:
            f.write(service_b)
        with open(os.path.join(tmpdir, "caller_b.py"), "w") as f:
            f.write(caller_b)

        finding_a = Finding(
            engine="bandit",
            title="Finding A",
            file="service_a.py",
            line=2,
        )
        finding_b = Finding(
            engine="bandit",
            title="Finding B",
            file="service_b.py",
            line=2,
        )

        calculate_blast_radius([finding_a, finding_b], tmpdir)
        # finding_a should only see caller_a (1 caller), NOT service_b callers (run_b1, run_b2)
        assert finding_a.blast_radius == 1
        # finding_b should only see caller_b (2 callers: run_b1, run_b2), NOT service_a callers
        assert finding_b.blast_radius == 2


def test_blast_radius_removesuffix_safety():
    """Ensure filenames like happy.py and crypto.py are not mangled by removesuffix."""
    with tempfile.TemporaryDirectory() as tmpdir:
        happy_code = """
# Module level config without enclosing function
API_KEY = "secret"
"""
        caller_code = """
import happy

def use_happy():
    return happy.API_KEY
"""
        with open(os.path.join(tmpdir, "happy.py"), "w") as f:
            f.write(happy_code)
        with open(os.path.join(tmpdir, "consumer.py"), "w") as f:
            f.write(caller_code)

        finding = Finding(
            engine="secrets",
            title="Secret finding",
            file="happy.py",
            line=2,
        )

        calculate_blast_radius([finding], tmpdir)
        # Should count 1 importer (consumer.py) and not mangle happy.py into 'h'
        assert finding.blast_radius == 1
