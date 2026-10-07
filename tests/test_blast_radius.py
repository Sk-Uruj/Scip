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
