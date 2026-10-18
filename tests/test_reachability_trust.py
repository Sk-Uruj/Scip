"""'Not reachable' / 'dead code' may only be claimed with positive evidence.

Each case is a realistic layout in which a real vulnerability has no visible caller. The old rule
labelled every one of them DEAD with HIGH false-positive likelihood, which cut the risk by ~80%.
"""
import textwrap

import pytest

from core.finding import Finding
from core.risk_graph import RiskGraph

APP = textwrap.dedent('''
    from flask import Flask
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"
''')


def analyse(tmp_path, files, file, line, with_app=False):
    layout = dict(files)
    if with_app:
        layout["app.py"] = APP
    for rel, text in layout.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    graph = RiskGraph(str(tmp_path)).build(force_rebuild=True)
    f = Finding(engine="bandit", title="x", file=file, line=line)
    graph.analyze_reachability([f])
    return f


HASH = '''
    import hashlib
    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()
'''


def test_repo_without_entrypoints_is_unknown_not_dead(tmp_path):
    f = analyse(tmp_path, {"util.py": HASH}, "util.py", 4)
    assert f.exposure == "UNKNOWN" and f.reachable is None and f.fp_likelihood is None


def test_library_function_exported_from_package_init_is_not_dead(tmp_path):
    f = analyse(tmp_path, {"mylib/__init__.py": "from .auth import hash_password\n", "mylib/auth.py": HASH},
                "mylib/auth.py", 4, with_app=True)
    assert f.exposure != "DEAD" and f.fp_likelihood != "HIGH"


def test_function_listed_in___all___is_not_dead(tmp_path):
    code = HASH + "\n    __all__ = ['hash_password']\n"
    f = analyse(tmp_path, {"util.py": code}, "util.py", 4, with_app=True)
    assert f.exposure != "DEAD"


def test_django_management_command_is_a_cli_entrypoint(tmp_path):
    f = analyse(tmp_path, {"app/management/commands/sync.py": '''
        import subprocess
        from django.core.management.base import BaseCommand
        class Command(BaseCommand):
            def handle(self, *args, **kwargs):
                subprocess.call("rm -rf " + kwargs["path"], shell=True)
    '''}, "app/management/commands/sync.py", 6)
    assert f.exposure == "CLI" and f.reachable is True and f.fp_likelihood is None


HOOKS = {
    "celery app.task": ("""
        import subprocess
        from celery import Celery
        app = Celery()
        @app.task
        def job(path):
            subprocess.call("rm -rf " + path, shell=True)
    """, 7),
    "celery shared_task": ("""
        import subprocess
        from celery import shared_task
        @shared_task
        def job(path):
            subprocess.call("rm -rf " + path, shell=True)
    """, 6),
    "django signal receiver": ("""
        import subprocess
        from django.dispatch import receiver
        from django.db.models.signals import post_save
        @receiver(post_save)
        def on_save(sender, **kwargs):
            subprocess.call("rm -rf " + kwargs["path"], shell=True)
    """, 7),
}


@pytest.mark.parametrize("name", list(HOOKS))
def test_framework_hooks_are_entrypoints(tmp_path, name):
    code, line = HOOKS[name]
    f = analyse(tmp_path, {"tasks.py": code}, "tasks.py", line)
    assert f.exposure == "WORKER" and f.reachable is True, name


def test_function_stored_in_a_dispatch_table_is_not_dead(tmp_path):
    f = analyse(tmp_path, {"h.py": '''
        import hashlib
        def h_md5(pw):
            return hashlib.md5(pw.encode()).hexdigest()
        HANDLERS = {"md5": h_md5}
        def run(kind, pw):
            return HANDLERS[kind](pw)
    '''}, "h.py", 4, with_app=True)
    assert f.exposure != "DEAD" and f.fp_likelihood != "HIGH"


def test_function_passed_as_a_callback_inside_a_route_is_reachable(tmp_path):
    f = analyse(tmp_path, {"cb.py": '''
        import subprocess
        def cleanup(path):
            subprocess.call("rm " + path, shell=True)
    ''', "app.py": APP + '''
from cb import cleanup
import threading

@app.route("/clean")
def clean():
    threading.Timer(1, cleanup)
    return "ok"
'''}, "cb.py", 4)
    assert f.exposure == "HTTP" and f.reachable is True


def test_truly_unreferenced_code_is_dead_but_never_high_confidence(tmp_path):
    f = analyse(tmp_path, {"old.py": HASH}, "old.py", 4, with_app=True)
    assert f.exposure == "DEAD"
    assert f.fp_likelihood == "MEDIUM", "dead code can never be proven by a static call graph"


def test_script_and_flask_route_paths_still_work(tmp_path):
    script = analyse(tmp_path / "s", {"tool.py": '''
        import hashlib
        def main():
            print(hashlib.md5(input().encode()).hexdigest())
        if __name__ == "__main__":
            main()
    '''}, "tool.py", 4)
    assert script.exposure == "CLI" and script.reachable is True
    route = analyse(tmp_path / "f", {"app.py": '''
        import hashlib
        from flask import Flask, request
        app = Flask(__name__)
        def hp(password):
            return hashlib.md5(password.encode()).hexdigest()
        @app.route("/login", methods=["POST"])
        def login():
            return hp(request.form["password"])
    '''}, "app.py", 6)
    assert route.exposure == "HTTP" and route.reachable is True


def test_test_files_stay_test(tmp_path):
    f = analyse(tmp_path, {"tests/test_x.py": HASH}, "tests/test_x.py", 4, with_app=True)
    assert f.exposure == "TEST"
