import os
import tempfile

from core.finding import Finding
from core.risk_graph import RiskGraph

APP = """
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "ok"
"""


def test_dead_code_fp_mapping():
    """With a real entrypoint in the repo, a function nobody calls, references or exports is DEAD,
    but only MEDIUM likelihood: a static call graph cannot prove it is unused."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write(APP)
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("def unused_dead_code():\n    pass\n")

        rg = RiskGraph(tmpdir).build(force_rebuild=True)
        f = Finding(engine="bandit", title="test", file="main.py", line=2)
        rg.analyze_reachability([f])
        assert f.exposure == "DEAD"
        assert f.fp_likelihood == "MEDIUM"
        assert "No callers" in f.fp_reason
