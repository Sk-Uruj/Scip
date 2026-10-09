import os
import tempfile
from core.finding import Finding
from core.risk_graph import RiskGraph

def test_dead_code_fp_mapping():
    with tempfile.TemporaryDirectory() as tmpdir:
        main_code = """
def unused_dead_code():
    pass
"""
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(main_code)
        
        rg = RiskGraph(tmpdir).build(force_rebuild=True)
        f = Finding(engine="bandit", title="test", file="main.py", line=2)
        rg.analyze_reachability([f])
        assert f.exposure == "DEAD"
        assert f.fp_likelihood == "HIGH"
        assert "Unreachable dead code" in f.fp_reason
