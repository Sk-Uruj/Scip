from core.finding import Finding
from core.pipeline import get_engines, run_scan
from engines.dummy_engine import DummyEngine


def test_pipeline_returns_findings():
    findings = run_scan(".", engines=[DummyEngine()])
    assert len(findings) >= 1
    assert findings[0].engine == "dummy"


def test_get_engines_defaults():
    engines = get_engines()
    names = [e.name for e in engines]
    assert "dependency" in names
    assert "secrets" in names
    assert "bandit" in names
    assert "semgrep" in names


def test_get_engines_disable_bandit_and_semgrep():
    engines = get_engines(run_bandit=False, run_semgrep=False)
    names = [e.name for e in engines]
    assert "bandit" not in names
    assert "semgrep" not in names
    assert "dependency" in names
    assert "secrets" in names


def test_get_engines_selective_list():
    engines = get_engines(enabled_engines=["bandit", "semgrep"])
    names = [e.name for e in engines]
    assert names == ["bandit", "semgrep"]


def test_pipeline_runs_multiple_engines():
    class MockEngine:
        def __init__(self, name):
            self.name = name

        def scan(self, path):
            return [
                Finding(
                    engine=self.name,
                    title=f"Finding from {self.name}",
                    file="test.py",
                    severity=5.0,
                )
            ]

    findings = run_scan(".", engines=[MockEngine("bandit"), MockEngine("semgrep")])
    assert len(findings) == 2
    assert {f.engine for f in findings} == {"bandit", "semgrep"}


def test_main_engines_validation(tmp_path):
    from core.pipeline import main
    # 1. Valid engine list
    assert main([str(tmp_path), "--engines", "dependency,secrets", "--offline", "--no-history"]) == 0

    # 2. Unknown typo engine name returns 2
    assert main([str(tmp_path), "--engines", "bandt"]) == 2

    # 3. Unconstructed engine (churn) returns 2, constructed engine (crypto) returns 0
    assert main([str(tmp_path), "--engines", "churn"]) == 2
    assert main([str(tmp_path), "--engines", "crypto"]) == 0

    # 4. Empty comma string returns 2
    assert main([str(tmp_path), "--engines", ","]) == 2


def test_main_make_baseline(tmp_path):
    import json
    from core.pipeline import main
    base_file = tmp_path / "baseline.json"
    code_file = tmp_path / "app.py"
    code_file.write_text("import yaml\n", encoding="utf-8")

    assert main([str(tmp_path), "--make-baseline", str(base_file), "--offline", "--no-history", "--no-bandit", "--no-semgrep"]) == 0
    assert base_file.exists()
    data = json.loads(base_file.read_text(encoding="utf-8"))
    assert data.get("version") == 2
    assert "fingerprints" in data


def test_main_ci_mode_ignores_repo_baseline(tmp_path, monkeypatch):
    import json
    from core.pipeline import main
    from core.finding import Finding
    from core.suppression import compute_finding_fingerprint

    test_finding = Finding(
        engine="dummy",
        title="Test finding",
        file="app.py",
        line=1,
        severity=5.0,
    )
    fp = compute_finding_fingerprint(test_finding)

    repo_base = tmp_path / ".scip-baseline.json"
    repo_base.write_text(json.dumps({"version": 2, "fingerprints": [fp]}), encoding="utf-8")
    (tmp_path / "app.py").write_text("print('test')\n", encoding="utf-8")

    class MockEngine:
        name = "dummy"
        stats = {}

        def is_available(self):
            return True

        def scan(self, path):
            return [test_finding]

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockEngine()])

    out_file = tmp_path / "out.json"
    # In CI mode, repo baseline is NOT auto-loaded without explicit --baseline, so finding survives
    code_ci = main([str(tmp_path), "--ci", "--output", str(out_file)])
    assert code_ci == 0
    data_ci = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data_ci) == 1
    assert data_ci[0]["title"] == "Test finding"
    assert data_ci[0]["extra"].get("suppressed") is not True

    # In local mode, repo baseline IS auto-loaded, so finding is suppressed and filtered
    code_local = main([str(tmp_path), "--output", str(out_file)])
    assert code_local == 0
    data_local = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data_local) == 0


def test_main_missing_explicit_baseline_exits_2(tmp_path):
    from core.pipeline import main
    missing_file = tmp_path / "nonexistent_baseline.json"
    code = main([str(tmp_path), "--baseline", str(missing_file), "--offline", "--no-history", "--no-bandit", "--no-semgrep"])
    assert code == 2


def test_main_strict_mode_fails_on_skipped_or_errored_engine(tmp_path, monkeypatch):
    from core.pipeline import main

    class SkippedEngine:
        name = "dummy_skipped"
        stats = {"skipped": True, "note": "missing binary"}

        def is_available(self):
            return False

        def scan(self, path):
            return []

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [SkippedEngine()])

    # Without --strict, exits 0
    assert main([str(tmp_path)]) == 0
    # With --strict, exits 2
    assert main([str(tmp_path), "--strict"]) == 2

    class ErroredEngine:
        name = "dummy_errored"
        stats = {"errors": ["Command failed"]}

        def is_available(self):
            return True

        def scan(self, path):
            return []

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [ErroredEngine()])
    assert main([str(tmp_path), "--strict"]) == 2


def test_main_fail_on_severity_gating(tmp_path, monkeypatch):
    from core.pipeline import main

    high_finding = Finding(engine="dummy", title="Critical issue", file="app.py", line=1, severity=8.5)
    med_finding = Finding(engine="dummy", title="Medium issue", file="app.py", line=1, severity=5.0)

    class MockHigh:
        name = "dummy"
        stats = {}

        def is_available(self):
            return True

        def scan(self, path):
            return [high_finding]

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockHigh()])
    # In CI mode, default fail threshold is HIGH (>= 7.0), so 8.5 fails with 1
    assert main([str(tmp_path), "--ci"]) == 1
    # With explicit --fail-on CRITICAL (>= 9.0), 8.5 passes with 0
    assert main([str(tmp_path), "--fail-on", "CRITICAL"]) == 0
    # With explicit --fail-on HIGH (>= 7.0), 8.5 fails with 1
    assert main([str(tmp_path), "--fail-on", "HIGH"]) == 1

    class MockMed:
        name = "dummy"
        stats = {}

        def is_available(self):
            return True

        def scan(self, path):
            return [med_finding]

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockMed()])
    # 5.0 is below HIGH threshold in CI mode, passes with 0
    assert main([str(tmp_path), "--ci"]) == 0
    # With --fail-on MEDIUM (>= 4.0), 5.0 fails with 1
    assert main([str(tmp_path), "--fail-on", "MEDIUM"]) == 1


def test_main_include_suppressed_cli(tmp_path, monkeypatch):
    import json
    from core.pipeline import main

    (tmp_path / "app.py").write_text("eval(cmd) # nosec\n", encoding="utf-8")
    suppressed_finding = Finding(engine="bandit", title="Eval", file="app.py", line=1, severity=8.0)

    class MockBandit:
        name = "bandit"
        stats = {}

        def is_available(self):
            return True

        def scan(self, path):
            return [suppressed_finding]

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockBandit()])

    out_file = tmp_path / "out.json"
    # Without --include-suppressed: finding is filtered out
    assert main([str(tmp_path), "--output", str(out_file)]) == 0
    assert len(json.loads(out_file.read_text(encoding="utf-8"))) == 0

    # With --include-suppressed: finding is included and marked suppressed
    assert main([str(tmp_path), "--include-suppressed", "--output", str(out_file)]) == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["extra"].get("suppressed") is True
