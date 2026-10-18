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

    # Local mode no longer auto-loads it either: a baseline inside the scanned repo is
    # attacker-controlled input and could hide the repo's own findings.
    code_local = main([str(tmp_path), "--output", str(out_file)])
    assert code_local == 0
    data_local = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data_local) == 1

    # ...unless the person running SCIP explicitly trusts it
    code_trust = main([str(tmp_path), "--trust-repo-baseline", "--output", str(out_file)])
    assert code_trust == 0
    assert len(json.loads(out_file.read_text(encoding="utf-8"))) == 0

    # CI mode never trusts it, even with the flag
    main([str(tmp_path), "--ci", "--trust-repo-baseline", "--output", str(out_file)])
    assert len(json.loads(out_file.read_text(encoding="utf-8"))) == 1

    # An explicit --baseline FILE is always honoured
    main([str(tmp_path), "--baseline", str(repo_base), "--output", str(out_file)])
    assert len(json.loads(out_file.read_text(encoding="utf-8"))) == 0


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


def test_pipeline_no_scoring_opt_out(tmp_path, monkeypatch):
    """Verify that --no-scoring bypasses scoring and retains legacy ordering."""
    f1 = Finding(engine="bandit", title="High Sev", file="a.py", severity=9.0, exploitability=0.1)
    f2 = Finding(engine="bandit", title="Low Sev High Exploit", file="b.py", severity=3.0, exploitability=0.9)

    class MockEngine:
        name = "bandit"
        stats = {}
        def is_available(self):
            return True
        def scan(self, path):
            return [f1.clone(), f2.clone()]

    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockEngine()])

    # Run with default scoring
    res_scored = run_scan(str(tmp_path), engines=[MockEngine()], scoring=True)
    assert all(f.risk_score > 0 for f in res_scored)

    # Run with scoring=False: risk_score remains 0, sorted by (-severity, -exploitability)
    res_unscored = run_scan(str(tmp_path), engines=[MockEngine()], scoring=False)
    assert all(f.risk_score == 0.0 for f in res_unscored)
    assert res_unscored[0].severity == 9.0
    assert res_unscored[1].severity == 3.0


def test_pipeline_exclude_tests_and_details_cli(tmp_path, monkeypatch, capsys):
    app_code = """from fastapi import FastAPI
app = FastAPI()

@app.get("/api")
def api_route():
    vulnerable()

def vulnerable():
    pass
"""
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

    f_prod = Finding(
        engine="bandit",
        title="Prod Vulnerability",
        file="app.py",
        line=9,
        severity=7.5,
        fix_hint="Validate input",
    )
    f_test = Finding(
        engine="bandit",
        title="Test Flaw",
        file="tests/test_foo.py",
        line=20,
        severity=5.0,
    )

    class MockEngine:
        name = "bandit"
        stats = {}
        def is_available(self):
            return True
        def scan(self, path):
            return [f_prod.clone(), f_test.clone()]

    from core.pipeline import main
    monkeypatch.setattr("core.pipeline.get_engines", lambda **kw: [MockEngine()])

    rc = main([str(tmp_path), "--exclude-tests", "--details"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Excluded 1 test fixture finding(s)" in captured.err
    assert "REACHABLE ATTACK PATHS & REMEDIATION HINTS" in captured.out
    assert "Prod Vulnerability" in captured.out
    assert "Validate input" in captured.out


def test_cli_training_path_is_explicit_and_only_then_demotes(tmp_path):
    import json
    from core.pipeline import main
    repo = tmp_path / "repo"
    (repo / "labs").mkdir(parents=True)
    (repo / "labs" / "app.py").write_text('DB_PASSWORD = "Tr0ub4dor&3xyz"\n', encoding="utf-8")
    out = tmp_path / "out.json"

    assert main([str(repo), "--engines", "secrets", "--no-history", "--output", str(out)]) == 0
    plain = json.loads(out.read_text(encoding="utf-8"))
    assert plain and plain[0].get("fp_likelihood") is None

    assert main([str(repo), "--engines", "secrets", "--no-history", "--training-path", "labs",
                 "--output", str(out)]) == 0
    declared = json.loads(out.read_text(encoding="utf-8"))
    assert declared[0]["fp_likelihood"] == "HIGH"
    assert declared[0]["risk_score"] < plain[0]["risk_score"]


def _two_finding_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "labs").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "labs" / "demo.py").write_text('DB_PASSWORD = "Tr0ub4dor&3xyz"\n', encoding="utf-8")
    (repo / "src" / "app.py").write_text('API_PASSWORD = "Zq8x2Lm9Pw4Rt7Yb"\n', encoding="utf-8")
    return repo


def test_json_output_includes_the_score_explanation(tmp_path):
    import json
    from core.pipeline import main
    repo = _two_finding_repo(tmp_path)
    out = tmp_path / "out.json"
    main([str(repo), "--engines", "secrets", "--no-history", "--output", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data and all(x.get("explanation") for x in data)
    assert "risk" in data[0]["explanation"].lower() or "score" in data[0]["explanation"].lower()


def test_hide_fp_is_opt_in_accounted_for_and_recoverable(tmp_path, capsys):
    import json
    from core.pipeline import main
    repo = _two_finding_repo(tmp_path)
    out = tmp_path / "out.json"
    base = [str(repo), "--engines", "secrets", "--no-history", "--training-path", "labs", "--output", str(out)]

    # default: nothing is hidden, the demoted finding is still reported
    main(base)
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 2

    # --hide-fp: hidden from the report, but counted, explained, and saved to a sidecar file
    capsys.readouterr()
    main(base + ["--hide-fp"])
    err = capsys.readouterr().err
    visible = json.loads(out.read_text(encoding="utf-8"))
    assert [x["file"] for x in visible] == ["src/app.py"]
    assert "hid 1 likely false positive" in err and "training/example" in err
    sidecar = tmp_path / "out.hidden-fp.json"
    hidden = json.loads(sidecar.read_text(encoding="utf-8"))
    assert [x["file"] for x in hidden] == ["labs/demo.py"]


def test_hide_fp_never_hides_protected_findings(tmp_path):
    """A KEV-listed bug or provider-format token inside a declared training path stays visible."""
    import json
    from core.pipeline import main
    from tests import fake_secrets as fs
    repo = tmp_path / "repo"
    (repo / "labs").mkdir(parents=True)
    (repo / "labs" / "keys.py").write_text(f'GH = "{fs.github_token()}"\n', encoding="utf-8")
    out = tmp_path / "out.json"
    main([str(repo), "--engines", "secrets", "--no-history", "--training-path", "labs", "--hide-fp",
          "--output", str(out)])
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 1
