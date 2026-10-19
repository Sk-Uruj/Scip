"""Tests for BanditEngine."""
import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Finding
from core.taxonomy import BANDIT_TO_CWE
from engines.bandit_engine import (
    BanditEngine,
    BANDIT_RULE_CALIBRATION,
    RULE_SEVERITY_BASE,
    RULE_EXPLOIT_BASE,
    COMMON_FIX_HINTS,
    REMEDIATION_TEMPLATES,
    get_remediation_metadata,
    _calculate_severity,
    _calculate_exploitability,
    _rel_path,
)


# --------------------------------------------------------------------------- #
# Unit tests: Helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sev,conf,expected",
    [
        ("HIGH", "HIGH", 8.5),
        ("HIGH", "MEDIUM", 8.0),
        ("HIGH", "LOW", 7.5),
        ("MEDIUM", "HIGH", 5.5),
        ("MEDIUM", "MEDIUM", 5.0),
        ("MEDIUM", "LOW", 4.5),
        ("LOW", "HIGH", 3.0),
        ("LOW", "MEDIUM", 2.5),
        ("LOW", "LOW", 2.0),
    ],
)
def test_calculate_severity(sev, conf, expected):
    assert _calculate_severity(sev, conf) == expected


def test_rel_path(tmp_path):
    sub = tmp_path / "app" / "main.py"
    assert _rel_path(str(sub), tmp_path) == "app/main.py"


# --------------------------------------------------------------------------- #
# Unit tests: Finding generation from canned Bandit JSON
# --------------------------------------------------------------------------- #
CANNED_BANDIT_OUTPUT = {
    "errors": [],
    "metrics": {
        "_totals": {"loc": 25, "nosec": 0},
        "app.py": {"loc": 25, "nosec": 0},
    },
    "results": [
        {
            "code": "11 yaml.load(data, Loader=yaml.Loader)\n",
            "col_offset": 4,
            "end_col_offset": 40,
            "filename": "app.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
            "issue_severity": "MEDIUM",
            "issue_text": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
            "line_number": 11,
            "line_range": [11],
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b506_yaml_load.html",
            "test_id": "B506",
            "test_name": "yaml_load",
        },
        {
            "code": "15 hashlib.md5(b'test').hexdigest()\n",
            "col_offset": 4,
            "end_col_offset": 35,
            "filename": "crypto.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
            "issue_severity": "HIGH",
            "issue_text": "Use of weak MD5 hash function.",
            "line_number": 15,
            "line_range": [15],
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b303_md5.html",
            "test_id": "B303",
            "test_name": "hash_func",
        },
    ],
}


def test_parse_canned_bandit_output(tmp_path):
    engine = BanditEngine()
    raw_stdout = "[main] INFO Running...\n" + json.dumps(CANNED_BANDIT_OUTPUT)
    findings = engine._parse_output(raw_stdout, tmp_path)

    assert len(findings) == 2
    # B506 (yaml.load code execution, sev 8.5) is prioritized above B303 (md5 hash, sev 7.0)
    assert findings[0].file == "app.py"
    assert findings[0].cwe == "CWE-502"
    assert findings[0].severity == 8.5
    assert findings[0].exploitability == 0.75
    assert "yaml.safe_load" in findings[0].fix_hint
    assert findings[0].extra["remediation"]["auto_fixable"] is True
    assert findings[0].extra["remediation"]["safe_alternative"] == "yaml.safe_load"
    assert "yaml.safe_load" in findings[0].extra["remediation"]["replacement_pattern"]

    assert findings[1].engine == "bandit"
    assert findings[1].file == "crypto.py"
    assert findings[1].line == 15
    assert findings[1].cwe == "CWE-327"
    assert findings[1].severity == 7.0
    assert findings[1].exploitability == 0.30
    assert "B303" in findings[1].title
    assert "hashlib.sha256" in findings[1].fix_hint
    assert findings[1].extra["remediation"]["auto_fixable"] is True
    assert findings[1].extra["remediation"]["safe_alternative"] == "hashlib.sha256"
    assert engine.stats["findings_count"] == 2


@pytest.mark.parametrize(
    "sev,conf,test_id,expected_sev,expected_exploit",
    [
        ("MEDIUM", "HIGH", "B506", 8.5, 0.75),   # yaml_load: calibrated RCE
        ("MEDIUM", "LOW", "B506", 7.5, 0.38),    # yaml_load: low confidence damping (negative CONF_ADJUST and 0.5 factor)
        ("HIGH", "HIGH", "B102", 9.0, 0.80),     # exec: critical RCE
        ("HIGH", "HIGH", "B602", 9.0, 0.75),     # subprocess shell=True
        ("MEDIUM", "HIGH", "B608", 9.0, 0.75),   # SQL injection
        ("LOW", "HIGH", "B113", 4.0, 0.20),      # timeout: low severity
        ("LOW", "MEDIUM", "B108", 4.0, 0.20),    # tmp directory
        ("LOW", "HIGH", "B403", 3.0, 0.10),      # bare import pickle: low severity
        ("LOW", "HIGH", "B404", 3.0, 0.10),      # bare import subprocess: low severity
    ],
)
def test_calibrated_severity_and_exploitability(sev, conf, test_id, expected_sev, expected_exploit):
    assert _calculate_severity(sev, conf, test_id=test_id) == expected_sev
    assert _calculate_exploitability(sev, conf, test_id=test_id) == expected_exploit


def test_bandit_rule_calibration_key_sets_match():
    """Verify that RULE_SEVERITY_BASE, RULE_EXPLOIT_BASE, and BANDIT_TO_CWE have 100% key parity."""
    assert set(RULE_SEVERITY_BASE.keys()) == set(RULE_EXPLOIT_BASE.keys())
    assert set(RULE_SEVERITY_BASE.keys()) == set(BANDIT_TO_CWE.keys())
    assert len(BANDIT_RULE_CALIBRATION) >= 75


def test_import_rules_score_below_call_rules():
    """Verify that bare import rules (B4xx) always score strictly below call rules in the same family."""
    # Pickle: import (B403) vs call (B301)
    assert RULE_SEVERITY_BASE["B403"] < RULE_SEVERITY_BASE["B301"]
    assert RULE_EXPLOIT_BASE["B403"] < RULE_EXPLOIT_BASE["B301"]
    # Subprocess: import (B404) vs shell=True (B602)
    assert RULE_SEVERITY_BASE["B404"] < RULE_SEVERITY_BASE["B602"]
    assert RULE_EXPLOIT_BASE["B404"] < RULE_EXPLOIT_BASE["B602"]
    # XML: import (B405) vs parser call (B314)
    assert RULE_SEVERITY_BASE["B405"] < RULE_SEVERITY_BASE["B314"]
    assert RULE_EXPLOIT_BASE["B405"] < RULE_EXPLOIT_BASE["B314"]
    # Telnet: import (B401) vs call (B312)
    assert RULE_SEVERITY_BASE["B401"] < RULE_SEVERITY_BASE["B312"]
    assert RULE_EXPLOIT_BASE["B401"] < RULE_EXPLOIT_BASE["B312"]


def test_calculate_severity_and_exploitability_unknown_fallback():
    """Verify that unknown rule IDs gracefully fall back to generic severity/exploitability."""
    # Unknown rule ID fallback
    assert _calculate_severity("HIGH", "HIGH", test_id="B999") == 8.5
    assert _calculate_severity("MEDIUM", "MEDIUM", test_id=None) == 5.0
    assert _calculate_exploitability("HIGH", "HIGH", test_id="B999") == 0.70
    assert _calculate_exploitability("LOW", "LOW", test_id=None) == pytest.approx(0.08, abs=0.01)


def test_calculate_severity_and_exploitability_case_insensitivity():
    """Verify that test IDs and severity/confidence levels are case-insensitive."""
    assert _calculate_severity("medium", "high", test_id="b506") == _calculate_severity("MEDIUM", "HIGH", test_id="B506")
    assert _calculate_exploitability("medium", "high", test_id="b506") == _calculate_exploitability("MEDIUM", "HIGH", test_id="B506")


def test_calculate_severity_and_exploitability_clamping():
    """Verify that outputs stay bounded in [1.0, 10.0] for severity and [0.05, 1.0] for exploitability."""
    assert 1.0 <= _calculate_severity("LOW", "LOW", test_id="B101") <= 10.0
    assert 1.0 <= _calculate_severity("HIGH", "HIGH", test_id="B102") <= 10.0
    assert 0.05 <= _calculate_exploitability("LOW", "LOW", test_id="B101") <= 1.0
    assert 0.05 <= _calculate_exploitability("HIGH", "HIGH", test_id="B102") <= 1.0


def test_bandit_empty_output(tmp_path):
    engine = BanditEngine()
    findings = engine._parse_output("", tmp_path)
    assert findings == []
    assert engine._parse_output("no json here", tmp_path) == []


def test_bandit_no_py_files(tmp_path):
    engine = BanditEngine()
    findings = engine.scan(str(tmp_path))
    assert findings == []
    assert engine.stats.get("files_scanned") == 0


def test_bandit_target_not_found():
    engine = BanditEngine()
    findings = engine.scan("non_existent_dir_12345")
    assert findings == []
    assert "Directory does not exist" in engine.stats.get("errors", [])


# --------------------------------------------------------------------------- #
# Integration-level test on synthetic Python file
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not BanditEngine().is_available(), reason="Bandit not installed")
def test_bandit_real_scan_synthetic(tmp_path):
    py_file = tmp_path / "vuln.py"
    py_file.write_text(
        "import yaml\n"
        "def bad(data):\n"
        "    return yaml.load(data, Loader=yaml.Loader)\n",
        encoding="utf-8",
    )
    engine = BanditEngine(tests=["B506"])
    findings = engine.scan(str(tmp_path))

    assert len(findings) >= 1
    f = findings[0]
    assert f.engine == "bandit"
    assert f.file == "vuln.py"
    assert f.line == 3
    assert "B506" in f.title
    assert "yaml.safe_load" in f.fix_hint
    assert engine.stats["findings_count"] >= 1


def test_bandit_handles_timeout(tmp_path):
    (tmp_path / "sample.py").write_text("print('hello')", encoding="utf-8")
    engine = BanditEngine(timeout=1)
    with patch.object(engine, "is_available", return_value=True), patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="bandit", timeout=1)
    ):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert any("Timed out" in e for e in engine.stats.get("errors", []))


def test_bandit_non_json_output_records_error(tmp_path):
    (tmp_path / "sample.py").write_text("print('hello')", encoding="utf-8")
    engine = BanditEngine()
    mock_proc = MagicMock(returncode=1, stdout="", stderr="ModuleNotFoundError: No module named 'bandit'")
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run", return_value=mock_proc):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert len(engine.stats["errors"]) >= 1
        assert "ModuleNotFoundError" in engine.stats["errors"][0]


def test_bandit_has_py_with_env_in_path(tmp_path):
    # Directory path contains 'env' as a substring (e.g. env_project or /home/env/)
    repo_dir = tmp_path / "env_project"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("print('test')", encoding="utf-8")

    engine = BanditEngine()
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
        findings = engine.scan(str(repo_dir))
        assert findings == []
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert kwargs["cwd"] == str(repo_dir)
        assert args[0][-1] == "."


def test_bandit_include_suppressed_passes_flag(tmp_path):
    (tmp_path / "main.py").write_text("print('test')", encoding="utf-8")
    engine = BanditEngine(include_suppressed=True)
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
        engine.scan(str(tmp_path))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "--ignore-nosec" in cmd


def test_bandit_exclude_paths_passes_x_flag(tmp_path):
    (tmp_path / "main.py").write_text("print('test')", encoding="utf-8")
    engine = BanditEngine(exclude_paths=["tests", "fixtures"])
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
        engine.scan(str(tmp_path))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-x" in cmd
        assert any("tests" in arg and "fixtures" in arg for arg in cmd)



def test_rel_path_relative_to_root_when_cwd_is_subdirectory(tmp_path, monkeypatch):
    repo_dir = tmp_path / "repo"
    sub_dir = repo_dir / "sub"
    sub_dir.mkdir(parents=True)
    monkeypatch.chdir(sub_dir)

    # ./x.py should resolve relative to repo_dir root, not the sub_dir cwd
    assert _rel_path("./x.py", repo_dir) == "x.py"
    assert _rel_path("models/user.py", repo_dir) == "models/user.py"


def test_bandit_relative_config_file_resolved(tmp_path):
    cfg = tmp_path / "custom_bandit.yaml"
    cfg.write_text("skips: ['B101']\n", encoding="utf-8")
    engine = BanditEngine(config_file=str(cfg))
    assert Path(engine.config_file).is_absolute()
    assert Path(engine.config_file).exists()


def test_bandit_repo_with_python_in_env_dir_not_skipped(tmp_path):
    repo_dir = tmp_path / "repo"
    env_dir = repo_dir / "env"
    env_dir.mkdir(parents=True)
    (env_dir / "worker.py").write_text("print('working')", encoding="utf-8")

    engine = BanditEngine()
    # env/ is not a virtualenv exclude directory; files under env/ must be detected
    assert engine._has_python_files(repo_dir) is True


# --------------------------------------------------------------------------- #
# Remediation Hints & Guidance Tests
# --------------------------------------------------------------------------- #
def test_common_fix_hints_key_parity():
    """Verify that COMMON_FIX_HINTS has 100% key parity with BANDIT_RULE_CALIBRATION."""
    assert set(COMMON_FIX_HINTS.keys()) == set(BANDIT_RULE_CALIBRATION.keys())
    for test_id, hint in COMMON_FIX_HINTS.items():
        assert isinstance(hint, str)
        assert len(hint.strip()) > 15, f"Fix hint for {test_id} is too short: {hint!r}"


def test_remediation_metadata_structure():
    """Verify structured remediation metadata format and auto_fixable status."""
    for auto_id in ["B201", "B113", "B506", "B303", "B501", "B614", "B701"]:
        meta = get_remediation_metadata(auto_id)
        assert meta is not None
        assert meta["auto_fixable"] is True
        assert meta["safe_alternative"] is not None
        assert meta["tier"] in {"mechanical", "needs_review"}
        assert meta["description"]

    # Non-auto-fixable rules
    for non_auto in ["B102", "B306", "B307", "B324", "B602", "B604"]:
        meta = get_remediation_metadata(non_auto)
        assert meta is not None
        assert meta["auto_fixable"] is False
        assert meta["tier"] == "manual"

    # Unmapped rules return None (not attached to finding extra to avoid duplication)
    assert get_remediation_metadata("B999") is None
    assert get_remediation_metadata("B101") is None


def test_remediation_templates_parity_with_rule_patchers():
    """Verify that REMEDIATION_TEMPLATES auto_fixable set and tiers match RULE_PATCHERS exactly."""
    from remediation.code_patcher import RULE_PATCHERS

    auto_fixable_templates = {k for k, v in REMEDIATION_TEMPLATES.items() if v.get("auto_fixable")}
    assert auto_fixable_templates == set(RULE_PATCHERS.keys())
    for k, patcher in RULE_PATCHERS.items():
        assert patcher.tier == REMEDIATION_TEMPLATES[k]["tier"]
        assert patcher.review_note != ""


def test_classify_file_role():
    """Verify path-based role classification for test, doc, sample, and production code."""
    from engines.bandit_engine import classify_file_role

    assert classify_file_role("tests/test_api.py")["is_test_code"] is True
    assert classify_file_role("src/tests/sub/test_foo.py")["file_role"] == "test"
    assert classify_file_role("tests/conftest.py")["is_test_code"] is True
    assert classify_file_role("app/fixtures/users.py")["is_test_code"] is True
    assert classify_file_role("app/mock_service.py")["is_test_code"] is True

    assert classify_file_role("docs/getting_started.py")["file_role"] == "docs"
    assert classify_file_role("examples/quickstart.py")["is_sample_code"] is True
    assert classify_file_role("demos/demo_app.py")["file_role"] == "sample"

    prod = classify_file_role("backend/services/auth.py")
    assert prod["file_role"] == "production"
    assert prod["is_test_code"] is False
    assert prod["is_sample_code"] is False


def test_damping_and_calibration_in_test_and_sample_code(tmp_path):
    """Verify exploitability damping clamps at 0.05 (2 decimals) and rule-specific FP calibration."""
    engine = BanditEngine()

    # 1. Test code B101 (assert): should have HIGH fp_likelihood
    r_b101 = {
        "test_id": "B101",
        "test_name": "assert_used",
        "issue_severity": "LOW",
        "issue_confidence": "HIGH",
        "filename": "tests/test_calc.py",
        "line_number": 10,
    }
    f_b101 = engine._make_finding(r_b101, tmp_path)
    assert f_b101.exposure == "TEST"
    assert f_b101.fp_likelihood == "HIGH"
    assert "assert statement in test code" in f_b101.fp_reason
    assert f_b101.exploitability >= 0.05
    # Verify no duplicate false_positive_risk in extra
    assert "false_positive_risk" not in f_b101.extra
    assert f_b101.extra.get("fp_likelihood") == "HIGH"

    # 2. Test code B602 (subprocess): should have LOW fp_likelihood
    r_b602 = {
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "filename": "tests/test_runner.py",
        "line_number": 25,
    }
    f_b602 = engine._make_finding(r_b602, tmp_path)
    assert f_b602.exposure == "TEST"
    assert f_b602.fp_likelihood == "LOW"

    # 3. Sample code: damped exploitability, fp_likelihood MEDIUM
    r_sample = {
        "test_id": "B105",
        "test_name": "hardcoded_password_string",
        "issue_severity": "LOW",
        "issue_confidence": "MEDIUM",
        "filename": "examples/demo.py",
        "line_number": 5,
    }
    f_sample = engine._make_finding(r_sample, tmp_path)
    assert f_sample.exposure is None
    assert f_sample.fp_likelihood == "MEDIUM"
    assert f_sample.exploitability == 0.12  # B105 MEDIUM conf = 0.30 * 0.8 = 0.24, damped by 0.5 to 0.12

    # 4. Low exploitability damped in test code: verify it clamps at 0.05
    r_clamp = {
        "test_id": "B403",
        "test_name": "import_pickle",
        "issue_severity": "LOW",
        "issue_confidence": "LOW",
        "filename": "tests/test_loader.py",
        "line_number": 1,
    }
    f_clamp = engine._make_finding(r_clamp, tmp_path)
    assert f_clamp.exploitability == 0.05  # clamped at 0.05


def test_enclosing_scope_interleaved_nesting_and_classes():
    """Verify that combined scope stack accurately extracts interleaved class and function scopes."""
    from engines.bandit_engine import extract_enclosing_scope_from_source

    code = (
        "class A:\n"                 # 1
        "    x = 1\n"                # 2
        "    def f(self):\n"         # 3
        "        y = 2\n"            # 4
        "        class B:\n"         # 5
        "            z = 3\n"        # 6
        "            def g(self):\n" # 7
        "                return 42\n" # 8
    )

    # Line 2: inside class A, outside any function
    fn2, cls2, sc2 = extract_enclosing_scope_from_source(code, 2)
    assert fn2 is None
    assert cls2 == "A"
    assert sc2 == "A"

    # Line 4: inside method f of class A
    fn4, cls4, sc4 = extract_enclosing_scope_from_source(code, 4)
    assert fn4 == "f"
    assert cls4 == "A"
    assert sc4 == "A.f"

    # Line 6: inside class B inside method f of class A
    fn6, cls6, sc6 = extract_enclosing_scope_from_source(code, 6)
    assert fn6 == "f"
    assert cls6 == "B"
    assert sc6 == "A.f.B"

    # Line 8: inside method g inside class B inside method f inside class A
    fn8, cls8, sc8 = extract_enclosing_scope_from_source(code, 8)
    assert fn8 == "g"
    assert cls8 == "B"
    assert sc8 == "A.f.B.g"


def test_enclosing_scope_nested_classes_without_functions():
    """Verify nested classes report qualified scope Outer.Inner."""
    from engines.bandit_engine import extract_enclosing_scope_from_source

    code = (
        "class Outer:\n"      # 1
        "    class Inner:\n"  # 2
        "        val = 10\n"  # 3
    )
    fn3, cls3, sc3 = extract_enclosing_scope_from_source(code, 3)
    assert fn3 is None
    assert cls3 == "Inner"
    assert sc3 == "Outer.Inner"


def test_path_sandboxing_in_make_finding(tmp_path):
    """Verify that _make_finding rejects absolute paths outside root or path traversal."""
    engine = BanditEngine()

    # Raw filename pointing to /etc/passwd or outside root
    r = {
        "test_id": "B101",
        "filename": "../../outside_repo.py",
        "line_number": 1,
    }
    f = engine._make_finding(r, tmp_path)
    # The AST scope extraction should have safely fallen back to None without reading external files
    assert f.extra.get("enclosing_scope") is None


def test_finding_fields_preservation_and_redaction():
    """Verify Finding dataclass defines exposure, fp_likelihood, fp_reason, and redact_finding preserves them."""
    from core.finding import Finding
    from core.redact import redact_finding

    f = Finding(
        engine="bandit",
        title="Bandit B105: Possible hardcoded password: 'secret123'",
        file="tests/test_auth.py",
        line=12,
        exposure="TEST",
        fp_likelihood="HIGH",
        fp_reason="Test credential in test fixture",
        evidence="password = 'secret123'",
    )
    redacted = redact_finding(f)
    assert redacted.exposure == "TEST"
    assert redacted.fp_likelihood == "HIGH"
    assert redacted.fp_reason == "Test credential in test fixture"
    assert "secret123" not in redacted.evidence
    assert "secret123" not in redacted.title


def test_bandit_exclude_paths_real_bandit(tmp_path):
    """Verify that exclude_paths=['tests'] excludes tests/ from scan using real Bandit."""
    engine = BanditEngine(exclude_paths=["tests"])
    if not engine.is_available():
        pytest.skip("Bandit not installed")

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    # Use unskipped rule B303 (hashlib.md5) so findings are produced
    (tests_dir / "test_something.py").write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")

    findings = engine.scan(str(tmp_path))
    # main.py should be scanned; test_something.py must be excluded
    files = {f.file.replace("\\", "/") for f in findings}
    assert "main.py" in files
    assert not any("test_something.py" in f for f in files)


def test_bandit_resilient_load_json():
    """Verify _load_json parses Bandit JSON even with ANSI colors, leading log braces, and trailing text."""
    # 1. Standard valid JSON
    valid = '{"results": [{"test_id": "B303"}], "metrics": {}}'
    assert BanditEngine._load_json(valid) == {"results": [{"test_id": "B303"}], "metrics": {}}

    # 2. None or non-JSON
    assert BanditEngine._load_json("") is None
    assert BanditEngine._load_json("Bandit failed to run") is None

    # 3. ANSI escapes + leading non-Bandit JSON braces + trailing output
    noisy_output = (
        "\x1b[33m[WARN] Logger initialized with options: {'debug': True}\x1b[0m\n"
        "[INFO] Starting Bandit scan...\n"
        '{"errors": [], "results": [{"test_id": "B101"}], "metrics": {"_totals": {"loc": 10}}}\n'
        "\x1b[32mScan complete.\x1b[0m\n"
    )
    parsed = BanditEngine._load_json(noisy_output)
    assert parsed is not None
    assert "results" in parsed
    assert parsed["results"][0]["test_id"] == "B101"
    assert parsed["metrics"]["_totals"]["loc"] == 10


def test_bandit_dynamic_timeout_scaling(tmp_path):
    """Verify dynamic timeout calculation based on codebase size, and explicit override preservation."""
    # Base case: no python files
    engine = BanditEngine()
    count, loc = engine._estimate_python_workload(tmp_path)
    assert count == 0
    assert loc == 0

    # Create small python file (~100 bytes)
    (tmp_path / "app.py").write_text("print('hello world')\n" * 5, encoding="utf-8")
    count, loc = engine._estimate_python_workload(tmp_path)
    assert count == 1
    assert loc > 0

    # User specified an explicit timeout override
    custom_engine = BanditEngine(timeout=42)
    assert custom_engine.timeout == 42


def test_bandit_preflight_cli_sanitization(tmp_path):
    """Verify malicious or malformed test/skip flags and missing config paths are sanitized."""
    # Malicious injection in tests and skips
    engine = BanditEngine(
        tests=["B303", "-v", "--config=/evil", "B501"],
        skips=["B101", "--debug", "invalid;flag", "B403"],
        config_file=str(tmp_path / "nonexistent_config.yaml"),
    )

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"results": [], "metrics": {}}'
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        (tmp_path / "test.py").write_text("x = 1\n", encoding="utf-8")
        engine.scan(str(tmp_path))

        assert mock_run.called
        cmd = mock_run.call_args[0][0]

        # Ensure -t only has sanitized B303,B501
        assert "-t" in cmd
        t_idx = cmd.index("-t")
        assert cmd[t_idx + 1] == "B303,B501"

        # Ensure -s only has sanitized B101,B403
        assert "-s" in cmd
        s_idx = cmd.index("-s")
        assert cmd[s_idx + 1] == "B101,B403"

        # Ensure non-existent config file is not included in cmd and recorded in errors
        assert "-c" not in cmd
        assert any("Config file not found" in err for err in engine.stats["errors"])


def test_bandit_all_79_rules_calibrated_and_mapped():
    """Verify that all rules in BANDIT_TO_CWE have valid calibration entries and fix hints."""
    from core.taxonomy import BANDIT_TO_CWE, normalize_cwe

    assert len(BANDIT_TO_CWE) == 79
    for rule_id, cwe in BANDIT_TO_CWE.items():
        assert rule_id in BANDIT_RULE_CALIBRATION, f"Missing calibration for {rule_id}"
        sev, exploit = BANDIT_RULE_CALIBRATION[rule_id]
        assert 1.0 <= sev <= 10.0, f"Severity out of range for {rule_id}: {sev}"
        assert 0.05 <= exploit <= 1.0, f"Exploitability out of range for {rule_id}: {exploit}"

        assert rule_id in COMMON_FIX_HINTS, f"Missing fix hint for {rule_id}"
        assert len(COMMON_FIX_HINTS[rule_id].strip()) > 15

        norm = normalize_cwe(cwe)
        assert norm.startswith("CWE-"), f"Invalid CWE normalization for {cwe}"


def test_bandit_metrics_and_syntax_errors(tmp_path):
    """Verify engine stats capture LOC, nosec counts, and Bandit syntax errors in target files."""
    engine = BanditEngine()
    data = {
        "errors": [
            {"filename": "syntax_err.py", "reason": "SyntaxError: invalid syntax on line 4"},
            {"filename": "syntax_err.py", "reason": "IndentationError: unindent does not match"},
            {"filename": "bad_token.py", "reason": "TokenError: EOF in multi-line statement"},
        ],
        "metrics": {
            "_totals": {"loc": 100, "nosec": 2},
            "app.py": {"loc": 100, "nosec": 2},
        },
        "results": [],
    }
    findings = engine._parse_output(data, tmp_path)
    assert findings == []
    # In real Bandit output, files that fail to parse with SyntaxError are emitted into
    # "errors" and omitted from "metrics"; files_scanned reflects only files that were successfully analyzed.
    assert engine.stats["files_scanned"] == 1
    assert engine.stats["loc"] == 100
    assert engine.stats["nosec"] == 2
    # files_with_errors must count unique files (syntax_err.py + bad_token.py = 2)
    assert engine.stats["files_with_errors"] == 2
    assert any("syntax_err.py" in err and "SyntaxError" in err for err in engine.stats["errors"])


def test_bandit_corrupted_interrupted_json_handling(tmp_path):
    """Verify corrupted, truncated, or whitespace stdout records parse error in stats and returns []."""
    engine = BanditEngine()

    truncated = '{"results": [{"test_id": "B101", "filename": "app.py", "line_number": 1'
    assert engine._load_json(truncated) is None
    assert engine._parse_output(truncated, tmp_path) == []
    assert engine.stats.get("parse_error") is True
    assert any("Failed to parse" in err for err in engine.stats.get("errors", []))

    # Reset engine and test empty/whitespace
    engine2 = BanditEngine()
    assert engine2._load_json("   \n\t  ") is None
    assert engine2._parse_output("   \n\t  ", tmp_path) == []
    assert engine2.stats.get("parse_error") is True

    # Test random text with braces
    engine3 = BanditEngine()
    assert engine3._load_json("{ not valid json at all }") is None
    assert engine3._parse_output("{ not valid json at all }", tmp_path) == []
    assert engine3.stats.get("parse_error") is True


def test_bandit_subprocess_exit_code_1_with_empty_stdout(tmp_path):
    """Verify Bandit returncode 1 with empty stdout records failure in stats and returns []."""
    engine = BanditEngine()
    (tmp_path / "app.py").write_text("print('test')\n", encoding="utf-8")

    # Case A: Exit code 1 with stderr
    mock_proc_stderr = MagicMock(returncode=1, stdout="", stderr="Bandit crashed unexpectedly: MemoryError")
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run", return_value=mock_proc_stderr):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert engine.stats["parse_error"] is True
        assert any("Bandit crashed unexpectedly" in err for err in engine.stats.get("errors", []))

    # Case B: Exit code 1 with empty stderr and empty stdout
    mock_proc_empty = MagicMock(returncode=1, stdout="", stderr="")
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run", return_value=mock_proc_empty):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert engine.stats["parse_error"] is True
        assert any("exit code 1, failed to parse JSON output" in err for err in engine.stats.get("errors", []))


def test_bandit_engine_stats_reset_between_scans(tmp_path):
    """Verify that scanning multiple targets re-initializes engine.stats without carrying over errors."""
    engine = BanditEngine()

    # Scan 1: Non-existent directory generates error
    engine.scan("non_existent_dir_abc123")
    assert len(engine.stats["errors"]) > 0
    assert "Directory does not exist" in engine.stats["errors"][0]

    # Scan 2: Valid repo must start with fresh empty errors list and reset counts
    valid_dir = tmp_path / "clean_repo"
    valid_dir.mkdir()
    (valid_dir / "clean.py").write_text("print('clean')\n", encoding="utf-8")

    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "metrics": {}}', stderr="")
        findings = engine.scan(str(valid_dir))
        assert findings == []
        assert engine.stats["errors"] == []
        assert engine.stats["parse_error"] is False
        assert engine.stats["files_with_errors"] == 0
        assert engine.stats["target"] == str(valid_dir.resolve())


def test_bandit_multi_json_in_stdout_prefers_bandit_report():
    """Verify _load_json isolates the Bandit payload when wrappers print non-Bandit JSON."""
    raw = (
        '{"wrapper": "started", "timestamp": 123456}\n'
        '{"errors": [], "results": [{"test_id": "B303", "filename": "crypto.py"}], "metrics": {}}\n'
        '{"wrapper": "finished", "status": "ok"}\n'
    )
    extracted = BanditEngine._load_json(raw)
    assert extracted is not None
    assert "results" in extracted
    assert extracted["results"][0]["test_id"] == "B303"

    # Negative case: only wrapper JSON is present, without Bandit results or metrics
    only_wrappers = (
        '{"wrapper": "started", "timestamp": 123456}\n'
        '{"wrapper": "progress", "percent": 50}\n'
        '{"wrapper": "finished", "status": "ok"}\n'
    )
    assert BanditEngine._load_json(only_wrappers) is None


def test_bandit_dynamic_timeout_loc_scaling_tiers(tmp_path):
    """Verify timeout scaling tiers for various LOC sizes."""
    engine = BanditEngine()

    # Tier 1: 0 LOC -> base 60s
    with patch.object(engine, "is_available", return_value=True), patch.object(engine, "_estimate_python_workload", return_value=(5, 0)):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='{"results": []}')
            (tmp_path / "x.py").write_text("x = 1\n", encoding="utf-8")
            engine.scan(str(tmp_path))
            assert mock_run.call_args[1]["timeout"] == 60

    # Tier 2: 20,000 LOC -> 60 + 2*30 = 120s
    with patch.object(engine, "is_available", return_value=True), patch.object(engine, "_estimate_python_workload", return_value=(50, 20000)):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='{"results": []}')
            engine.scan(str(tmp_path))
            assert mock_run.call_args[1]["timeout"] == 120

    # Tier 3: 150,000 LOC -> capped at 300s
    with patch.object(engine, "is_available", return_value=True), patch.object(engine, "_estimate_python_workload", return_value=(500, 150000)):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='{"results": []}')
            engine.scan(str(tmp_path))
            assert mock_run.call_args[1]["timeout"] == 300


def test_bandit_subprocess_exit_code_1_with_findings(tmp_path):
    """Verify Bandit returncode 1 with valid JSON results is successfully parsed as findings."""
    engine = BanditEngine()
    py = tmp_path / "main.py"
    py.write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")

    json_payload = {
        "errors": [],
        "metrics": {"_totals": {"loc": 2, "nosec": 0}},
        "results": [
            {
                "test_id": "B303",
                "test_name": "hash_func",
                "filename": "main.py",
                "line_number": 2,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Use of weak MD5 hash function.",
                "code": "2 h = hashlib.md5(b'test')\n",
            }
        ],
    }

    # Exit code 1 indicates Bandit found issues; stdout contains the JSON
    mock_proc = MagicMock(returncode=1, stdout=json.dumps(json_payload), stderr="")
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run", return_value=mock_proc):
        findings = engine.scan(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].extra.get("test_id") == "B303"
        assert "B303" in findings[0].title
        assert engine.stats["findings_count"] == 1


def test_bandit_exclude_paths_nested_real_bandit(tmp_path):
    """Verify BanditEngine excludes nested directory (e.g. src/tests/) using real Bandit."""
    engine = BanditEngine(exclude_paths=["src/tests"])
    if not engine.is_available():
        pytest.skip("Bandit not installed")

    tests_dir = tmp_path / "src" / "tests"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_something.py").write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")
    (tmp_path / "src" / "main.py").write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")

    findings = engine.scan(str(tmp_path))
    files = {f.file.replace("\\", "/") for f in findings}
    assert any("src/main.py" in f for f in files)
    assert not any("test_something.py" in f for f in files)


def test_bandit_non_ascii_findings_and_evidence(tmp_path):
    """Verify non-ASCII text in filenames, issue text, and evidence does not raise Unicode errors."""
    engine = BanditEngine()
    raw = {
        "test_id": "B105",
        "test_name": "hardcoded_password_string",
        "filename": "données/café.py",
        "line_number": 1,
        "issue_severity": "LOW",
        "issue_confidence": "MEDIUM",
        "issue_text": "Possible mot de passe secret dans la fonction vérifiée: 'secret123'",
        "code": "1 pwd = 'secret123'  # vérifié ☕\n",
    }
    f = engine._make_finding(raw, tmp_path)
    assert "café" in f.file
    assert f.line == 1
    assert "vérifiée" in f.title
    assert "vérifié ☕" in f.evidence


def test_path_sandboxing_symlink_pointing_outside(tmp_path):
    """Verify that _make_finding rejects reading files reached via in-root symlinks pointing outside root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_py = outside / "secret.py"
    secret_py.write_text("class LeakedScope:\n    pass\n", encoding="utf-8")

    symlink_file = repo / "symlink.py"
    try:
        symlink_file.symlink_to(secret_py)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks require administrator/developer mode on Windows")

    engine = BanditEngine()
    r = {
        "test_id": "B101",
        "filename": "symlink.py",
        "line_number": 1,
    }
    f = engine._make_finding(r, repo)
    assert f.extra.get("enclosing_scope") is None


def test_bandit_exclude_paths_nested_directory(tmp_path):
    """Verify that exclude_paths with nested directory (e.g. tests/unit) formats -x flags properly."""
    engine = BanditEngine(exclude_paths=["tests/unit", "fixtures\\data"])
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
        engine.scan(str(tmp_path))
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "-x" in cmd
        x_val = cmd[cmd.index("-x") + 1]
        assert "tests/unit" in x_val
        assert "fixtures/data" in x_val
