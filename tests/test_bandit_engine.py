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
        assert "tests,fixtures" in cmd



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
    """Verify that REMEDIATION_TEMPLATES auto_fixable set matches RULE_PATCHERS exactly."""
    from remediation.code_patcher import RULE_PATCHERS

    auto_fixable_templates = {k for k, v in REMEDIATION_TEMPLATES.items() if v.get("auto_fixable")}
    assert auto_fixable_templates == set(RULE_PATCHERS.keys())


