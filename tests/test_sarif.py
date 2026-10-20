"""Unit and integration tests for SARIF v2.1.0 export and GitHub Code Scanning integration."""
import json
from pathlib import Path

import pytest

from core.finding import Finding
from core.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    export_sarif,
    findings_to_sarif,
    generate_markdown_summary,
    _map_level,
    _normalize_uri,
    _get_rule_id,
)


def _make_dummy_finding(**kwargs) -> Finding:
    defaults = {
        "engine": "bandit",
        "title": "SQL Injection in query formulation",
        "file": "app/db.py",
        "line": 42,
        "cwe": "CWE-89",
        "severity": 8.5,
        "description": "Possible SQL injection detected via string formatting.",
        "evidence": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "fix_hint": "Use parameterized queries or ORM methods instead of string formatting.",
        "risk_score": 75.0,
        "exploitability": 0.8,
        "exposure": "HTTP",
        "extra": {"test_id": "B608", "col_offset": 5},
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestSarifExport:
    def test_schema_and_version(self):
        doc = findings_to_sarif([])
        assert doc["$schema"] == SARIF_SCHEMA
        assert doc["version"] == SARIF_VERSION
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "SCIP"
        assert run["results"] == []

    def test_findings_to_sarif_structure(self):
        finding = _make_dummy_finding()
        doc = findings_to_sarif([finding])
        run = doc["runs"][0]

        # Check driver and rules
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "bandit-B608"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["security-severity"] == "8.5"
        assert "external/cwe/cwe-89" in rule["properties"]["tags"]
        assert "help" in rule
        assert "markdown" in rule["help"]

        # Check results
        results = run["results"]
        assert len(results) == 1
        res = results[0]
        assert res["ruleId"] == "bandit-B608"
        assert res["level"] == "error"
        assert "SQL Injection" in res["message"]["text"]
        assert "Remediation:" in res["message"]["text"]

        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app/db.py"
        assert loc["region"]["startLine"] == 42
        assert loc["region"]["startColumn"] == 5
        assert loc["region"]["snippet"]["text"] == finding.evidence

        assert res["properties"]["risk_score"] == 75.0
        assert res["properties"]["severity"] == 8.5
        assert res["properties"]["exposure"] == "HTTP"

        # Check fix_hint
        assert "parameterized queries" in res["properties"]["fix_hint"]

    def test_severity_level_mapping(self):
        assert _map_level(9.5) == "error"
        assert _map_level(7.0) == "error"
        assert _map_level(6.9) == "warning"
        assert _map_level(4.0) == "warning"
        assert _map_level(3.9) == "note"
        assert _map_level(0.0) == "note"

    def test_rule_id_derivation(self):
        f_bandit = _make_dummy_finding(engine="bandit", extra={"test_id": "B105"})
        assert _get_rule_id(f_bandit) == "bandit-B105"

        f_semgrep = _make_dummy_finding(engine="semgrep", extra={"rule_id": "python.flask.security.audit"})
        assert _get_rule_id(f_semgrep) == "python.flask.security.audit"

        f_secrets = _make_dummy_finding(engine="secrets", extra={"rule": "aws-secret-access-key"})
        assert _get_rule_id(f_secrets) == "secrets-aws-secret-access-key"

        f_crypto = _make_dummy_finding(engine="crypto", extra={"rule": "weak-hash-md5"})
        assert _get_rule_id(f_crypto) == "crypto-weak-hash-md5"

        f_dep = _make_dummy_finding(engine="dependency", extra={"cve": "CVE-2023-1234"})
        assert _get_rule_id(f_dep) == "CVE-2023-1234"

        f_generic = _make_dummy_finding(engine="custom", cwe="CWE-79", extra={})
        assert _get_rule_id(f_generic) == "CWE-79"

    def test_uri_normalization(self):
        assert _normalize_uri(r"app\views.py") == "app/views.py"
        assert _normalize_uri(r".\app\models.py") == "app/models.py"
        assert _normalize_uri("/app/views.py") == "app/views.py"
        assert _normalize_uri("") == "."

    def test_suppressed_finding(self):
        f = _make_dummy_finding(extra={"suppressed": True, "suppression_reason": "Approved exception"})
        doc = findings_to_sarif([f])
        res = doc["runs"][0]["results"][0]
        assert "suppressions" in res
        assert res["suppressions"][0]["status"] == "accepted"
        assert res["suppressions"][0]["justification"] == "Approved exception"

    def test_export_sarif_file(self, tmp_path):
        out_file = tmp_path / "sub" / "results.sarif"
        findings = [_make_dummy_finding(), _make_dummy_finding(severity=3.0, line=None)]
        exported = export_sarif(findings, out_file)

        assert exported.exists()
        with open(exported, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 2
        # None line defaulted to 1
        assert data["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_generate_markdown_summary(self):
        findings = [
            _make_dummy_finding(severity=9.5, title="Critical Remote Code Execution"),
            _make_dummy_finding(severity=7.5, title="High SQL Injection"),
            _make_dummy_finding(severity=5.0, title="Medium Weak Crypto"),
            _make_dummy_finding(severity=2.0, title="Low Debug Info Leak"),
        ]
        md = generate_markdown_summary(findings)
        assert "## 🛡️ SCIP Security Scan Results" in md
        assert "**Total Findings:** 4" in md
        assert "🔴 Critical" in md
        assert "Top Risk Findings" in md
        assert "Critical Remote Code Execution" in md

    def test_empty_markdown_summary(self):
        md = generate_markdown_summary([])
        assert "Total Findings:** 0" in md
        assert "No vulnerabilities or exposed secrets detected!" in md


class TestPipelineSarifCli:
    def test_pipeline_sarif_flag(self, tmp_path):
        from core.pipeline import main
        sarif_out = tmp_path / "scan.sarif"
        # Run pipeline with dummy scan on empty directory
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        code = main([
            str(empty_dir),
            "--sarif-out", str(sarif_out),
            "--no-bandit",
            "--no-semgrep",
            "--no-crypto",
            "--no-history",
            "--offline",
        ])
        assert code == 0
        assert sarif_out.exists()
        with open(sarif_out, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "SCIP"


class TestChangedFilesScope:
    def test_is_file_in_changed_set(self):
        from core.pipeline import is_file_in_changed_set
        changed = {"app/views.py", "core/sarif.py"}

        assert is_file_in_changed_set("app/views.py", changed) is True
        assert is_file_in_changed_set(r"app\views.py", changed) is True
        assert is_file_in_changed_set("./app/views.py", changed) is True
        assert is_file_in_changed_set("other/file.py", changed) is False
        assert is_file_in_changed_set("", changed) is False

    def test_resolve_changed_files_list(self):
        from core.pipeline import resolve_changed_files
        res = resolve_changed_files(changed_files="app/views.py, core/sarif.py")
        assert res == {"app/views.py", "core/sarif.py"}

    def test_resolve_changed_files_from_file(self, tmp_path):
        from core.pipeline import resolve_changed_files
        cf_file = tmp_path / "changes.txt"
        cf_file.write_text("app/views.py\ncore/pipeline.py\n", encoding="utf-8")
        res = resolve_changed_files(changed_files=str(cf_file))
        assert res == {"app/views.py", "core/pipeline.py"}

    def test_pipeline_changed_files_cli(self, tmp_path):
        from core.pipeline import main
        sarif_out = tmp_path / "scan.sarif"
        empty_dir = tmp_path / "repo"
        empty_dir.mkdir()

        code = main([
            str(empty_dir),
            "--sarif-out", str(sarif_out),
            "--changed-files", "some/file.py",
            "--no-bandit",
            "--no-semgrep",
            "--no-crypto",
            "--no-history",
            "--offline",
        ])
        assert code == 0
        assert sarif_out.exists()
