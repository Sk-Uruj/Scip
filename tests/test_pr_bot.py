"""Unit and integration tests for CodeRabbit-style PR review bot and suggestions engine."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Finding
from core.suggestions import CodeSuggestion, generate_code_suggestion, _extract_target_version
from scripts.github_pr_bot import (
    COMMENT_MARKER,
    GitHubClient,
    build_mermaid_attack_paths,
    build_sticky_summary,
    run_pr_bot,
)


def _make_sample_finding(**kwargs) -> Finding:
    defaults = {
        "engine": "dependency",
        "title": "Vulnerable pillow version",
        "file": "requirements.txt",
        "line": 10,
        "cwe": "CWE-787",
        "severity": 8.5,
        "description": "Heap buffer overflow in libwebp",
        "evidence": "pillow==6.2.0",
        "fix_hint": "Upgrade pillow from 6.2.0 to 10.0.1 or later.",
        "risk_score": 78.5,
        "exploitability": 0.8,
        "exposure": "HTTP",
        "extra": {"package": "pillow"},
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestSuggestionsEngine:
    def test_extract_target_version(self):
        assert _extract_target_version("Upgrade pillow from 6.2.0 to 10.0.1 or later.") == "10.0.1"
        assert _extract_target_version("Use django>=4.2.26") == "4.2.26"
        assert _extract_target_version("") is None

    def test_dependency_suggestion(self):
        finding = _make_sample_finding()
        suggestion = generate_code_suggestion(finding)
        assert suggestion is not None
        assert suggestion.file == "requirements.txt"
        assert suggestion.line == 10
        assert suggestion.replacement == "pillow>=10.0.1"
        md = suggestion.to_markdown()
        assert "```suggestion" in md
        assert "pillow>=10.0.1" in md

    def test_flask_debug_suggestion(self):
        finding = _make_sample_finding(
            engine="bandit",
            file="app.py",
            line=45,
            evidence="app.run(host='0.0.0.0', port=5000, debug=True)",
            extra={"test_id": "B201"},
        )
        suggestion = generate_code_suggestion(finding)
        assert suggestion is not None
        assert suggestion.replacement == "app.run(host='0.0.0.0', port=5000, debug=False)"
        assert "debug mode" in suggestion.explanation

    def test_yaml_safe_load_suggestion(self):
        finding = _make_sample_finding(
            engine="bandit",
            file="parser.py",
            line=12,
            evidence="config = yaml.load(raw_data)",
            extra={"test_id": "B506"},
        )
        suggestion = generate_code_suggestion(finding)
        assert suggestion is not None
        assert suggestion.replacement == "config = yaml.safe_load(raw_data)"

    def test_requests_timeout_suggestion(self):
        finding = _make_sample_finding(
            engine="bandit",
            file="client.py",
            line=25,
            evidence="resp = requests.get('https://example.com')",
            extra={"test_id": "B113"},
        )
        suggestion = generate_code_suggestion(finding)
        assert suggestion is not None
        assert suggestion.replacement == "resp = requests.get('https://example.com', timeout=10)"

    def test_no_line_returns_none(self):
        finding = _make_sample_finding(line=None)
        assert generate_code_suggestion(finding) is None


class TestPRBotSummary:
    def test_build_sticky_summary_clean(self):
        md = build_sticky_summary([], pr_number=12)
        assert COMMENT_MARKER in md
        assert "🟢 **Clean Security Status**" in md
        assert "Clean Security Bill of Health!" in md

    def test_build_sticky_summary_with_findings(self):
        findings = [
            _make_sample_finding(severity=9.5, risk_score=92.0),
            _make_sample_finding(severity=7.2, risk_score=65.0),
        ]
        md = build_sticky_summary(findings, pr_number=12)
        assert COMMENT_MARKER in md
        assert "🔴 **Critical Risk**" in md
        assert "Priority Action Items" in md
        assert "pillow" in md

    def test_build_mermaid_attack_paths(self):
        finding = _make_sample_finding(
            extra={"attack_path": ["HTTP Ingress /api/login", "auth/views.py:45", "db/query.py:120"]}
        )
        mermaid = build_mermaid_attack_paths([finding])
        assert "```mermaid" in mermaid
        assert "graph LR" in mermaid
        assert "HTTP Ingress /api/login" in mermaid
        assert "db/query.py:120" in mermaid


class TestPRBotClientAndExecution:
    @patch("scripts.github_pr_bot.GitHubClient")
    def test_run_pr_bot_update_existing_comment(self, mock_client_cls, tmp_path):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_pr_comments.return_value = [
            {"id": 401, "body": f"Old report {COMMENT_MARKER}"}
        ]

        findings_file = tmp_path / "findings.json"
        f = _make_sample_finding()
        findings_file.write_text(json.dumps([f.to_dict()]), encoding="utf-8")

        code = run_pr_bot(
            token="ghp_dummy",
            repo="org/repo",
            pr_number=99,
            commit_sha="abcd1234ef56",
            findings_file=findings_file,
            enable_comment=True,
            enable_suggestions=True,
        )
        assert code == 0
        mock_client.update_comment.assert_called_once()
        mock_client.submit_pull_review.assert_called_once()

    @patch("scripts.github_pr_bot.GitHubClient")
    def test_run_pr_bot_create_new_comment(self, mock_client_cls, tmp_path):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_pr_comments.return_value = []

        findings_file = tmp_path / "findings.json"
        findings_file.write_text("[]", encoding="utf-8")

        code = run_pr_bot(
            token="ghp_dummy",
            repo="org/repo",
            pr_number=50,
            commit_sha="1234567890ab",
            findings_file=findings_file,
            enable_comment=True,
            enable_suggestions=False,
        )
        assert code == 0
        mock_client.post_pr_comment.assert_called_once()
        mock_client.submit_pull_review.assert_not_called()
