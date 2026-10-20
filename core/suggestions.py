"""Code suggestion generator for GitHub PR reviews.

Generates native GitHub ```suggestion diff blocks for instant one-click
commit remediation in pull request reviews.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.finding import Finding


@dataclass
class CodeSuggestion:
    file: str
    line: int
    end_line: Optional[int]
    replacement: str
    explanation: str

    def to_markdown(self) -> str:
        """Render suggestion as a GitHub Markdown review comment with ```suggestion block."""
        return (
            f"> 🛡️ **SCIP Recommendation**: {self.explanation}\n\n"
            f"```suggestion\n"
            f"{self.replacement}\n"
            f"```"
        )


def _extract_target_version(fix_hint: str) -> Optional[str]:
    """Extract recommended version from fix hint string (e.g. 'Upgrade pillow from 6.2.0 to 10.0.1 or later.')."""
    if not fix_hint:
        return None
    match = re.search(r"(?:to|>=)\s*([0-9]+(?:\.[0-9a-zA-Z]+)+)", fix_hint)
    if match:
        return match.group(1)
    return None


def generate_code_suggestion(finding: Finding, repo_path: Optional[str] = None) -> Optional[CodeSuggestion]:
    """Generate a high-confidence CodeSuggestion for a finding if an exact fix can be formulated."""
    if not finding.line or finding.line < 1:
        return None

    # 1. Dependency Engine: Requirements upgrade suggestions
    if finding.engine == "dependency" and finding.file.endswith(("requirements.txt", "requirements.in", ".txt")):
        target_version = _extract_target_version(finding.fix_hint)
        package = finding.extra.get("package")
        if not package and "==" in finding.evidence:
            package = finding.evidence.split("==")[0].strip()

        if package and target_version:
            # Match existing syntax style (>= or ==)
            rel_path = finding.file.replace("\\", "/")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=f"{package}>={target_version}",
                explanation=f"Upgrade `{package}` to `{target_version}` or later to remediate {finding.cwe or 'vulnerability'}.",
            )

    # 2. Bandit AST Patcher suggestions
    if finding.engine == "bandit":
        test_id = finding.extra.get("test_id")
        rel_path = finding.file.replace("\\", "/")

        # B201: Flask app debug=True -> debug=False
        if test_id == "B201" and finding.evidence and "debug=True" in finding.evidence:
            replacement = finding.evidence.replace("debug=True", "debug=False")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Disable Flask debug mode in production to prevent arbitrary code execution and console access.",
            )

        # B506: yaml.load -> yaml.safe_load
        if test_id == "B506" and finding.evidence and "yaml.load(" in finding.evidence:
            replacement = finding.evidence.replace("yaml.load(", "yaml.safe_load(")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Use `yaml.safe_load()` instead of `yaml.load()` to prevent arbitrary object deserialization.",
            )

        # B501: requests verify=False -> verify=True
        if test_id == "B501" and finding.evidence and "verify=False" in finding.evidence:
            replacement = finding.evidence.replace("verify=False", "verify=True")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Enable TLS certificate verification (`verify=True`) to prevent man-in-the-middle attacks.",
            )

        # B113: requests call without timeout
        if test_id == "B113" and finding.evidence:
            ev = finding.evidence.strip()
            # If requests.get(...) or requests.post(...) ends with ')'
            if ev.endswith(")") and "timeout=" not in ev:
                # Add timeout parameter
                replacement = ev[:-1] + ", timeout=10)"
                return CodeSuggestion(
                    file=rel_path,
                    line=finding.line,
                    end_line=finding.line,
                    replacement=replacement,
                    explanation="Add an explicit timeout (`timeout=10`) to prevent unhandled network hangs.",
                )

    # 3. Direct suggested_fix in extra metadata
    if finding.extra.get("suggested_fix"):
        return CodeSuggestion(
            file=finding.file.replace("\\", "/"),
            line=finding.line,
            end_line=finding.extra.get("end_line", finding.line),
            replacement=str(finding.extra["suggested_fix"]),
            explanation=finding.fix_hint or "Apply recommended security remediation.",
        )

    return None
