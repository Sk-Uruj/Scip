"""Export SCIP findings as SARIF v2.1.0 for GitHub Code Scanning and CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard (v2.1.0)
used natively by GitHub Code Scanning, Azure DevOps, VS Code, and many security dashboards.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.finding import Finding

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _map_level(severity: float) -> str:
    """Map SCIP numerical severity (0.0 - 10.0) to SARIF reporting level."""
    if severity >= 7.0:
        return "error"
    if severity >= 4.0:
        return "warning"
    return "note"


def _normalize_uri(file_path: str, repo_path: Optional[str] = None) -> str:
    """Convert file path into a clean, repo-relative POSIX path for GitHub SARIF matching."""
    if not file_path:
        return "."

    # Normalize all backslashes to forward slashes across all platforms (Linux/macOS/Windows)
    clean_path = file_path.replace("\\", "/")

    if repo_path:
        clean_repo = repo_path.replace("\\", "/").rstrip("/")
        if clean_path.startswith(clean_repo + "/"):
            clean_path = clean_path[len(clean_repo) + 1 :]

    while clean_path.startswith("./") or clean_path.startswith("/"):
        clean_path = clean_path.lstrip("./").lstrip("/")

    # If windows drive letter remained (e.g. D:/something outside repo), strip it
    clean_path = re.sub(r"^[a-zA-Z]:/", "", clean_path)
    return clean_path or "."


def _get_rule_id(finding: Finding) -> str:
    """Derive a unique, stable rule identifier for the finding."""
    extra = finding.extra or {}
    if finding.engine == "bandit" and extra.get("test_id"):
        return f"bandit-{extra['test_id']}"
    if finding.engine == "semgrep" and extra.get("rule_id"):
        return str(extra["rule_id"])
    if finding.engine == "secrets" and extra.get("rule"):
        return f"secrets-{extra['rule']}"
    if finding.engine == "crypto" and extra.get("rule"):
        return f"crypto-{extra['rule']}"
    if extra.get("cve"):
        return str(extra["cve"])
    if finding.cwe:
        return finding.cwe

    # Fallback to engine and title slug
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in finding.title[:32]).strip("-")
    return f"{finding.engine}-{slug}" if slug else finding.engine


def _get_rule_name(finding: Finding) -> str:
    """Get human-readable rule name."""
    extra = finding.extra or {}
    if extra.get("rule_title"):
        return str(extra["rule_title"])
    title_head = finding.title.split(":")[0].strip()
    return title_head or finding.title[:60]


def _build_rule_help(finding: Finding) -> Dict[str, str]:
    """Generate plain text and rich Markdown help documentation for GitHub Code Scanning UI."""
    plain = (
        f"{finding.title}\n\n"
        f"Engine: {finding.engine}\n"
        f"Severity: {finding.severity:.1f} / 10.0\n"
        f"Risk Score: {finding.risk_score:.2f} / 100.0\n"
        f"CWE: {finding.cwe or 'N/A'}\n"
        f"Exposure: {finding.exposure or 'N/A'}\n\n"
        f"Remediation:\n{finding.fix_hint or 'Review the affected code and apply standard security mitigations.'}\n\n"
        f"Details:\n{finding.description or finding.title}"
    )

    md_lines = [
        f"### {finding.title}",
        "",
        "| Attribute | Value |",
        "|---|---|",
        f"| **Engine** | `{finding.engine}` |",
        f"| **Severity** | `{finding.severity:.1f} / 10.0` |",
        f"| **Risk Score** | `{finding.risk_score:.2f} / 100.0` |",
        f"| **Exploitability** | `{finding.exploitability:.2f}` |",
        f"| **Exposure** | `{finding.exposure or 'N/A'}` |",
    ]
    if finding.cwe:
        md_lines.append(f"| **CWE** | [{finding.cwe}](https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html) |")

    if finding.fix_hint:
        md_lines.extend([
            "",
            "### Remediation Hint",
            f"> {finding.fix_hint}",
        ])

    if finding.description and finding.description != finding.title:
        md_lines.extend([
            "",
            "### Details",
            finding.description,
        ])

    if finding.evidence:
        md_lines.extend([
            "",
            "### Evidence",
            "```",
            finding.evidence.strip(),
            "```",
        ])

    return {
        "text": plain,
        "markdown": "\n".join(md_lines),
    }


def findings_to_sarif(
    findings: List[Finding],
    repo_path: Optional[str] = None,
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Convert a list of SCIP Finding objects into SARIF v2.1.0 dictionary."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = _get_rule_id(f)
        level = _map_level(f.severity)

        if rule_id not in rules_dict:
            tags = ["security", f.engine.lower()]
            if f.cwe:
                tags.append(f"external/cwe/{f.cwe.lower()}")
                tags.append(f.cwe)

            rule_help = _build_rule_help(f)
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": _get_rule_name(f),
                "shortDescription": {"text": f.title[:150]},
                "fullDescription": {"text": f.description or f.title},
                "help": rule_help,
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": tags,
                    "security-severity": f"{max(0.0, min(10.0, float(f.severity))):.1f}",
                    "precision": "very-high" if (f.extra.get("corroborated") or f.severity >= 7.0) else "high",
                    "problem.severity": "error" if level == "error" else ("warning" if level == "warning" else "recommendation"),
                },
            }

        # Format message
        msg_parts = [f.title]
        if f.description and f.description != f.title:
            msg_parts.append(f.description)
        if f.fix_hint:
            msg_parts.append(f"Remediation: {f.fix_hint}")
        message_text = "\n\n".join(msg_parts)

        start_line = max(1, f.line if f.line is not None else 1)
        region: Dict[str, Any] = {"startLine": start_line}
        if f.extra.get("col_offset") and int(f.extra["col_offset"]) >= 1:
            region["startColumn"] = int(f.extra["col_offset"])
        if f.extra.get("end_line") and int(f.extra["end_line"]) >= start_line:
            region["endLine"] = int(f.extra["end_line"])
        if f.extra.get("end_col_offset") and int(f.extra["end_col_offset"]) >= 1:
            region["endColumn"] = int(f.extra["end_col_offset"])
        if f.evidence:
            region["snippet"] = {"text": f.evidence[:500]}

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _normalize_uri(f.file, repo_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
            "properties": {
                "risk_score": round(f.risk_score, 2),
                "severity": round(f.severity, 1),
                "exploitability": round(f.exploitability, 2),
                "exposure": f.exposure,
                "engine": f.engine,
                "cwe": f.cwe,
                "fp_likelihood": f.fp_likelihood,
                "fix_hint": f.fix_hint or None,
            },
        }

        # Suppressed findings support
        if f.extra.get("suppressed"):
            result["suppressions"] = [
                {
                    "kind": "inSource" if f.extra.get("suppression_type") == "inline" else "external",
                    "status": "accepted",
                    "justification": f.extra.get("suppression_reason") or "Suppressed finding",
                }
            ]

        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SCIP",
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/scip-security/scip",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(
    findings: List[Finding],
    output_path: str | Path,
    repo_path: Optional[str] = None,
    tool_version: str = "1.0.0",
    indent: int = 2,
) -> Path:
    """Export findings as SARIF v2.1.0 to a file."""
    sarif_doc = findings_to_sarif(findings, repo_path=repo_path, tool_version=tool_version)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(sarif_doc, fh, indent=indent)
    return out


def generate_markdown_summary(findings: List[Finding]) -> str:
    """Generate a clean GitHub Actions step summary markdown for $GITHUB_STEP_SUMMARY."""
    crit_count = sum(1 for f in findings if f.severity >= 9.0)
    high_count = sum(1 for f in findings if 7.0 <= f.severity < 9.0)
    med_count = sum(1 for f in findings if 4.0 <= f.severity < 7.0)
    low_count = sum(1 for f in findings if f.severity < 4.0)

    lines = [
        "## 🛡️ SCIP Security Scan Results",
        "",
        f"**Total Findings:** {len(findings)}",
        "",
        "| Severity | Level | Count |",
        "|---|---|---|",
        f"| 🔴 Critical | 9.0 - 10.0 | **{crit_count}** |",
        f"| 🟠 High | 7.0 - 8.9 | **{high_count}** |",
        f"| 🟡 Medium | 4.0 - 6.9 | **{med_count}** |",
        f"| 🔵 Low / Note | < 4.0 | **{low_count}** |",
        "",
    ]

    if not findings:
        lines.append("🎉 **No vulnerabilities or exposed secrets detected!**")
        return "\n".join(lines)

    top_findings = sorted(findings, key=lambda f: (-f.risk_score, -f.severity))[:15]
    lines.extend([
        "### Top Risk Findings",
        "",
        "| # | Engine | Sev | Risk | Location | Title |",
        "|---|---|---|---|---|---|",
    ])

    for i, f in enumerate(top_findings, 1):
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        title = f.title.replace("|", "\\|")
        if len(title) > 65:
            title = title[:62] + "..."
        lines.append(
            f"| {i} | {f.engine} | {f.severity:.1f} | {f.risk_score:.1f} | {loc} | {title} |"
        )

    if len(findings) > 15:
        lines.extend([
            "",
            f"*... and {len(findings) - 15} more finding(s). See the SARIF report or Code Scanning tab for the full list.*",
        ])

    return "\n".join(lines)
