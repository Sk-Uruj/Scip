"""SCIP GitHub Pull Request Review Bot.

Posts CodeRabbit-style interactive security reviews on pull requests:
1. In-place sticky PR summary comment with risk score badge and Mermaid attack paths.
2. Batched inline review comments with native GitHub ```suggestion diff blocks.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.finding import Finding
from core.suggestions import generate_code_suggestion

log = logging.getLogger("scip.pr_bot")
COMMENT_MARKER = "<!-- scip-security-bot-summary -->"


class GitHubClient:
    """GitHub REST API client using requests with explicit timeouts and SSL verification."""

    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{repo}"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SCIP-Security-Bot",
        })

    def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            resp = self.session.request(method=method, url=url, json=data, timeout=30)
            if resp.status_code == 204:
                return None
            resp.raise_for_status()
            return resp.json() if resp.text else None
        except requests.RequestException as e:
            log.error(f"GitHub API Error {method} {url}: {e}")
            raise RuntimeError(f"GitHub API Error: {e}") from e

    def get_pr_comments(self, pr_number: int) -> List[Dict[str, Any]]:
        return self._request("GET", f"issues/{pr_number}/comments") or []

    def post_pr_comment(self, pr_number: int, body: str) -> Dict[str, Any]:
        return self._request("POST", f"issues/{pr_number}/comments", {"body": body})

    def update_comment(self, comment_id: int, body: str) -> Dict[str, Any]:
        return self._request("PATCH", f"issues/comments/{comment_id}", {"body": body})

    def submit_pull_review(
        self,
        pr_number: int,
        commit_sha: str,
        body: str,
        comments: List[Dict[str, Any]],
        event: str = "COMMENT",
    ) -> Dict[str, Any]:
        """Submit a single batched PR review with inline comments."""
        payload = {
            "commit_id": commit_sha,
            "body": body,
            "event": event,
            "comments": comments,
        }
        return self._request("POST", f"pulls/{pr_number}/reviews", payload)


def build_mermaid_attack_paths(findings: List[Finding]) -> str:
    """Generate Mermaid flowchart representing reachable ingress attack paths."""
    reachable = [f for f in findings if f.extra.get("attack_path") and f.exposure not in ("REPO", "HIST")][:3]
    if not reachable:
        return ""

    lines = [
        "### ⚡ Reachable Attack Vectors",
        "",
        "```mermaid",
        "graph LR",
    ]

    for idx, f in enumerate(reachable):
        path = f.extra.get("attack_path", [])
        if len(path) >= 2:
            prev_node = f"E{idx}_0"
            lines.append(f'    {prev_node}["{path[0]}"]')
            for step_idx, step in enumerate(path[1:], 1):
                cur_node = f"E{idx}_{step_idx}"
                clean_step = step.replace('"', "'")
                lines.append(f'    {cur_node}["{clean_step}"]')
                lines.append(f"    {prev_node} --> {cur_node}")
                prev_node = cur_node
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def build_sticky_summary(findings: List[Finding], pr_number: int) -> str:
    """Build rich CodeRabbit-style executive PR summary."""
    crit_count = sum(1 for f in findings if f.severity >= 9.0)
    high_count = sum(1 for f in findings if 7.0 <= f.severity < 9.0)
    med_count = sum(1 for f in findings if 4.0 <= f.severity < 7.0)
    low_count = sum(1 for f in findings if f.severity < 4.0)

    max_risk = max((f.risk_score for f in findings), default=0.0)
    if crit_count > 0 or max_risk >= 70.0:
        badge = "🔴 **Critical Risk**"
    elif high_count > 0 or max_risk >= 50.0:
        badge = "🟠 **High Risk**"
    elif med_count > 0 or max_risk >= 30.0:
        badge = "🟡 **Moderate Risk**"
    elif findings:
        badge = "🔵 **Low Risk**"
    else:
        badge = "🟢 **Clean Security Status**"

    lines = [
        COMMENT_MARKER,
        "## 🛡️ SCIP Security Review",
        "",
        f"**Security Posture:** {badge} | **Max Risk Score:** `{max_risk:.1f}/100` | **Total Alerts:** `{len(findings)}`",
        "",
        "| Severity | Range | Detected in PR |",
        "|---|---|---|",
        f"| 🔴 Critical | 9.0 - 10.0 | **{crit_count}** |",
        f"| 🟠 High | 7.0 - 8.9 | **{high_count}** |",
        f"| 🟡 Medium | 4.0 - 6.9 | **{med_count}** |",
        f"| 🔵 Low | < 4.0 | **{low_count}** |",
        "",
    ]

    if not findings:
        lines.extend([
            "🎉 **Clean Security Bill of Health!**",
            "",
            "No vulnerabilities, dangerous patterns, or exposed credentials were detected in the files modified by this pull request.",
        ])
        return "\n".join(lines)

    # Attack paths diagram
    attack_paths_md = build_mermaid_attack_paths(findings)
    if attack_paths_md:
        lines.append(attack_paths_md)

    # Top actionable findings
    lines.extend([
        "### 🎯 Priority Action Items",
        "",
        "| # | Engine | Sev | Risk | Exposure | Location | Vulnerability |",
        "|---|---|---|---|---|---|---|",
    ])

    top_findings = sorted(findings, key=lambda f: (-f.risk_score, -f.severity))[:8]
    for i, f in enumerate(top_findings, 1):
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        exposure = f.exposure or ("REACHABLE" if f.reachable else "N/A")
        title = f.title.replace("|", "\\|")
        if len(title) > 60:
            title = title[:57] + "..."
        lines.append(
            f"| {i} | `{f.engine}` | {f.severity:.1f} | {f.risk_score:.1f} | `{exposure}` | {loc} | {title} |"
        )

    lines.extend([
        "",
        "💡 *Review the inline comments below for one-click code suggestions where available.*",
    ])

    return "\n".join(lines)


def run_pr_bot(
    token: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    findings_file: str | Path,
    enable_comment: bool = True,
    enable_suggestions: bool = True,
) -> int:
    """Execute the PR review bot against GitHub API."""
    client = GitHubClient(token=token, repo=repo)

    path = Path(findings_file)
    if not path.exists():
        log.warning(f"Findings file {findings_file} not found; treating as 0 findings.")
        findings: List[Finding] = []
    else:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        findings = [Finding(**item) for item in raw_data]

    # 1. Post or update sticky overview comment
    if enable_comment:
        summary_body = build_sticky_summary(findings, pr_number)
        try:
            existing_comments = client.get_pr_comments(pr_number)
            existing_scip_comment = next(
                (c for c in existing_comments if COMMENT_MARKER in (c.get("body") or "")),
                None,
            )
            if existing_scip_comment:
                log.info(f"Updating existing SCIP comment #{existing_scip_comment['id']}")
                client.update_comment(existing_scip_comment["id"], summary_body)
            else:
                log.info("Posting new SCIP sticky PR review comment")
                client.post_pr_comment(pr_number, summary_body)
        except Exception as e:
            log.error(f"Failed to post/update sticky comment: {e}")

    # 2. Post batched inline review comments with one-click suggestions
    if enable_suggestions and findings and commit_sha:
        review_comments: List[Dict[str, Any]] = []

        for f in findings:
            if not f.line or f.line < 1:
                continue

            suggestion = generate_code_suggestion(f)
            if suggestion:
                review_comments.append({
                    "path": suggestion.file,
                    "line": suggestion.line,
                    "body": suggestion.to_markdown(),
                })
            elif f.severity >= 7.0 and f.fix_hint:
                # High severity finding without direct replacement: post rich explanatory comment
                rel_file = f.file.replace("\\", "/")
                comment_body = (
                    f"> ⚠️ **[SCIP Alert] {f.title}** (Severity: {f.severity:.1f}/10, Risk: {f.risk_score:.1f}/100)\n\n"
                    f"{f.description}\n\n"
                    f"**Remediation:**\n{f.fix_hint}"
                )
                review_comments.append({
                    "path": rel_file,
                    "line": f.line,
                    "body": comment_body,
                })

        if review_comments:
            # GitHub API allows max 30 comments per review batch
            batch = review_comments[:25]
            log.info(f"Submitting batched PR review with {len(batch)} inline comment(s)")
            try:
                client.submit_pull_review(
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    body="🛡️ **SCIP Security Review**: Analyzed modified files and generated inline recommendations.",
                    comments=batch,
                )
            except Exception as e:
                log.error(f"Failed to submit inline pull review: {e}")

    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    findings_path = os.environ.get("SCIP_RESULTS_PATH", "scip-results.json")

    enable_comment = os.environ.get("ENABLE_PR_COMMENT", "true").lower() == "true"
    enable_suggestions = os.environ.get("ENABLE_SUGGESTIONS", "true").lower() == "true"

    if not token:
        log.error("GITHUB_TOKEN environment variable is required to run PR bot.")
        return 1
    if not repo:
        log.error("GITHUB_REPOSITORY environment variable is required.")
        return 1

    pr_number = None
    commit_sha = os.environ.get("GITHUB_SHA", "")

    if event_path and Path(event_path).exists():
        try:
            with open(event_path, "r", encoding="utf-8") as ef:
                event_data = json.load(ef)
            pr = event_data.get("pull_request")
            if pr:
                pr_number = pr.get("number")
                commit_sha = pr.get("head", {}).get("sha", commit_sha)
        except Exception as e:
            log.warning(f"Could not parse GITHUB_EVENT_PATH: {e}")

    if not pr_number:
        # Check GITHUB_REF (e.g. refs/pull/12/merge)
        ref = os.environ.get("GITHUB_REF", "")
        match = re.search(r"refs/pull/(\d+)/", ref)
        if match:
            pr_number = int(match.group(1))

    if not pr_number:
        log.info("Not running in a pull request context; skipping PR bot commenting.")
        return 0

    log.info(f"Running SCIP PR bot on {repo} PR #{pr_number} (SHA: {commit_sha[:8]})")
    return run_pr_bot(
        token=token,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        findings_file=findings_path,
        enable_comment=enable_comment,
        enable_suggestions=enable_suggestions,
    )


if __name__ == "__main__":
    sys.exit(main())
