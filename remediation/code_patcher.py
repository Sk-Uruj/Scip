"""Automated code-pattern remediation for SAST findings (Step 9 Integration).

Provides rule-based patch generation and application for Bandit findings:
- B506: yaml.load(...) -> yaml.safe_load(...)
- B303: hashlib.md5(...) -> hashlib.sha256(...)
- B201: app.run(debug=True) -> app.run(debug=False)
- B306: tempfile.mktemp() -> tempfile.NamedTemporaryFile()
- B113: requests.get(...) -> requests.get(..., timeout=10)
- B501: verify=False -> verify=True
- B604: shell=True -> shell=False
- B614: torch.load(...) -> torch.load(..., weights_only=True)
- B701: autoescape=False -> autoescape=True

All edits are made on a copy of the repository (or in-memory diff).
The original repository is never modified directly.
"""
from __future__ import annotations

import difflib
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from core.finding import Finding
from engines.bandit_engine import patch_code_snippet
from remediation.apply import make_workspace

log = logging.getLogger("scip.remediation.code_patcher")


@dataclass
class CodeEditRecord:
    file: str
    line: int
    test_id: str
    original: str
    patched: str
    applied: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CodePatchResult:
    workspace: Path
    diff: str = ""
    edits: List[CodeEditRecord] = field(default_factory=list)

    @property
    def applied(self) -> List[CodeEditRecord]:
        return [e for e in self.edits if e.applied]

    @property
    def skipped(self) -> List[CodeEditRecord]:
        return [e for e in self.edits if not e.applied]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace": str(self.workspace),
            "diff": self.diff,
            "applied_count": len(self.applied),
            "skipped_count": len(self.skipped),
            "edits": [e.to_dict() for e in self.edits],
        }


def _extract_test_id(finding: Union[Finding, Dict[str, Any]]) -> str:
    """Extract Bandit test_id from a Finding object or dictionary."""
    if isinstance(finding, Finding):
        return str((finding.extra or {}).get("test_id") or "").upper()
    if isinstance(finding, dict):
        extra = finding.get("extra") or {}
        if "test_id" in extra:
            return str(extra["test_id"]).upper()
        # Fallback to parsing from title e.g. "Bandit B506: ..."
        title = finding.get("title", "")
        if "Bandit " in title:
            parts = title.split("Bandit ", 1)[1].split(":", 1)
            if parts:
                return parts[0].strip().upper()
    return ""


def _extract_line(finding: Union[Finding, Dict[str, Any]]) -> Optional[int]:
    """Extract 1-indexed line number from finding."""
    if isinstance(finding, Finding):
        return finding.line
    if isinstance(finding, dict):
        line = finding.get("line")
        return int(line) if line is not None else None
    return None


def _extract_file(finding: Union[Finding, Dict[str, Any]]) -> str:
    """Extract normalized relative file path from finding."""
    if isinstance(finding, Finding):
        return finding.file
    if isinstance(finding, dict):
        return finding.get("file", "")
    return ""


def can_auto_patch(finding: Union[Finding, Dict[str, Any]]) -> bool:
    """Return True if this finding has an automated code fix available."""
    if isinstance(finding, Finding):
        remediation = (finding.extra or {}).get("remediation") or {}
        if remediation.get("auto_fixable"):
            return True
    elif isinstance(finding, dict):
        extra = finding.get("extra") or {}
        remediation = extra.get("remediation") or {}
        if remediation.get("auto_fixable"):
            return True

    test_id = _extract_test_id(finding)
    return test_id in {"B506", "B303", "B201", "B306", "B113", "B501", "B604", "B614", "B701"}


def patch_line(line: str, test_id: str) -> Tuple[Optional[str], str]:
    """Attempt to patch a single line using rule-specific pattern replacements.

    Returns (patched_line, '') or (None, failure_reason).
    """
    patched = patch_code_snippet(line, test_id)
    if patched is not None and patched != line:
        return patched, ""
    return None, f"Rule {test_id} pattern not found or already safe on target line"


def generate_file_patch(
    file_rel_path: str,
    original_content: str,
    findings: List[Union[Finding, Dict[str, Any]]],
) -> Tuple[str, str, List[CodeEditRecord]]:
    """Apply rule-based patches to file content for all applicable findings.

    Returns (new_content, unified_diff, edit_records).
    """
    lines = original_content.splitlines(keepends=True)
    edits: List[CodeEditRecord] = []
    line_modified = [False] * len(lines)

    # Sort findings by line number ascending
    sorted_findings = sorted(
        findings,
        key=lambda f: (_extract_line(f) or 0),
    )

    for f in sorted_findings:
        test_id = _extract_test_id(f)
        line_no = _extract_line(f)

        if not can_auto_patch(f):
            edits.append(CodeEditRecord(
                file=file_rel_path,
                line=line_no or 0,
                test_id=test_id,
                original="",
                patched="",
                applied=False,
                reason=f"Rule {test_id} is not marked as auto-fixable",
            ))
            continue

        if line_no is None or line_no < 1 or line_no > len(lines):
            edits.append(CodeEditRecord(
                file=file_rel_path,
                line=line_no or 0,
                test_id=test_id,
                original="",
                patched="",
                applied=False,
                reason=f"Line number {line_no} out of range for file",
            ))
            continue

        idx = line_no - 1
        orig_line = lines[idx]

        # Check line or surrounding context if multi-line call
        patched_line, reason = patch_line(orig_line, test_id)
        if patched_line is not None:
            lines[idx] = patched_line
            line_modified[idx] = True
            edits.append(CodeEditRecord(
                file=file_rel_path,
                line=line_no,
                test_id=test_id,
                original=orig_line.rstrip("\r\n"),
                patched=patched_line.rstrip("\r\n"),
                applied=True,
                reason="",
            ))
        else:
            edits.append(CodeEditRecord(
                file=file_rel_path,
                line=line_no,
                test_id=test_id,
                original=orig_line.rstrip("\r\n"),
                patched="",
                applied=False,
                reason=reason,
            ))

    new_content = "".join(lines)
    diff = ""
    if any(line_modified):
        orig_split = original_content.splitlines(keepends=True)
        new_split = new_content.splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(
            orig_split,
            new_split,
            fromfile=f"a/{file_rel_path}",
            tofile=f"b/{file_rel_path}",
        ))
        diff = "".join(diff_lines)

    return new_content, diff, edits


def apply_code_patches(
    repo_path: Union[str, Path],
    findings: List[Union[Finding, Dict[str, Any]]],
    dest_path: Optional[Union[str, Path]] = None,
) -> CodePatchResult:
    """Apply code patches to a clean copy of the repo, returning a CodePatchResult with diff."""
    repo = Path(repo_path).resolve()
    if dest_path:
        dest = Path(dest_path).resolve()
    else:
        dest = repo.parent / "remediation_out" / "code_workspace"

    workspace = make_workspace(repo, dest)

    # Group findings by file
    findings_by_file: Dict[str, List[Union[Finding, Dict[str, Any]]]] = {}
    for f in findings:
        f_path = _extract_file(f)
        if f_path:
            findings_by_file.setdefault(f_path, []).append(f)

    all_diffs: List[str] = []
    all_edits: List[CodeEditRecord] = []

    for rel_f, file_findings in sorted(findings_by_file.items()):
        target_file = workspace / rel_f
        if not target_file.exists():
            for f in file_findings:
                all_edits.append(CodeEditRecord(
                    file=rel_f,
                    line=_extract_line(f) or 0,
                    test_id=_extract_test_id(f),
                    original="",
                    patched="",
                    applied=False,
                    reason=f"Target file does not exist in workspace: {rel_f}",
                ))
            continue

        try:
            content = target_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = target_file.read_text(encoding="latin-1")
            except Exception as e:
                for f in file_findings:
                    all_edits.append(CodeEditRecord(
                        file=rel_f,
                        line=_extract_line(f) or 0,
                        test_id=_extract_test_id(f),
                        original="",
                        patched="",
                        applied=False,
                        reason=f"Cannot read file: {e}",
                    ))
                continue

        new_content, diff, edits = generate_file_patch(rel_f, content, file_findings)
        all_edits.extend(edits)

        if diff:
            target_file.write_text(new_content, encoding="utf-8")
            all_diffs.append(diff)

    full_diff = "\n".join(all_diffs)
    return CodePatchResult(workspace=workspace, diff=full_diff, edits=all_edits)
