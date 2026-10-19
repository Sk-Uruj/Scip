"""Automated code-pattern remediation for SAST findings.

Provides AST-based patch generation and application for Bandit findings:
- B201: app.run(..., debug=True) -> app.run(..., debug=False) [mechanical]
- B113: requests call without timeout -> timeout=10 added [needs_review]
- B506: yaml.load(stream, ...) -> yaml.safe_load(stream) [needs_review]
- B303: hashlib.md5/sha1(...) -> hashlib.sha256(...) [needs_review]
- B501: requests call verify=False -> verify=True [needs_review]
- B614: torch.load(...) -> torch.load(..., weights_only=True) [needs_review]
- B701: Jinja2 autoescape=False -> autoescape=True [needs_review]

All edits are verified with ast.parse before being accepted and are written to a
clean copy of the repository. The original repository is never modified directly.
"""
from __future__ import annotations

import ast
import difflib
import logging
import os
import re
import stat
import tokenize
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from core.finding import Finding
from remediation.apply import make_workspace

log = logging.getLogger("scip.remediation.code_patcher")


class PatchTier(str, Enum):
    MECHANICAL = "mechanical"
    NEEDS_REVIEW = "needs_review"


class PatchStatus(str, Enum):
    APPLIED = "applied"
    NOT_AUTO_FIXABLE = "not_auto_fixable"
    PATTERN_NOT_FOUND = "pattern_not_found"
    SYNTAX_ERROR = "syntax_error"
    PATH_TRAVERSAL = "path_traversal"
    SYMLINK_SKIPPED = "symlink_skipped"
    FILE_NOT_FOUND = "file_not_found"
    FILE_READ_ERROR = "file_read_error"
    INVALID_LINE = "invalid_line"


@dataclass
class CodeEditRecord:
    file: str
    line: int
    test_id: str
    tier: str
    status: str
    original: str = ""
    patched: str = ""
    reason: str = ""

    @property
    def applied(self) -> bool:
        return self.status == PatchStatus.APPLIED.value

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


# --------------------------------------------------------------------------- #
# Source text and line handling helpers
# --------------------------------------------------------------------------- #
def split_python_lines(text: str) -> List[str]:
    """Split Python source text into lines preserving exact newlines (\\r\\n, \\n, \\r).

    Unlike str.splitlines(), does NOT split on \\f, \\x1c-\\x1e, \\x85, \\u2028, or \\u2029,
    matching Python parser line numbers exactly.
    """
    parts = re.split(r"(\r\n|\r|\n)", text)
    lines: List[str] = []
    for i in range(0, len(parts) - 1, 2):
        lines.append(parts[i] + parts[i + 1])
    if len(parts) % 2 == 1 and parts[-1]:
        lines.append(parts[-1])
    return lines


def byte_col_to_char_col(line: str, byte_offset: int) -> int:
    """Convert UTF-8 byte offset to unicode character index for a line."""
    if byte_offset <= 0:
        return 0
    return len(line.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore"))


def get_node_span(src: str, node: ast.AST) -> Tuple[int, int]:
    """Convert AST node line and column byte offsets to absolute character index span."""
    lines = split_python_lines(src)
    line_starts = [0]
    for l in lines:
        line_starts.append(line_starts[-1] + len(l))

    start_line_idx = node.lineno - 1
    start_line_text = lines[start_line_idx] if 0 <= start_line_idx < len(lines) else ""
    start_char_col = byte_col_to_char_col(start_line_text, node.col_offset)
    start = line_starts[start_line_idx] + start_char_col

    end_lineno = getattr(node, "end_lineno", node.lineno)
    end_line_idx = end_lineno - 1
    end_line_text = lines[end_line_idx] if 0 <= end_line_idx < len(lines) else ""
    end_byte_col = getattr(node, "end_col_offset", node.col_offset)
    end_char_col = byte_col_to_char_col(end_line_text, end_byte_col)
    end = line_starts[end_line_idx] + end_char_col

    return start, end


def format_unified_diff(original: str, patched: str, rel_path: str) -> str:
    """Generate a clean unified diff, properly handling missing trailing newlines."""
    orig_has_nl = original.endswith(("\n", "\r"))
    patched_has_nl = patched.endswith(("\n", "\r"))

    orig_lines = split_python_lines(original)
    patched_lines = split_python_lines(patched)

    norm_orig = [l if l.endswith(("\n", "\r")) else l + "\n" for l in orig_lines]
    norm_patched = [l if l.endswith(("\n", "\r")) else l + "\n" for l in patched_lines]

    diff_lines = list(
        difflib.unified_diff(
            norm_orig,
            norm_patched,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )
    if not diff_lines:
        return ""

    res: List[str] = []
    for i, l in enumerate(diff_lines):
        res.append(l)
        is_last = (i == len(diff_lines) - 1) or (
            i + 1 < len(diff_lines) and diff_lines[i + 1].startswith(("@@", "---"))
        )
        if not orig_has_nl and l.startswith("-") and not l.startswith("---") and (
            is_last or (i + 1 < len(diff_lines) and diff_lines[i + 1].startswith("+"))
        ):
            res.append("\\ No newline at end of file\n")
        elif not patched_has_nl and l.startswith("+") and not l.startswith("+++") and is_last:
            res.append("\\ No newline at end of file\n")
    return "".join(res)


# --------------------------------------------------------------------------- #
# AST Rule Patchers
# --------------------------------------------------------------------------- #
def _patch_b201_flask_debug(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B201: app.run(..., debug=True) -> app.run(..., debug=False)."""
    for kw in call_node.keywords:
        if kw.arg == "debug":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                v_start, v_end = get_node_span(src, kw.value)
                return src[:v_start] + "False" + src[v_end:], ""
    return None, "debug=True argument not found in app.run() call"


def _insert_call_kwarg(src: str, call_node: ast.Call, kwarg_str: str) -> str:
    """Safely insert a keyword argument into an ast.Call node without regex mangling or comment corruption."""
    start, end = get_node_span(src, call_node)
    all_args = sorted(list(call_node.args) + list(call_node.keywords), key=lambda n: (n.lineno, n.col_offset))
    if not all_args:
        call_text = src[start:end]
        paren_idx = call_text.rfind(")")
        if paren_idx != -1:
            return src[: start + paren_idx] + kwarg_str + src[start + paren_idx :]
        return src[: end - 1] + kwarg_str + src[end - 1 :]

    last_arg = all_args[-1]
    _, last_end = get_node_span(src, last_arg)
    between = src[last_end:end]

    # Detect comment in `between`
    hash_idx = between.find("#")
    if hash_idx != -1:
        prefix = between[:hash_idx]
        suffix = between[hash_idx:]
        if "," in prefix:
            comma_idx = prefix.rfind(",")
            new_prefix = prefix[: comma_idx + 1] + " " + kwarg_str + prefix[comma_idx + 1 :]
        else:
            new_prefix = ", " + kwarg_str + " " if prefix.strip() == "" else prefix.rstrip() + ", " + kwarg_str + " "
        return src[:last_end] + new_prefix + suffix + src[end:]
    else:
        paren_idx = between.rfind(")")
        if paren_idx == -1:
            paren_idx = len(between)
        prefix = between[:paren_idx]
        suffix = between[paren_idx:]
        if "," in prefix:
            comma_idx = prefix.rfind(",")
            new_prefix = prefix[: comma_idx + 1] + " " + kwarg_str + prefix[comma_idx + 1 :]
        else:
            new_prefix = prefix + ", " + kwarg_str
        return src[:last_end] + new_prefix + suffix + src[end:]


def _patch_b113_requests_timeout(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B113: requests.get(...) -> requests.get(..., timeout=10)."""
    if any(kw.arg == "timeout" for kw in call_node.keywords):
        return None, "requests call already specifies a timeout parameter"

    new_src = _insert_call_kwarg(src, call_node, "timeout=10")
    return new_src, ""


def _patch_b506_yaml_load(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B506: yaml.load(stream, ...) -> yaml.safe_load(stream)."""
    if not call_node.args:
        return None, "yaml.load() has no stream argument"

    start, end = get_node_span(src, call_node)
    stream_arg = call_node.args[0]
    s_start, s_end = get_node_span(src, stream_arg)
    stream_text = src[s_start:s_end]

    # yaml.safe_load takes only stream; loaders (positional or keyword) are eliminated
    new_call = f"yaml.safe_load({stream_text})"
    return src[:start] + new_call + src[end:], ""


def _patch_b303_hashlib(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B303: hashlib.md5/sha1(...) -> hashlib.sha256(...)."""
    if (
        isinstance(call_node.func, ast.Attribute)
        and call_node.func.attr in ("md5", "sha1")
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id == "hashlib"
    ):
        v_start, v_end = get_node_span(src, call_node.func.value)
        attr_name = call_node.func.attr
        dot_idx = src.find(".", v_end)
        if dot_idx != -1:
            attr_start = src.find(attr_name, dot_idx)
            if attr_start != -1:
                attr_end = attr_start + len(attr_name)
                return src[:attr_start] + "sha256" + src[attr_end:], ""

    return None, "hashlib.md5 or sha1 call pattern not found"


def _patch_b501_verify_true(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B501: requests call verify=False -> verify=True."""
    for kw in call_node.keywords:
        if kw.arg == "verify":
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                v_start, v_end = get_node_span(src, kw.value)
                return src[:v_start] + "True" + src[v_end:], ""
    return None, "verify=False argument not found in request call"


def _patch_b614_torch_load(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B614: torch.load(...) -> torch.load(..., weights_only=True)."""
    if any(kw.arg == "weights_only" for kw in call_node.keywords):
        return None, "torch.load() already specifies weights_only"

    new_src = _insert_call_kwarg(src, call_node, "weights_only=True")
    return new_src, ""


def _patch_b701_jinja2_autoescape(src: str, call_node: ast.Call) -> Tuple[Optional[str], str]:
    """B701: Environment(..., autoescape=False) -> Environment(..., autoescape=True)."""
    for kw in call_node.keywords:
        if kw.arg == "autoescape":
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                v_start, v_end = get_node_span(src, kw.value)
                return src[:v_start] + "True" + src[v_end:], ""
    return None, "autoescape=False argument not found in Jinja2 call"


@dataclass(frozen=True)
class RulePatcher:
    test_id: str
    tier: str  # "mechanical" | "needs_review"
    description: str
    patch_fn: Callable[[str, ast.Call], Tuple[Optional[str], str]]
    call_filter: Callable[[ast.Call], bool]
    postcondition: Optional[Callable[[ast.Call], bool]] = None


def _is_flask_run_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "run"


def _is_requests_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        method = node.func.attr
        if method in {"get", "post", "put", "delete", "patch", "head", "options", "request"}:
            if isinstance(node.func.value, ast.Name) and node.func.value.id in {"requests", "session"}:
                return True
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr in {"requests", "session"}:
                return True
    return False


def _is_requests_or_verify_call(node: ast.Call) -> bool:
    if any(kw.arg == "verify" for kw in node.keywords):
        return True
    return _is_requests_call(node)


def _is_yaml_load_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "load"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "yaml"
    )


def _is_hashlib_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"md5", "sha1"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hashlib"
    )


def _is_torch_load_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "load"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "torch"
    )


def _is_jinja2_autoescape_call(node: ast.Call) -> bool:
    if any(kw.arg == "autoescape" for kw in node.keywords):
        return True
    if isinstance(node.func, ast.Name) and "Environment" in node.func.id:
        return True
    if isinstance(node.func, ast.Attribute) and "Environment" in node.func.attr:
        return True
    return False


def _post_b201(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "debug":
            return isinstance(kw.value, ast.Constant) and kw.value.value is False
    return False


def _post_b113(call: ast.Call) -> bool:
    return any(kw.arg == "timeout" for kw in call.keywords)


def _post_b506(call: ast.Call) -> bool:
    is_safe = (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "safe_load"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "yaml"
    )
    no_loader = not any(kw.arg == "Loader" for kw in call.keywords)
    return is_safe and no_loader


def _post_b303(call: ast.Call) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "sha256"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "hashlib"
    )


def _post_b501(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "verify":
            return isinstance(kw.value, ast.Constant) and kw.value.value is True
    return False


def _post_b614(call: ast.Call) -> bool:
    return any(
        kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def _post_b701(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "autoescape":
            return isinstance(kw.value, ast.Constant) and kw.value.value is True
    return False


# Single authoritative registry of auto-patchable rules
RULE_PATCHERS: Dict[str, RulePatcher] = {
    "B201": RulePatcher(
        test_id="B201",
        tier=PatchTier.MECHANICAL.value,
        description="Disable debug mode in Flask app.run().",
        patch_fn=_patch_b201_flask_debug,
        call_filter=_is_flask_run_call,
        postcondition=_post_b201,
    ),
    "B113": RulePatcher(
        test_id="B113",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Add timeout=10 parameter to requests call.",
        patch_fn=_patch_b113_requests_timeout,
        call_filter=_is_requests_call,
        postcondition=_post_b113,
    ),
    "B506": RulePatcher(
        test_id="B506",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Replace unsafe yaml.load() with yaml.safe_load().",
        patch_fn=_patch_b506_yaml_load,
        call_filter=_is_yaml_load_call,
        postcondition=_post_b506,
    ),
    "B303": RulePatcher(
        test_id="B303",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Replace MD5/SHA1 hash with SHA-256.",
        patch_fn=_patch_b303_hashlib,
        call_filter=_is_hashlib_call,
        postcondition=_post_b303,
    ),
    "B501": RulePatcher(
        test_id="B501",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Enable TLS certificate verification on HTTPS request.",
        patch_fn=_patch_b501_verify_true,
        call_filter=_is_requests_or_verify_call,
        postcondition=_post_b501,
    ),
    "B614": RulePatcher(
        test_id="B614",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Specify weights_only=True in torch.load().",
        patch_fn=_patch_b614_torch_load,
        call_filter=_is_torch_load_call,
        postcondition=_post_b614,
    ),
    "B701": RulePatcher(
        test_id="B701",
        tier=PatchTier.NEEDS_REVIEW.value,
        description="Enable autoescape=True in Jinja2 environment.",
        patch_fn=_patch_b701_jinja2_autoescape,
        call_filter=_is_jinja2_autoescape_call,
        postcondition=_post_b701,
    ),
}


# --------------------------------------------------------------------------- #
# Finding metadata extraction & resolution
# --------------------------------------------------------------------------- #
def _extract_test_id(finding: Union[Finding, Dict[str, Any]]) -> str:
    """Extract Bandit test_id from a Finding object or dictionary."""
    if isinstance(finding, Finding):
        return str((finding.extra or {}).get("test_id") or "").upper()
    if isinstance(finding, dict):
        extra = finding.get("extra") or {}
        if "test_id" in extra:
            return str(extra["test_id"]).upper()
        title = finding.get("title", "")
        if "Bandit " in title:
            parts = title.split("Bandit ", 1)[1].split(":", 1)
            if parts:
                return parts[0].strip().upper()
    return ""


def _extract_line(finding: Union[Finding, Dict[str, Any]]) -> Optional[int]:
    """Safely extract 1-indexed line number from finding."""
    if isinstance(finding, Finding):
        return finding.line
    if isinstance(finding, dict):
        raw_line = finding.get("line")
        try:
            return int(raw_line) if raw_line is not None else None
        except (ValueError, TypeError):
            return None
    return None


def _extract_file(finding: Union[Finding, Dict[str, Any]]) -> str:
    """Extract normalized relative file path from finding."""
    if isinstance(finding, Finding):
        return finding.file
    if isinstance(finding, dict):
        return str(finding.get("file") or "")
    return ""


def can_auto_patch(finding: Union[Finding, Dict[str, Any]]) -> bool:
    """Return True if this finding has an automated code fix available in RULE_PATCHERS."""
    test_id = _extract_test_id(finding)
    return test_id in RULE_PATCHERS


def safe_resolve_target(workspace: Path, rel_f: str) -> Tuple[Optional[Path], str]:
    """Safely resolve rel_f within workspace, guarding against path traversal and symlinks."""
    ws = workspace.resolve()
    raw_str = str(rel_f).strip()

    # Reject absolute paths (POSIX leading slash or Windows drive letters)
    if raw_str.startswith(("/", "\\")) or ":" in raw_str:
        return None, f"Absolute or drive-qualified path rejected: {rel_f}"

    cleaned_p = Path(raw_str)
    if any(p == ".." for p in cleaned_p.parts):
        return None, f"Path traversal rejected: {rel_f}"

    # Walk components with os.lstat BEFORE resolving symlinks
    cur = ws
    for part in cleaned_p.parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode):
                return None, f"Symlink rejected: {cur}"
        except (FileNotFoundError, OSError):
            pass

    # Now resolve target and ensure it remains strictly inside workspace
    target = cur.resolve()
    try:
        target.relative_to(ws)
    except ValueError:
        return None, f"Path escapes workspace: {rel_f}"

    return target, ""


# --------------------------------------------------------------------------- #
# Core Patching Pipeline
# --------------------------------------------------------------------------- #
def patch_file_content(
    content: str,
    findings: List[Union[Finding, Dict[str, Any]]],
    file_rel_path: str = "",
) -> Tuple[str, List[CodeEditRecord]]:
    """Apply rule-based AST patches to file content for all applicable findings.

    Returns (new_content, edit_records). If any patch introduces a SyntaxError,
    the file is left completely untouched and a SYNTAX_ERROR record is generated.
    """
    # Pre-flight syntax check on original content
    try:
        ast.parse(content)
    except SyntaxError as e:
        records = [
            CodeEditRecord(
                file=file_rel_path,
                line=_extract_line(f) or 0,
                test_id=_extract_test_id(f),
                tier="unknown",
                status=PatchStatus.SYNTAX_ERROR.value,
                reason=f"Original source file has syntax error: {e}",
            )
            for f in findings
        ]
        return content, records

    current_content = content
    edits: List[CodeEditRecord] = []

    # Process findings in descending line order so multi-line collapses at line N
    # never invalidate line numbers or AST spans of preceding lines (< N).
    sorted_findings = sorted(findings, key=lambda f: (_extract_line(f) or 0), reverse=True)

    for f in sorted_findings:
        test_id = _extract_test_id(f)
        line_no = _extract_line(f)

        patcher = RULE_PATCHERS.get(test_id)
        if not patcher:
            edits.append(
                CodeEditRecord(
                    file=file_rel_path,
                    line=line_no or 0,
                    test_id=test_id,
                    tier="manual",
                    status=PatchStatus.NOT_AUTO_FIXABLE.value,
                    reason=f"Rule {test_id} is not marked as auto-fixable",
                )
            )
            continue

        if line_no is None or line_no < 1:
            edits.append(
                CodeEditRecord(
                    file=file_rel_path,
                    line=line_no or 0,
                    test_id=test_id,
                    tier=patcher.tier,
                    status=PatchStatus.INVALID_LINE.value,
                    reason=f"Invalid line number {line_no}",
                )
            )
            continue

        # Re-parse current AST to match exact spans
        try:
            tree = ast.parse(current_content)
        except SyntaxError as e:
            edits.append(
                CodeEditRecord(
                    file=file_rel_path,
                    line=line_no,
                    test_id=test_id,
                    tier=patcher.tier,
                    status=PatchStatus.SYNTAX_ERROR.value,
                    reason=f"Unexpected syntax error: {e}",
                )
            )
            continue

        # Collect candidate Call nodes on target line
        candidate_calls: List[ast.Call] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                node_end = getattr(node, "end_lineno", node.lineno)
                if node.lineno <= line_no <= node_end:
                    if patcher.call_filter(node):
                        candidate_calls.append(node)

        # Disambiguate using finding's col_offset if available
        finding_col_byte = None
        if isinstance(f, Finding):
            finding_col_byte = (f.extra or {}).get("col_offset")
        elif isinstance(f, dict):
            finding_col_byte = (f.get("extra") or {}).get("col_offset")
            if finding_col_byte is None:
                finding_col_byte = f.get("col_offset")

        if finding_col_byte is not None and candidate_calls:
            candidate_calls.sort(key=lambda c: abs(c.col_offset - finding_col_byte))

        matching_call = None
        patched_src = None
        patch_reason = ""

        # Try candidate calls; pick the first one that successfully transforms
        for call in candidate_calls:
            res_src, reason = patcher.patch_fn(current_content, call)
            if res_src is not None and res_src != current_content:
                matching_call = call
                patched_src = res_src
                patch_reason = ""
                break
            else:
                patch_reason = reason

        if not matching_call or patched_src is None:
            edits.append(
                CodeEditRecord(
                    file=file_rel_path,
                    line=line_no,
                    test_id=test_id,
                    tier=patcher.tier,
                    status=PatchStatus.PATTERN_NOT_FOUND.value,
                    reason=patch_reason or f"No matching call found for rule {test_id} on line {line_no}",
                )
            )
            continue

        # Safety Net 1: Verify patched source compiles cleanly
        try:
            new_tree = ast.parse(patched_src)
        except SyntaxError as e:
            edits.append(
                CodeEditRecord(
                    file=file_rel_path,
                    line=line_no,
                    test_id=test_id,
                    tier=patcher.tier,
                    status=PatchStatus.SYNTAX_ERROR.value,
                    reason=f"Patched code introduced syntax error: {e}",
                )
            )
            continue

        # Safety Net 2: Verify postcondition (e.g. timeout actually present in AST, not in comment)
        if patcher.postcondition is not None:
            passed_post = False
            for node in ast.walk(new_tree):
                if isinstance(node, ast.Call):
                    if patcher.postcondition(node):
                        passed_post = True
                        break
            if not passed_post:
                edits.append(
                    CodeEditRecord(
                        file=file_rel_path,
                        line=line_no,
                        test_id=test_id,
                        tier=patcher.tier,
                        status=PatchStatus.PATTERN_NOT_FOUND.value,
                        reason=f"Postcondition failed for rule {test_id}: fix was not properly reflected in AST",
                    )
                )
                continue

        # Extract before/after line representation for reporting
        orig_lines = split_python_lines(current_content)
        new_lines = split_python_lines(patched_src)
        orig_line_str = orig_lines[line_no - 1].rstrip("\r\n") if line_no <= len(orig_lines) else ""
        new_line_str = new_lines[line_no - 1].rstrip("\r\n") if line_no <= len(new_lines) else ""

        current_content = patched_src
        edits.append(
            CodeEditRecord(
                file=file_rel_path,
                line=line_no,
                test_id=test_id,
                tier=patcher.tier,
                status=PatchStatus.APPLIED.value,
                original=orig_line_str,
                patched=new_line_str,
                reason="",
            )
        )

    # Sort edits in ascending line order for readable, deterministic reporting
    edits.sort(key=lambda e: e.line)
    return current_content, edits


def generate_file_patch(
    file_rel_path: str,
    original_content: str,
    findings: List[Union[Finding, Dict[str, Any]]],
) -> Tuple[str, str, List[CodeEditRecord]]:
    """Patch file content and generate a unified diff."""
    new_content, edits = patch_file_content(original_content, findings, file_rel_path)
    diff = ""
    if new_content != original_content:
        diff = format_unified_diff(original_content, new_content, file_rel_path)
    return new_content, diff, edits


def apply_code_patches(
    repo_path: Union[str, Path],
    findings: List[Union[Finding, Dict[str, Any]]],
    dest_path: Optional[Union[str, Path]] = None,
) -> CodePatchResult:
    """Apply verified code patches to a workspace copy of the repo, never touching the original."""
    repo = Path(repo_path).resolve()
    if dest_path:
        dest = Path(dest_path).resolve()
    else:
        # Use a unique destination to prevent concurrent collision
        dest = repo.parent / "remediation_out" / f"code_ws_{uuid.uuid4().hex[:8]}"

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
        target_path, err = safe_resolve_target(workspace, rel_f)
        if not target_path or not target_path.exists():
            status = PatchStatus.SYMLINK_SKIPPED.value if "Symlink" in err else (
                PatchStatus.PATH_TRAVERSAL.value if "escapes" in err or "rejected" in err else PatchStatus.FILE_NOT_FOUND.value
            )
            for f in file_findings:
                all_edits.append(
                    CodeEditRecord(
                        file=rel_f,
                        line=_extract_line(f) or 0,
                        test_id=_extract_test_id(f),
                        tier="unknown",
                        status=status,
                        reason=err or f"File not found in workspace: {rel_f}",
                    )
                )
            continue

        # Detect encoding using tokenize.open, then read with newline="" to preserve CRLF
        try:
            with tokenize.open(target_path) as tok_stream:
                encoding = tok_stream.encoding
            with open(target_path, "r", encoding=encoding, newline="") as f_in:
                original_content = f_in.read()
        except Exception as e:
            for f in file_findings:
                all_edits.append(
                    CodeEditRecord(
                        file=rel_f,
                        line=_extract_line(f) or 0,
                        test_id=_extract_test_id(f),
                        tier="unknown",
                        status=PatchStatus.FILE_READ_ERROR.value,
                        reason=f"Cannot read file with encoding detection: {e}",
                    )
                )
            continue

        new_content, diff, edits = generate_file_patch(rel_f, original_content, file_findings)
        all_edits.extend(edits)

        if diff:
            # Write back using exact same encoding and exact newline style
            with open(target_path, "w", encoding=encoding, newline="") as f_out:
                f_out.write(new_content)
            all_diffs.append(diff)

    full_diff = "\n".join(all_diffs)
    return CodePatchResult(workspace=workspace, diff=full_diff, edits=all_edits)


def patch_single_snippet(code: str, test_id: str, line_no: int = 1) -> Tuple[Optional[str], str]:
    """Helper to patch a single code snippet string using the AST patcher."""
    patched, edits = patch_file_content(code, [{"line": line_no, "extra": {"test_id": test_id}}])
    if edits and edits[0].applied:
        return patched, ""
    reason = edits[0].reason if edits else "No edits applied"
    return None, reason

