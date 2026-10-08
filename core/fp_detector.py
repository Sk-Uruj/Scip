"""Automated false-positive heuristics and contextual safety detectors.

Analyzes finding context, file path, AST characteristics, and evidence snippets
to identify patterns that static analyzers flag as vulnerabilities but which are
safe-by-design or protocol-mandated, such as:
  1. RFC 7232 AWS S3 / COS ETag checksums (MD5 used non-cryptographically)
  2. Offline DDL database migrations (ALTER TABLE / PRAGMA) and whitelisted column identifiers
  3. Database initialization seed credentials and demo fixtures (CWE-1188)
  4. Mock test fixtures and dummy credentials in unit/integration test suites
"""
from __future__ import annotations

import ast
import hashlib
import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple

from core.finding import Finding
from core.risk_graph import is_test_path
from engines.blast_radius_engine import find_enclosing_function

log = logging.getLogger("scip.fp_detector")

ETAG_PATTERNS = [
    re.compile(r"\betag\b", re.IGNORECASE),
    re.compile(r"\bcompute_etag\b", re.IGNORECASE),
    re.compile(r"\bcalculate_etag\b", re.IGNORECASE),
]

DDL_SQL_PATTERNS = [
    re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bCREATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bPRAGMA\b", re.IGNORECASE),
]

SEED_FILE_PATTERNS = [
    re.compile(r"\binit_db\.py$", re.IGNORECASE),
    re.compile(r"\bseed.*\.py$", re.IGNORECASE),
    re.compile(r"\bfixtures?.*\.py$", re.IGNORECASE),
    re.compile(r"\bdb_init\.py$", re.IGNORECASE),
]

SEED_VAR_PATTERNS = [
    re.compile(r"\bSEED_", re.IGNORECASE),
    re.compile(r"\bDEMO_", re.IGNORECASE),
    re.compile(r"\bFIXTURE_", re.IGNORECASE),
    re.compile(r"\bDEFAULT_USERS?\b", re.IGNORECASE),
    re.compile(r"\bSAMPLE_ACCOUNTS?\b", re.IGNORECASE),
]

PROD_NEGATIVE_PATTERN = re.compile(r"(?:\b|_)(prod|production|live|staging|stage|stg|release)(?:\b|_)", re.IGNORECASE)
DEV_POSITIVE_PATTERN = re.compile(r"(?:\b|_)(dev|development|test|mock|demo|local|sample|example)(?:\b|_)", re.IGNORECASE)

DEMO_WORDLIST = {
    "alice123", "bob123", "bob456", "carol789", "admin", "password", "changeme",
    "testpass", "demo", "dev", "123456", "secret", "root", "guest", "default", "test"
}

GATED_SEED_PATTERNS = [
    re.compile(r"(--seed|if\s+DEBUG|if\s+.*env.*(dev|test)|if\s+not\s+.*count|SELECT\s+COUNT|os\.getenv\(['\"](DEBUG|ENV)['\"]\))", re.IGNORECASE)
]

CI_AND_CONFIG_FILES = (
    "docker-compose", ".env", "jenkinsfile", ".gitlab-ci", "workflow", "config.", "settings."
)

SECURITY_PRNG_PATTERNS = [
    re.compile(r"(?:\b|_)(token|secret|session|csrf|auth|nonce|salt|jwt|api_key|apikey|otp|pin|password|passwd|reset|verify|code|key)(?:\b|_)", re.IGNORECASE),
]

REF_ID_PATTERNS = [
    re.compile(r"(?:\b|_)(id|ref|ref_id|payment_id|invoice_id|order_id|tx_id|display_id|tracking|suffix|filename)(?:\b|_)", re.IGNORECASE),
    re.compile(r"['\"][A-Z]+-['\"]"),
]

PROVIDER_KEY_PREFIXES = (
    "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "glpat-", "slack-", "xoxb-", "xoxp-", "sk_live_", "sk_test_",
    "sq0atp-", "sq0csp-", "access_token$", "PRIVATE KEY"
)

SKIP_DIRS = {
    ".git", ".svn", ".hg", "venv", ".venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".tox", ".eggs", "dist", "build",
    ".idea", ".vscode"
}


def _get_repo_prod_files(repo_path: str) -> List[Tuple[str, str]]:
    """Index non-fixture production code and CI configs in repo, skipping virtualenvs and git."""
    contents: List[Tuple[str, str]] = []
    repo = Path(repo_path).resolve()
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            low_fn = fn.lower()
            rel_p = os.path.relpath(os.path.join(root, fn), repo).replace("\\", "/").removeprefix("./")
            if any(p.search(fn) for p in SEED_FILE_PATTERNS) or rel_p.startswith("seeds/") or "/seeds/" in rel_p or rel_p.startswith("fixtures/") or "/fixtures/" in rel_p or is_test_path(rel_p):
                continue
            if low_fn.endswith((".py", ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".sh")) or any(c in low_fn for c in CI_AND_CONFIG_FILES):
                try:
                    with open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore") as fh:
                        contents.append((rel_p, fh.read()))
                except Exception:
                    pass
    return contents


def _get_enclosing_block_text(file_lines: List[str], line_no: Optional[int], full_path: Optional[str]) -> str:
    """Extract source text for the enclosing function or conditional block."""
    if not file_lines:
        return ""
    if not line_no:
        return "".join(file_lines[:30])

    if full_path and os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                tree = ast.parse(fh.read(), filename=full_path)
            smallest_node = None
            smallest_span = float("inf")
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.If)):
                    start = getattr(node, "lineno", 0)
                    end = getattr(node, "end_lineno", start)
                    if start <= line_no <= end:
                        span = end - start
                        if span < smallest_span:
                            smallest_span = span
                            smallest_node = node
            if smallest_node:
                s_idx = max(0, smallest_node.lineno - 1)
                e_idx = min(len(file_lines), getattr(smallest_node, "end_lineno", line_no))
                return "".join(file_lines[s_idx:e_idx])
        except Exception:
            pass

    # Fallback to local window around line_no
    s_idx = max(0, line_no - 15)
    e_idx = min(len(file_lines), line_no + 5)
    return "".join(file_lines[s_idx:e_idx])


def check_ast_sql_variable_safety(
    file_path: Optional[str],
    line_no: Optional[int],
    evidence: str
) -> bool:
    """Resolve SQL interpolated variables using AST backward walk.
    
    A literal, literal tuple/dict lookup, or enum member evaluates as safe (FP).
    Any external/request input or unresolved variable evaluates as unsafe (not FP).
    """
    code_text = ""
    target_line = line_no
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                code_text = fh.read()
        except Exception:
            code_text = ""

    if not code_text and evidence:
        code_text = evidence
        target_line = 1

    if not code_text:
        return False

    try:
        tree = ast.parse(code_text)
    except Exception:
        try:
            tree = ast.parse(f"def _dummy():\n    {code_text}")
            target_line = 2
        except Exception:
            return False

    # Find candidate SQL formatting or execute nodes
    candidate_nodes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.JoinedStr, ast.Call, ast.BinOp)):
            lineno = getattr(node, "lineno", None)
            if target_line is not None and lineno is not None:
                if abs(lineno - target_line) <= 4:
                    candidate_nodes.append(node)
            else:
                candidate_nodes.append(node)

    if not candidate_nodes:
        if not re.search(r"\{|\%s|\%d|\.format\(", evidence):
            return True
        return False

    sql_node = None
    for n in candidate_nodes:
        if isinstance(n, ast.JoinedStr):
            sql_node = n
            break
        elif isinstance(n, ast.Call) and getattr(getattr(n, "func", None), "attr", "") == "execute":
            sql_node = n
            break
    if not sql_node:
        sql_node = candidate_nodes[0]

    variables_to_check: List[Tuple[str, int]] = []

    if isinstance(sql_node, ast.JoinedStr):
        for val in sql_node.values:
            if isinstance(val, ast.FormattedValue):
                for sub in ast.walk(val.value):
                    if isinstance(sub, ast.Name):
                        variables_to_check.append((sub.id, getattr(val, "lineno", target_line or 1)))
    elif isinstance(sql_node, ast.Call):
        for arg in sql_node.args:
            if isinstance(arg, ast.JoinedStr):
                for val in arg.values:
                    if isinstance(val, ast.FormattedValue):
                        for sub in ast.walk(val.value):
                            if isinstance(sub, ast.Name):
                                variables_to_check.append((sub.id, getattr(val, "lineno", target_line or 1)))
            elif isinstance(arg, ast.Call) and getattr(getattr(arg, "func", None), "attr", "") == "format":
                for f_arg in arg.args:
                    for sub in ast.walk(f_arg):
                        if isinstance(sub, ast.Name):
                            variables_to_check.append((sub.id, getattr(f_arg, "lineno", target_line or 1)))
    elif isinstance(sql_node, ast.BinOp) and isinstance(sql_node.op, ast.Mod):
        for sub in ast.walk(sql_node.right):
            if isinstance(sub, ast.Name):
                variables_to_check.append((sub.id, getattr(sub, "lineno", target_line or 1)))

    if not variables_to_check:
        return True

    def _is_constant_or_seq_of_constants(elem: ast.AST) -> bool:
        if isinstance(elem, ast.Constant):
            return True
        if isinstance(elem, ast.Name):
            return elem.id.isupper()
        if isinstance(elem, (ast.List, ast.Tuple, ast.Set)):
            return all(_is_constant_or_seq_of_constants(x) for x in elem.elts)
        return False

    def _is_var_safe(v_name: str, use_line: int, visited: Set[str]) -> bool:
        if v_name in visited:
            return False
        visited.add(v_name)

        found_def = None
        best_line = -1
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.For)):
                node_line = getattr(node, "lineno", 0)
                if node_line <= use_line and node_line >= best_line:
                    is_match = False
                    if isinstance(node, ast.Assign):
                        for t in node.targets:
                            for sub in ast.walk(t):
                                if isinstance(sub, ast.Name) and sub.id == v_name:
                                    is_match = True
                    elif isinstance(node, ast.AnnAssign):
                        if isinstance(node.target, ast.Name) and node.target.id == v_name:
                            is_match = True
                    elif isinstance(node, ast.For):
                        for sub in ast.walk(node.target):
                            if isinstance(sub, ast.Name) and sub.id == v_name:
                                is_match = True
                    if is_match:
                        found_def = (node, node_line)
                        best_line = node_line

        if not found_def:
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        as_name = alias.asname or alias.name
                        if as_name == v_name:
                            return True
            return False

        def_node, def_line = found_def

        if isinstance(def_node, ast.Assign):
            return _eval_expr_safety(def_node.value, def_line, visited)
        elif isinstance(def_node, ast.AnnAssign):
            if def_node.value:
                return _eval_expr_safety(def_node.value, def_line, visited)
            return False
        elif isinstance(def_node, ast.For):
            return _eval_iter_safety(def_node.iter, def_line, visited)
        return False

    def _eval_expr_safety(expr: ast.AST, cur_line: int, visited: Set[str]) -> bool:
        if isinstance(expr, ast.Constant):
            return True
        elif isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    for sub in ast.walk(v.value):
                        if isinstance(sub, ast.Name):
                            if not _is_var_safe(sub.id, cur_line, visited.copy()):
                                return False
            return True
        elif isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name):
                val_name = expr.value.id
                if val_name.isupper() or val_name[0].isupper() or "Enum" in val_name:
                    return True
            elif isinstance(expr.value, ast.Attribute):
                return True
            return False
        elif isinstance(expr, ast.Subscript):
            if isinstance(expr.value, ast.Dict):
                return all(isinstance(v, ast.Constant) for v in expr.value.values)
            elif isinstance(expr.value, (ast.List, ast.Tuple)):
                return all(_is_constant_or_seq_of_constants(elt) for elt in expr.value.elts)
            elif isinstance(expr.value, ast.Name):
                return _is_var_safe(expr.value.id, cur_line, visited.copy())
            return False
        elif isinstance(expr, ast.Dict):
            return all(isinstance(v, ast.Constant) for v in expr.values)
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return all(_is_constant_or_seq_of_constants(elt) for elt in expr.elts)
        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute):
                if expr.func.attr in ("lower", "upper", "strip"):
                    return _eval_expr_safety(expr.func.value, cur_line, visited)
                elif expr.func.attr == "get" and isinstance(expr.func.value, ast.Name):
                    return _is_var_safe(expr.func.value.id, cur_line, visited.copy())
            return False
        elif isinstance(expr, ast.Name):
            return _is_var_safe(expr.id, cur_line, visited.copy())
        return False

    def _eval_iter_safety(iter_expr: ast.AST, cur_line: int, visited: Set[str]) -> bool:
        if isinstance(iter_expr, (ast.List, ast.Tuple)):
            return all(_is_constant_or_seq_of_constants(elt) for elt in iter_expr.elts)
        elif isinstance(iter_expr, ast.Name):
            return _is_var_safe(iter_expr.id, cur_line, visited.copy())
        return False

    for var_name, var_line in variables_to_check:
        if not _is_var_safe(var_name, var_line, set()):
            return False

    return True


def is_provider_format_secret(f: Finding, line_text: str = "") -> bool:
    """Determine whether secret Finding is a provider-formatted key rather than generic password."""
    evidence = f.evidence or ""
    title = (f.title or "").lower()
    check_id = (f.extra.get("check_id") or "").lower()
    combined = f"{evidence} {line_text} {title} {check_id}"

    if any(p in combined for p in PROVIDER_KEY_PREFIXES):
        return True
    if any(k in title or k in check_id for k in ("aws", "github", "stripe", "slack", "private_key", "bearer")):
        return True
    if f.extra.get("is_provider_token") is True or bool(f.extra.get("provider_prefix")):
        return True
    return False


def _detect_single_finding_fp(
    f: Finding,
    repo_path: Optional[str],
    prod_files: Optional[List[Tuple[str, str]]]
) -> None:
    """Evaluate a single finding for false-positive indicators."""
    evidence = f.evidence or ""
    title = f.title or ""
    desc = f.description or ""
    combined_text = f"{title} {desc} {evidence}"

    norm_file = (f.file or "").replace("\\", "/").removeprefix("./")
    full_path = None
    enclosing_func = None
    file_lines: List[str] = []

    if repo_path and f.file:
        full_path = os.path.join(str(repo_path), norm_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    file_lines = fh.readlines()
            except Exception:
                pass
            if f.line:
                enclosing_func = find_enclosing_function(full_path, f.line)

    line_text = ""
    if file_lines and f.line and 1 <= f.line <= len(file_lines):
        line_text = file_lines[f.line - 1]
    else:
        line_text = evidence

    # 1. Test suite mock passwords / secret fixtures
    # Exempt provider-format keys (e.g. AKIA...) and damp only generic passwords
    if is_test_path(f.file) or f.exposure == "TEST":
        if f.cwe in ("CWE-259", "CWE-798") or f.engine in ("secrets", "bandit"):
            if not is_provider_format_secret(f, line_text):
                f.fp_likelihood = "HIGH"
                f.fp_reason = "Mock test credential in test suite"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                return

    # 2. Database bootstrap seed credentials / demo fixtures (CWE-1188) with mandatory env and cross guards
    is_seed_file = (
        any(p.search(norm_file) for p in SEED_FILE_PATTERNS)
        or norm_file.startswith("seeds/") or "/seeds/" in norm_file
        or norm_file.startswith("fixtures/") or "/fixtures/" in norm_file
    )
    is_credential = (
        f.cwe in ("CWE-259", "CWE-798", "CWE-1188")
        or f.engine == "secrets"
        or (f.engine == "bandit" and (f.cwe in ("CWE-259", "CWE-798") or any(b in title for b in ("B105", "B106", "B107"))))
    )

    if is_seed_file and is_credential:
        matches_seed_var = any(p.search(evidence) for p in SEED_VAR_PATTERNS)
        if not matches_seed_var and file_lines and f.line:
            start_l = max(0, f.line - 15)
            end_l = min(len(file_lines), f.line + 5)
            window = "".join(file_lines[start_l:end_l])
            matches_seed_var = any(p.search(window) for p in SEED_VAR_PATTERNS)

        # Guard 1: Environment guard - Fail-closed: Must have positive dev signal AND no negative prod/staging signal
        search_text = f"{line_text} {evidence} {f.extra.get('variable', '')}"
        has_dev_signal = bool(DEV_POSITIVE_PATTERN.search(search_text))
        has_prod_signal = bool(PROD_NEGATIVE_PATTERN.search(search_text))
        g_env = has_dev_signal and not has_prod_signal

        # Guard 2: Demo Pattern guard - Strictly verify against demo wordlist and patterns
        val_candidates = re.findall(
            r"(?:password|passwd|secret|token|api_key|key|pw)[\"'\s:=]+[\"']([^\"']+)[\"']",
            line_text + " " + evidence,
            re.IGNORECASE,
        )
        if not val_candidates:
            val_candidates = (
                re.findall(r":\s*[\"']([^\"']+)[\"']", line_text + " " + evidence)
                or re.findall(r"=\s*[\"']([^\"']+)[\"']", line_text + " " + evidence)
            )

        g_demo = False
        for cand in val_candidates:
            cand_lower = cand.lower().strip()
            if cand_lower in DEMO_WORDLIST or re.match(r"^[a-zA-Z]+123$", cand_lower) or re.match(r"^test[a-zA-Z0-9]*$", cand_lower):
                g_demo = True
                break

        # Guard 3: Gating guard - Scoped strictly to the enclosing seed block/function
        is_pure_fixture_dir = (
            norm_file.startswith("seeds/") or "/seeds/" in norm_file
            or norm_file.startswith("fixtures/") or "/fixtures/" in norm_file
            or norm_file.startswith("tests/") or "/tests/" in norm_file
        )
        if is_pure_fixture_dir:
            g_gate = True
        else:
            block_text = _get_enclosing_block_text(file_lines, f.line, full_path)
            g_gate = any(p.search(block_text) for p in GATED_SEED_PATTERNS)

        # Guard 4: Cross-file guard - In-memory secret value search across production files
        valid_candidates = [
            v.strip() for v in val_candidates
            if len(v.strip()) >= 6 and not v.strip().startswith("{") and not v.strip().endswith("}")
        ]

        if not valid_candidates:
            # Fails closed if candidate secret value is missing or shorter than 6 characters
            g_cross = False
        else:
            in_prod = False
            if prod_files:
                for rel_p, content in prod_files:
                    if rel_p == norm_file:
                        continue
                    for cand in valid_candidates:
                        if cand in content:
                            in_prod = True
                            break
                    if in_prod:
                        break
            g_cross = not in_prod

        guards_passed = sum(1 for g in (g_env, g_demo, g_gate, g_cross) if g)

        # Environment and cross-file checks are strictly mandatory
        required = g_env and g_cross
        if (matches_seed_var or is_seed_file):
            if required and g_demo and g_gate:
                f.fp_likelihood = "HIGH"
                f.fp_reason = "Database bootstrap seed credentials / demo fixture (all 4 guards passed)"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                f.extra["seed_classification"] = "SEED"
                f.extra["damping_multiplier"] = 0.20
                f.extra["guard_note"] = f"Guarded seed fixture (4/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"
                return
            elif required and (g_demo or g_gate):
                f.fp_likelihood = "MEDIUM"
                f.fp_reason = "Database bootstrap fixture (mild damping: 3/4 guards passed)"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                f.extra["seed_classification"] = "SEED"
                f.extra["damping_multiplier"] = 0.60
                f.extra["guard_note"] = f"Partially guarded seed fixture (3/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"
                return
            else:
                f.extra["seed_classification"] = "NOT_SEED"
                f.extra["damping_multiplier"] = 1.0
                f.extra["guard_note"] = f"Unguarded credential ({guards_passed}/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"

    # 3. Protocol-mandated S3 ETags (RFC 7232 MD5 checksum)
    # Require weak-hash finding (B324, CWE-327/328) AND etag signal in enclosing function, nearby code, or description.
    is_weak_hash = (
        f.cwe in ("CWE-327", "CWE-328")
        or "B324" in (f.title or "")
        or "B324" in (getattr(f, "id", "") or "")
        or (f.engine in ("bandit", "crypto") and any(h in (f.title or "").lower() or h in (f.description or "").lower() for h in ("md5", "sha1", "hash")))
    )
    if is_weak_hash:
        matches_etag_func = bool(enclosing_func and any(p.search(enclosing_func) for p in ETAG_PATTERNS))
        nearby_lines = ""
        if file_lines and f.line:
            s_idx = max(0, f.line - 10)
            e_idx = min(len(file_lines), f.line + 10)
            nearby_lines = "".join(file_lines[s_idx:e_idx])
        matches_etag_code = any(p.search(nearby_lines) for p in ETAG_PATTERNS) or any(p.search(evidence) for p in ETAG_PATTERNS)
        matches_etag_text = any(p.search(f.description or "") for p in ETAG_PATTERNS) or any(p.search(f.title or "") for p in ETAG_PATTERNS)

        if matches_etag_func or matches_etag_code or matches_etag_text:
            f.fp_likelihood = "HIGH"
            f.fp_reason = "RFC 7232 AWS S3 ETag compliance (non-cryptographic checksum)"
            f.extra["fp_likelihood"] = f.fp_likelihood
            f.extra["fp_reason"] = f.fp_reason
            return

    # 4. Dynamic SQL: AST backward walk verification
    if f.cwe == "CWE-89" or "sql" in combined_text.lower() or "B608" in (f.title or ""):
        is_safe = check_ast_sql_variable_safety(full_path, f.line, evidence)
        if is_safe:
            is_ddl = any(p.search(evidence) for p in DDL_SQL_PATTERNS)
            f.fp_likelihood = "HIGH"
            f.fp_reason = "DDL schema migration with static column definitions" if is_ddl else "Dynamic identifier whitelisted from internal constant/enum"
            f.extra["fp_likelihood"] = f.fp_likelihood
            f.extra["fp_reason"] = f.fp_reason
            return

    # 5. Weak PRNG (Bandit B311 / CWE-330): Distinguish Security Primitives from Reference IDs
    if f.cwe == "CWE-330" or "B311" in (f.title or ""):
        context_str = f"{f.title} {enclosing_func or ''} {evidence} {f.description or ''}"
        is_sec = any(p.search(context_str) for p in SECURITY_PRNG_PATTERNS)
        is_ref = any(p.search(context_str) for p in REF_ID_PATTERNS)

        # Security patterns strictly take precedence on any overlap
        if is_sec:
            f.extra["is_security_token"] = True
            f.extra["prng_context"] = "security_sensitive"
            f.extra["is_ref_id"] = False
        elif is_ref:
            f.extra["is_ref_id"] = True
            f.extra["prng_context"] = "reference_id"
            if not f.title.startswith("[REF-ID]"):
                f.title = f"[REF-ID] {f.title}"
            f.fix_hint = "For transaction reference IDs, standard PRNG may be acceptable, but use secrets.choice or uuid4 to prevent reference enumeration/prediction."


def detect_false_positives(findings: List[Finding], repo_path: Optional[str] = None) -> List[Finding]:
    """Inspect findings and tag high-confidence false positive and seed patterns."""
    prod_files: Optional[List[Tuple[str, str]]] = None
    if repo_path and os.path.isdir(repo_path):
        try:
            prod_files = _get_repo_prod_files(repo_path)
        except Exception as exc:
            log.warning("Failed pre-indexing repository production files: %s", exc)

    for f in findings:
        try:
            _detect_single_finding_fp(f, repo_path, prod_files)
        except Exception as exc:
            loc = f"{getattr(f, 'file', '')}:{getattr(f, 'line', '')}"
            log.warning("False-positive evaluation failed for finding '%s' at %s: %s", getattr(f, "title", "finding"), loc, exc)
            continue

    return findings
