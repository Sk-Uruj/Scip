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

NEGATIVE_GATE_PATTERNS = [
    re.compile(r"(!=\s*[\"'](?:dev|test|local)[\"'])", re.IGNORECASE),
    re.compile(r"(not\s+in\s*[\(\[][^)]*[\"'](?:dev|test|local)[\"'])", re.IGNORECASE),
    re.compile(r"(\bif\s+not\s+.*(?:DEBUG|debug|ENV|env)\b)", re.IGNORECASE),
    re.compile(r"((?:DEBUG|debug)\s*(?:==|\bis\b)\s*False\b)", re.IGNORECASE),
    re.compile(r"((?:DEBUG|debug)\s*!=\s*(?:1|True|true)\b)", re.IGNORECASE),
    re.compile(r"(os\.(?:environ\.get|getenv)\([\"'](?:DEBUG|ENV)[\"']\)\s*!=\s*[\"']?(?:1|true|dev|test)[\"']?)", re.IGNORECASE),
]

POSITIVE_GATE_PATTERNS = [
    re.compile(r"--seed\b", re.IGNORECASE),
    re.compile(r"\bif\s+(?:DEBUG|debug)\b", re.IGNORECASE),
    re.compile(r"\bif\s+.*env.*(?:==|\bin\b)\s*[\"'](dev|test|local|sample)[\"']", re.IGNORECASE),
    re.compile(r"os\.(?:environ\.get|getenv)\([\"'](DEBUG|ENV)[\"']\)", re.IGNORECASE),
    re.compile(r"SELECT\s+COUNT\b", re.IGNORECASE),
    re.compile(r"\bif\s+not\s+.*count\b", re.IGNORECASE),
]


def _is_dev_gated(block_text: str) -> bool:
    """Evaluate whether an enclosing block is gated for dev/seed execution with correct polarity."""
    if not block_text:
        return False
    # Negative polarity checks immediately disqualify the gate (e.g. if env != "dev" means prod!)
    if any(p.search(block_text) for p in NEGATIVE_GATE_PATTERNS):
        return False
    return any(p.search(block_text) for p in POSITIVE_GATE_PATTERNS)


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


SQL_KEYWORDS = {
    "select", "insert", "update", "delete", "alter", "create", "drop",
    "pragma", "from", "where", "table", "into", "values", "set", "join"
}


def _is_log_or_print_call(call_node: ast.Call) -> bool:
    """Check if a Call node is a logging or print statement."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id.lower() in ("print", "log", "logger", "logging", "debug", "info", "warn", "warning", "error", "critical")
    elif isinstance(func, ast.Attribute):
        if func.attr.lower() in ("print", "log", "logger", "logging", "debug", "info", "warn", "warning", "error", "critical"):
            return True
        if isinstance(func.value, ast.Name) and func.value.id.lower() in ("log", "logger", "logging", "sys"):
            return True
    return False


def _contains_sql_keyword(text: str) -> bool:
    """Check if a string contains any SQL keyword as a word token."""
    tokens = set(re.findall(r"[a-zA-Z]+", text.lower()))
    return bool(tokens & SQL_KEYWORDS)


def check_ast_sql_variable_safety(
    file_path: Optional[str],
    line_no: Optional[int],
    evidence: str
) -> bool:
    """Resolve SQL interpolated variables using full AST semantic evaluation.

    Fail-closed policy:
    - Pure string constants, static DDL, whitelisted literal dict lookups, or Enums evaluate as safe (FP).
    - Unresolved variables, string concatenations with external input, .format(kw=val),
      request attributes (e.g. request.args['col'], flask.request.args, request.json.column),
      or imported helper objects evaluate as unsafe (not FP).
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

    # 1. Identify the SQL query node in AST
    db_methods = {"execute", "executemany", "execute_sql", "raw", "cursor_execute"}
    candidate_executes: List[ast.Call] = []
    candidate_sql_nodes: List[Tuple[int, ast.AST]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr.lower() in db_methods:
            if node.args:
                lineno = getattr(node, "lineno", None)
                dist = abs(lineno - target_line) if (target_line and lineno) else 0
                if dist <= 6:
                    candidate_executes.append(node)

        elif isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
            if isinstance(node, ast.Call) and _is_log_or_print_call(node):
                continue
            lineno = getattr(node, "lineno", None)
            dist = abs(lineno - target_line) if (target_line and lineno) else 0
            if dist <= 6:
                has_sql = False
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        if _contains_sql_keyword(sub.value):
                            has_sql = True
                            break
                prio = dist if has_sql else (dist + 10)
                candidate_sql_nodes.append((prio, node))

    target_sql_expr: Optional[ast.AST] = None
    if candidate_executes:
        candidate_executes.sort(key=lambda c: abs((getattr(c, "lineno", 0) or 0) - (target_line or 0)))
        target_sql_expr = candidate_executes[0].args[0]
    elif candidate_sql_nodes:
        candidate_sql_nodes.sort(key=lambda item: item[0])
        target_sql_expr = candidate_sql_nodes[0][1]

    if target_sql_expr is None:
        if re.search(r"\{|\%s|\%d|\.format\(|\+", evidence):
            return False
        return False

    # 2. Fully evaluate safety of target_sql_expr
    def _eval_expr_safety(expr: ast.AST, cur_line: int, visited: Set[str]) -> bool:
        if isinstance(expr, ast.Constant):
            return True

        elif isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    if not _eval_expr_safety(v.value, getattr(v, "lineno", cur_line), visited):
                        return False
            return True

        elif isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Add):
                return (_eval_expr_safety(expr.left, cur_line, visited)
                        and _eval_expr_safety(expr.right, cur_line, visited))
            elif isinstance(expr.op, ast.Mod):
                if isinstance(expr.right, (ast.Tuple, ast.List)):
                    return all(_eval_expr_safety(e, cur_line, visited) for e in expr.right.elts)
                return _eval_expr_safety(expr.right, cur_line, visited)
            return False

        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute):
                method = expr.func.attr
                if method == "format":
                    if not _eval_expr_safety(expr.func.value, cur_line, visited):
                        return False
                    if not all(_eval_expr_safety(a, cur_line, visited) for a in expr.args):
                        return False
                    if not all(_eval_expr_safety(kw.value, cur_line, visited) for kw in expr.keywords):
                        return False
                    return True
                elif method in ("lower", "upper", "strip", "lstrip", "rstrip"):
                    return _eval_expr_safety(expr.func.value, cur_line, visited)
                elif method == "get":
                    if not _eval_expr_safety(expr.func.value, cur_line, visited):
                        return False
                    if len(expr.args) > 1 and not _eval_expr_safety(expr.args[1], cur_line, visited):
                        return False
                    return True
            return False

        elif isinstance(expr, ast.Attribute):
            chain = []
            curr = expr
            while isinstance(curr, ast.Attribute):
                chain.append(curr.attr.lower())
                curr = curr.value
            if isinstance(curr, ast.Name):
                chain.append(curr.id.lower())
            
            if any(k in chain for k in ("request", "req", "params", "args", "query", "json", "data", "headers", "cookies", "flask", "django")):
                return False

            if isinstance(curr, ast.Name):
                root_id = curr.id
                if root_id.isupper() or root_id.endswith("Enum") or (root_id[0].isupper() and expr.attr.isupper()):
                    return True
            return False

        elif isinstance(expr, ast.Subscript):
            if isinstance(expr.value, ast.Dict):
                return all(isinstance(v, ast.Constant) for v in expr.value.values)
            elif isinstance(expr.value, (ast.List, ast.Tuple)):
                return all(isinstance(e, ast.Constant) for e in expr.value.elts)
            elif isinstance(expr.value, ast.Name):
                return _eval_var_safety(expr.value.id, cur_line, visited.copy(), require_container_constants=True)
            return False

        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return all(_eval_expr_safety(e, cur_line, visited) for e in expr.elts)

        elif isinstance(expr, ast.Dict):
            return all(_eval_expr_safety(v, cur_line, visited) for v in expr.values)

        elif isinstance(expr, ast.Name):
            return _eval_var_safety(expr.id, cur_line, visited.copy())

        return False

    def _eval_var_safety(v_name: str, use_line: int, visited: Set[str], require_container_constants: bool = False) -> bool:
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
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        for sub in ast.walk(t):
                            if isinstance(sub, ast.Name) and sub.id == v_name:
                                found_def = (node, getattr(node, "lineno", 0))
                                break
                    if found_def:
                        break

        if not found_def:
            # FAIL-CLOSED: Imported names or function parameters are UNTRUSTED
            return False

        def_node, def_line = found_def

        if isinstance(def_node, ast.Assign):
            if require_container_constants:
                val = def_node.value
                if isinstance(val, ast.Dict):
                    return all(isinstance(v, ast.Constant) for v in val.values)
                elif isinstance(val, (ast.List, ast.Tuple)):
                    return all(isinstance(e, ast.Constant) for e in val.elts)
                return False
            return _eval_expr_safety(def_node.value, def_line, visited)

        elif isinstance(def_node, ast.AnnAssign):
            if def_node.value:
                return _eval_expr_safety(def_node.value, def_line, visited)
            return False

        elif isinstance(def_node, ast.For):
            iter_node = def_node.iter
            iter_items = None
            if isinstance(iter_node, (ast.List, ast.Tuple)):
                iter_items = iter_node.elts
            elif isinstance(iter_node, ast.Name):
                for stmt in ast.walk(tree):
                    if isinstance(stmt, ast.Assign):
                        for t in stmt.targets:
                            if isinstance(t, ast.Name) and t.id == iter_node.id:
                                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                                    iter_items = stmt.value.elts
                                break
            if not iter_items:
                return False

            if isinstance(def_node.target, ast.Name) and def_node.target.id == v_name:
                return all(isinstance(it, ast.Constant) for it in iter_items)
            elif isinstance(def_node.target, (ast.Tuple, ast.List)):
                target_names = [sub.id for sub in def_node.target.elts if isinstance(sub, ast.Name)]
                if v_name not in target_names:
                    return False
                idx = target_names.index(v_name)
                for item in iter_items:
                    if isinstance(item, (ast.Tuple, ast.List)) and idx < len(item.elts):
                        if not isinstance(item.elts[idx], ast.Constant):
                            return False
                    else:
                        return False
                return True

        return False

    return _eval_expr_safety(target_sql_expr, target_line or 1, set())


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

    # 0. Intent/context classifier (training, example, intentionally vulnerable code)
    is_training_path = False
    for path_marker in ("dockerized_labs/", "examples/", "docs/", "training/", "tutorial/"):
        if path_marker in norm_file:
            is_training_path = True
            break
            
    has_vulnerable_comment = False
    if file_lines and f.line:
        s_idx = max(0, f.line - 5)
        e_idx = min(len(file_lines), f.line + 3)
        window = "".join(file_lines[s_idx:e_idx])
        if re.search(r"#\s*vulnerable:?", window, re.IGNORECASE) or re.search(r"intentionally vulnerable", window, re.IGNORECASE):
            has_vulnerable_comment = True
            
    if is_training_path or has_vulnerable_comment:
        f.fp_likelihood = "HIGH"
        f.fp_reason = "Intent classified as training/example code"
        f.extra["damping_multiplier"] = 0.1
        f.extra["fp_likelihood"] = f.fp_likelihood
        f.extra["fp_reason"] = f.fp_reason
        return

    # 1. Test suite mock passwords / secret fixtures
    # Exempt provider-format keys (e.g. AKIA...) and damp only generic passwords
    is_test = is_test_path(f.file) or f.exposure == "TEST"
    is_cred = (
        f.cwe in ("CWE-259", "CWE-798")
        or f.engine == "secrets"
        or (f.engine == "bandit" and (f.cwe in ("CWE-259", "CWE-798") or any(b in (f.title or "") for b in ("B105", "B106", "B107"))))
    )
    if is_test and is_cred:
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

        # Guard 3: Gating guard - Scoped strictly to the enclosing seed block/function with polarity validation
        is_pure_fixture_dir = (
            norm_file.startswith("seeds/") or "/seeds/" in norm_file
            or norm_file.startswith("fixtures/") or "/fixtures/" in norm_file
            or norm_file.startswith("tests/") or "/tests/" in norm_file
        )
        if is_pure_fixture_dir:
            g_gate = True
        else:
            block_text = _get_enclosing_block_text(file_lines, f.line, full_path)
            g_gate = _is_dev_gated(block_text)

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

        # STRICT REQUIREMENTS:
        # 1. Environment (g_env) and cross-file (g_cross) checks are strictly mandatory.
        # 2. Demo-value guard (g_demo) is strictly required for ANY damping.
        #    A random/production-like password behind DEBUG is still a readable committed secret.
        #    Only g_demo guarantees the value itself is a throwaway mock/demo fixture.
        if (matches_seed_var or is_seed_file):
            if g_env and g_cross and g_demo:
                if g_gate:
                    f.fp_likelihood = "HIGH"
                    f.fp_reason = "Database bootstrap seed credentials / demo fixture (all 4 guards passed)"
                    f.extra["fp_likelihood"] = f.fp_likelihood
                    f.extra["fp_reason"] = f.fp_reason
                    f.extra["seed_classification"] = "SEED_FULL"
                    f.extra["guard_note"] = f"Guarded seed fixture (4/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"
                    return
                else:
                    f.fp_likelihood = "MEDIUM"
                    f.fp_reason = "Database bootstrap fixture (mild damping: 3/4 guards passed, missing runtime gate)"
                    f.extra["fp_likelihood"] = f.fp_likelihood
                    f.extra["fp_reason"] = f.fp_reason
                    f.extra["seed_classification"] = "SEED_PARTIAL"
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
    is_sql_finding = (
        f.cwe == "CWE-89"
        or "B608" in (f.title or "")
        or "B608" in (getattr(f, "id", "") or "")
        or (f.engine == "semgrep" and "sql" in (f.extra.get("check_id") or "").lower())
    )
    if is_sql_finding:
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
