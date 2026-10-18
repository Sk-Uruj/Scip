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
import fnmatch
import hashlib
import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from core.finding import Finding
from core.risk_graph import is_test_path
from engines.secrets_engine import PROVIDER_RULES
from engines.blast_radius_engine import find_enclosing_function

log = logging.getLogger("scip.fp_detector")

_PROVIDER_RULE_IDS = {r.id for r in PROVIDER_RULES if r.id not in ("jwt", "db-url-password")}

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



# --------------------------------------------------------------------------- #
# Guard: a weak hash of SENSITIVE data is never an "ETag false positive"
# --------------------------------------------------------------------------- #
_SENSITIVE_WORDS = {
    "password", "passwd", "pwd", "passphrase", "passcode", "pass", "secret", "token", "credential",
    "credentials", "otp", "session", "auth", "authorization", "ssn", "pin",
}
_SENSITIVE_COMPOUNDS = re.compile(
    r"(apikey|privatekey|secretkey|accesskey|authkey|signingkey|encryptionkey|sessionid)")


def _identifier_words(name: str) -> List[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [w for w in re.split(r"[_\W]+", spaced.lower()) if w]


def _is_sensitive_identifier(name: str) -> bool:
    if not name:
        return False
    words = _identifier_words(name)
    if any(w in _SENSITIVE_WORDS for w in words):
        return True
    return bool(_SENSITIVE_COMPOUNDS.search("".join(words)))


def _names_in(node: ast.AST) -> set:
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            names.add(n.attr)
    return names


def _hashed_data_is_sensitive(file_lines: List[str], line_no: Optional[int], evidence: str) -> bool:
    """True when anything flowing into the hash call on ``line_no`` is credential-like.

    Looks at (1) the identifiers inside the call, (2) the enclosing function's name and
    parameters, and (3) one level of taint: ``data = user.password.encode()`` makes ``data``
    sensitive. Falls back to a text check of the evidence when the file cannot be parsed.
    """
    fallback = any(_is_sensitive_identifier(tok) for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", evidence or ""))
    if not file_lines or not line_no:
        return fallback
    try:
        tree = ast.parse("".join(file_lines))
    except (SyntaxError, ValueError):
        return fallback

    funcs = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.lineno <= line_no <= (getattr(n, "end_lineno", n.lineno) or n.lineno)]
    func = min(funcs, key=lambda n: (getattr(n, "end_lineno", n.lineno) - n.lineno), default=None)

    tainted: set = set()
    scope = func if func is not None else tree
    if func is not None:
        tainted.add(func.name)
        tainted.update(a.arg for a in func.args.args + func.args.kwonlyargs + func.args.posonlyargs)
    sensitive_names = {n for n in tainted if _is_sensitive_identifier(n)}
    for _ in range(2):                                   # propagate through assignments
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                rhs = _names_in(node.value)
                if any(_is_sensitive_identifier(n) or n in sensitive_names for n in rhs):
                    for t in node.targets:
                        sensitive_names.update(_names_in(t))

    call_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno <= line_no <= (getattr(node, "end_lineno", node.lineno) or node.lineno):
            for arg in list(node.args) + [k.value for k in node.keywords]:
                call_names |= _names_in(arg)
    names = call_names | sensitive_names
    if any(_is_sensitive_identifier(n) for n in names) or (sensitive_names & call_names):
        return True
    # a hash call whose argument we could not name (e.g. md5(get_input())): judge by the function context
    return bool(func is not None and _is_sensitive_identifier(func.name))


def _matches_training_path(norm_file: str, training_paths: Sequence[str]) -> bool:
    """True if the file lies under (or matches) a path the user declared as training material."""
    path = norm_file.strip("/")
    for raw in training_paths or ():
        pat = (raw or "").replace("\\", "/").strip().strip("/")
        if not pat:
            continue
        if path == pat or path.startswith(pat + "/") or fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat + "/*"):
            return True
    return False


def _detect_single_finding_fp(
    f: Finding,
    repo_path: Optional[str],
    training_paths: Sequence[str] = (),
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

    # 0. Intent classifier: code the PERSON RUNNING SCIP declared to be training / example material
    #    (--training-path). Never inferred from the scanned repo: folder names and comments such as
    #    "intentionally vulnerable" are attacker-controlled and would let any code opt itself out.
    if _matches_training_path(norm_file, training_paths):
        f.fp_likelihood = "HIGH"
        f.fp_reason = "Intent classified as training/example code (declared with --training-path)"
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

        etag_signal = matches_etag_func or matches_etag_code or matches_etag_text
        if etag_signal and _hashed_data_is_sensitive(file_lines, f.line, evidence):
            # Words like "etag" in a comment or name are NOT evidence when the hashed value is a
            # password/secret/token. Keep the finding and say why.
            f.extra["fp_guard"] = "weak hash of credential-like data: not treated as an ETag checksum"
            etag_signal = False
        if etag_signal:
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


def _protected_reason(f: Finding) -> Optional[str]:
    """Findings that must never be labelled a false positive, whichever rule fired."""
    extra = f.extra or {}
    if extra.get("kev"):
        return "actively exploited (CISA KEV)"
    if f.engine == "secrets" and extra.get("rule") in _PROVIDER_RULE_IDS:
        return "provider-format credential"
    return None


def _clear_fp(f: Finding, why: str) -> None:
    f.fp_likelihood = None
    f.fp_reason = None
    for key in ("fp_likelihood", "fp_reason", "damping_multiplier"):
        f.extra.pop(key, None)
    f.extra["fp_blocked"] = f"not demoted: {why}"


def detect_false_positives(findings: List[Finding], repo_path: Optional[str] = None,
                           training_paths: Sequence[str] = ()) -> List[Finding]:
    """Inspect findings and tag high-confidence false positive and seed patterns.

    ``training_paths``: paths the caller declared as training/example code (see --training-path)."""
    for f in findings:
        try:
            _detect_single_finding_fp(f, repo_path, training_paths)
        except Exception as exc:
            loc = f"{getattr(f, 'file', '')}:{getattr(f, 'line', '')}"
            log.warning("False-positive evaluation failed for finding '%s' at %s: %s", getattr(f, "title", "finding"), loc, exc)
            continue

    # Safety rail: no rule (including ones that ran earlier, e.g. in the risk graph) may demote these.
    for f in findings:
        why = _protected_reason(f)
        if why and (getattr(f, "fp_likelihood", None) or f.extra.get("fp_likelihood")):
            _clear_fp(f, why)

    return findings
