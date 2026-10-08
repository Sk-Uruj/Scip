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

import os
import re
from typing import List, Optional

from core.finding import Finding
from core.risk_graph import is_test_path
from engines.blast_radius_engine import find_enclosing_function

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

WHITELISTED_SQL_PATTERNS = [
    re.compile(r"\{entered_col\}", re.IGNORECASE),
    re.compile(r"\{col_name\}", re.IGNORECASE),
    re.compile(r"\{tier_col\}", re.IGNORECASE),
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
    re.compile(r"(?:\b|_)(token|secret|session|csrf|auth|nonce|salt|jwt|api_key|apikey)(?:\b|_)", re.IGNORECASE),
]

REF_ID_PATTERNS = [
    re.compile(r"(?:\b|_)(id|ref|ref_id|payment_id|invoice_id|order_id|tx_id|display_id|tracking|code|suffix|filename)(?:\b|_)", re.IGNORECASE),
    re.compile(r"['\"][A-Z]+-['\"]"),
]


def detect_false_positives(findings: List[Finding], repo_path: Optional[str] = None) -> List[Finding]:
    """Inspect findings and tag high-confidence false positive and seed patterns."""
    for f in findings:
        evidence = f.evidence or ""
        title = f.title or ""
        desc = f.description or ""
        combined_text = f"{title} {desc} {evidence}"

        norm_file = (f.file or "").replace("\\", "/").lstrip("./")
        full_path = None
        enclosing_func = None
        if repo_path and f.file:
            full_path = os.path.join(str(repo_path), norm_file)
            if os.path.isfile(full_path) and f.line:
                enclosing_func = find_enclosing_function(full_path, f.line)

        # 1. Test suite mock passwords / secret fixtures
        if is_test_path(f.file) or f.exposure == "TEST":
            if f.cwe in ("CWE-259", "CWE-798") or f.engine in ("secrets", "bandit"):
                f.fp_likelihood = "HIGH"
                f.fp_reason = "Mock test credential in test suite"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                continue

        # 2. Database bootstrap seed credentials / demo fixtures (CWE-1188) with environmental guards
        is_seed_file = any(p.search(norm_file) for p in SEED_FILE_PATTERNS) or "/seeds/" in norm_file.lower() or "/fixtures/" in norm_file.lower()
        if is_seed_file and (f.cwe in ("CWE-259", "CWE-798") or f.engine in ("secrets", "bandit")):
            matches_seed_var = any(p.search(evidence) for p in SEED_VAR_PATTERNS)
            file_lines = []
            if full_path and os.path.isfile(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        file_lines = fh.readlines()
                except Exception:
                    pass

            line_text = ""
            if file_lines and f.line and 1 <= f.line <= len(file_lines):
                line_text = file_lines[f.line - 1]
            else:
                line_text = evidence

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

            # Guard 2: Demo Pattern guard - Strictly verify against demo wordlist and patterns (never use Shannon entropy for short strings)
            val_candidates = re.findall(r"(?:password|passwd|secret|token|api_key|key|pw)[\"'\s:=]+[\"']([^\"']+)[\"']", line_text + " " + evidence, re.IGNORECASE)
            if not val_candidates:
                val_candidates = re.findall(r":\s*[\"']([^\"']+)[\"']", line_text + " " + evidence) or re.findall(r"=\s*[\"']([^\"']+)[\"']", line_text + " " + evidence)

            g_demo = False
            for cand in val_candidates:
                cand_lower = cand.lower()
                if cand_lower in DEMO_WORDLIST or re.match(r"^[a-zA-Z]+123$", cand) or re.match(r"^test[a-zA-Z0-9]*$", cand_lower):
                    g_demo = True
                    break

            # Guard 3: Gating guard - Gated execution (e.g. --seed / DEBUG) or dedicated fixtures directory
            is_pure_fixture_dir = "/seeds/" in norm_file.lower() or "/fixtures/" in norm_file.lower() or "/tests/" in norm_file.lower()
            file_content = "".join(file_lines) if file_lines else ""
            is_gated = any(p.search(file_content) for p in GATED_SEED_PATTERNS)
            g_gate = is_pure_fixture_dir or is_gated

            # Guard 4: Cross-file guard - Check working tree for occurrences of secret variable in non-fixture production code & CI configs
            in_prod_file = False
            raw_var = f.extra.get("variable")
            if repo_path and raw_var and len(raw_var) >= 6:
                for root, _, files in os.walk(repo_path):
                    for fn in files:
                        low_fn = fn.lower()
                        if (low_fn.endswith((".py", ".env", ".yml", ".yaml", ".json")) or any(c in low_fn for c in CI_AND_CONFIG_FILES)) and not any(p.search(fn) for p in SEED_FILE_PATTERNS) and "test" not in low_fn:
                            fp = os.path.join(root, fn)
                            try:
                                with open(fp, "r", encoding="utf-8", errors="ignore") as pf:
                                    if raw_var in pf.read():
                                        in_prod_file = True
                                        break
                            except Exception:
                                pass
                    if in_prod_file:
                        break
            g_cross = not in_prod_file

            guards_passed = sum([1 for g in (g_env, g_demo, g_gate, g_cross) if g])

            if (matches_seed_var or is_seed_file):
                if guards_passed == 4:
                    f.fp_likelihood = "HIGH"
                    f.fp_reason = "Database bootstrap seed credentials / demo fixture (all 4 guards passed)"
                    f.extra["fp_likelihood"] = f.fp_likelihood
                    f.extra["fp_reason"] = f.fp_reason
                    f.extra["seed_classification"] = "SEED"
                    f.extra["damping_multiplier"] = 0.20
                    f.extra["guard_note"] = f"Guarded seed fixture (4/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"
                    continue
                elif guards_passed == 3:
                    f.fp_likelihood = "MEDIUM"
                    f.fp_reason = "Database bootstrap fixture (mild damping: 3/4 guards passed)"
                    f.extra["fp_likelihood"] = f.fp_likelihood
                    f.extra["fp_reason"] = f.fp_reason
                    f.extra["seed_classification"] = "SEED"
                    f.extra["damping_multiplier"] = 0.60
                    f.extra["guard_note"] = f"Partially guarded seed fixture (3/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"
                    continue
                else:
                    f.extra["seed_classification"] = "NOT_SEED"
                    f.extra["damping_multiplier"] = 1.0
                    f.extra["guard_note"] = f"Unguarded credential ({guards_passed}/4 guards passed: env={g_env}, demo={g_demo}, gate={g_gate}, cross={g_cross})"

        # 3. Protocol-mandated S3 ETags (RFC 7232 MD5 checksum)
        if f.cwe in ("CWE-327", "CWE-328") or f.engine in ("bandit", "crypto"):
            matches_etag_text = any(p.search(combined_text) for p in ETAG_PATTERNS) or "metadata" in f.file.lower()
            matches_etag_func = bool(enclosing_func and any(p.search(enclosing_func) for p in ETAG_PATTERNS))
            if matches_etag_text or matches_etag_func:
                f.fp_likelihood = "HIGH"
                f.fp_reason = "RFC 7232 AWS S3 ETag compliance (non-cryptographic checksum)"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                continue

        # 4. Dynamic SQL: DDL migrations or whitelisted identifier mapping
        if f.cwe == "CWE-89" or "sql" in combined_text.lower():
            if any(p.search(evidence) for p in DDL_SQL_PATTERNS):
                f.fp_likelihood = "HIGH"
                f.fp_reason = "DDL schema migration with static column definitions"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                continue
            if any(p.search(evidence) for p in WHITELISTED_SQL_PATTERNS):
                f.fp_likelihood = "HIGH"
                f.fp_reason = "Dynamic identifier whitelisted from internal constant/enum"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                continue

        # 5. Weak PRNG (Bandit B311 / CWE-330): Distinguish Security Primitives from Reference IDs
        if f.cwe == "CWE-330" or "B311" in (f.title or ""):
            context_str = f"{f.title} {enclosing_func or ''} {evidence} {f.description or ''}"
            is_sec = any(p.search(context_str) for p in SECURITY_PRNG_PATTERNS)
            is_ref = any(p.search(context_str) for p in REF_ID_PATTERNS)

            if is_ref and not is_sec:
                f.extra["is_ref_id"] = True
                f.extra["prng_context"] = "reference_id"
                if not f.title.startswith("[REF-ID]"):
                    f.title = f"[REF-ID] {f.title}"
                f.fix_hint = "For transaction reference IDs, standard PRNG may be acceptable, but use secrets.choice or uuid4 to prevent reference enumeration/prediction."
            elif is_sec:
                f.extra["is_security_token"] = True
                f.extra["prng_context"] = "security_sensitive"

    return findings
