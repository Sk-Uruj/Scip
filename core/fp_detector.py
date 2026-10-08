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

        # 2. Database bootstrap seed credentials / demo fixtures (CWE-1188)
        is_seed_file = any(p.search(norm_file) for p in SEED_FILE_PATTERNS) or "/seeds/" in norm_file.lower() or "/fixtures/" in norm_file.lower()
        if is_seed_file and (f.cwe in ("CWE-259", "CWE-798") or f.engine in ("secrets", "bandit")):
            matches_seed_var = any(p.search(evidence) for p in SEED_VAR_PATTERNS)
            if not matches_seed_var and full_path and os.path.isfile(full_path) and f.line:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        lines = fh.readlines()
                    start_l = max(0, f.line - 15)
                    end_l = min(len(lines), f.line + 5)
                    window = "".join(lines[start_l:end_l])
                    matches_seed_var = any(p.search(window) for p in SEED_VAR_PATTERNS)
                except Exception:
                    pass
            if matches_seed_var or is_seed_file:
                f.fp_likelihood = "HIGH"
                f.fp_reason = "Database bootstrap seed credentials / demo fixture (CWE-1188)"
                f.extra["fp_likelihood"] = f.fp_likelihood
                f.extra["fp_reason"] = f.fp_reason
                f.extra["is_seed_fixture"] = True
                continue

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

    return findings
