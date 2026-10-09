"""Cross-tool finding deduplication and alert correlation.

Identifies findings from code-level SAST engines (Bandit, Semgrep, Secrets, Crypto)
that point to the exact same code location and vulnerability class, merging them into
a single high-fidelity, corroborated finding.

Dependency vulnerability findings (OSV / CVEs) are explicitly exempt from code-level
deduplication because multiple distinct CVEs frequently affect the same manifest line.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Dict, List, Set

from core.finding import Finding
from core.taxonomy import is_compatible_cwe, normalize_cwe

log = logging.getLogger("scip.dedup")

# Explicit vulnerability-class keywords for fallback similarity checks when CWE is missing.
# Excludes generic credential/secret words like 'password', 'secret', 'token', 'credential' which cause false merges.
VULNERABILITY_CLASS_KEYWORDS = [
    "yaml", "pickle", "md5", "sha1", "des", "rc4", "ssl", "tls", "sql",
    "exec", "eval", "shell", "subprocess", "ssrf", "xss", "csrf", "mktemp", "timeout",
]
KEYWORD_PATTERNS = {k: re.compile(rf"\b{k}\b", re.IGNORECASE) for k in VULNERABILITY_CLASS_KEYWORDS}


def _norm_path(path: str) -> str:
    """Normalize file path to POSIX relative form without leading dots or slashes."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./") or p.startswith("/"):
        p = p[2:] if p.startswith("./") else p[1:]
    return p


def _extract_keywords(text: str) -> Set[str]:
    """Extract whole-word security keywords using word boundaries."""
    return {k for k, pat in KEYWORD_PATTERNS.items() if pat.search(text)}


def _are_duplicates(f1: Finding, f2: Finding) -> bool:
    """Determine whether two code-level findings refer to the same root vulnerability."""
    # 1. Scope: Never dedup dependency findings or history-only secrets
    if f1.engine == "dependency" or f2.engine == "dependency":
        return False
    if f1.extra.get("vuln_id") or f2.extra.get("vuln_id"):
        return False
    if f1.extra.get("in_working_tree") is False or f2.extra.get("in_working_tree") is False:
        return False

    # 2. Never merge findings from the same engine or cluster with common engine
    if f1.engine == f2.engine:
        return False
    f1_engines = set(f1.extra.get("corroborating_engines") or [f1.engine])
    f2_engines = set(f2.extra.get("corroborating_engines") or [f2.engine])
    if bool(f1_engines & f2_engines):
        return False

    # 3. Must refer to the exact same file
    if _norm_path(f1.file) != _norm_path(f2.file):
        return False

    # 4. Check line proximity: Both must have line numbers; require line-range overlap
    if f1.line is None or f2.line is None:
        return False

    r1 = set(f1.extra.get("line_range") or [f1.line])
    r2 = set(f2.extra.get("line_range") or [f2.line])
    if not (r1 & r2):
        return False

    # 5. Check CWE compatibility
    if is_compatible_cwe(f1.cwe, f2.cwe):
        return True

    # 6. Keyword fallback: ONLY use when at least one side lacks a known normalized CWE
    cwe1_missing = normalize_cwe(f1.cwe) is None
    cwe2_missing = normalize_cwe(f2.cwe) is None
    if cwe1_missing or cwe2_missing:
        kw1 = _extract_keywords(f"{f1.title} {f1.description}")
        kw2 = _extract_keywords(f"{f2.title} {f2.description}")
        if kw1 and kw2 and bool(kw1 & kw2):
            return True

    return False


def _slim_source(f: Finding) -> dict:
    """Create a lightweight representation of a source finding to avoid JSON bloat."""
    rule_id = f.extra.get("test_id") or f.extra.get("check_id") or f.title
    return {
        "engine": f.engine,
        "rule": rule_id,
        "severity": f.severity,
        "cwe": f.cwe,
        "line": f.line,
    }


def _merge_pair(base: Finding, incoming: Finding) -> Finding:
    """Merge two corroborated findings cleanly, picking one primary finding for all core fields."""
    # Choose primary finding:
    # 1. An active (unsuppressed) finding ALWAYS takes precedence over a suppressed finding
    base_suppressed = bool(base.extra.get("suppressed"))
    incoming_suppressed = bool(incoming.extra.get("suppressed"))

    ENGINE_PRIORITY = {"semgrep": 3, "bandit": 2, "secrets": 1, "dependency": 0}
    if base_suppressed and not incoming_suppressed:
        primary, secondary = incoming, base
    elif incoming_suppressed and not base_suppressed:
        primary, secondary = base, incoming
    elif incoming.severity > base.severity:
        primary, secondary = incoming, base
    elif incoming.severity < base.severity:
        primary, secondary = base, incoming
    else:
        p_incoming = ENGINE_PRIORITY.get(incoming.engine, 0)
        p_base = ENGINE_PRIORITY.get(base.engine, 0)
        if p_incoming > p_base:
            primary, secondary = incoming, base
        else:
            primary, secondary = base, incoming

    # Track distinct corroborating engines
    base_engines = list(base.extra.get("corroborating_engines") or [base.engine])
    incoming_engines = list(incoming.extra.get("corroborating_engines") or [incoming.engine])
    all_engines = sorted(list(set(base_engines + incoming_engines)))

    max_sev = max(base.severity, incoming.severity)
    is_corroborated = len(all_engines) > 1

    # Slim source tracking (avoid bloating output with full dict copies)
    sources = list(base.extra.get("sources") or [_slim_source(base)])
    sources.append(_slim_source(incoming))

    merged_extra = dict(primary.extra)
    merged_suppressed = base_suppressed and incoming_suppressed
    merged_extra["suppressed"] = merged_suppressed
    if not merged_suppressed:
        merged_extra.pop("suppression_reason", None)

    # Preserve all rule IDs across merged findings (3-way union to preserve historical cluster rules)
    all_rules = set(primary.extra.get("all_rules") or []) | set(secondary.extra.get("all_rules") or [])
    for f_item in (primary, secondary):
        for k in ("test_id", "check_id", "vuln_id", "rule", "secret_type"):
            v = f_item.extra.get(k)
            if v:
                all_rules.add(str(v))
    merged_extra["all_rules"] = sorted(list(all_rules))

    merged_extra.update({
        "corroborating_engines": all_engines,
        "corroborated": is_corroborated,
        "sources_count": len(sources),
        "sources": sources,
    })

    # Core attributes come entirely from primary finding to ensure consistency
    return Finding(
        engine=primary.engine,
        title=primary.title,
        file=primary.file,
        line=primary.line,
        cwe=normalize_cwe(primary.cwe),
        severity=max_sev,
        description=primary.description,
        evidence=primary.evidence,
        fix_hint=primary.fix_hint,
        exploitability=max(base.exploitability, incoming.exploitability),
        reachable=primary.reachable if primary.reachable is not None else secondary.reachable,
        blast_radius=max(base.blast_radius, incoming.blast_radius),
        churn=max(base.churn, incoming.churn),
        code_health_penalty=max(base.code_health_penalty, incoming.code_health_penalty),
        risk_score=max(base.risk_score, incoming.risk_score),
        explanation=primary.explanation or secondary.explanation,
        extra=merged_extra,
    )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate and correlate findings across code-level scanning engines.

    Dependency findings and git-history-only findings are passed through directly without deduplication.
    """
    if not findings:
        return []

    # Separate dependency and history findings from active code-level findings
    passthrough_findings: List[Finding] = []
    code_findings: List[Finding] = []

    for f in findings:
        if f.engine == "dependency" or f.extra.get("vuln_id") or f.extra.get("in_working_tree") is False:
            passthrough_findings.append(f)
        else:
            code_findings.append(f)

    # Group code findings by normalized file path for localized comparisons
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in code_findings:
        by_file[_norm_path(f.file)].append(f)

    deduped_code: List[Finding] = []

    for file_path, file_findings in by_file.items():
        clusters: List[Finding] = []

        for candidate in file_findings:
            matched = False
            for i, cluster in enumerate(clusters):
                if _are_duplicates(cluster, candidate):
                    clusters[i] = _merge_pair(cluster, candidate)
                    matched = True
                    break
            if not matched:
                # Deep copy via clone() to avoid mutating original
                c_copy = candidate.clone()
                c_copy.extra.setdefault("corroborating_engines", [candidate.engine])
                c_copy.extra.setdefault("corroborated", False)
                clusters.append(c_copy)

        deduped_code.extend(clusters)

    all_findings = passthrough_findings + deduped_code
    all_findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
    return all_findings
