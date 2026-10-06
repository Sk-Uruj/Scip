"""Composite Risk Scoring Engine.

Formulates a normalized 0-100 risk score using five key security and repository signals:
  1. Severity (S_CVSS): CVSS score mapped linearly (CVSS / 10)
  2. Exploitability (S_EPSS): EPSS probability
  3. Active Exploitation (S_KEV): CISA KEV membership (1.0 if active, 0.0 otherwise)
  4. Reachability (S_Reach): Call graph reachability (1.0 if reachable, 0.0 if unused, 0.5 if unknown/null)
  5. Code Churn (S_Churn): Normalized git line churn (0.0 to 1.0)

Calculated as:
  Risk Score = 100 * sum(w_i * S_i)

Weights are dynamically loaded from .env file or environment variables with defaults:
  WEIGHT_CVSS  = 0.35
  WEIGHT_EPSS  = 0.25
  WEIGHT_KEV   = 0.20
  WEIGHT_REACH = 0.15
  WEIGHT_CHURN = 0.05
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from core.finding import Finding
from engines.churn_engine import get_git_churn, normalize_churn
from engines.blast_radius_engine import calculate_blast_radius
from engines.code_health_engine import calculate_code_health_penalties

log = logging.getLogger("scip.scoring")

DEFAULT_WEIGHTS = {
    "WEIGHT_CVSS": 0.35,
    "WEIGHT_EPSS": 0.25,
    "WEIGHT_KEV": 0.20,
    "WEIGHT_REACH": 0.15,
    "WEIGHT_CHURN": 0.05,
}


def load_weights(repo_path: Optional[str] = None) -> Dict[str, float]:
    """Load scoring weights from .env file or environment variables."""
    weights = dict(DEFAULT_WEIGHTS)

    env_paths = []
    if repo_path:
        env_paths.append(Path(repo_path).resolve() / ".env")
    env_paths.append(Path(__file__).resolve().parent.parent / ".env")

    for env_path in env_paths:
        if env_path.exists():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip().upper(), v.strip()
                            if k in weights:
                                try:
                                    weights[k] = float(v)
                                except ValueError:
                                    pass
                break
            except Exception as e:
                log.debug("Error reading .env from %s: %s", env_path, e)

    # Allow environment variable overrides
    for k in weights:
        if k in os.environ:
            try:
                weights[k] = float(os.environ[k])
            except ValueError:
                pass

    return weights


def calculate_finding_risk_score(f: Finding, weights: Optional[Dict[str, float]] = None) -> Finding:
    """Calculate normalized 0-100 risk score and explanation string for a finding."""
    if weights is None:
        weights = load_weights()

    w_cvss = weights.get("WEIGHT_CVSS", 0.35)
    w_epss = weights.get("WEIGHT_EPSS", 0.25)
    w_kev = weights.get("WEIGHT_KEV", 0.20)
    w_reach = weights.get("WEIGHT_REACH", 0.15)
    w_churn = weights.get("WEIGHT_CHURN", 0.05)

    # 1. CVSS Severity normalized (0.0 to 1.0)
    s_cvss = max(0.0, min(1.0, float(f.severity) / 10.0))

    # 2. EPSS Exploitability (0.0 to 1.0)
    epss_raw = f.exploitability if (f.exploitability is not None and f.exploitability > 0) else f.extra.get("epss", 0.0)
    s_epss = max(0.0, min(1.0, float(epss_raw or 0.0)))

    # 3. CISA KEV (1.0 if active, 0.0 otherwise)
    s_kev = 1.0 if bool(f.extra.get("kev")) else 0.0

    # 4. Reachability (1.0 if reachable, 0.0 if unused, 0.5 if unknown/null)
    if f.reachable is True:
        s_reach = 1.0
    elif f.reachable is False:
        s_reach = 0.0
    else:
        s_reach = 0.5

    # 5. Code Churn (0.0 to 1.0)
    s_churn = max(0.0, min(1.0, float(f.churn or f.extra.get("churn", 0.0))))

    # Risk Score = 100 * sum(w_i * S_i)
    weighted_sum = (
        (w_cvss * s_cvss) +
        (w_epss * s_epss) +
        (w_kev * s_kev) +
        (w_reach * s_reach) +
        (w_churn * s_churn)
    )

    risk_score = round(max(0.0, min(100.0, 100.0 * weighted_sum)), 2)

    explanation = (
        f"Risk Score: {risk_score:.2f}/100 | "
        f"CVSS: {f.severity:.1f} (s={s_cvss:.2f}, w={w_cvss:.2f}), "
        f"EPSS: {s_epss:.4f} (w={w_epss:.2f}), "
        f"KEV: {int(s_kev)} (w={w_kev:.2f}), "
        f"Reach: {s_reach:.1f} (w={w_reach:.2f}), "
        f"Churn: {s_churn:.2f} (w={w_churn:.2f})"
    )

    f.risk_score = risk_score
    f.explanation = explanation
    return f


def score_and_sort_findings(findings: List[Finding], repo_path: Optional[str] = None) -> List[Finding]:
    """Score all findings and sort in descending order of risk_score (highest risk on top)."""
    weights = load_weights(repo_path=repo_path)
    
   
    if repo_path:
        churn_counts = get_git_churn(repo_path)
        normalized_churn = normalize_churn(churn_counts)
        for f in findings:
            
            normalized_file = f.file.replace('\\', '/')
            if normalized_file in normalized_churn:
                f.churn = round(normalized_churn[normalized_file], 2)
            else:
                
                for k, v in normalized_churn.items():
                    if normalized_file.endswith(k) or k.endswith(normalized_file):
                        f.churn = round(v, 2)
                        break

        calculate_blast_radius(findings, repo_path)
        calculate_code_health_penalties(findings, repo_path)

    for f in findings:
        calculate_finding_risk_score(f, weights=weights)

    return sorted(findings, key=lambda f: (-f.risk_score, -f.severity, -f.exploitability))
