"""Composite Risk Scoring Engine.

Formulates a normalized 0-100 risk score using seven key security and repository signals:
  1. Severity (S_CVSS): CVSS score mapped linearly (CVSS / 10)
  2. Exploitability (S_EPSS): EPSS probability for CVEs, or static rule exploitability heuristic
  3. Active Exploitation (S_KEV): CISA KEV membership (1.0 if active, 0.0 otherwise)
  4. Reachability (S_Reach): Call graph reachability (1.0 if reachable, 0.0 if unused, 0.5 if unknown/null)
  5. Blast Radius (S_Blast): Transitive call-graph blast radius (linear saturation min(1.0, blast_radius / 10.0))
  6. Code Churn (S_Churn): Normalized git line churn (0.0 to 1.0)
  7. Code Health (S_Health): Technical debt and complexity penalty (0.0 to 1.0)

Calculated as:
  Risk Score = 100 * sum(w_i * S_i) / sum(w_i)

Weights are dynamically loaded from .env file or environment variables with defaults:
  WEIGHT_CVSS   = 0.30
  WEIGHT_EPSS   = 0.20
  WEIGHT_KEV    = 0.15
  WEIGHT_REACH  = 0.15
  WEIGHT_BLAST  = 0.10
  WEIGHT_CHURN  = 0.05
  WEIGHT_HEALTH = 0.05
"""
from dataclasses import asdict, dataclass
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
    "WEIGHT_CVSS": 0.30,
    "WEIGHT_EPSS": 0.20,
    "WEIGHT_KEV": 0.15,
    "WEIGHT_REACH": 0.15,
    "WEIGHT_BLAST": 0.10,
    "WEIGHT_CHURN": 0.05,
    "WEIGHT_HEALTH": 0.05,
}


@dataclass
class ScoringConfig:
    """Configurable and bounded tuning knobs for composite risk scoring."""
    fp_damping_factor: float = 0.20        # Uniform damping for ALL confirmed HIGH false positives (0.05 to 1.0)
    secret_repo_reach: float = 0.80        # Exposure reach weight for secrets in working tree (0.0 to 1.0)
    secret_hist_reach: float = 0.50        # Exposure reach weight for secrets in git history (0.0 to 1.0)
    prng_ref_id_discount: float = 0.50     # Discount for reference/display IDs vs security tokens (0.1 to 1.0)

    def __post_init__(self):
        if not (0.05 <= self.fp_damping_factor <= 1.0):
            raise ValueError(f"fp_damping_factor must be between 0.05 and 1.0, got {self.fp_damping_factor}")
        if not (0.0 <= self.secret_repo_reach <= 1.0):
            raise ValueError(f"secret_repo_reach must be between 0.0 and 1.0, got {self.secret_repo_reach}")
        if not (0.0 <= self.secret_hist_reach <= 1.0):
            raise ValueError(f"secret_hist_reach must be between 0.0 and 1.0, got {self.secret_hist_reach}")
        if not (0.1 <= self.prng_ref_id_discount <= 1.0):
            raise ValueError(f"prng_ref_id_discount must be between 0.1 and 1.0, got {self.prng_ref_id_discount}")


DEFAULT_SCORING_CONFIG = ScoringConfig()


def _normalize_to_repo_rel(file_path: str, repo_path: str) -> str:
    """Normalize a finding file path to a repository-relative POSIX path."""
    if not file_path:
        return ""
    try:
        p = Path(file_path)
        r = Path(repo_path).resolve()
        if p.is_absolute():
            return p.resolve().relative_to(r).as_posix()
        abs_p = (r / p).resolve()
        try:
            return abs_p.relative_to(r).as_posix()
        except ValueError:
            pass
    except Exception:
        pass

    norm = file_path.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


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


def calculate_finding_risk_score(
    f: Finding,
    weights: Optional[Dict[str, float]] = None,
    config: Optional[ScoringConfig] = None,
) -> Finding:
    """Calculate normalized 0-100 risk score and explanation string for a finding."""
    if weights is None:
        weights = load_weights()
    config = config or DEFAULT_SCORING_CONFIG

    w_cvss = weights.get("WEIGHT_CVSS", 0.30)
    w_epss = weights.get("WEIGHT_EPSS", 0.20)
    w_kev = weights.get("WEIGHT_KEV", 0.15)
    w_reach = weights.get("WEIGHT_REACH", 0.15)
    w_blast = weights.get("WEIGHT_BLAST", 0.10)
    w_churn = weights.get("WEIGHT_CHURN", 0.05)
    w_health = weights.get("WEIGHT_HEALTH", 0.05)

    # 1. CVSS Severity normalized (0.0 to 1.0)
    s_cvss = max(0.0, min(1.0, float(getattr(f, "severity", 0.0) or 0.0) / 10.0))

    # 2. Exploitability: distinguish true EPSS probability vs static heuristic
    extra = getattr(f, "extra", {}) or {}
    has_epss = bool(extra.get("epss") is not None or (getattr(f, "engine", "") == "dependency" and (getattr(f, "exploitability", 0.0) or 0.0) > 0))
    if has_epss:
        epss_raw = extra.get("epss") if extra.get("epss") is not None else getattr(f, "exploitability", 0.0)
        s_epss = max(0.0, min(1.0, float(epss_raw or 0.0)))
        exploit_label = f"EPSS: {s_epss:.4f}"
    else:
        exploit_raw = getattr(f, "exploitability", 0.0)
        s_epss = max(0.0, min(1.0, float(exploit_raw or 0.0)))
        exploit_label = f"Exploit: {s_epss:.2f}"

    # 3. CISA KEV (1.0 if active, 0.0 otherwise)
    s_kev = 1.0 if bool(extra.get("kev")) else 0.0

    # 4. Reachability & Exposure Tier (Secrets use REPO / HIST exposure model)
    reach = getattr(f, "reachable", None)
    exposure = getattr(f, "exposure", None) or extra.get("exposure")
    if exposure == "HTTP":
        s_reach = 1.0
    elif exposure == "REPO":
        s_reach = config.secret_repo_reach
    elif exposure in ("WORKER", "HIST"):
        s_reach = config.secret_hist_reach
    elif exposure == "CLI":
        s_reach = 0.3
    elif exposure in ("TEST", "DEAD", "INTNL", "NONE") or reach is False:
        s_reach = 0.0
    elif reach is True:
        s_reach = 1.0
    else:
        # reach is None / exposure UNKNOWN (analysis could not determine) -> neutral 0.5
        s_reach = 0.5

    # 5. Blast Radius (0.0 to 1.0, linear saturation capped at 10 callers)
    blast_cnt = int(getattr(f, "blast_radius", 0) or 0)
    s_blast = max(0.0, min(1.0, float(blast_cnt) / 10.0))

    # 6. Code Churn (0.0 to 1.0)
    churn_val = getattr(f, "churn", 0.0) or extra.get("churn", 0.0)
    s_churn = max(0.0, min(1.0, float(churn_val or 0.0)))

    # 7. Code Health Penalty (0.0 to 1.0)
    health_val = getattr(f, "code_health_penalty", 0.0) or extra.get("code_health_penalty", 0.0)
    s_health = max(0.0, min(1.0, float(health_val or 0.0)))

    # Total weight normalization (prevents scores overflowing 100 with custom weights)
    total_weight = w_cvss + w_epss + w_kev + w_reach + w_blast + w_churn + w_health
    if total_weight <= 0:
        total_weight = 1.0

    # Risk Score = 100 * sum(w_i * S_i) / sum(w_i)
    weighted_sum = (
        (w_cvss * s_cvss) +
        (w_epss * s_epss) +
        (w_kev * s_kev) +
        (w_reach * s_reach) +
        (w_blast * s_blast) +
        (w_churn * s_churn) +
        (w_health * s_health)
    )

    risk_score = round(max(0.0, min(100.0, 100.0 * (weighted_sum / total_weight))), 2)

    # 8. PRNG Context Adjustment (Reference ID vs Security Token)
    ref_id_note = ""
    if extra.get("is_ref_id"):
        risk_score = round(risk_score * config.prng_ref_id_discount, 2)
        ref_id_note = f", PRNG Ref-ID: {config.prng_ref_id_discount:.2f}x"

    # 9. Rotation & Live Verification overrides
    status_note = ""
    if extra.get("rotated"):
        risk_score = round(risk_score * 0.2, 2)
        status_note = ", Rotated: 0.2x"
    elif extra.get("live_verified"):
        risk_score = round(min(100.0, risk_score * 1.5), 2)
        status_note = ", Live Verified: 1.5x"

    # 10. Graded Seed & Verified False Positive Damping
    fp_likely = getattr(f, "fp_likelihood", None) or extra.get("fp_likelihood")
    fp_damped = False
    damping_factor = 1.0
    damping_label = "FP Damped"

    if extra.get("damping_multiplier"):
        damping_factor = float(extra["damping_multiplier"])
        if damping_factor < 1.0:
            risk_score = round(risk_score * damping_factor, 2)
            fp_damped = True
            damping_label = "Seed Damped" if extra.get("seed_classification") == "SEED" else "FP Damped"
    elif fp_likely == "HIGH":
        damping_factor = config.fp_damping_factor
        risk_score = round(risk_score * damping_factor, 2)
        fp_damped = True
        damping_label = "FP Damped"
    elif fp_likely == "MEDIUM":
        damping_factor = 0.60
        risk_score = round(risk_score * damping_factor, 2)
        fp_damped = True
        damping_label = "Seed Damped" if extra.get("seed_classification") == "SEED" else "FP Damped"

    reach_label = exposure if exposure else ("YES" if reach is True else ("NO" if reach is False else "?"))
    reach_info = f"Exposure: {reach_label} (s={s_reach:.2f}, w={w_reach:.2f}"
    if extra.get("attack_path"):
        reach_info += f", hops={len(extra['attack_path'])}"
    reach_info += ")"

    fp_note = f", {damping_label}: {damping_factor:.2f}x ({getattr(f, 'fp_reason', '') or extra.get('fp_reason', '')})" if fp_damped else ""
    explanation = (
        f"Risk Score: {risk_score:.2f}/100 | "
        f"CVSS: {f.severity:.1f} (s={s_cvss:.2f}, w={w_cvss:.2f}), "
        f"{exploit_label} (w={w_epss:.2f}), "
        f"KEV: {int(s_kev)} (w={w_kev:.2f}), "
        f"{reach_info}, "
        f"Blast: {s_blast:.2f} (w={w_blast:.2f}, count={blast_cnt}), "
        f"Churn: {s_churn:.2f} (w={w_churn:.2f}), "
        f"Health: {s_health:.2f} (w={w_health:.2f})"
        f"{ref_id_note}{status_note}{fp_note}"
    )

    f.risk_score = risk_score
    f.explanation = explanation
    f.extra["scoring_config"] = asdict(config)
    return f


def score_and_sort_findings(
    findings: List[Finding],
    repo_path: Optional[str] = None,
    weights: Optional[Dict[str, float]] = None,
    config: Optional[ScoringConfig] = None,
) -> List[Finding]:
    """Score all findings and sort in descending order of risk_score (highest risk on top)."""
    weights = weights or load_weights(repo_path=repo_path)
    config = config or DEFAULT_SCORING_CONFIG

    if repo_path:
        churn_counts = get_git_churn(repo_path)
        normalized_churn = normalize_churn(churn_counts)
        for f in findings:
            if not f.file:
                continue
            rel_file = _normalize_to_repo_rel(f.file, repo_path)
            if rel_file in normalized_churn:
                f.churn = round(normalized_churn[rel_file], 2)
            else:
                matched = False
                for k, v in normalized_churn.items():
                    if k == rel_file or k.endswith("/" + rel_file):
                        f.churn = round(v, 2)
                        matched = True
                        break
                if not matched:
                    f.churn = 0.0

        try:
            from core.risk_graph import RiskGraph
            risk_graph = RiskGraph(repo_path).build()
            risk_graph.analyze_reachability(findings)
        except Exception as e:
            log.warning("RiskGraph analysis failed, falling back to basic blast radius: %s", e)
            calculate_blast_radius(findings, repo_path)

        calculate_code_health_penalties(findings, repo_path)

        # Detect and tag safe-by-design / protocol-mandated false positives
        try:
            from core.fp_detector import detect_false_positives
            detect_false_positives(findings, repo_path=repo_path)
        except Exception as e:
            log.debug("FP detection error: %s", e)

    for f in findings:
        calculate_finding_risk_score(f, weights=weights, config=config)

    return sorted(findings, key=lambda f: (-f.risk_score, -f.severity, -f.exploitability))
