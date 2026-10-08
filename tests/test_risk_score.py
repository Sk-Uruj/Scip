import os
import tempfile
import pytest
from core.finding import Finding
from scoring.risk_score import (
    DEFAULT_WEIGHTS,
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    load_weights,
    calculate_finding_risk_score,
    score_and_sort_findings,
    _normalize_to_repo_rel,
)
from engines.secrets_engine import mask_secret
import json
from engines.churn_engine import get_git_churn


def test_default_weights():
    weights = load_weights()
    assert weights["WEIGHT_CVSS"] == 0.30
    assert weights["WEIGHT_EPSS"] == 0.20
    assert weights["WEIGHT_KEV"] == 0.15
    assert weights["WEIGHT_REACH"] == 0.15
    assert weights["WEIGHT_BLAST"] == 0.10
    assert weights["WEIGHT_CHURN"] == 0.05
    assert weights["WEIGHT_HEALTH"] == 0.05
    # Total sum is 1.00
    assert pytest.approx(sum(weights.values()), rel=1e-5) == 1.00


def test_calculate_finding_risk_score_baseline():
    f = Finding(
        engine="bandit",
        title="Test Vuln",
        file="app.py",
        severity=10.0,  # s_cvss = 1.0
        exploitability=0.5,  # s_epss = 0.5
        reachable=True,  # s_reach = 1.0
        blast_radius=5,  # s_blast = 5/10 = 0.5
        churn=0.2,  # s_churn = 0.2
        code_health_penalty=0.4,  # s_health = 0.4
    )
    # Expected weighted sum:
    # 0.30*1.0 + 0.20*0.5 + 0.15*0 + 0.15*1.0 + 0.10*0.5 + 0.05*0.2 + 0.05*0.4
    # = 0.30 + 0.10 + 0.0 + 0.15 + 0.05 + 0.01 + 0.02 = 0.63 -> 63.00
    res = calculate_finding_risk_score(f)
    assert res.risk_score == pytest.approx(63.00, abs=0.1)
    assert "Risk Score: 63.00/100" in res.explanation
    assert "Blast: 0.50 (w=0.10, count=5)" in res.explanation
    assert "Health: 0.40 (w=0.05)" in res.explanation
    assert "Exploit: 0.50" in res.explanation


def test_blast_radius_and_health_feed_formula():
    """Verify that increasing blast radius and code health penalty increases the risk score."""
    f_low = Finding(
        engine="bandit",
        title="Vuln",
        file="app.py",
        severity=5.0,
        blast_radius=0,
        code_health_penalty=0.0,
    )
    calculate_finding_risk_score(f_low)

    f_high = Finding(
        engine="bandit",
        title="Vuln",
        file="app.py",
        severity=5.0,
        blast_radius=10,
        code_health_penalty=1.0,
    )
    calculate_finding_risk_score(f_high)

    assert f_high.risk_score > f_low.risk_score
    # Difference should correspond to blast (0.10 * 1.0) + health (0.05 * 1.0) = 0.15 * 100 = 15 points
    assert pytest.approx(f_high.risk_score - f_low.risk_score, abs=0.1) == 15.0


def test_epss_vs_heuristic_explanation_distinction():
    """CVE/dependency findings format as EPSS, static findings format as Exploit."""
    # Dependency finding with genuine EPSS
    f_dep = Finding(
        engine="dependency",
        title="CVE-2023-1234",
        file="requirements.txt",
        severity=7.0,
        exploitability=0.1234,
        extra={"epss": 0.1234, "cve": "CVE-2023-1234"},
    )
    calculate_finding_risk_score(f_dep)
    assert "EPSS: 0.1234" in f_dep.explanation
    assert "Exploit:" not in f_dep.explanation

    # SAST finding with static heuristic
    f_sast = Finding(
        engine="bandit",
        title="B101: assert_used",
        file="test.py",
        severity=4.0,
        exploitability=0.60,
    )
    calculate_finding_risk_score(f_sast)
    assert "Exploit: 0.60" in f_sast.explanation
    assert "EPSS:" not in f_sast.explanation


def test_weight_normalization_with_custom_weights():
    """Custom weights that don't sum to 1.0 are properly normalized so score stays <= 100."""
    f_max = Finding(
        engine="dependency",
        title="Critical",
        file="a.py",
        severity=10.0,
        exploitability=1.0,
        reachable=True,
        blast_radius=10,
        churn=1.0,
        code_health_penalty=1.0,
        extra={"epss": 1.0, "kev": True},
    )
    # Double all weights: total sum = 2.0
    double_weights = {k: v * 2.0 for k, v in DEFAULT_WEIGHTS.items()}
    calculate_finding_risk_score(f_max, weights=double_weights)
    assert f_max.risk_score == 100.0


def test_env_override_and_file_loading(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("WEIGHT_CVSS=0.50\nWEIGHT_BLAST=0.20\n", encoding="utf-8")

    weights = load_weights(repo_path=str(tmp_path))
    assert weights["WEIGHT_CVSS"] == 0.50
    assert weights["WEIGHT_BLAST"] == 0.20

    # Environment variable has highest priority
    monkeypatch.setenv("WEIGHT_CVSS", "0.80")
    weights2 = load_weights(repo_path=str(tmp_path))
    assert weights2["WEIGHT_CVSS"] == 0.80


def test_safe_defaults_no_attribute_error():
    """Defensive lookups ensure minimally-initialized findings never raise AttributeError."""
    f = Finding(engine="test", title="Min", file="min.py")
    res = calculate_finding_risk_score(f)
    assert res.risk_score >= 0.0
    assert isinstance(res.explanation, str)


def test_exact_churn_path_matching():
    """Ensure churn matching does not falsely cross between pipeline.py and test_pipeline.py."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (tmp_path := tmpdir)
        f_real = Finding(engine="bandit", title="Real", file="pipeline.py")
        f_test = Finding(engine="bandit", title="Test", file="test_pipeline.py")
        f_sub = Finding(engine="bandit", title="Sub", file="sub/pipeline.py")

        # Mock churn dictionary
        findings = [f_real, f_test, f_sub]
        # Simulate churn results
        normalized_churn = {
            "pipeline.py": 0.85,
            "other.py": 0.10,
        }

        # Test _normalize_to_repo_rel
        assert _normalize_to_repo_rel("pipeline.py", tmp_path) == "pipeline.py"
        assert _normalize_to_repo_rel("./pipeline.py", tmp_path) == "pipeline.py"
        assert _normalize_to_repo_rel("test_pipeline.py", tmp_path) == "test_pipeline.py"

        # Apply churn matching
        for f in findings:
            rel = _normalize_to_repo_rel(f.file, tmp_path)
            if rel in normalized_churn:
                f.churn = round(normalized_churn[rel], 2)
            else:
                matched = False
                for k, v in normalized_churn.items():
                    if k == rel or k.endswith("/" + rel):
                        f.churn = round(v, 2)
                        matched = True
                        break
                if not matched:
                    f.churn = 0.0

        assert f_real.churn == 0.85
        # test_pipeline.py must NOT receive pipeline.py's churn
        assert f_test.churn == 0.0
        # sub/pipeline.py must receive it only if sub/pipeline.py was in churn
        assert f_sub.churn == 0.0


def test_churn_memoization():
    """Verify get_git_churn is memoized and cache_clear works."""
    get_git_churn.cache_clear()
    info_before = get_git_churn.cache_info()
    assert info_before.hits == 0

    # Call with non-git or dummy directory
    res1 = get_git_churn(".")
    res2 = get_git_churn(".")

    info_after = get_git_churn.cache_info()
    assert info_after.hits >= 1
    assert res1 == res2
    get_git_churn.cache_clear()


def test_score_and_sort_findings_descending():
    f1 = Finding(engine="bandit", title="Low", file="a.py", severity=2.0)
    f2 = Finding(engine="bandit", title="High", file="b.py", severity=9.0, blast_radius=8)
    f3 = Finding(engine="bandit", title="Med", file="c.py", severity=5.0)

    sorted_res = score_and_sort_findings([f1, f2, f3])
    assert sorted_res[0].title == "High"
    assert sorted_res[1].title == "Med"
    assert sorted_res[2].title == "Low"
    assert sorted_res[0].risk_score > sorted_res[1].risk_score > sorted_res[2].risk_score


def test_scoring_config_bounds_validation():
    """ScoringConfig validates that multipliers are strictly bounded in [0.05, 1.0]."""
    # Valid config initializes fine
    cfg = ScoringConfig(secret_repo_reach=0.85, secret_hist_reach=0.45)
    assert cfg.secret_repo_reach == 0.85

    # Out of bounds (> 1.0) must raise ValueError
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        ScoringConfig(secret_repo_reach=1.5)

    # Out of bounds (< 0.05) must raise ValueError
    with pytest.raises(ValueError, match="must be between 0.05 and 1.0"):
        ScoringConfig(fp_damping_factor=0.01)


def test_serialized_report_contains_no_raw_secrets(tmp_path):
    """Ensure raw secret values, unsalted hashes, and length hints never leak from real engine scan."""
    from engines.secrets_engine import SecretsEngine
    import hashlib

    raw_secret = "ghp_VerySuperSecretToken123456789XYZ"
    code = f"""def get_client():
    token = "{raw_secret}"
    return token
"""
    (tmp_path / "auth.py").write_text(code, encoding="utf-8")

    engine = SecretsEngine(scan_history=False)
    findings = engine.scan(str(tmp_path))
    assert len(findings) >= 1

    for f in findings:
        calculate_finding_risk_score(f)

    report_json = json.dumps([f.to_dict() for f in findings])

    # Raw secret must never appear in report
    assert raw_secret not in report_json

    # Unsalted hash of raw secret must never appear
    raw_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
    assert raw_hash not in report_json
    assert raw_hash[:8] not in report_json

    # No exact length hint or entropy leaking length
    assert f"length: {len(raw_secret)}" not in report_json
    assert '"entropy"' not in report_json

    # Masked value format
    for f in findings:
        mv = f.extra.get("masked_value", "")
        assert mv.startswith("ghp_") or mv == "********"
        assert raw_secret[4:] not in mv


def test_committed_secret_in_tests_has_repo_reach():
    """Secrets committed in tests/ have exposure=TEST but must score reachability using secret_repo_reach, not 0.0."""
    f = Finding(
        engine="secrets",
        title="Live API Key in Tests",
        file="tests/test_client.py",
        line=10,
        cwe="CWE-798",
        severity=9.0,
        exposure="TEST",
    )
    calculate_finding_risk_score(f)
    assert "s=0.80" in f.explanation
    assert f.risk_score > 30.0

