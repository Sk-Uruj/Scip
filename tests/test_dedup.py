"""Tests for finding deduplication and alert correlation."""
from core.dedup import (
    _are_duplicates,
    _extract_keywords,
    _merge_pair,
    _norm_path,
    deduplicate_findings,
)
from core.finding import Finding


def test_norm_path():
    assert _norm_path("app\\main.py") == "app/main.py"
    assert _norm_path("./src/app.py") == "src/app.py"
    assert _norm_path("/root/test.py") == "root/test.py"


def test_extract_keywords():
    kw = _extract_keywords("Use of unsafe yaml load and eval injection")
    assert "yaml" in kw
    assert "eval" in kw
    assert "sql" not in kw


def test_are_duplicates_same_line_same_cwe():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load: Use of unsafe yaml",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is True


def test_are_duplicates_different_file():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load",
        file="other.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is False


def test_are_duplicates_different_lines():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load",
        file="app.py",
        line=95,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is False


def test_are_duplicates_keyword_match():
    f1 = Finding(
        engine="bandit",
        title="Call to requests without timeout",
        file="client.py",
        line=20,
        cwe="CWE-400",
        severity=4.5,
    )
    f2 = Finding(
        engine="custom",
        title="HTTP request has no timeout set",
        file="client.py",
        line=20,
        cwe=None,
        severity=5.0,
    )
    assert _are_duplicates(f1, f2) is True


def test_deduplicate_findings_merges_and_boosts():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
        exploitability=0.4,
        description="Short desc",
        fix_hint="Use safe_load",
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load: Use of unsafe yaml",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
        exploitability=0.75,
        description="Longer description with remediation details",
        fix_hint="Replace yaml.load with yaml.safe_load",
    )
    f3 = Finding(
        engine="bandit",
        title="Bandit B113: Call to requests without timeout",
        file="app.py",
        line=16,
        cwe="CWE-400",
        severity=4.5,
        exploitability=0.2,
    )

    merged = deduplicate_findings([f1, f2, f3])
    assert len(merged) == 2

    top = merged[0]
    assert top.line == 11
    # Severity should be max(5.5, 8.5) + 0.3 corroboration bonus = 8.8
    assert top.severity == 8.8
    assert top.exploitability == 0.75
    assert top.cwe == "CWE-502"
    assert top.extra["corroborated"] is True
    assert set(top.extra["corroborating_engines"]) == {"bandit", "semgrep"}
    assert top.extra["sources_count"] == 2

    # Second finding is untouched
    second = merged[1]
    assert second.line == 16
    assert second.extra["corroborated"] is False
    assert second.severity == 4.5


def test_dependency_findings_never_dedup_on_same_manifest_line():
    # Two distinct CVEs for the same dependency at the exact same line in requirements.txt
    f1 = Finding(
        engine="dependency",
        title="CVE-2024-53908 in django",
        file="requirements.txt",
        line=11,
        cwe="CWE-89",
        severity=9.0,
        extra={"vuln_id": "CVE-2024-53908"},
    )
    f2 = Finding(
        engine="dependency",
        title="CVE-2023-31047 in django",
        file="requirements.txt",
        line=11,
        cwe="CWE-20",
        severity=7.5,
        extra={"vuln_id": "CVE-2023-31047"},
    )
    res = deduplicate_findings([f1, f2])
    assert len(res) == 2
    assert {f.extra["vuln_id"] for f in res} == {"CVE-2024-53908", "CVE-2023-31047"}


def test_adjacent_line_distinct_secrets_do_not_merge():
    f1 = Finding(
        engine="secrets",
        title="Hardcoded user1 password",
        file="views.py",
        line=1164,
        cwe="CWE-798",
        extra={"fingerprint": "fp_user1_pwd"},
    )
    f2 = Finding(
        engine="secrets",
        title="Hardcoded user2 password",
        file="views.py",
        line=1165,
        cwe="CWE-798",
        extra={"fingerprint": "fp_user2_pwd"},
    )
    res = deduplicate_findings([f1, f2])
    assert len(res) == 2


def test_same_engine_findings_on_same_line_do_not_merge():
    # Two distinct Bandit checks on the same line
    f1 = Finding(
        engine="bandit",
        title="Bandit B602: subprocess with shell=True",
        file="challenge/views.py",
        line=45,
        cwe="CWE-78",
        extra={"test_id": "B602"},
    )
    f2 = Finding(
        engine="bandit",
        title="Bandit B603: subprocess without shell=True",
        file="challenge/views.py",
        line=45,
        cwe="CWE-78",
        extra={"test_id": "B603"},
    )
    res = deduplicate_findings([f1, f2])
    assert len(res) == 2


def test_history_secrets_do_not_dedup():
    f_hist = Finding(
        engine="secrets",
        title="Historical secret",
        file="app.py",
        line=10,
        cwe="CWE-798",
        extra={"in_working_tree": False},
    )
    f_active = Finding(
        engine="bandit",
        title="Active password",
        file="app.py",
        line=10,
        cwe="CWE-259",
    )
    res = deduplicate_findings([f_hist, f_active])
    assert len(res) == 2


def test_keyword_fallback_does_not_override_incompatible_cwes():
    # CWE-89 (SQLi) and CWE-259 (Hardcoded password) both mention "password" in description
    f1 = Finding(
        engine="bandit",
        title="SQL injection in password reset query",
        file="auth.py",
        line=30,
        cwe="CWE-89",
        description="User password query vulnerable to sql injection",
    )
    f2 = Finding(
        engine="secrets",
        title="Hardcoded password detected",
        file="auth.py",
        line=30,
        cwe="CWE-259",
        description="Plaintext password assigned in variable",
    )
    # They should NOT merge because both have known, distinct, incompatible CWEs
    res = deduplicate_findings([f1, f2])
    assert len(res) == 2


def test_line_none_does_not_merge():
    f1 = Finding(engine="bandit", title="Finding 1", file="app.py", line=None, cwe="CWE-78")
    f2 = Finding(engine="semgrep", title="Finding 2", file="app.py", line=None, cwe="CWE-78")
    res = deduplicate_findings([f1, f2])
    assert len(res) == 2


def test_bandit_b105_and_secrets_corroborate():
    # Bandit B105 (CWE-259) and Secrets engine (CWE-798) represent hardcoded credential family
    f_ban = Finding(
        engine="bandit",
        title="Bandit B105: Possible hardcoded password",
        file="settings.py",
        line=25,
        cwe="CWE-259",
        severity=7.5,
        extra={"test_id": "B105"},
    )
    f_sec = Finding(
        engine="secrets",
        title="Generic Secret",
        file="settings.py",
        line=25,
        cwe="CWE-798",
        severity=8.0,
        extra={"rule": "secret-key"},
    )
    res = deduplicate_findings([f_ban, f_sec])
    assert len(res) == 1
    assert res[0].extra["corroborated"] is True
    assert set(res[0].extra["corroborating_engines"]) == {"bandit", "secrets"}
    assert "B105" in res[0].extra["all_rules"]


def test_three_engine_merge_preserves_all_rules():
    f_bandit = Finding(
        engine="bandit",
        title="Bandit B105: Hardcoded password",
        file="config.py",
        line=15,
        cwe="CWE-259",
        severity=7.0,
        extra={"test_id": "B105"},
    )
    f_semgrep = Finding(
        engine="semgrep",
        title="Semgrep: Hardcoded API secret",
        file="config.py",
        line=15,
        cwe="CWE-798",
        severity=8.0,
        extra={"check_id": "rules.python.hardcoded-token"},
    )
    f_secrets = Finding(
        engine="secrets",
        title="Secrets: High-entropy secret token",
        file="config.py",
        line=15,
        cwe="CWE-798",
        severity=7.5,
        extra={"rule": "secret-token-rule"},
    )

    res = deduplicate_findings([f_bandit, f_semgrep, f_secrets])
    assert len(res) == 1
    merged = res[0]
    assert set(merged.extra["corroborating_engines"]) == {"bandit", "semgrep", "secrets"}
    assert merged.extra["corroborated"] is True
    assert set(merged.extra["all_rules"]) == {"B105", "rules.python.hardcoded-token", "secret-token-rule"}
    assert len(merged.extra["sources"]) == 3
    # Semgrep wins due to highest severity
    assert merged.engine == "semgrep"


def test_candidate_shallow_copy_safety():
    original_extra = {"test_id": "B105"}
    f = Finding(
        engine="bandit",
        title="Password",
        file="config.py",
        line=10,
        cwe="CWE-259",
        extra=dict(original_extra),
    )
    res = deduplicate_findings([f])
    assert len(res) == 1
    # Mutating merged extra must not mutate original finding's extra dict
    assert "corroborating_engines" in res[0].extra
    assert "corroborating_engines" not in original_extra


def test_unrecognized_cwe_string_triggers_keyword_fallback():
    from core.dedup import _are_duplicates

    # One side has NVD-CWE-Other and the other has None, with matching vulnerability keyword 'timeout'
    f1 = Finding(
        engine="bandit",
        title="Call to requests without timeout",
        file="client.py",
        line=20,
        cwe="NVD-CWE-Other",
        severity=4.5,
    )
    f2 = Finding(
        engine="custom",
        title="HTTP request has no timeout configured",
        file="client.py",
        line=20,
        cwe=None,
        severity=5.0,
    )
    assert _are_duplicates(f1, f2) is True


def test_crypto_hash_cwe327_and_cwe328_compatibility():
    f1 = Finding(
        engine="bandit",
        title="Bandit B324: Use of weak MD5 hash for security",
        file="helpers.py",
        line=76,
        cwe="CWE-327",
        severity=8.8,
    )
    f2 = Finding(
        engine="crypto",
        title="Use of broken hash algorithm MD5",
        file="helpers.py",
        line=76,
        cwe="CWE-328",
        severity=7.0,
    )
    assert _are_duplicates(f1, f2) is True

    res = deduplicate_findings([f1, f2])
    assert len(res) == 1
    assert res[0].extra.get("corroborated") is True
    assert set(res[0].extra.get("corroborating_engines")) == {"bandit", "crypto"}

