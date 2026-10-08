"""Tests for automated false-positive detection heuristics."""
from core.finding import Finding
from core.fp_detector import detect_false_positives
from scoring.risk_score import calculate_finding_risk_score


def test_detect_s3_etag_false_positive():
    f = Finding(
        engine="bandit",
        title="Bandit B324: Use of weak MD5 hash for security",
        file="helpers.py",
        line=76,
        cwe="CWE-327",
        severity=8.8,
        description="compute_etag calculates AWS S3 ETag hash",
        evidence="return hashlib.md5(contents).hexdigest()",
    )
    detect_false_positives([f])
    assert f.fp_likelihood == "HIGH"
    assert "S3 ETag" in f.fp_reason

    # Risk score must be damped by 0.4x
    calculate_finding_risk_score(f)
    assert "FP Damped" in f.explanation


def test_detect_ddl_migration_sql_false_positive():
    f = Finding(
        engine="semgrep",
        title="SQL query with formatted string",
        file="init_db.py",
        line=202,
        cwe="CWE-89",
        severity=8.5,
        evidence='cur.execute(f"ALTER TABLE files ADD COLUMN {col_name} {col_def}")',
    )
    detect_false_positives([f])
    assert f.fp_likelihood == "HIGH"
    assert "DDL schema migration" in f.fp_reason


def test_detect_whitelisted_sql_identifier_false_positive():
    f = Finding(
        engine="semgrep",
        title="SQL query with formatted string",
        file="tiering_engine.py",
        line=179,
        cwe="CWE-89",
        severity=8.5,
        evidence="UPDATE files SET {entered_col} = ?",
    )
    detect_false_positives([f])
    assert f.fp_likelihood == "HIGH"
    assert "whitelisted" in f.fp_reason


def test_detect_test_fixture_secret_false_positive():
    f = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="tests/test_auth.py",
        line=45,
        cwe="CWE-259",
        severity=7.5,
        evidence='password = "testpass123"',
    )
    detect_false_positives([f])
    assert f.fp_likelihood == "HIGH"
    assert "Mock test credential" in f.fp_reason


def test_true_positive_not_flagged_as_fp():
    # Insecure PRNG in payment transaction generation
    f = Finding(
        engine="bandit",
        title="Bandit B311: Standard pseudo-random generators not suitable for security",
        file="main.py",
        line=404,
        cwe="CWE-330",
        severity=6.5,
        evidence="random.choices(string.ascii_uppercase + string.digits, k=8)",
    )
    detect_false_positives([f])
    assert f.fp_likelihood is None


def test_detect_s3_etag_via_ast_enclosing_function(tmp_path):
    code = """def compute_etag(contents: bytes) -> str:
    # generic line without keyword
    return hashlib.md5(contents).hexdigest()
"""
    helper_file = tmp_path / "helpers.py"
    helper_file.write_text(code, encoding="utf-8")

    f = Finding(
        engine="bandit",
        title="Bandit B324: Use of weak hash",
        file="helpers.py",
        line=3,
        cwe="CWE-327",
        severity=8.8,
        description="Weak hash used.",
        evidence="return hashlib.md5(contents).hexdigest()",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert "S3 ETag" in f.fp_reason


def test_detect_seed_data_credentials_fixture(tmp_path):
    code = """SEED_USERS = [
    {"username": "alice_dev", "password": "alice123"},
]
"""
    db_file = tmp_path / "init_db.py"
    db_file.write_text(code, encoding="utf-8")

    f = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="init_db.py",
        line=2,
        cwe="CWE-259",
        severity=6.3,
        evidence='{"username": "alice_dev", "password": "alice123"}',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert f.extra.get("is_seed_fixture") is True
    assert "seed credentials" in f.fp_reason.lower()

