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

    # Risk score must be damped by 0.2x
    calculate_finding_risk_score(f)
    assert "FP Damped" in f.explanation


def test_detect_ddl_migration_sql_false_positive(tmp_path):
    code = """def migrate():
    MIGRATIONS = [("status", "TEXT"), ("retries", "INTEGER")]
    for col_name, col_def in MIGRATIONS:
        cur.execute(f"ALTER TABLE files ADD COLUMN {col_name} {col_def}")
"""
    (tmp_path / "init_db.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL query with formatted string",
        file="init_db.py",
        line=4,
        cwe="CWE-89",
        severity=8.5,
        evidence='cur.execute(f"ALTER TABLE files ADD COLUMN {col_name} {col_def}")',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert "DDL schema migration" in f.fp_reason


def test_detect_whitelisted_sql_identifier_false_positive(tmp_path):
    code = """DEMOTION_CHAIN = [("HOT", "COOL", 120)]
def manage_tiers():
    for from_tier, to_tier, _ in DEMOTION_CHAIN:
        entered_col = f"{to_tier.lower()}_entered_at"
        conn.execute(f"UPDATE files SET {entered_col} = ?", (to_tier,))
"""
    (tmp_path / "tiering_engine.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL query with formatted string",
        file="tiering_engine.py",
        line=5,
        cwe="CWE-89",
        severity=8.5,
        evidence="UPDATE files SET {entered_col} = ?",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert "whitelisted" in f.fp_reason


def test_sql_fp_adversarial_request_field(tmp_path):
    """Adversarial check: dynamic SQL using request parameters must NEVER be flagged as FP."""
    code = """def update_record(request):
    col_name = request.json.get("column_name")
    cur.execute(f"ALTER TABLE files ADD COLUMN {col_name} TEXT")
"""
    (tmp_path / "api.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL query with formatted string",
        file="api.py",
        line=3,
        cwe="CWE-89",
        severity=8.5,
        evidence='cur.execute(f"ALTER TABLE files ADD COLUMN {col_name} TEXT")',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


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


def test_test_path_live_provider_key_exempt():
    """Live provider-format keys in test paths must NOT be blanket-damped as FP."""
    f = Finding(
        engine="secrets",
        title="AWS Access Key ID",
        file="tests/conftest.py",
        line=10,
        cwe="CWE-798",
        severity=8.5,
        evidence='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        extra={"is_provider_token": True, "provider_prefix": "AKIA"},
    )
    detect_false_positives([f])
    assert f.fp_likelihood is None


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
    code = """if os.getenv("DEBUG"):
    SEED_USERS = [
        {"username": "alice_dev", "password": "alice123"},
    ]
"""
    db_file = tmp_path / "init_db.py"
    db_file.write_text(code, encoding="utf-8")

    f = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="init_db.py",
        line=3,
        cwe="CWE-259",
        severity=6.3,
        evidence='{"username": "alice_dev", "password": "alice123"}',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert f.extra.get("seed_classification") == "SEED"
    assert "Guarded seed fixture" in f.extra.get("guard_note", "")
    assert "seed_guards" not in f.extra
    assert "is_seed_fixture" not in f.extra
    assert f.extra.get("damping_multiplier") == 0.20
    assert "seed credentials" in f.fp_reason.lower()


def test_carol_prod_and_bob_staging_never_damped(tmp_path):
    """Ungated migration with production or staging users must fail seed guards and NOT be damped."""
    code = """def seed_users():
    SEED_USERS = [
        {"username": "carol_prod", "password": "carol_prod_secret!"},
        {"username": "bob_staging", "password": "bob_staging_secret!"},
    ]
"""
    db_file = tmp_path / "init_db.py"
    db_file.write_text(code, encoding="utf-8")

    f_carol = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="init_db.py",
        line=3,
        cwe="CWE-259",
        severity=7.5,
        evidence='{"username": "carol_prod", "password": "carol_prod_secret!"}',
    )
    detect_false_positives([f_carol], repo_path=str(tmp_path))
    # Must fail env guard and gating guard -> at most 2 guards pass -> NOT damped
    assert f_carol.fp_likelihood is None
    assert f_carol.extra.get("seed_classification") == "NOT_SEED"
    assert "Unguarded credential" in f_carol.extra.get("guard_note", "")
    assert "env=False" in f_carol.extra.get("guard_note", "")
    assert "gate=False" in f_carol.extra.get("guard_note", "")
    assert "seed_guards" not in f_carol.extra
    assert "is_seed_fixture" not in f_carol.extra
    assert f_carol.extra.get("damping_multiplier") == 1.0


def test_demo_value_guard_rejects_8char_random(tmp_path):
    """An 8-character random password must fail demo value guard despite low Shannon entropy."""
    code = """if os.getenv("DEBUG"):
    SEED_USERS = [
        {"username": "alice_dev", "password": "k8#mP9$x"},
    ]
"""
    db_file = tmp_path / "init_db.py"
    db_file.write_text(code, encoding="utf-8")

    f = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="init_db.py",
        line=3,
        cwe="CWE-259",
        severity=8.0,
        evidence='{"username": "alice_dev", "password": "k8#mP9$x"}',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    # Fails demo value guard because k8#mP9$x is not in demo wordlist or pattern
    # Passes env, gate, cross (3/4 guards) -> at best MEDIUM mild damping, NOT HIGH
    assert f.fp_likelihood == "MEDIUM"
    assert f.extra.get("seed_classification") == "SEED"
    assert "3/4 guards passed" in f.extra.get("guard_note", "")
    assert "demo=False" in f.extra.get("guard_note", "")
    assert f.extra.get("damping_multiplier") == 0.60


def test_seed_value_in_config_fails_cross_file_guard(tmp_path):
    """If a seed secret value appears in config.py or .env, cross-file guard fails and it is NOT damped."""
    init_code = """if os.getenv("DEBUG"):
    ADMIN_DEV_TOKEN = "testpass123"
"""
    (tmp_path / "init_db.py").write_text(init_code, encoding="utf-8")

    config_code = """# Production configuration
AUTH_SECRET = "testpass123"
"""
    (tmp_path / "config.py").write_text(config_code, encoding="utf-8")

    f = Finding(
        engine="secrets",
        title="Hard-coded password",
        file="init_db.py",
        line=2,
        cwe="CWE-259",
        severity=7.0,
        evidence='ADMIN_DEV_TOKEN = "testpass123"',
        extra={"variable": "ADMIN_DEV_TOKEN"},
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    # Secret value is leaked into config.py, cross-file guard fails.
    # Because env and cross are strictly mandatory, it fails and is NOT damped.
    assert f.fp_likelihood is None
    assert f.extra.get("seed_classification") == "NOT_SEED"
    assert "cross=False" in f.extra.get("guard_note", "")
    assert f.extra.get("damping_multiplier") == 1.0


def test_prng_context_token_vs_ref_id():
    """Security tokens remain full severity; transaction reference IDs receive [REF-ID] tag."""
    f_token = Finding(
        engine="bandit",
        title="Bandit B311: Standard pseudo-random generators not suitable for security",
        file="auth.py",
        line=50,
        cwe="CWE-330",
        severity=6.5,
        evidence="session_token = ''.join(random.choices(chars, k=32))",
    )
    detect_false_positives([f_token])
    assert f_token.extra.get("is_ref_id") is not True

    f_ref = Finding(
        engine="bandit",
        title="Bandit B311: Standard pseudo-random generators not suitable for security",
        file="payments.py",
        line=120,
        cwe="CWE-330",
        severity=6.5,
        evidence="payment_ref_id = 'PAY-' + ''.join(random.choices(chars, k=8))",
    )
    detect_false_positives([f_ref])
    assert f_ref.extra.get("is_ref_id") is True
    assert "[REF-ID]" in f_ref.title


def test_prng_otp_and_reset_code_retains_security_priority():
    """reset_code, verification_code, and otp must retain security classification and never be tagged [REF-ID]."""
    f = Finding(
        engine="bandit",
        title="Bandit B311: Standard pseudo-random generators not suitable for security",
        file="auth.py",
        line=85,
        cwe="CWE-330",
        severity=6.5,
        evidence="reset_code = ''.join(random.choices(string.digits, k=6))",
    )
    detect_false_positives([f])
    assert f.extra.get("is_ref_id") is not True
    assert f.extra.get("is_security_token") is True
    assert "[REF-ID]" not in f.title
