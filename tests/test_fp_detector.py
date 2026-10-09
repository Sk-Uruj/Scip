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


def test_sql_fp_imported_request_rejected(tmp_path):
    """Imported request object inside an f-string must evaluate as UNSAFE (fail-closed)."""
    code = """from flask import request

def get_data():
    cur.execute(f"SELECT * FROM users WHERE id = {request.args['col']}")
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL injection",
        file="app.py",
        line=4,
        cwe="CWE-89",
        severity=9.0,
        evidence="cur.execute(f\"SELECT * FROM users WHERE id = {request.args['col']}\")",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


def test_sql_fp_attribute_chain_rejected(tmp_path):
    """Attribute chains like request.json.column or flask.request.args must NOT evaluate as safe."""
    code = """def update_data():
    cur.execute(f"UPDATE users SET col = {request.json.column}")
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL injection",
        file="app.py",
        line=2,
        cwe="CWE-89",
        severity=9.0,
        evidence="cur.execute(f\"UPDATE users SET col = {request.json.column}\")",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


def test_sql_fp_string_concatenation_rejected(tmp_path):
    """String concatenation with external user input must evaluate as UNSAFE."""
    code = """def search_user(user_input):
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="bandit",
        title="Bandit B608: Possible SQL injection vector through string-based query construction",
        file="app.py",
        line=2,
        cwe="CWE-89",
        severity=8.5,
        evidence="cur.execute(\"SELECT * FROM users WHERE name = '\" + user_input + \"'\")",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


def test_sql_fp_format_kwarg_rejected(tmp_path):
    """.format(col=user_input) keyword interpolation must evaluate as UNSAFE."""
    code = """def query_user(user_input):
    cur.execute("SELECT * FROM users WHERE name = '{col}'".format(col=user_input))
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="bandit",
        title="Bandit B608: SQL injection",
        file="app.py",
        line=2,
        cwe="CWE-89",
        severity=8.5,
        evidence="cur.execute(\"SELECT * FROM users WHERE name = '{col}'\".format(col=user_input))",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


def test_sql_fp_query_variable_built_elsewhere(tmp_path):
    """cur.execute(query) where query was built earlier must trace the query definition."""
    # Subtest A: unsafe query built earlier
    code_unsafe = """def run_query(user_col):
    query = "SELECT " + user_col + " FROM users"
    cur.execute(query)
"""
    (tmp_path / "unsafe.py").write_text(code_unsafe, encoding="utf-8")
    f_unsafe = Finding(
        engine="semgrep",
        title="SQL injection",
        file="unsafe.py",
        line=3,
        cwe="CWE-89",
        severity=8.5,
        evidence="cur.execute(query)",
    )
    detect_false_positives([f_unsafe], repo_path=str(tmp_path))
    assert f_unsafe.fp_likelihood is None

    # Subtest B: safe static DDL query built earlier
    code_safe = """def run_migration():
    query = "ALTER TABLE users ADD COLUMN age INT"
    cur.execute(query)
"""
    (tmp_path / "safe.py").write_text(code_safe, encoding="utf-8")
    f_safe = Finding(
        engine="semgrep",
        title="SQL injection",
        file="safe.py",
        line=3,
        cwe="CWE-89",
        severity=8.5,
        evidence="cur.execute(query)",
    )
    detect_false_positives([f_safe], repo_path=str(tmp_path))
    assert f_safe.fp_likelihood == "HIGH"


def test_sql_fp_picks_execute_over_adjacent_log_fstring(tmp_path):
    """The detector must evaluate the SQL execute call, not an adjacent logging f-string."""
    code = """import logging
logger = logging.getLogger(__name__)

def update_table(user_col):
    logger.info(f"Updating table with {user_col}")
    cur.execute(f"ALTER TABLE users ADD COLUMN {user_col} TEXT")
"""
    (tmp_path / "db.py").write_text(code, encoding="utf-8")
    f = Finding(
        engine="semgrep",
        title="SQL injection",
        file="db.py",
        line=6,
        cwe="CWE-89",
        severity=8.5,
        evidence='cur.execute(f"ALTER TABLE users ADD COLUMN {user_col} TEXT")',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood is None


def test_test_path_bandit_exec_not_mock_credential():
    """Bandit findings in tests/ like exec/pickle/shell must NOT be tagged as Mock test credential."""
    f = Finding(
        engine="bandit",
        title="Bandit B102: Use of exec detected",
        file="tests/test_dynamic.py",
        line=12,
        cwe="CWE-78",
        severity=7.5,
        evidence="exec(code_str)",
    )
    detect_false_positives([f])
    assert f.fp_likelihood is None


def test_intent_classifier_dockerized_labs(tmp_path):
    f = Finding(
        engine="bandit",
        title="Hardcoded password",
        file="dockerized_labs/lab1/vulnerable_app.py",
        line=10,
        cwe="CWE-259",
        severity=9.0,
        evidence="conn = connect(password='admin123')",
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert "Intent classified as training/example code" in f.fp_reason
    assert f.extra.get("damping_multiplier") == 0.1

def test_intent_classifier_vulnerable_comment(tmp_path):
    code = """
# intentionally vulnerable to SQL injection
def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    
    f = Finding(
        engine="bandit",
        title="SQL injection",
        file="app.py",
        line=4,
        cwe="CWE-89",
        severity=9.0,
        evidence='f"SELECT * FROM users WHERE id = {uid}"',
    )
    detect_false_positives([f], repo_path=str(tmp_path))
    assert f.fp_likelihood == "HIGH"
    assert "Intent classified as training/example code" in f.fp_reason
    assert f.extra.get("damping_multiplier") == 0.1
