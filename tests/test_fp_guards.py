"""The false-positive detector must only demote findings it has real evidence for."""
import textwrap

import pytest

from core.finding import Finding
from core.fp_detector import detect_false_positives


def weak_hash(tmp_path, code, line):
    (tmp_path / "a.py").write_text(textwrap.dedent(code), encoding="utf-8")
    f = Finding(engine="bandit", title="Bandit B324: Use of weak MD5 hash for security", file="a.py", line=line,
                cwe="CWE-327", description="Use of weak MD5 hash for security.", severity=8.8,
                evidence="md5 call", extra={"test_id": "B324"})
    detect_false_positives([f], repo_path=str(tmp_path))
    return f


def test_genuine_etag_is_still_a_false_positive(tmp_path):
    f = weak_hash(tmp_path, '''
        import hashlib

        def file_etag(contents):
            """Return the S3-style ETag for these bytes."""
            return hashlib.md5(contents).hexdigest()
    ''', 5)
    assert f.fp_likelihood == "HIGH" and "ETag" in f.fp_reason


@pytest.mark.parametrize("name,code,line", [
    ("comment mentions etag", '''
        import hashlib
        def hash_password(password):
            # compute_etag helper, S3 ETag convention (RFC 7232)
            return hashlib.md5(password.encode()).hexdigest()
    ''', 5),
    ("function is named compute_etag", '''
        import hashlib
        def compute_etag(password):
            return hashlib.md5(password.encode()).hexdigest()
    ''', 4),
    ("docstring says 'Not an ETag'", '''
        import hashlib
        def store_credentials(user_password):
            """Hash the user's password. Not an ETag."""
            return hashlib.md5(user_password.encode()).hexdigest()
    ''', 5),
    ("taint: data derived from user.password", '''
        import hashlib
        def checksum_for(user):
            # S3 ETag convention
            data = user.password.encode()
            return hashlib.md5(data).hexdigest()
    ''', 6),
    ("camelCase sensitive name", '''
        import hashlib
        def etag(userPassword):
            return hashlib.md5(userPassword.encode()).hexdigest()
    ''', 4),
    ("api key", '''
        import hashlib
        def etag(api_key):
            return hashlib.md5(api_key.encode()).hexdigest()
    ''', 4),
])
def test_etag_words_never_excuse_hashing_a_credential(tmp_path, name, code, line):
    f = weak_hash(tmp_path, code, line)
    assert f.fp_likelihood is None, f"{name}: wrongly demoted ({f.fp_reason})"
    assert "credential-like" in f.extra.get("fp_guard", "")


def test_non_sensitive_identifiers_that_contain_auth_or_key_are_not_blocked(tmp_path):
    """'author' contains 'auth', 'cache_key' contains 'key': neither is credential data."""
    f = weak_hash(tmp_path, '''
        import hashlib
        def etag(author_name, cache_key):
            return hashlib.md5((author_name + cache_key).encode()).hexdigest()
    ''', 4)
    assert f.fp_likelihood == "HIGH"


@pytest.mark.parametrize("extra,engine", [({"kev": True}, "dependency"),
                                          ({"rule": "github-token"}, "secrets")])
def test_protected_findings_can_never_be_demoted(extra, engine):
    f = Finding(engine=engine, title="x", file="a.py", line=1, severity=9.0, extra=dict(extra))
    f.fp_likelihood, f.fp_reason = "HIGH", "set by an earlier rule"
    f.extra.update(fp_likelihood="HIGH", fp_reason="set by an earlier rule", damping_multiplier=0.1)
    detect_false_positives([f], repo_path=None)
    assert f.fp_likelihood is None and "damping_multiplier" not in f.extra
    assert "not demoted" in f.extra["fp_blocked"]


def test_unprotected_findings_keep_their_demotion():
    f = Finding(engine="bandit", title="x", file="a.py", line=1, extra={})
    f.fp_likelihood, f.fp_reason = "MEDIUM", "internal only"
    detect_false_positives([f], repo_path=None)
    assert f.fp_likelihood == "MEDIUM"
