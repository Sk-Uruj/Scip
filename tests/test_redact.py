"""Credential values must never appear in a report, whichever engine found them."""
import json

import pytest

from core.finding import Finding
from core.pipeline import run_scan
from core.redact import redact_finding
from engines.bandit_engine import BanditEngine
from tests import fake_secrets as fs


def dump(findings):
    return json.dumps([f.to_dict() for f in findings])


def bandit_b105(literal="xy7"):
    return Finding(
        engine="bandit", title=f"Bandit B105: Possible hardcoded password: '{literal}'",
        file="app.py", line=3, cwe="CWE-259", severity=5.0,
        description=f"Possible hardcoded password: '{literal}'",
        evidence=f'2 def f():\n3     password = "{literal}"\n4     return password',
        fix_hint="Move the password to an environment variable.",
        extra={"test_id": "B105", "issue_text": f"Possible hardcoded password: '{literal}'"})


@pytest.mark.parametrize("literal", ["xy7", "hunter22pass", "Tr0ub4dor&3xyz", "a-much-longer-passphrase-value"])
def test_bandit_style_finding_is_masked_everywhere(literal):
    f = redact_finding(bandit_b105(literal))
    assert literal not in dump([f])
    assert "password" in f.evidence                       # context is kept
    assert f.extra["redacted"] is True


def test_masking_is_idempotent():
    once = redact_finding(bandit_b105())
    snapshot = json.dumps(once.to_dict())
    assert json.dumps(redact_finding(once).to_dict()) == snapshot


def test_non_credential_findings_are_left_alone():
    f = Finding(engine="bandit", title="Bandit B324: Use of weak MD5 hash", file="a.py", line=1,
                cwe="CWE-327", description="Use of weak MD5 hash for security.",
                evidence='1 h = hashlib.md5(b"hello world").hexdigest()', extra={"test_id": "B324"})
    before = f.to_dict()
    assert redact_finding(f).to_dict() == before


def test_secrets_engine_findings_are_skipped():
    f = Finding(engine="secrets", title="Hard-coded secret", file="a.py", line=1, evidence='K = "ghp_****"')
    assert redact_finding(f).evidence == 'K = "ghp_****"'


def test_placeholders_in_credential_evidence_stay_readable():
    f = Finding(engine="semgrep", title="Semgrep hardcoded-secret", file="a.py", line=1, cwe="CWE-798",
                evidence='API_KEY = "your_api_key_here"')
    assert redact_finding(f).evidence == 'API_KEY = "your_api_key_here"'


def test_long_random_token_next_to_a_credential_finding_is_scrubbed():
    tok = fs.random_token(5, 48)
    f = bandit_b105("xy7")
    f.evidence = f'password = "xy7"  # backup key {tok}'
    out = redact_finding(f)
    assert tok not in out.evidence and "xy7" not in out.evidence


def test_semgrep_metavars_in_extra_are_masked():
    f = Finding(engine="semgrep", title="Semgrep hardcoded-password", file="a.py", line=1, cwe="CWE-798",
                evidence='password = "hunter22pass"',
                extra={"check_id": "x", "metavars": {"$PASS": {"abstract_content": "hunter22pass"}}})
    out = redact_finding(f)
    assert "hunter22pass" not in dump([out])


# ---- end to end with the real Bandit and the real pipeline (regression for the reported leak) ----
@pytest.mark.skipif(not BanditEngine().is_available(), reason="bandit not installed")
def test_real_bandit_run_never_prints_the_literal(tmp_path):
    values = ["xy7", "k3j", "p9q", "Tr0ub4dor&3xyz"]
    (tmp_path / "app.py").write_text(
        f'password = "{values[0]}"\nADMIN_TOKEN = "{values[1]}"\n'
        f'def connect(passwd="{values[2]}"):\n    pass\nDB_PASSWORD = "{values[3]}"\n', encoding="utf-8")
    findings = BanditEngine().scan(str(tmp_path))
    assert len(findings) >= 3
    blob = dump(findings)
    for v in values:
        assert v not in blob, f"raw credential {v!r} leaked"


@pytest.mark.skipif(not BanditEngine().is_available(), reason="bandit not installed")
def test_full_pipeline_output_never_prints_the_literal(tmp_path):
    (tmp_path / "app.py").write_text('password = "xy7"\nADMIN_TOKEN = "k3j"\n', encoding="utf-8")
    findings = run_scan(str(tmp_path), engines=[BanditEngine()], scoring=False)
    assert findings
    blob = dump(findings)
    assert "xy7" not in blob and "k3j" not in blob


def test_neighbouring_credential_line_in_another_findings_snippet_is_masked():
    """Bandit prints context lines. An MD5 warning whose snippet includes a password line
    used to carry that password into the report."""
    f = Finding(engine="bandit", title="Bandit B324: Use of weak MD5 hash", file="a.py", line=2, cwe="CWE-327",
                description="Use of weak MD5 hash for security.", extra={"test_id": "B324"},
                evidence='1 password = "hunter22pass"\n2 h = hashlib.md5(data).hexdigest()\n3 api_key = "k3j"')
    out = redact_finding(f)
    assert "hunter22pass" not in out.evidence and "k3j" not in out.evidence
    assert "hashlib.md5(data)" in out.evidence                   # the finding itself stays readable


@pytest.mark.parametrize("line", ['connect(passwd="p9q")', '{"password": "p9q"}', "secret_key = 'p9q'",
                                  'self.token = "p9q"'])
def test_assignment_styles_are_all_covered(line):
    f = Finding(engine="semgrep", title="Semgrep something", file="a.py", line=1, evidence=line)
    assert "p9q" not in redact_finding(f).evidence
