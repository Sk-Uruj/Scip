"""Tests for the secrets engine. All 'secrets' are fake and generated at runtime."""
import json
import os
import shutil
import subprocess

import pytest

from engines.secrets_engine import (
    SecretsEngine,
    fingerprint,
    is_placeholder,
    mask_secret,
    scan_lines,
    shannon_entropy,
)
from tests import fake_secrets as fs

HAS_GIT = shutil.which("git") is not None


# ------------------------------------------------------------------ helpers --
def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def scan(root, **kw):
    kw.setdefault("scan_history", False)
    return SecretsEngine(**kw).scan(str(root))


def rules(findings):
    return {f.extra["rule"] for f in findings}


def git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "Tester", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "Tester", "GIT_COMMITTER_EMAIL": "t@example.org"}
    subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True, env=env)


def commit_all(repo, msg):
    git(repo, "add", "-A")
    git(repo, "commit", "-m", msg)


def new_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    return path


# ------------------------------------------------------------- unit helpers --
def test_entropy_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy(fs.random_token()) > 4.5
    assert shannon_entropy("passwordpassword") < 3.1


def test_masking_never_reveals_much():
    assert mask_secret("abc") == "a**"
    key = fs.aws_access_key_id()               # built at runtime: no AWS-shaped literal in the source
    m = mask_secret(key)
    assert m.startswith("AKIA****") and "20 chars" in m and key[-4:] not in m


def test_fingerprint_is_stable_and_short():
    assert fingerprint("x") == fingerprint("x") != fingerprint("y")
    assert len(fingerprint("x")) == 16


@pytest.mark.parametrize("v", ["changeme", "your_api_key_here", "<password>", "${DB_PASS}", "xxxxxxxx",
                               "password", "{{ secret }}", "****", "os.environ['X']", "REPLACE_ME",
                               "%(password)s", "example-token"])
def test_placeholders(v):
    assert is_placeholder(v)


@pytest.mark.parametrize("v", ["Tr0ub4dor&3", "hunter22", fs.strong_password()])
def test_non_placeholders(v):
    assert not is_placeholder(v)


# ------------------------------------------------------------ provider rules --
PROVIDER_CASES = [
    ("aws-access-key-id", lambda: f'AWS_KEY = "{fs.aws_access_key_id()}"'),
    ("aws-secret-access-key", lambda: f'aws_secret_access_key = "{fs.aws_secret_key()}"'),
    ("github-token", lambda: f'token: {fs.github_token()}'),
    ("stripe-live-key", lambda: f'stripe.api_key = "{fs.stripe_live_key()}"'),
    ("google-api-key", lambda: f'KEY="{fs.google_api_key()}"'),
    ("slack-token", lambda: f'SLACK = "{fs.slack_token()}"'),
    ("anthropic-key", lambda: f'client = Anthropic(api_key="{fs.anthropic_key()}")'),
    ("jwt", lambda: f'Authorization = "Bearer {fs.jwt()}"'),
]


@pytest.mark.parametrize("rule_id,make_line", PROVIDER_CASES)
def test_provider_rule_detects_and_masks(tmp_path, rule_id, make_line):
    line = make_line()
    write(tmp_path, "app.py", line + "\n")
    findings = scan(tmp_path)
    assert rule_id in rules(findings), f"{rule_id} not detected in: {rules(findings)}"
    # the raw secret must never appear anywhere in the serialised findings
    blob = json.dumps([f.to_dict() for f in findings])
    secret_part = line.split('"')[1] if '"' in line else line.split()[-1]
    assert secret_part not in blob


def test_private_key_detected_with_cwe_321_and_distinct_keys(tmp_path):
    write(tmp_path, "keys/a.pem", fs.private_key_pem(1))
    write(tmp_path, "keys/b.pem", fs.private_key_pem(2))
    findings = [f for f in scan(tmp_path) if f.extra["rule"] == "private-key"]
    assert len(findings) == 2                      # two different keys are two findings
    assert all(f.cwe == "CWE-321" for f in findings)
    assert all(f.severity >= 9.0 for f in findings)
    body_line = fs.private_key_pem(1).splitlines()[1]
    assert body_line not in json.dumps([f.to_dict() for f in findings])


def test_db_url_password_detected_and_only_password_masked(tmp_path):
    write(tmp_path, "settings.py", 'DATABASE_URL = "postgres://admin:S3cretPw99@db.internal:5432/app"\n')
    f = scan(tmp_path)[0]
    assert f.extra["rule"] == "db-url-password"
    assert "S3cretPw99" not in json.dumps(f.to_dict())
    assert "db.internal" in f.evidence


def test_db_url_with_placeholder_not_flagged(tmp_path):
    write(tmp_path, "a.py", 'U = "postgres://user:${DB_PASS}@host/db"\nV = "postgres://user:password@host/db"\n')
    assert scan(tmp_path) == []


# ---------------------------------------------------------- generic + entropy --
def test_generic_password_assignment_variants(tmp_path):
    pw = fs.strong_password()
    write(tmp_path, "a.py",
          f'DB_PASSWORD = "{pw}"\n'
          f"app.config['SECRET_KEY'] = '{fs.random_token(21, 50)}'\n"
          f'creds = {{"password": "{fs.strong_password(22)}"}}\n')
    found = scan(tmp_path)
    assert len(found) == 3
    assert {f.line for f in found} == {1, 2, 3}
    assert all(f.extra["rule"] in ("generic-password", "generic-secret") for f in found)
    pw_f = next(f for f in found if f.line == 1)
    assert pw_f.cwe == "CWE-259" and pw_f.extra["variable"] == "DB_PASSWORD"


def test_weak_default_password_is_low_confidence(tmp_path):
    write(tmp_path, "a.py", 'password = "admin"\n')
    f = scan(tmp_path)[0]
    assert f.extra["confidence"] == "low" and f.severity < 5


def test_strong_random_secret_is_high_confidence(tmp_path):
    write(tmp_path, "a.py", f'SECRET_KEY = "{fs.random_token(30, 50)}"\n')
    f = scan(tmp_path)[0]
    assert f.extra["confidence"] == "high" and f.severity >= 7.5


@pytest.mark.parametrize("line", [
    'password = os.environ["DB_PASSWORD"]',
    'password = request.form["password"]',
    'API_KEY = "your_api_key_here"',
    'password = getpass.getpass("Enter password: ")',
    'password_field = "password"',
    'token_url = "https://example.com/oauth/token"',
    'error_message_password = "The password you entered is wrong"',
    'secret = "${SECRET}"',
    'if password == "x":',
    'password = ""',
    'PASSWORD_LABEL = "Enter your password"',
])
def test_safe_lines_are_not_flagged(tmp_path, line):
    write(tmp_path, "a.py", line + "\n")
    assert scan(tmp_path) == []


def test_unquoted_values_only_in_config_files(tmp_path):
    write(tmp_path, ".env", "DB_PASSWORD=hunter22hunter\nDEBUG=true\n")
    write(tmp_path, "config.yml", "db:\n  password: Sup3rS3cretValue\n  host: localhost\n")
    write(tmp_path, "code.py", "password = hunter22hunter\n")      # invalid python, unquoted -> ignored
    found = scan(tmp_path)
    assert {f.file for f in found} == {".env", "config.yml"}


def test_high_entropy_string_flagged_but_hashes_are_not(tmp_path):
    write(tmp_path, "a.py", f'blob = "{fs.random_token(40, 48)}"\n')
    write(tmp_path, "b.py", 'sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"\n')
    write(tmp_path, "c.html", f'<script integrity="{fs.random_token(41, 48)}"></script>\n')
    found = scan(tmp_path)
    assert [f.file for f in found] == ["a.py"]
    assert found[0].extra["rule"] == "high-entropy-string" and found[0].extra["confidence"] == "low"


def test_entropy_can_be_disabled(tmp_path):
    write(tmp_path, "a.py", f'blob = "{fs.random_token(40, 48)}"\n')
    assert scan(tmp_path, use_entropy=False) == []


def test_inline_suppression(tmp_path):
    write(tmp_path, "a.py", f'K = "{fs.aws_access_key_id()}"  # scip:ignore\n')
    assert scan(tmp_path) == []


def test_provider_rule_wins_over_generic_for_same_secret(tmp_path):
    write(tmp_path, "a.py", f'github_token = "{fs.github_token()}"\n')
    found = scan(tmp_path)
    assert len(found) == 1 and found[0].extra["rule"] == "github-token"


# ----------------------------------------------------------- files & dedupe --
def test_same_secret_in_two_files_is_one_finding_with_two_locations(tmp_path):
    tok = fs.github_token()
    write(tmp_path, "a.py", f'T="{tok}"\n')
    write(tmp_path, "sub/b.py", f'\n\nX="{tok}"\n')
    found = scan(tmp_path)
    assert len(found) == 1
    assert {(l["file"], l["line"]) for l in found[0].extra["locations"]} == {("a.py", 1), ("sub/b.py", 3)}


def test_skips_binary_vendor_dirs_lockfiles_and_big_files(tmp_path):
    tok = fs.github_token()
    write(tmp_path, "node_modules/x/index.js", f'var t="{tok}"\n')
    write(tmp_path, "venv/lib/a.py", f'T="{tok}"\n')
    write(tmp_path, "poetry.lock", f'T="{tok}"\n')
    write(tmp_path, "vendor.min.js", f'T="{tok}"\n')
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01" + tok.encode())
    write(tmp_path, "big.txt", f'T="{tok}"\n' + "a" * 2000)
    e = SecretsEngine(scan_history=False, max_file_size=1000)
    assert e.scan(str(tmp_path)) == []
    assert e.stats["files_skipped"] >= 2


def test_test_files_are_tagged(tmp_path):
    write(tmp_path, "tests/test_x.py", f'T="{fs.github_token()}"\n')
    write(tmp_path, "src/y.py", f'T="{fs.github_token(99)}"\n')
    by_file = {f.file: f for f in scan(tmp_path)}
    assert by_file["tests/test_x.py"].extra["is_test_file"] is True
    assert by_file["src/y.py"].extra["is_test_file"] is False


def test_scan_lines_reports_correct_line_numbers():
    lines = [(10, "x = 1"), (11, f'K = "{fs.aws_access_key_id()}"'), (12, "y = 2")]
    m = scan_lines(lines, "a.py")
    assert [x.line for x in m] == [11]
    assert fs.aws_access_key_id() not in m[0].masked_line


# ------------------------------------------------------------ git history --
pytestmark_git = pytest.mark.skipif(not HAS_GIT, reason="git not installed")


@pytestmark_git
def test_secret_deleted_from_files_is_still_found_in_history(tmp_path):
    repo = new_repo(tmp_path / "r")
    tok = fs.github_token()
    write(repo, "app.py", "x = 1\ny = 2\n" + f'TOKEN = "{tok}"\n')
    commit_all(repo, "add token")
    write(repo, "app.py", 'import os\nTOKEN = os.environ["TOKEN"]\n')
    commit_all(repo, "use env var")

    now = scan(repo)                                    # history off
    assert now == []

    found = SecretsEngine(scan_history=True).scan(str(repo))
    assert len(found) == 1
    f = found[0]
    assert f.extra["in_history"] and not f.extra["in_working_tree"]
    assert f.title.startswith("Secret in git history")
    assert f.file == "app.py" and f.line == 3           # line number at the commit that added it
    assert f.extra["first_seen"]["author"] == "Tester"
    assert "rotate" in f.fix_hint.lower()
    assert tok not in json.dumps(f.to_dict())


@pytestmark_git
def test_secret_in_files_and_history_is_one_finding_with_both_flags(tmp_path):
    repo = new_repo(tmp_path / "r")
    tok = fs.github_token()
    write(repo, "app.py", f'T = "{tok}"\n')
    commit_all(repo, "oops")
    found = SecretsEngine().scan(str(repo))
    assert len(found) == 1
    assert found[0].extra["in_working_tree"] and found[0].extra["in_history"]
    assert found[0].title.startswith("Hard-coded secret")


@pytestmark_git
def test_uncommitted_secret_is_working_tree_only(tmp_path):
    repo = new_repo(tmp_path / "r")
    write(repo, "a.py", "x = 1\n")
    commit_all(repo, "init")
    write(repo, "new.py", f'T = "{fs.github_token()}"\n')           # never committed
    f = SecretsEngine().scan(str(repo))[0]
    assert f.extra["in_working_tree"] and not f.extra["in_history"]


@pytestmark_git
def test_deleted_private_key_file_found_in_history(tmp_path):
    repo = new_repo(tmp_path / "r")
    write(repo, "deploy/id_rsa", fs.private_key_pem())
    commit_all(repo, "add key")
    (repo / "deploy" / "id_rsa").unlink()
    commit_all(repo, "remove key")
    found = SecretsEngine().scan(str(repo))
    assert len(found) == 1 and found[0].extra["rule"] == "private-key"
    assert not found[0].extra["in_working_tree"]


@pytestmark_git
def test_history_only_looks_at_added_lines_not_context(tmp_path):
    repo = new_repo(tmp_path / "r")
    write(repo, "a.py", f'T = "{fs.github_token()}"\n')
    commit_all(repo, "c1")
    write(repo, "a.py", f'T = "{fs.github_token()}"\n# unrelated change\n')   # same secret stays
    commit_all(repo, "c2")
    f = SecretsEngine().scan(str(repo))[0]
    assert len(f.extra["history_occurrences"]) == 1      # only the commit that ADDED it


@pytestmark_git
def test_history_scan_is_scoped_to_scanned_subfolder(tmp_path):
    repo = new_repo(tmp_path / "mono")
    write(repo, "sub/a.py", f'T = "{fs.github_token(1)}"\n')
    write(repo, "other/b.py", f'T = "{fs.github_token(2)}"\n')
    commit_all(repo, "both")
    (repo / "sub" / "a.py").unlink()
    (repo / "other" / "b.py").unlink()
    commit_all(repo, "remove both")
    found = SecretsEngine().scan(str(repo / "sub"))
    assert len(found) == 1 and found[0].file == "a.py"   # path relative to scanned folder, other/ ignored


@pytestmark_git
def test_non_git_folder_and_empty_repo_do_not_crash(tmp_path):
    write(tmp_path / "plain", "a.py", f'T = "{fs.github_token()}"\n')
    e = SecretsEngine()
    assert len(e.scan(str(tmp_path / "plain"))) == 1
    assert e.stats["history_scanned"] is False and "not a git repository" in e.stats["history_note"]

    empty = new_repo(tmp_path / "empty")
    e2 = SecretsEngine()
    assert e2.scan(str(empty)) == []
    assert e2.stats["history_scanned"] is True and e2.stats["commits_scanned"] == 0


@pytestmark_git
def test_multiple_secrets_same_commit_and_crlf(tmp_path):
    repo = new_repo(tmp_path / "r")
    content = f'A = "{fs.github_token(1)}"\r\nB = "{fs.stripe_live_key()}"\r\n'
    (repo / "a.py").write_bytes(content.encode())
    commit_all(repo, "crlf")
    (repo / "a.py").unlink()
    commit_all(repo, "rm")
    found = SecretsEngine().scan(str(repo))
    assert {f.extra["rule"] for f in found} == {"github-token", "stripe-live-key"}


# ------------------------------------------------ false-positive regressions --
# Each case below produced a false alarm when the engine was first run on ~35,000
# real-world files (stdlib + installed packages). They must stay quiet.
@pytest.mark.parametrize("line", [
    'tokentype = "do_string"',                                   # parser token, not a credential
    'token.markup = "autolink"',
    'this.tokenType = "WHITESPACE";',
    'TOKEN_COMMENT: "comment",',
    '_token = rf\'(?:[a-z]+)Qx9zLm\'',                           # regex in an f-string
    'db_password = f"{user}-abc123XYZ"',                         # f-string = interpolation
    'token = "blanks"',                                          # plain word assigned to a token
    'eos_token = "end_of_text_marker"',                          # NLP special token
    'CHALLENGE_PASSWORD: "challengePassword",',                  # identifier used as a value
    "Token: '#dcdccc',",                                         # colour code
    'password: string?',                                         # type annotation
    '>>> pdf = Pdf.open("test.pdf", password="Zq8x2Lm9Pw")',     # doctest example
    '_SK_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"',        # marker string, no key body
    'padding_side = "left_side_padding"',
])
def test_known_false_positive_patterns_stay_quiet(tmp_path, line):
    write(tmp_path, "a.py", line + "\n")
    assert scan(tmp_path) == [], f"false positive on: {line}"


def test_token_assigned_a_real_looking_value_is_still_caught(tmp_path):
    write(tmp_path, "a.py", f'auth_token = "{fs.random_token(51, 36)}"\naccess_token = "{fs.random_token(52, 36)}"\n')
    assert len(scan(tmp_path)) == 2


def test_camelcase_key_names_still_match(tmp_path):
    write(tmp_path, "a.js", f'const dbPassword = "{fs.strong_password(53)}";\nconst apiKey = "{fs.random_token(54, 36)}";\n')
    assert {f.extra["variable"] for f in scan(tmp_path)} == {"dbPassword", "apiKey"}


def test_identifier_filter_does_not_hide_random_letter_passwords(tmp_path):
    # purely-alphabetic but random -> many case flips -> must still be flagged
    import random
    r = random.Random(7)
    pw = "".join(r.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(18))
    write(tmp_path, "a.py", f'admin_password = "{pw}"\n')
    assert len(scan(tmp_path)) == 1


def test_embedded_base64_blob_is_not_reported_as_secrets(tmp_path):
    lines = "".join(f'    "{fs.random_token(60 + i, 70)}"\n' for i in range(12))
    write(tmp_path, "media.py", "ICON = (\n" + lines + ")\n")
    assert scan(tmp_path) == []


def test_many_entropy_hits_in_one_file_are_treated_as_data(tmp_path):
    body = "".join(f'x{i} = "{fs.random_token(80 + i, 48)}"\n' for i in range(8))
    write(tmp_path, "table.py", body)
    assert scan(tmp_path) == []


def test_private_key_marker_followed_by_real_body_is_caught_even_single_line(tmp_path):
    key = fs.private_key_pem(60).strip().replace("\n", "\\n")
    write(tmp_path, "a.py", f'KEY = "{key}"\n')
    f = scan(tmp_path)
    assert len(f) == 1 and f[0].extra["rule"] == "private-key"


def test_local_database_url_is_downgraded(tmp_path):
    write(tmp_path, "a.py", 'A = "postgres://postgres:S3cretPw99@localhost:5432/dev"\n'
                            'B = "postgres://postgres:Other7Pw88@db.prod.example.net:5432/app"\n')
    sev = {f.line: f.severity for f in scan(tmp_path)}
    assert sev[1] < 5 < sev[2]


def test_same_secret_local_and_prod_keeps_the_higher_severity(tmp_path):
    # order matters for the bug this guards against: the localhost line comes FIRST
    write(tmp_path, "a.py", 'A = "postgres://postgres:S3cretPw99@localhost:5432/dev"\n'
                            'B = "postgres://postgres:S3cretPw99@db.prod.example.net:5432/app"\n')
    found = scan(tmp_path)
    assert len(found) == 1 and len(found[0].extra["locations"]) == 2
    assert found[0].severity >= 8.0


def test_docs_examples_are_low_confidence_but_real_tokens_in_docs_are_not_downgraded(tmp_path):
    write(tmp_path, "README.md", f'password = "{fs.strong_password(61)}"\nGH = {fs.github_token(62)}\n')
    by_line = {f.line: f for f in scan(tmp_path)}
    assert by_line[1].severity <= 4.0 and by_line[1].extra["confidence"] == "low"
    assert by_line[2].severity >= 9.0                        # provider-format token in a README is still serious


def test_masking_replaces_only_the_secret_position_not_every_occurrence(tmp_path):
    write(tmp_path, "a.py", 'U = "postgres://postgres:postgres@db.prod.example.net/app"\n')
    f = scan(tmp_path)
    # username and scheme keep their text; only the password span is masked
    assert f == [] or "postgres://postgres:" in f[0].evidence      # 'postgres' password is a placeholder-ish default
    write(tmp_path, "b.py", 'U = "postgres://alice:Sup3rS3cretPw@db.prod.example.net/app"\n')
    g = [x for x in scan(tmp_path) if x.file == "b.py"][0]
    assert "alice" in g.evidence and "Sup3rS3cretPw" not in g.evidence and "Sup3****" in g.evidence


# ------------------------------------------------- recall regressions (found on vulpy / pygoat) --
def test_repeated_letter_secret_is_still_reported_as_weak_secret(tmp_path):
    # vulpy/bad/vulpy.py: app.config['SECRET_KEY'] = 'aaaaaaa'  -> was silently missed
    write(tmp_path, "a.py", "app.config['SECRET_KEY'] = 'aaaaaaa'\n")
    f = scan(tmp_path)
    assert len(f) == 1 and f[0].extra["confidence"] == "low"


@pytest.mark.parametrize("line", ['k = "xxxxxxxx"', 'PASSWORD = "00000000"', 'password = "********"'])
def test_filler_characters_are_still_placeholders(tmp_path, line):
    write(tmp_path, "a.py", line + "\n")
    assert scan(tmp_path) == []


def test_dummy_looking_provider_tokens_are_downgraded(tmp_path):
    # pygoat: a Stripe-style api_key whose tail is obviously dummy (alphabet order)
    dummy = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
    write(tmp_path, "a.py", f'"api_key": "{dummy}"\n')
    f = scan(tmp_path)
    assert len(f) == 1 and f[0].severity <= 4.0 and f[0].extra["confidence"] == "low"


def test_random_provider_tokens_keep_full_severity(tmp_path):
    write(tmp_path, "a.py", f'"api_key": "{fs.stripe_live_key()}"\n')
    assert scan(tmp_path)[0].severity >= 9.0


@pytest.mark.parametrize("line", [
    'ADMIN_PASSWORD = "admin"',
    'db_password = "dbadmin"',
    'root_password = "root"',
    'mysql_password = "mysql"',
])
def test_classic_weak_defaults_named_after_the_account_are_flagged(tmp_path, line):
    write(tmp_path, "a.py", line + "\n")
    f = scan(tmp_path)
    assert len(f) == 1 and f[0].extra["confidence"] == "low"


def test_value_that_merely_repeats_the_variable_name_is_ignored(tmp_path):
    write(tmp_path, "a.py", 'user_password = "user_password"\nsecret = "secret1"\n')
    assert [x.line for x in scan(tmp_path)] == [2]       # line 1 is a label, line 2 is a (weak) secret


# ------------------------------------------- evidence must not echo undetected tokens --
def test_neighbouring_undetected_token_on_same_line_is_not_echoed(tmp_path):
    # found by comparing against another tool's output on pygoat: a JWT was detected and masked,
    # but a csrftoken value on the same line was printed in full in `evidence`.
    csrf = fs.random_token(70, 48)
    write(tmp_path, "a.js", f'// h.append("Cookie", "csrftoken={csrf}; jwt={fs.jwt()}");\n')
    found = scan(tmp_path)
    assert len(found) >= 1
    blob = json.dumps([f.to_dict() for f in found])
    assert csrf not in blob
    assert any("csrftoken=" in f.evidence for f in found)          # still useful context


def test_scrub_leaves_ordinary_code_alone():
    from engines.secrets_engine import scrub_tokens
    line = 'result = some_function_with_a_long_descriptive_name(arg)  # production-db.internal:5432'
    assert scrub_tokens(line) == line


def test_cli_output_flag_writes_utf8_json(tmp_path):
    import sys
    from core.pipeline import main
    repo = tmp_path / "r"
    write(repo, "a.py", f'T = "{fs.github_token()}"\n')
    out = tmp_path / "out.json"
    assert main([str(repo), "--no-history", "-o", str(out)]) == 0
    raw = out.read_bytes()
    assert not raw.startswith(b"\xff\xfe")                          # not UTF-16
    data = json.loads(raw.decode("utf-8"))
    assert data and data[0]["engine"] == "secrets"


# ------------------------------------------------------------- new enhancements --
@pytest.mark.parametrize("rule_id,line_builder", [
    ("huggingface-token", lambda: 'HF_TOKEN = "' + 'h' + 'f_' + "".join(chr(65 + (i % 26)) for i in range(35)) + '"'),
    ("discord-bot-token", lambda: 'DISCORD_BOT = "' + 'N' + "".join(chr(65 + (i % 26)) for i in range(24)) + '.' + 'A1B2C3' + '.' + "".join(chr(97 + (i % 26)) for i in range(28)) + '"'),
    ("twilio-api-key", lambda: 'TWILIO_KEY = "' + 'S' + 'K' + "".join(hex(i % 16)[2:] for i in range(32)) + '"'),
    ("vault-token", lambda: 'VAULT = "' + 'h' + 'v' + 's.' + "".join(chr(97 + (i % 26)) for i in range(24)) + '"'),
    ("gcp-service-account", lambda: '{"private_key": "' + '-----BEGIN PRIVATE KEY-----' + "".join(chr(65 + (i % 26)) for i in range(50)) + '"}'),
])
def test_new_provider_rules(tmp_path, rule_id, line_builder):
    line = line_builder()
    write(tmp_path, "secrets.py", line + "\n")
    found = scan(tmp_path)
    assert rule_id in rules(found)


def test_getenv_hardcoded_defaults_detected(tmp_path):
    code = (
        'db_pass = os.getenv("DB_PASSWORD", "supersecret12345")\n'
        'api_key = os.environ.get("API_KEY", "prod_api_key_xyz987")\n'
    )
    write(tmp_path, "config.py", code)
    found = scan(tmp_path)
    flagged_vars = {str(f.extra.get("variable", "")).lower() for f in found}
    assert any("password" in v for v in flagged_vars)
    assert any("api_key" in v for v in flagged_vars)
    assert any("supersecret" in f.description or "generic" in f.extra.get("rule", "") for f in found)


def test_uuid_not_flagged_as_high_entropy(tmp_path):
    code = 'ID = "550e8400-e29b-41d4-a716-446655440000"\n'
    write(tmp_path, "record.py", code)
    found = scan(tmp_path, use_entropy=True)
    assert not any(f.extra.get("rule") == "high-entropy-string" for f in found)

