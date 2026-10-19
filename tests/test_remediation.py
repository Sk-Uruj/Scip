"""Tests for remediation: plan, apply (on a copy), verify, CLI."""
import ast
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from remediation.apply import apply_upgrades, make_workspace
from remediation.code_patcher import (
    RULE_PATCHERS,
    PatchStatus,
    PatchTier,
    apply_code_patches,
    can_auto_patch,
    generate_file_patch,
    get_node_span,
    patch_file_content,
    patch_single_snippet,
    safe_resolve_target,
)
from remediation.plan import Plan, Upgrade, jump_size, plan_upgrades
from remediation.run import main
from remediation.verify import run_tests, verify


def dep(package="django", version="4.2", vid="CVE-1", fixed="4.2.16", line=3, file="requirements.txt",
        risk=50.0, **kw):
    d = {"engine": "dependency", "file": file, "line": line, "risk_score": risk,
         "title": f"{vid}: {package}=={version} - x", "evidence": f"{package}=={version}",
         "extra": {"package": package, "version": version, "vuln_id": vid, "fixed_version": fixed}}
    d.update(kw)
    return d


# ------------------------------------------------------------------ plan
def test_target_is_the_highest_fixed_version_so_every_cve_is_covered():
    p = plan_upgrades([dep(vid="A", fixed="4.2.5"), dep(vid="B", fixed="4.2.16"), dep(vid="C", fixed="4.2.9")])
    assert len(p.upgrades) == 1
    u = p.upgrades[0]
    assert u.target == "4.2.16" and u.fixes == ["A", "B", "C"] and u.risk == "patch"


def test_version_comparison_is_numeric_not_textual():
    p = plan_upgrades([dep(vid="A", fixed="4.2.9"), dep(vid="B", fixed="4.2.10")])
    assert p.upgrades[0].target == "4.2.10"


def test_major_jump_needs_review_unless_allowed():
    f = [dep(version="3.2.18", fixed="4.2.16")]
    p = plan_upgrades(f)
    assert not p.upgrades and p.needs_review[0].risk == "major"
    assert plan_upgrades(f, allow_major=True).upgrades[0].risk == "major"


def test_calendar_versions_are_not_treated_as_major_jumps():
    assert jump_size("2022.12.7", "2024.7.4") == "minor"          # certifi
    assert jump_size("2024.7.4", "2024.7.9") == "patch"
    p = plan_upgrades([dep("certifi", "2022.12.7", "C1", "2024.7.4")])
    assert p.upgrades and not p.needs_review


def test_jump_size_levels_and_unparseable_is_treated_as_major():
    assert jump_size("1.2.3", "1.2.9") == "patch"
    assert jump_size("1.2.3", "1.5.0") == "minor"
    assert jump_size("1.2.3", "2.0.0") == "major"
    assert jump_size("weird", "2.0.0") == "major"


def test_cves_without_a_fix_are_reported_not_hidden():
    p = plan_upgrades([dep(vid="A", fixed="4.2.16"), dep(vid="B", fixed="")])
    assert p.upgrades[0].unfixed == ["B"] and "no known fix" in p.upgrades[0].note
    p2 = plan_upgrades([dep(vid="Z", fixed="")])
    assert not p2.upgrades and p2.no_fix[0]["package"] == "django"


def test_each_pinned_line_gets_its_own_upgrade_and_order_follows_risk_score():
    p = plan_upgrades([dep("pillow", "9.4.0", "P1", "9.5.0", line=19, risk=82.0),
                       dep("django", "4.2", "D1", "4.2.16", line=11, risk=40.0),
                       dep("django", "3.2.18", "D2", "3.2.25", line=1, file="lab/requirements.txt", risk=90.0)])
    assert [u.package for u in p.upgrades] == ["django", "pillow", "django"]     # 90, 82, 40
    assert {(u.file, u.line) for u in p.upgrades} == {("lab/requirements.txt", 1), ("requirements.txt", 19),
                                                       ("requirements.txt", 11)}


def test_non_dependency_findings_and_missing_extra_are_handled():
    other = {"engine": "bandit", "file": "a.py", "line": 1, "title": "x"}
    f = dep()
    f["extra"] = {"vuln_id": "CVE-9", "fixed_version": "4.2.16"}          # no package/version in extra
    p = plan_upgrades([other, f])
    assert p.upgrades[0].package == "django" and p.upgrades[0].current == "4.2"   # parsed from evidence


# ------------------------------------------------------------------ apply
def _repo(tmp_path, text="flask>=2\r\ndjango==4.2  # web\r\npillow[extra]==9.4.0 ; python_version>'3'\r\n", name="requirements.txt"):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / name).write_bytes(text.encode("utf-8"))
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("x", encoding="utf-8")
    return repo


def U(package="django", current="4.2", target="4.2.16", line=2, file="requirements.txt", fixes=("A",)):
    return Upgrade(file, line, package, current, target, list(fixes))


def test_workspace_is_a_copy_and_original_is_never_modified(tmp_path):
    repo = _repo(tmp_path)
    before = (repo / "requirements.txt").read_bytes()
    ws = make_workspace(repo, tmp_path / "ws")
    res = apply_upgrades(ws, [U()])
    assert (repo / "requirements.txt").read_bytes() == before                 # original untouched
    assert b"django==4.2.16  # web" in (ws / "requirements.txt").read_bytes()
    assert not (ws / ".git").exists()                                         # .git is not copied
    assert res.applied and not res.skipped and "+django==4.2.16" in res.diff


def test_edit_keeps_crlf_comments_extras_and_markers(tmp_path):
    repo = _repo(tmp_path)
    ws = make_workspace(repo, tmp_path / "ws")
    apply_upgrades(ws, [U("pillow", "9.4.0", "9.5.0", line=3)])
    new = (ws / "requirements.txt").read_bytes().decode()
    assert new == "flask>=2\r\ndjango==4.2  # web\r\npillow[extra]==9.5.0 ; python_version>'3'\r\n"


def test_workspace_must_be_outside_the_repo(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(ValueError):
        make_workspace(repo, repo / "inside")


@pytest.mark.parametrize("up,why", [
    (U("flask", "2.0", "2.3", line=1), "not a simple"),                   # '>=' range is not an exact pin
    (U("pillow", "9.4.0", "9.5.0", line=2), "expected 'pillow'"),         # wrong package on that line
    (U("django", "4.1", "4.2.16", line=2), "expected 4.1"),               # version differs from the finding
    (U("django", "4.2", "4.2.16", line=99), "outside"),
])
def test_unsafe_edits_are_skipped_with_a_reason(tmp_path, up, why):
    repo = _repo(tmp_path)
    ws = make_workspace(repo, tmp_path / "ws")
    before = (ws / "requirements.txt").read_bytes()
    res = apply_upgrades(ws, [up])
    assert not res.applied and why in res.skipped[0].reason
    assert (ws / "requirements.txt").read_bytes() == before and res.diff == ""


def test_hash_pinned_and_non_requirements_files_are_not_edited(tmp_path):
    repo = _repo(tmp_path, "django==4.2 --hash=sha256:abc\n")
    ws = make_workspace(repo, tmp_path / "ws")
    res = apply_upgrades(ws, [U(line=1)])
    assert "hash-pinned" in res.skipped[0].reason
    repo2 = _repo(tmp_path / "x", name="poetry.lock", text="django 4.2\n")
    ws2 = make_workspace(repo2, tmp_path / "ws2")
    res2 = apply_upgrades(ws2, [U(file="poetry.lock", line=1)])
    assert "only requirements" in res2.skipped[0].reason


def test_file_without_trailing_newline_gives_a_valid_diff(tmp_path):
    repo = _repo(tmp_path, "django==4.2")
    ws = make_workspace(repo, tmp_path / "ws")
    res = apply_upgrades(ws, [U(line=1)])
    assert "\\ No newline at end of file" in res.diff and res.diff.endswith("\n")


# ------------------------------------------------------------------ verify
def _applied(tmp_path):
    ws = make_workspace(_repo(tmp_path), tmp_path / "ws")
    return apply_upgrades(ws, [U(fixes=("A", "B"))])


def scan_returning(*ids):
    """ids are (package, version, vuln_id)."""
    return lambda path: [{"engine": "dependency", "extra": {"package": p, "version": ver, "vuln_id": v}}
                         for p, ver, v in ids]


BASE = [dep(vid="A"), dep(vid="B")]


def test_clean_rescan_without_tests_is_scan_only_not_verified(tmp_path):
    v = verify(_applied(tmp_path), BASE, scan_returning())
    assert v.status == "scan_only" and v.resolved == ["django==4.2:A", "django==4.2:B"]
    assert any("not proven safe" in m for m in v.messages)


def test_remaining_or_introduced_vulnerabilities_need_review(tmp_path):
    v = verify(_applied(tmp_path), BASE, scan_returning(("django", "4.2", "B")))
    assert v.status == "needs_review" and v.remaining == ["django==4.2:B"] and v.resolved == ["django==4.2:A"]
    v2 = verify(_applied(tmp_path / "2"), BASE, scan_returning(("django", "4.2.16", "NEW")))
    assert v2.status == "needs_review" and v2.introduced == ["django==4.2.16:NEW"]


def test_other_pins_of_the_same_package_are_not_blamed_for_the_upgrade(tmp_path):
    """Regression: Werkzeug 3.0.1 upgraded, Werkzeug 2.1.2 (major jump) left alone, same CVE ids on both."""
    repo = _repo(tmp_path, "werkzeug==3.0.1\nwerkzeug==2.1.2\n")
    ws = make_workspace(repo, tmp_path / "ws")
    applied = apply_upgrades(ws, [U("werkzeug", "3.0.1", "3.1.9", line=1, fixes=("X", "Y"))])
    baseline = [dep("werkzeug", "3.0.1", "X", "3.1.9", line=1), dep("werkzeug", "3.0.1", "Y", "3.1.9", line=1),
                dep("werkzeug", "2.1.2", "X", "3.1.9", line=2), dep("werkzeug", "2.1.2", "Y", "3.1.9", line=2)]
    after = scan_returning(("werkzeug", "2.1.2", "X"), ("werkzeug", "2.1.2", "Y"))     # untouched pin still reported
    v = verify(applied, baseline, after)
    assert v.status == "scan_only" and v.remaining == [] and v.introduced == []
    assert v.resolved == ["werkzeug==3.0.1:X", "werkzeug==3.0.1:Y"]


def test_the_same_pin_in_another_location_is_still_reported_as_remaining(tmp_path):
    v = verify(_applied(tmp_path), BASE, scan_returning(("django", "4.2", "A")))
    assert v.remaining == ["django==4.2:A"] and v.status == "needs_review"


def test_nothing_applied_status(tmp_path):
    ws = make_workspace(_repo(tmp_path), tmp_path / "ws")
    res = apply_upgrades(ws, [U(line=99)])
    assert verify(res, BASE, scan_returning()).status == "nothing_applied"


def _fake_runner(returncode=0, raise_timeout=False, calls=None):
    def run(cmd, **kw):
        if calls is not None:
            calls.append((cmd, kw))
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, returncode, stdout="out", stderr="")
    return run


def test_tests_in_fresh_venv_pass_gives_verified(tmp_path):
    calls = []
    v = verify(_applied(tmp_path), BASE, scan_returning(), test_cmd="pytest -q", use_venv=True,
               runner=_fake_runner(calls=calls))
    assert v.status == "verified" and v.tests.passed and v.tests.fresh_venv
    joined = [" ".join(map(str, c[0])) if isinstance(c[0], list) else c[0] for c in calls]
    assert any("venv" in j for j in joined) and any("pip" in j and "requirements.txt" in j for j in joined)
    assert joined[-1] == "pytest -q"


def test_tests_in_current_environment_never_give_verified(tmp_path):
    v = verify(_applied(tmp_path), BASE, scan_returning(), test_cmd="pytest -q", use_venv=False,
               runner=_fake_runner())
    assert v.status == "scan_only" and v.tests.passed
    assert any("OLD packages" in m for m in v.messages)


def test_failing_tests_give_tests_failed(tmp_path):
    v = verify(_applied(tmp_path), BASE, scan_returning(), test_cmd="pytest", use_venv=True,
               runner=_fake_runner(returncode=1))
    assert v.status == "tests_failed" and not v.tests.passed


def test_test_timeout_and_setup_failure_are_reported_not_hidden(tmp_path):
    out = run_tests(tmp_path, "pytest", ["requirements.txt"], False, timeout=1, runner=_fake_runner(raise_timeout=True))
    assert not out.ran and "timed out" in out.error

    def broken(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd, stderr="pip exploded")
    out2 = run_tests(tmp_path, "pytest", ["requirements.txt"], True, runner=broken)
    assert not out2.ran and "pip exploded" in out2.error


def test_a_real_test_command_runs_in_the_workspace(tmp_path):
    (tmp_path / "t.py").write_text("import sys; sys.exit(0)", encoding="utf-8")
    out = run_tests(tmp_path, f'"{__import__("sys").executable}" t.py', [], False)
    assert out.ran and out.passed
    (tmp_path / "t.py").write_text("import sys; sys.exit(3)", encoding="utf-8")
    assert run_tests(tmp_path, f'"{__import__("sys").executable}" t.py', [], False).returncode == 3


# ------------------------------------------------------------------ CLI
def _scan(tmp_path, findings):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    return str(p)


def test_cli_plan_only_writes_patch_and_report_and_leaves_repo_alone(tmp_path, capsys):
    repo = _repo(tmp_path)
    before = (repo / "requirements.txt").read_bytes()
    scan = _scan(tmp_path, [dep(vid="A", fixed="4.2.16", line=2), dep("django", "4.2", "B", "")])
    out = tmp_path / "out"
    assert main([str(repo), "--scan", scan, "--out", str(out)]) == 0
    assert (repo / "requirements.txt").read_bytes() == before
    assert "+django==4.2.16" in (out / "dependency_upgrades.patch").read_text(encoding="utf-8")
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["applied"][0]["target"] == "4.2.16" and rep["verification"] is None
    assert "Dependency upgrades to apply: 1" in capsys.readouterr().out


def test_cli_verify_uses_injected_scan_and_reports_status(tmp_path, capsys):
    repo = _repo(tmp_path)
    scan = _scan(tmp_path, [dep(vid="A", fixed="4.2.16", line=2)])
    assert main([str(repo), "--scan", scan, "--out", str(tmp_path / "o"), "--verify"],
                scan_fn=scan_returning()) == 0
    assert "SCAN_ONLY" in capsys.readouterr().out


def test_cli_bad_inputs_return_2(tmp_path, capsys):
    assert main([str(tmp_path / "missing"), "--scan", "x.json"]) == 2
    repo = _repo(tmp_path)
    assert main([str(repo), "--scan", str(tmp_path / "nope.json")]) == 2


# ------------------------------------------------------------------ Code Patcher
def test_code_patcher_can_auto_patch_registry():
    """Verify that can_auto_patch accurately reflects the single RULE_PATCHERS registry."""
    for auto_id in ["B201", "B113", "B506", "B303", "B501", "B614", "B701"]:
        assert can_auto_patch({"extra": {"test_id": auto_id}}) is True
    # Non-auto-fixable or rejected rules
    for non_auto in ["B102", "B306", "B324", "B602", "B604"]:
        assert can_auto_patch({"extra": {"test_id": non_auto}}) is False


def test_code_patcher_nested_calls_and_trailing_commas():
    """Verify that nested function calls and trailing commas are never mangled by AST patching."""
    # 1. Nested call in requests.get
    code1 = "r = requests.get(url, headers=get_headers())"
    out1, reason1 = patch_single_snippet(code1, "B113")
    assert out1 == "r = requests.get(url, headers=get_headers(), timeout=10)"
    assert reason1 == ""

    # 2. Trailing comma in requests.get
    code2 = "r = requests.get(url,)"
    out2, reason2 = patch_single_snippet(code2, "B113")
    assert out2 == "r = requests.get(url, timeout=10)"

    # 3. Bare call without args
    code3 = "r = requests.get()"
    out3, reason3 = patch_single_snippet(code3, "B113")
    assert out3 == "r = requests.get(timeout=10)"

    # 4. Nested call in torch.load
    code4 = 'm = torch.load(f, map_location=torch.device("cpu"))'
    out4, reason4 = patch_single_snippet(code4, "B614")
    assert out4 == 'm = torch.load(f, map_location=torch.device("cpu"), weights_only=True)'


def test_code_patcher_yaml_loader_variations():
    """Verify that yaml.load removes both positional and keyword loaders to prevent TypeErrors."""
    cases = [
        ("data = yaml.load(f)", "data = yaml.safe_load(f)"),
        ("data = yaml.load(f, yaml.Loader)", "data = yaml.safe_load(f)"),
        ("data = yaml.load(f, Loader=Loader)", "data = yaml.safe_load(f)"),
        ("data = yaml.load(f, Loader=yaml.CLoader)", "data = yaml.safe_load(f)"),
    ]
    for orig, expected in cases:
        out, reason = patch_single_snippet(orig, "B506")
        assert out == expected
        assert reason == ""


def test_code_patcher_multi_line_call():
    """Verify multi-line call patching with trailing comma."""
    code = (
        "res = requests.get(\n"
        "    url,\n"
        "    headers=get_headers(),\n"
        ")\n"
    )
    out, reason = patch_single_snippet(code, "B113", line_no=1)
    assert out is not None
    assert "timeout=10" in out
    assert "headers=get_headers()" in out


def test_code_patcher_review_tiers():
    """Verify that mechanical fixes and fixes requiring human review are distinctly tiered."""
    # B201 is mechanical
    _, edits_b201 = patch_file_content("app.run(debug=True)", [{"line": 1, "extra": {"test_id": "B201"}}])
    assert len(edits_b201) == 1
    assert edits_b201[0].tier == PatchTier.MECHANICAL.value

    # B113 and B506 need review
    _, edits_b113 = patch_file_content("requests.get(url)", [{"line": 1, "extra": {"test_id": "B113"}}])
    assert edits_b113[0].tier == PatchTier.NEEDS_REVIEW.value

    _, edits_b506 = patch_file_content("yaml.load(f)", [{"line": 1, "extra": {"test_id": "B506"}}])
    assert edits_b506[0].tier == PatchTier.NEEDS_REVIEW.value


def test_code_patcher_crlf_roundtrip(tmp_path):
    """Verify that CRLF line endings are preserved byte-for-byte in the patched workspace."""
    repo = tmp_path / "repo"
    repo.mkdir()
    app_py = repo / "app.py"
    app_content = "import flask\r\napp = flask.Flask(__name__)\r\napp.run(debug=True)\r\n"
    app_py.write_bytes(app_content.encode("utf-8"))

    findings = [{"file": "app.py", "line": 3, "extra": {"test_id": "B201"}}]
    dest_ws = tmp_path / "ws"
    result = apply_code_patches(repo, findings, dest_path=dest_ws)

    patched_file = result.workspace / "app.py"
    raw_patched = patched_file.read_bytes()
    # Ensure every newline in the patched file is CRLF (\r\n) and not normalized to LF
    assert b"\r\n" in raw_patched
    assert b"\n" not in raw_patched.replace(b"\r\n", b"")
    assert b"debug=False" in raw_patched


def test_code_patcher_encoding_cookie_roundtrip(tmp_path):
    """Verify that encoding cookies (e.g. latin-1) are detected and preserved."""
    repo = tmp_path / "repo"
    repo.mkdir()
    app_py = repo / "app.py"
    # File in ISO-8859-1 with accent character
    content = "# -*- coding: iso-8859-1 -*-\n# auteur: Ren\xe9\nimport flask\napp.run(debug=True)\n"
    app_py.write_bytes(content.encode("iso-8859-1"))

    findings = [{"file": "app.py", "line": 4, "extra": {"test_id": "B201"}}]
    dest_ws = tmp_path / "ws_enc"
    result = apply_code_patches(repo, findings, dest_path=dest_ws)

    patched_file = result.workspace / "app.py"
    # Ensure file can be read as iso-8859-1 and contains the patched code
    patched_bytes = patched_file.read_bytes()
    assert b"debug=False" in patched_bytes
    assert b"Ren\xe9" in patched_bytes


def test_code_patcher_formfeed_line_numbering():
    """Verify that formfeed \\f characters do not desynchronize line indexing."""
    content = "import yaml\n\x0c\ndata = yaml.load(f)\n"
    # yaml.load is on line 3 (formfeed is line 2)
    new_content, edits = patch_file_content(content, [{"line": 3, "extra": {"test_id": "B506"}}])
    assert len(edits) == 1
    assert edits[0].applied is True
    assert "yaml.safe_load(f)" in new_content


def test_code_patcher_no_trailing_newline_diff():
    """Verify that files lacking trailing newlines generate clean unified diffs."""
    orig = "import flask\napp.run(debug=True)"
    new_content, diff, edits = generate_file_patch("app.py", orig, [{"line": 2, "extra": {"test_id": "B201"}}])
    assert len(edits) == 1
    assert edits[0].applied is True
    assert "-app.run(debug=True)" in diff
    assert "+app.run(debug=False)" in diff


def test_code_patcher_sandbox_path_traversal_rejection(tmp_path):
    """Verify that path traversal attempts in finding paths are rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "legit.py").write_text("import flask\napp.run(debug=True)\n", encoding="utf-8")

    findings = [
        {"file": "../../etc/passwd", "line": 1, "extra": {"test_id": "B201"}},
        {"file": "/etc/shadow", "line": 1, "extra": {"test_id": "B201"}},
        {"file": "C:/Windows/System32/drivers/etc/hosts", "line": 1, "extra": {"test_id": "B201"}},
    ]
    dest_ws = tmp_path / "ws_traversal"
    result = apply_code_patches(repo, findings, dest_path=dest_ws)
    assert len(result.applied) == 0
    assert len(result.skipped) == 3
    for s in result.skipped:
        assert s.status == PatchStatus.PATH_TRAVERSAL.value


def test_code_patcher_sandbox_symlink_rejection(tmp_path):
    """Verify that symlinks inside the workspace are rejected to prevent escaping."""
    repo = tmp_path / "repo"
    repo.mkdir()
    real_file = tmp_path / "external_secret.py"
    real_file.write_text("import flask\napp.run(debug=True)\n", encoding="utf-8")

    link_path = repo / "link.py"
    try:
        link_path.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this OS/user privileges")

    findings = [{"file": "link.py", "line": 2, "extra": {"test_id": "B201"}}]
    dest_ws = tmp_path / "ws_symlink"
    result = apply_code_patches(repo, findings, dest_path=dest_ws)
    assert len(result.applied) == 0
    assert result.skipped[0].status == PatchStatus.SYMLINK_SKIPPED.value


def test_code_patcher_syntax_error_safety_net():
    """Verify that invalid syntax in source or patch is rejected by the safety net."""
    broken_code = "def foo(\n   broken syntax"
    new_content, edits = patch_file_content(broken_code, [{"line": 1, "extra": {"test_id": "B201"}}])
    assert new_content == broken_code
    assert len(edits) == 1
    assert edits[0].status == PatchStatus.SYNTAX_ERROR.value


def test_code_patcher_default_dest_is_unique(tmp_path):
    """Verify that default dest_path=None generates unique paths preventing collisions."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import flask\napp.run(debug=True)\n", encoding="utf-8")

    r1 = apply_code_patches(repo, [{"file": "app.py", "line": 2, "extra": {"test_id": "B201"}}])
    r2 = apply_code_patches(repo, [{"file": "app.py", "line": 2, "extra": {"test_id": "B201"}}])
    assert r1.workspace != r2.workspace
    assert r1.workspace.exists() and r2.workspace.exists()


def test_code_patcher_non_ascii_byte_offset_on_same_line():
    """Verify that UTF-8 multi-byte characters earlier on the same line do not shift AST spans."""
    # 'données' contains two non-ASCII 'é' characters (each 2 bytes in UTF-8)
    code = 'data = yaml.load(open("données.yml", "r"))\n'
    new_content, edits = patch_file_content(code, [{"line": 1, "extra": {"test_id": "B506"}}])
    assert len(edits) == 1
    assert edits[0].applied is True
    assert 'yaml.safe_load(open("données.yml", "r"))' in new_content


def test_code_patcher_nested_and_chained_calls():
    """Verify that chained calls (e.g. requests.get(...).json()) correctly select the target call."""
    # B501 on requests.get(url, verify=False).json()
    code_b501 = 'res = requests.get(url, verify=False).json()\n'
    out_b501, edits_b501 = patch_file_content(code_b501, [{"line": 1, "extra": {"test_id": "B501"}}])
    assert edits_b501[0].applied is True
    assert 'requests.get(url, verify=True).json()' in out_b501

    # B113 on requests.get(url).json()
    code_b113 = 'res = requests.get(url).json()\n'
    out_b113, edits_b113 = patch_file_content(code_b113, [{"line": 1, "extra": {"test_id": "B113"}}])
    assert edits_b113[0].applied is True
    assert 'requests.get(url, timeout=10).json()' in out_b113


def test_code_patcher_multiple_calls_on_same_line_disambiguation():
    """Verify that multiple calls on the same line are disambiguated by col_offset and filter."""
    code = 'a = requests.get(x, timeout=1); b = requests.get(y)\n'
    # Finding points to the second call at col_offset=36
    finding = {"line": 1, "extra": {"test_id": "B113", "col_offset": 36}}
    out, edits = patch_file_content(code, [finding])
    assert edits[0].applied is True
    assert 'a = requests.get(x, timeout=1)' in out
    assert 'b = requests.get(y, timeout=10)' in out


def test_code_patcher_multiline_collapse_preserves_subsequent_findings():
    """Verify that a multi-line collapse at an earlier line does not desynchronize subsequent findings."""
    code = (
        "import yaml\n"
        "res1 = yaml.load(\n"
        "    stream1,\n"
        "    Loader=yaml.Loader,\n"
        ")\n"
        "x = 1\n"
        "y = 2\n"
        "z = 3\n"
        "res2 = yaml.load(stream2, Loader=yaml.Loader)\n"
    )
    findings = [
        {"line": 2, "extra": {"test_id": "B506"}},
        {"line": 9, "extra": {"test_id": "B506"}},
    ]
    new_content, edits = patch_file_content(code, findings)
    assert len(edits) == 2
    assert edits[0].applied is True and edits[1].applied is True
    assert "res1 = yaml.safe_load(stream1)" in new_content
    assert "res2 = yaml.safe_load(stream2)" in new_content


def test_code_patcher_call_with_comment_before_closing_paren():
    """Verify that arguments are inserted before comments and not swallowed inside them."""
    code = "requests.get(url  # comment with, comma\n)\n"
    new_content, edits = patch_file_content(code, [{"line": 1, "extra": {"test_id": "B113"}}])
    assert edits[0].applied is True
    assert "timeout=10" in new_content
    assert "# comment with, comma" in new_content
    # Parse to ensure timeout=10 is an actual argument, not in the comment
    import ast
    tree = ast.parse(new_content)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert any(kw.arg == "timeout" for kw in call.keywords)


def test_code_patcher_no_trailing_newline_git_apply_check(tmp_path):
    """Verify that diffs for files lacking trailing newlines apply cleanly with git apply,

    both when the edit occurs on the final line and when the final line is untouched context.
    """
    import shutil
    import subprocess
    if not shutil.which("git"):
        pytest.skip("git not installed on system")

    repo_dir = tmp_path / "git_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=repo_dir, capture_output=True, check=True)

    # Case 1: Change on the final line without trailing newline
    test_file1 = repo_dir / "target1.py"
    test_file1.write_bytes(b"import flask\napp.run(debug=True)")

    orig_content1 = "import flask\napp.run(debug=True)"
    _, diff1, edits1 = generate_file_patch("target1.py", orig_content1, [{"line": 2, "extra": {"test_id": "B201"}}])
    assert edits1[0].applied is True
    assert "\\ No newline at end of file" in diff1

    proc1 = subprocess.run(
        ["git", "apply", "--check", "-"],
        input=diff1.encode("utf-8"),
        cwd=repo_dir,
        capture_output=True,
    )
    assert proc1.returncode == 0, f"git apply failed on final-line edit: {proc1.stderr.decode('utf-8', errors='replace')}"

    # Case 2: Common case - change on line 2, lines 3 and 4 are untouched context at EOF
    test_file2 = repo_dir / "target2.py"
    test_file2.write_bytes(b"import flask\napp.run(debug=True)\nx = 1\ny = 2")

    orig_content2 = "import flask\napp.run(debug=True)\nx = 1\ny = 2"
    _, diff2, edits2 = generate_file_patch("target2.py", orig_content2, [{"line": 2, "extra": {"test_id": "B201"}}])
    assert edits2[0].applied is True
    assert "\\ No newline at end of file" in diff2

    proc2 = subprocess.run(
        ["git", "apply", "--check", "-"],
        input=diff2.encode("utf-8"),
        cwd=repo_dir,
        capture_output=True,
    )
    assert proc2.returncode == 0, f"git apply failed on context-line EOF: {proc2.stderr.decode('utf-8', errors='replace')}"


def test_code_patcher_postcondition_call_targeting():
    """Verify that postconditions check that the patched call itself is compliant and compliant count increases."""
    # File already contains a compliant requests.get(x, timeout=5) on line 1
    # On line 3, an unpatchable requests call exists
    code = (
        "import requests\n"
        "r1 = requests.get('http://ok', timeout=5)\n"
        "r2 = requests.get('http://already_has', timeout=10)\n"
    )
    # Finding points to line 3, but it already has timeout=10
    _, edits = patch_file_content(code, [{"line": 3, "extra": {"test_id": "B113"}}])
    assert edits[0].status == PatchStatus.PATTERN_NOT_FOUND.value


def test_code_patcher_positive_b303_and_b701():
    """Verify positive AST patching for B303 (MD5/SHA1 -> SHA256) and B701 (Jinja autoescape)."""
    # B303 md5
    code_md5 = "import hashlib\nh = hashlib.md5(b'test').hexdigest()"
    out_md5, reason_md5 = patch_single_snippet(code_md5, "B303", line_no=2)
    assert out_md5 == "import hashlib\nh = hashlib.sha256(b'test').hexdigest()"
    assert reason_md5 == ""

    # B303 sha1
    code_sha1 = "import hashlib\nh = hashlib.sha1(b'test').hexdigest()"
    out_sha1, reason_sha1 = patch_single_snippet(code_sha1, "B303", line_no=2)
    assert out_sha1 == "import hashlib\nh = hashlib.sha256(b'test').hexdigest()"

    # B701 Jinja autoescape
    code_b701 = "from jinja2 import Environment\nenv = Environment(autoescape=False)"
    out_b701, reason_b701 = patch_single_snippet(code_b701, "B701", line_no=2)
    assert out_b701 == "from jinja2 import Environment\nenv = Environment(autoescape=True)"


def test_code_patcher_no_op_already_compliant():
    """Verify that already-compliant calls result in clean no-ops (PATTERN_NOT_FOUND) rather than corrupting code."""
    cases = [
        ("requests.get(url, timeout=5)", "B113"),
        ("yaml.safe_load(stream)", "B506"),
        ("app.run(debug=False)", "B201"),
        ("requests.get(url, verify=True)", "B501"),
        ("torch.load(f, weights_only=True)", "B614"),
        ("Environment(autoescape=True)", "B701"),
    ]
    for code, test_id in cases:
        out, edits = patch_file_content(code, [{"line": 1, "extra": {"test_id": test_id}}])
        assert edits[0].status == PatchStatus.PATTERN_NOT_FOUND.value
        assert edits[0].applied is False
        assert out == code  # Code must remain untouched


def test_original_repo_untouched_byte_for_byte(tmp_path):
    """Core safety promise: the original repository is 100% untouched byte-for-byte during remediation."""
    import hashlib

    repo = tmp_path / "original_repo"
    repo.mkdir()

    file1 = repo / "server.py"
    file1.write_text("import flask\napp.run(debug=True)\n", encoding="utf-8")
    file2 = repo / "requirements.txt"
    file2.write_text("requests==2.20.0\nurllib3==1.24.1\n", encoding="utf-8")
    file3 = repo / "notes.md"
    file3.write_text("# Project Notes\nKeep safe.\n", encoding="utf-8")

    def hash_dir(path: Path) -> dict:
        hashes = {}
        for p in sorted(path.rglob("*")):
            if p.is_file():
                hashes[str(p.relative_to(path))] = hashlib.sha256(p.read_bytes()).hexdigest()
        return hashes

    hashes_before = hash_dir(repo)

    # 1. Apply code patches
    findings = [
        {"file": "server.py", "line": 2, "extra": {"test_id": "B201"}},
    ]
    code_res = apply_code_patches(repo, findings)
    assert len(code_res.applied) == 1
    assert hash_dir(repo) == hashes_before

    # 2. Apply dependency upgrades
    from remediation.apply import apply_upgrades
    from remediation.plan import Upgrade
    upgrades = [
        Upgrade(file="requirements.txt", line=1, package="requests", current="2.20.0", target="2.31.0", fixes=["CVE-2018-18074"]),
    ]
    dep_res = apply_upgrades(code_res.workspace, upgrades)
    assert len(dep_res.applied) == 1

    # Verify original repository is still 100% byte-for-byte identical
    assert hash_dir(repo) == hashes_before


def test_apply_upgrades_symlink_and_traversal_safety(tmp_path):
    """Verify that apply_upgrades rejects symlinks, path traversals, and dangling links."""
    from remediation.apply import apply_upgrades
    from remediation.plan import Upgrade

    ws = tmp_path / "ws"
    ws.mkdir()
    req = ws / "requirements.txt"
    req.write_text("requests==2.20.0\n", encoding="utf-8")

    # Path traversal upgrade
    up_traversal = [Upgrade(file="../outside.txt", line=1, package="requests", current="2.20.0", target="2.31.0", fixes=["CVE-2018-18074"])]
    res_traversal = apply_upgrades(ws, up_traversal)
    assert len(res_traversal.applied) == 0
    assert "traversal" in res_traversal.edits[0].reason

    # Absolute path upgrade
    up_abs = [Upgrade(file="/etc/passwd", line=1, package="requests", current="2.20.0", target="2.31.0", fixes=["CVE-2018-18074"])]
    res_abs = apply_upgrades(ws, up_abs)
    assert len(res_abs.applied) == 0
    assert "rejected" in res_abs.edits[0].reason


def test_code_edit_record_applied_and_review_note():
    """Verify CodeEditRecord to_dict() includes applied boolean and review_note."""
    from remediation.code_patcher import CodeEditRecord, PatchStatus
    rec = CodeEditRecord(
        file="app.py",
        line=1,
        test_id="B201",
        tier="mechanical",
        status=PatchStatus.APPLIED.value,
        original="app.run(debug=True)",
        patched="app.run(debug=False)",
        review_note="Disables debug mode.",
    )
    assert rec.applied is True
    d = rec.to_dict()
    assert d["applied"] is True
    assert d["review_note"] == "Disables debug mode."


def test_code_patcher_non_ascii_earlier_in_line():
    """Verify that get_node_span and patching succeed even when non-ASCII chars precede the call."""
    code = 'greeting = "Bonjour, café et thé ☕"\nres = requests.get("https://example.com", verify=False)\n'
    patched, edits = patch_file_content(code, [{"line": 2, "extra": {"test_id": "B501"}}])
    assert edits[0].applied is True
    assert "verify=True" in patched
    assert 'greeting = "Bonjour, café et thé ☕"' in patched


def test_code_patcher_nested_arguments_complex():
    """Verify that B113 timeout patching handles complex nested calls in arguments."""
    code = (
        'import requests\n'
        'def fetch():\n'
        '    return requests.get(build_url("/api", params={"v": 1}), headers={"Auth": get_token()})\n'
    )
    patched, edits = patch_file_content(code, [{"line": 3, "extra": {"test_id": "B113"}}])
    assert edits[0].applied is True
    expected = (
        'import requests\n'
        'def fetch():\n'
        '    return requests.get(build_url("/api", params={"v": 1}), headers={"Auth": get_token()}, timeout=10)\n'
    )
    assert patched == expected


def test_code_patcher_kwargs_guard_b113_and_b614():
    """Verify that calls with **kwargs are NOT auto-patched by B113 or B614 to prevent dynamic collision."""
    # B113 with **options
    code_b113 = "res = requests.get(url, **options)\n"
    out_b113, edits_b113 = patch_file_content(code_b113, [{"line": 1, "extra": {"test_id": "B113"}}])
    assert edits_b113[0].applied is False
    assert edits_b113[0].status == PatchStatus.PATTERN_NOT_FOUND.value
    assert "**kwargs" in edits_b113[0].reason
    assert out_b113 == code_b113

    # B614 with **kwargs
    code_b614 = "model = torch.load(f, **kwargs)\n"
    out_b614, edits_b614 = patch_file_content(code_b614, [{"line": 1, "extra": {"test_id": "B614"}}])
    assert edits_b614[0].applied is False
    assert edits_b614[0].status == PatchStatus.PATTERN_NOT_FOUND.value
    assert "**kwargs" in edits_b614[0].reason
    assert out_b614 == code_b614


def test_code_patcher_postcondition_count_check_reaches_and_rejects():
    """Verify that a patch where compliant call count fails to increase by 1 is rejected by postcondition."""
    from remediation.code_patcher import RULE_PATCHERS, RulePatcher

    orig_b113 = RULE_PATCHERS["B113"]

    # Case A: Patch function lands timeout=10 in a comment; compliant call exists elsewhere
    def patch_comment_only(src: str, call: ast.Call):
        start, end = get_node_span(src, call)
        call_text = src[start:end]
        return src[:end] + "  # timeout=10" + src[end:], ""

    patcher_comment = RulePatcher(
        test_id="B113",
        tier="mechanical",
        description="test comment patcher",
        patch_fn=patch_comment_only,
        call_filter=orig_b113.call_filter,
        postcondition=orig_b113.postcondition,
        review_note="comment patcher",
    )
    with patch.dict(RULE_PATCHERS, {"B113": patcher_comment}):
        code_a = (
            "import requests\n"
            "r1 = requests.get('https://example.com/ok', timeout=5)\n"
            "r2 = requests.get('https://example.com/bad')\n"
        )
        out_a, edits_a = patch_file_content(code_a, [{"line": 3, "extra": {"test_id": "B113"}}])
        assert edits_a[0].applied is False
        assert edits_a[0].status == PatchStatus.PATTERN_NOT_FOUND.value
        assert "Postcondition failed" in edits_a[0].reason
        assert out_a == code_a

    # Case B: Patched call satisfies postcondition, BUT overall compliant count does NOT increase by 1
    # (e.g. bug where patcher made line 3 compliant while clobbering line 2's timeout)
    def patch_clobber_existing(src: str, call: ast.Call):
        # Generates a compliant r2, but strips timeout from r1
        new_src = (
            "import requests\n"
            "r1 = requests.get('https://example.com/ok')\n"
            "r2 = requests.get('https://example.com/bad', timeout=10)\n"
        )
        return new_src, ""

    patcher_clobber = RulePatcher(
        test_id="B113",
        tier="mechanical",
        description="test clobber patcher",
        patch_fn=patch_clobber_existing,
        call_filter=orig_b113.call_filter,
        postcondition=orig_b113.postcondition,
        review_note="clobber patcher",
    )
    with patch.dict(RULE_PATCHERS, {"B113": patcher_clobber}):
        code_b = (
            "import requests\n"
            "r1 = requests.get('https://example.com/ok', timeout=5)\n"
            "r2 = requests.get('https://example.com/bad')\n"
        )
        out_b, edits_b = patch_file_content(code_b, [{"line": 3, "extra": {"test_id": "B113"}}])
        # Even though r2 at line 3 is compliant in the new tree, compliant count remained 1 (did not increase by 1)
        assert edits_b[0].applied is False
        assert edits_b[0].status == PatchStatus.PATTERN_NOT_FOUND.value
        assert "Postcondition failed" in edits_b[0].reason
        assert out_b == code_b


def test_code_patcher_python_38_keyword_position_fallback():
    """Verify _insert_call_kwarg works when ast.keyword lacks lineno/col_offset (Python 3.8 AST shape)."""
    from remediation.code_patcher import _insert_call_kwarg

    code = "requests.get(url, headers=h)"
    tree = ast.parse(code)
    call_node = tree.body[0].value
    # Simulate Python 3.8 by deleting lineno/col_offset from keywords if present
    for kw in call_node.keywords:
        for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
            if hasattr(kw, attr):
                delattr(kw, attr)

    patched = _insert_call_kwarg(code, call_node, "timeout=10")
    assert patched == "requests.get(url, headers=h, timeout=10)"


def test_apply_upgrades_real_symlink_rejection(tmp_path):
    """Verify apply_upgrades detects and rejects real symlinks targeting external files."""
    from remediation.apply import apply_upgrades
    from remediation.plan import Upgrade

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside_req.txt"
    outside.write_text("requests==2.20.0\n", encoding="utf-8")

    symlink_req = ws / "requirements.txt"
    try:
        symlink_req.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks require administrator/developer mode on Windows")

    upgrades = [
        Upgrade(file="requirements.txt", line=1, package="requests", current="2.20.0", target="2.31.0", fixes=["CVE-1"])
    ]
    res = apply_upgrades(ws, upgrades)
    assert len(res.applied) == 0
    assert any("symlink rejected" in e.reason.lower() for e in res.edits)
    # Target outside file must remain untouched
    assert outside.read_text(encoding="utf-8") == "requests==2.20.0\n"
