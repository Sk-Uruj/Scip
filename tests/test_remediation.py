"""Tests for remediation: plan, apply (on a copy), verify, CLI."""
import json
import subprocess
from pathlib import Path

import pytest

from remediation.apply import apply_upgrades, make_workspace
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
