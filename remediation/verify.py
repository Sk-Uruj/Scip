"""Verify an applied upgrade plan.

Two independent checks, deliberately kept separate so the final status never over-claims:
  1. RESCAN : scan the patched copy again. The targeted vulnerabilities must be gone and no new ones may appear.
  2. TESTS  : run the project's own tests inside a fresh virtualenv built from the upgraded requirements.

Status meanings:
  verified     rescan clean AND tests passed in a fresh venv built from the upgraded requirements
  scan_only    rescan clean, but tests were not run (or ran in the current environment, which still has the OLD
               packages). Vulnerabilities are removed on paper; behaviour is NOT proven safe.
  needs_review rescan found vulnerabilities still present or newly introduced by the upgrade
  tests_failed the project's tests failed with the upgraded packages
  nothing_applied no upgrade could be applied
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .apply import ApplyResult
from .plan import norm_name

ScanFn = Callable[[str], Iterable[Any]]
Runner = Callable[..., subprocess.CompletedProcess]


@dataclass
class TestOutcome:
    ran: bool = False
    passed: bool = False
    fresh_venv: bool = False
    command: str = ""
    returncode: Optional[int] = None
    output_tail: str = ""
    error: str = ""


@dataclass
class Verification:
    status: str
    resolved: List[str] = field(default_factory=list)
    remaining: List[str] = field(default_factory=list)
    introduced: List[str] = field(default_factory=list)
    tests: TestOutcome = field(default_factory=TestOutcome)
    messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _ident(f: Any) -> Optional[Tuple[str, str, str]]:
    """(package, version, vuln_id) of a dependency finding (object or dict); None for other findings.

    The VERSION is part of the identity on purpose: the same package can be pinned at several versions in one
    repo (for example Werkzeug 2.1.2 and 3.0.1). Upgrading one pin must not be blamed for advisories that
    belong to another pin that was not touched.
    """
    get = (lambda k, d=None: f.get(k, d)) if isinstance(f, dict) else (lambda k, d=None: getattr(f, k, d))
    if get("engine") != "dependency":
        return None
    ex = get("extra") or {}
    if not ex.get("vuln_id"):
        return None
    return norm_name(str(ex.get("package", ""))), str(ex.get("version", "")), str(ex["vuln_id"])


def _idset(findings: Iterable[Any]) -> Set[Tuple[str, str, str]]:
    return {i for i in (_ident(f) for f in findings) if i}


def default_scan(path: str, offline: bool = False) -> List[Any]:
    from engines.dependency_engine import DependencyEngine
    return DependencyEngine(offline=offline).scan(path)


def run_tests(workspace: Path, cmd: str, requirement_files: List[str], use_venv: bool,
              timeout: int = 900, runner: Runner = subprocess.run) -> TestOutcome:
    out = TestOutcome(command=cmd, fresh_venv=use_venv)
    env = dict(os.environ)
    cwd = str(workspace)
    try:
        if use_venv:
            venv = Path(workspace) / ".scip_venv"
            runner([sys.executable, "-m", "venv", str(venv)], cwd=cwd, check=True, capture_output=True, text=True,
                   timeout=timeout)
            bindir = venv / ("Scripts" if os.name == "nt" else "bin")
            py = str(bindir / ("python.exe" if os.name == "nt" else "python"))
            for rf in requirement_files:
                runner([py, "-m", "pip", "install", "--disable-pip-version-check", "-r", rf], cwd=cwd, check=True,
                       capture_output=True, text=True, timeout=timeout)
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env["VIRTUAL_ENV"] = str(venv)
        proc = runner(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout, env=env)
        out.ran, out.returncode = True, proc.returncode
        out.passed = proc.returncode == 0
        out.output_tail = ((proc.stdout or "") + (proc.stderr or ""))[-1500:]
    except subprocess.TimeoutExpired:
        out.error = f"timed out after {timeout}s"
    except subprocess.CalledProcessError as exc:
        out.error = f"environment setup failed: {(exc.stderr or str(exc))[-500:]}"
    except OSError as exc:
        out.error = str(exc)
    return out


def verify(applied: ApplyResult, baseline: Iterable[Any], scan_fn: ScanFn,
           test_cmd: Optional[str] = None, use_venv: bool = False, timeout: int = 900,
           runner: Runner = subprocess.run) -> Verification:
    ok = applied.applied
    if not ok:
        return Verification("nothing_applied", messages=["No upgrade could be applied; see the skipped list."])

    before = _idset(baseline)
    after = _idset(scan_fn(str(applied.workspace)))
    targeted = {(e.upgrade.package, e.upgrade.current, v) for e in ok for v in e.upgrade.fixes}
    resolved = sorted(f"{p}=={ver}:{v}" for p, ver, v in targeted if (p, ver, v) not in after)
    remaining = sorted(f"{p}=={ver}:{v}" for p, ver, v in targeted if (p, ver, v) in after)
    introduced = sorted(f"{p}=={ver}:{v}" for p, ver, v in after - before)
    res = Verification("scan_only", resolved=resolved, remaining=remaining, introduced=introduced)
    if remaining:
        res.messages.append(f"{len(remaining)} targeted vulnerabilities are still reported after the upgrade "
                            "(the same package and version is still pinned elsewhere, or the fix did not work).")
    if introduced:
        res.messages.append(f"{len(introduced)} vulnerabilities are new (the upgraded version has its own advisories).")
    if remaining or introduced:
        res.status = "needs_review"

    if test_cmd:
        files = sorted({e.upgrade.file for e in ok})
        res.tests = run_tests(applied.workspace, test_cmd, files, use_venv, timeout, runner)
        t = res.tests
        if not t.ran:
            res.messages.append(f"Tests did not run: {t.error}")
        elif not t.passed:
            res.status = "tests_failed"
            res.messages.append("The project's tests FAILED with the upgraded packages.")
        elif not use_venv:
            res.messages.append("Tests passed, but in the current environment (still the OLD packages), "
                                "so they do not prove the upgrade is safe. Re-run with --venv.")
        elif res.status == "scan_only":
            res.status = "verified"
    else:
        res.messages.append("No tests were run (use --test-cmd and --venv). The upgrade is not proven safe.")
    return res
