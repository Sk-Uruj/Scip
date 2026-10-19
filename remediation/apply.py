"""Apply upgrade plans to a COPY of the repo and produce a unified diff. The original is never touched."""
from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from .plan import Upgrade, norm_name

IGNORE_DIRS = {".git", "venv", ".venv", "env", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
               ".tox", "dist", "build", ".scip_venv", "eval_scans", "remediation_out"}
_LINE = re.compile(r"^(?P<pre>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\s*\[[^\]]*\])?"
                   r"(?P<op>\s*===?\s*)(?P<ver>[A-Za-z0-9][A-Za-z0-9.+!_-]*)(?P<rest>.*)$", re.S)


@dataclass
class EditResult:
    upgrade: Upgrade
    applied: bool
    reason: str = ""


@dataclass
class ApplyResult:
    workspace: Path
    edits: List[EditResult] = field(default_factory=list)
    diff: str = ""

    @property
    def applied(self) -> List[EditResult]:
        return [e for e in self.edits if e.applied]

    @property
    def skipped(self) -> List[EditResult]:
        return [e for e in self.edits if not e.applied]


def make_workspace(repo: Path, dest: Path) -> Path:
    """Copy the repo (without .git, virtualenvs, caches) to `dest`."""
    repo, dest = Path(repo).resolve(), Path(dest).resolve()
    if dest == repo or repo in dest.parents:
        raise ValueError("workspace must be outside the repository")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(repo, dest, symlinks=True, ignore=shutil.ignore_patterns(*IGNORE_DIRS))
    return dest


def _edit_line(line: str, up: Upgrade) -> Tuple[Optional[str], str]:
    """Return (new_line, '') or (None, reason). Only changes the version number."""
    m = _LINE.match(line)
    if not m:
        return None, "line is not a simple 'name==version' pin"
    if norm_name(m.group("name")) != up.package:
        return None, f"line {up.line} pins '{m.group('name')}', expected '{up.package}'"
    if m.group("ver") != up.current:
        return None, f"line {up.line} pins version {m.group('ver')}, expected {up.current}"
    if "--hash" in m.group("rest"):
        return None, "hash-pinned requirement: regenerate the lock file instead (e.g. pip-compile)"
    return f"{m.group('pre')}{m.group('name')}{m.group('extras') or ''}{m.group('op')}{up.target}{m.group('rest')}", ""


def _diff(original: str, updated: str, rel: str) -> str:
    out: List[str] = []
    for line in difflib.unified_diff(original.splitlines(keepends=True), updated.splitlines(keepends=True),
                                     fromfile=f"a/{rel}", tofile=f"b/{rel}"):
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def apply_upgrades(workspace: Path, upgrades: List[Upgrade]) -> ApplyResult:
    ws = Path(workspace)
    res = ApplyResult(workspace=ws)
    by_file: dict = {}
    for up in upgrades:
        by_file.setdefault(up.file, []).append(up)

    diffs: List[str] = []
    for rel, ups in sorted(by_file.items()):
        path = ws / rel
        name = Path(rel).name.lower()
        if not (name.endswith(".txt") and ("require" in name or "dep" in name or "constraint" in name)):
            for up in ups:
                res.edits.append(EditResult(up, False, f"{Path(rel).name}: only requirements*.txt files are edited "
                                                       "automatically; update this file manually"))
            continue
        try:
            original = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            for up in ups:
                res.edits.append(EditResult(up, False, f"cannot read {rel}: {exc}"))
            continue
        lines = original.splitlines(keepends=True)
        for up in ups:
            if not (1 <= up.line <= len(lines)):
                res.edits.append(EditResult(up, False, f"line {up.line} is outside {rel}"))
                continue
            new, why = _edit_line(lines[up.line - 1], up)
            if new is None:
                res.edits.append(EditResult(up, False, why))
                continue
            lines[up.line - 1] = new
            res.edits.append(EditResult(up, True))
        updated = "".join(lines)
        if updated != original:
            path.write_bytes(updated.encode("utf-8"))
            diffs.append(_diff(original, updated, rel))
    res.diff = "".join(diffs)
    return res
