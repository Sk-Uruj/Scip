"""Plan dependency upgrades from dependency findings (dicts as written by `core.pipeline -o`)."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

RISK_ORDER = {"patch": 0, "minor": 1, "major": 2}


def norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Upgrade:
    file: str
    line: int
    package: str
    current: str
    target: str
    fixes: List[str]                 # vulnerability ids removed by moving to `target`
    unfixed: List[str] = field(default_factory=list)   # ids on this pin with no known fixed version
    risk: str = "patch"              # patch | minor | major  (size of the version jump)
    max_risk_score: float = 0.0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Plan:
    upgrades: List[Upgrade] = field(default_factory=list)       # safe to apply automatically
    needs_review: List[Upgrade] = field(default_factory=list)   # e.g. major version jumps
    no_fix: List[Dict[str, Any]] = field(default_factory=list)  # pins where no fixed version is known

    def to_dict(self) -> Dict[str, Any]:
        return {"upgrades": [u.to_dict() for u in self.upgrades],
                "needs_review": [u.to_dict() for u in self.needs_review],
                "no_fix": self.no_fix}


def _info(f: Dict[str, Any]) -> Optional[Tuple[str, str, str, str, int]]:
    """(package, version, vuln_id, fixed_version, line) from a dependency finding, or None."""
    if f.get("engine") != "dependency":
        return None
    ex = f.get("extra") or {}
    package, version = ex.get("package"), ex.get("version")
    if not (package and version):
        m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==\s*(\S+)\s*$", f.get("evidence") or "")
        if not m:
            return None
        package, version = m.group(1), m.group(2)
    vid = ex.get("vuln_id") or (f.get("title") or "").split(":", 1)[0].strip() or "UNKNOWN"
    return norm_name(package), str(version), str(vid), ex.get("fixed_version") or "", int(f.get("line") or 0)


def jump_size(current: str, target: str) -> str:
    try:
        c, t = Version(current), Version(target)
    except InvalidVersion:
        return "major"                       # cannot compare: treat as the riskiest
    if c.major >= 1000 or t.major >= 1000:       # calendar versions (certifi 2022.12.7): no breaking-change meaning
        return "minor" if (c.major, c.minor) != (t.major, t.minor) else "patch"
    if c.major != t.major:
        return "major"
    if c.minor != t.minor:
        return "minor"
    return "patch"


def plan_upgrades(findings: Iterable[Dict[str, Any]], allow_major: bool = False) -> Plan:
    """One upgrade per pinned line: the lowest version that fixes every CVE we know a fix for."""
    groups: Dict[Tuple[str, int, str, str], List[Tuple[str, str, float]]] = defaultdict(list)
    for f in findings:
        i = _info(f)
        if i is None:
            continue
        package, version, vid, fixed, line = i
        groups[(f.get("file") or "", line, package, version)].append((vid, fixed, float(f.get("risk_score") or 0)))

    plan = Plan()
    for (file, line, package, version), vulns in sorted(groups.items()):
        fixable = [(vid, fx) for vid, fx, _ in vulns if fx]
        unfixed = sorted({vid for vid, fx, _ in vulns if not fx})
        top = max(r for _, _, r in vulns)
        if not fixable:
            plan.no_fix.append({"file": file, "line": line, "package": package, "current": version,
                                "vulns": unfixed, "reason": "no fixed version is known for any of these"})
            continue
        try:
            target = max((fx for _, fx in fixable), key=Version)
        except InvalidVersion:
            plan.no_fix.append({"file": file, "line": line, "package": package, "current": version,
                                "vulns": sorted({v for v, _ in fixable}), "reason": "fixed version not comparable"})
            continue
        fixes = sorted({vid for vid, fx in fixable if Version(fx) <= Version(target)})
        risk = jump_size(version, target)
        note = {"patch": "bug-fix release", "minor": "new features, normally backwards compatible",
                "major": "major version jump: breaking changes are likely; review manually"}[risk]
        if unfixed:
            note += f"; {len(unfixed)} vulnerabilities have no known fix"
        up = Upgrade(file, line, package, version, target, fixes, unfixed, risk, round(top, 2), note)
        (plan.needs_review if (risk == "major" and not allow_major) else plan.upgrades).append(up)

    for lst in (plan.upgrades, plan.needs_review):
        lst.sort(key=lambda u: (-u.max_risk_score, u.package, u.file))
    return plan
