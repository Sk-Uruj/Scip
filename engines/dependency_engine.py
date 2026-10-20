"""Dependency vulnerability engine (Step 2).

Pipeline:
  1. Discover dependency files in the repo (requirements*.txt, pyproject.toml,
     poetry.lock, Pipfile.lock) and parse out (package, exact version).
  2. Ask OSV (https://osv.dev) which of those exact versions have known vulns.
  3. Fetch full advisory details, merge duplicates (GHSA / PYSEC / CVE aliases).
  4. Enrich with exploitability signals: EPSS probability + CISA KEV membership.
  5. Emit one Finding per (package, version, vulnerability).

Only EXACTLY pinned versions (==) can be checked, because OSV needs the version that
is actually installed. Loose specs like 'flask>=1.0' are counted and reported as
skipped, never guessed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
from packaging.version import InvalidVersion, Version

from core.cache import Cache
from core.cvss import cvss3_base_score
from core.finding import Finding
from engines.base import Engine

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

log = logging.getLogger("scip.dependency")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DAY = 24 * 3600
TIMEOUT = 20
OSV_BATCH_SIZE = 500
OSV_MAX_PAGES = 20
EPSS_BATCH_SIZE = 50

SKIP_DIRS = {
    ".git", ".hg", "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
}
REQ_FILE_RE = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$", re.I)

# Used only when OSV gives a text label (e.g. GHSA "HIGH") and no usable CVSS vector.
LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
DEFAULT_SEVERITY = 5.0  # assumed medium when an advisory has no severity at all


class NetworkError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Parsing dependency files
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Dependency:
    name: str                 # PEP 503 normalised name
    version: Optional[str]    # exact version, or None if not pinned
    file: str                 # path relative to repo root
    line: int


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_NAME_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$")
_PIN_RE = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)[=\s]*(\S+)")


def parse_requirement_line(line: str) -> Optional[Tuple[str, Optional[str]]]:
    """Parse one PEP 508-ish requirement. Returns (normalised_name, exact_version|None)."""
    line = line.split(";", 1)[0]                       # drop environment markers
    line = re.sub(r"--hash[=\s]\S+", "", line).strip()  # drop hashes
    if not line or line.startswith("-"):
        return None
    # URL / VCS requirements (git+https://..., https://...) have no checkable version.
    # 'name @ https://...' is allowed through and reported as unpinned.
    if "://" in line and not re.match(r"^\S+\s*@\s*\S+://", line):
        return None
    m = _NAME_RE.match(line)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).strip()
    pin = _PIN_RE.match(rest)
    version = pin.group(1) if pin else None
    return normalize_name(name), version


def _strip_comment(line: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", line)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", path, e)
        return None


def parse_requirements_file(path: Path, root: Path, _seen: Optional[Set[Path]] = None) -> List[Dependency]:
    seen = _seen if _seen is not None else set()
    real = path.resolve()
    if real in seen:
        return []
    seen.add(real)
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path, root)

    # join backslash-continued lines, remembering the first physical line number
    logical: List[Tuple[int, str]] = []
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        if start is None:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf, start = "", None
    if buf and start is not None:
        logical.append((start, buf))

    deps: List[Dependency] = []
    for lineno, raw in logical:
        line = _strip_comment(raw).strip()
        if not line:
            continue
        inc = _INCLUDE_RE.match(line)
        if inc:
            target = (path.parent / inc.group(1)).resolve()
            if target.exists():
                deps.extend(parse_requirements_file(target, root, seen))
            continue
        parsed = parse_requirement_line(line)
        if parsed:
            deps.append(Dependency(parsed[0], parsed[1], rel, lineno))
    return deps


def parse_pyproject(path: Path, root: Path) -> List[Dependency]:
    text = _read(path)
    if text is None:
        return []
    if tomllib is None:
        log.warning("tomllib unavailable; skipping %s (use Python 3.11+)", path)
        return []
    try:
        data = tomllib.loads(text)
    except Exception as e:  # tomllib.TOMLDecodeError
        log.warning("Bad TOML in %s: %s", path, e)
        return []
    project = data.get("project", {}) or {}
    reqs: List[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        reqs += [r for r in group if isinstance(r, str)]
    for group in (data.get("dependency-groups", {}) or {}).values():
        reqs += [r for r in group if isinstance(r, str)]

    lines = text.splitlines()
    rel = _rel(path, root)
    deps = []
    for r in reqs:
        parsed = parse_requirement_line(r)
        if not parsed:
            continue
        lineno = next((i for i, l in enumerate(lines, 1) if r in l), 1)
        deps.append(Dependency(parsed[0], parsed[1], rel, lineno))
    return deps


def parse_poetry_lock(path: Path, root: Path) -> List[Dependency]:
    text = _read(path)
    if text is None or tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception as e:
        log.warning("Bad TOML in %s: %s", path, e)
        return []
    lines = text.splitlines()
    rel = _rel(path, root)
    deps = []
    for pkg in data.get("package", []) or []:
        name, version = pkg.get("name"), pkg.get("version")
        if not name:
            continue
        lineno = next((i for i, l in enumerate(lines, 1) if l.strip() == f'name = "{name}"'), 1)
        deps.append(Dependency(normalize_name(name), version, rel, lineno))
    return deps


def parse_pipfile_lock(path: Path, root: Path) -> List[Dependency]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except ValueError as e:
        log.warning("Bad JSON in %s: %s", path, e)
        return []
    lines = text.splitlines()
    rel = _rel(path, root)
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section, {}) or {}).items():
            version = (info or {}).get("version", "") or ""
            version = version[2:] if version.startswith("==") else None
            lineno = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 1)
            deps.append(Dependency(normalize_name(name), version or None, rel, lineno))
    return deps


def discover_dependency_files(root: Path) -> List[Path]:
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if REQ_FILE_RE.match(fn) or fn in ("pyproject.toml", "poetry.lock", "Pipfile.lock"):
                found.append(Path(dirpath) / fn)
    return found


def collect_dependencies(root: Path) -> List[Dependency]:
    seen: Set[Dependency] = set()
    ordered: List[Dependency] = []
    for f in discover_dependency_files(root):
        if f.name == "pyproject.toml":
            parsed = parse_pyproject(f, root)
        elif f.name == "poetry.lock":
            parsed = parse_poetry_lock(f, root)
        elif f.name == "Pipfile.lock":
            parsed = parse_pipfile_lock(f, root)
        else:
            parsed = parse_requirements_file(f, root)
        for d in parsed:
            if d not in seen:
                seen.add(d)
                ordered.append(d)
    return ordered


# --------------------------------------------------------------------------- #
# Interpreting OSV advisories
# --------------------------------------------------------------------------- #
_SEV_PRIORITY = {"cvss3": 2, "label": 1, "none": 0}


@dataclass
class VulnInfo:
    id: str
    aliases: Set[str] = field(default_factory=set)
    summary: str = ""
    details: str = ""
    cvss: Optional[float] = None
    severity_source: str = "none"      # "cvss3" | "label" | "none"
    cwe: Optional[str] = None
    fixed: List[str] = field(default_factory=list)

    @property
    def cves(self) -> List[str]:
        return sorted(x for x in ({self.id} | self.aliases) if x.startswith("CVE-"))


def extract_severity(vuln: dict) -> Tuple[Optional[float], str]:
    for s in vuln.get("severity", []) or []:
        score = cvss3_base_score(str(s.get("score", "")))
        if score is not None:
            return score, "cvss3"
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in LABEL_SCORES:
        return LABEL_SCORES[label], "label"
    return None, "none"


def parse_osv_vuln(vuln: dict, package: str) -> Optional[VulnInfo]:
    if vuln.get("withdrawn"):
        return None
    cvss, source = extract_severity(vuln)
    cwe_ids = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    fixed: List[str] = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "PyPI" or normalize_name(pkg.get("name", "")) != package:
            continue
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev:
                        fixed.append(str(ev["fixed"]))
    details = vuln.get("details", "") or ""
    summary = vuln.get("summary") or (details.strip().splitlines()[0] if details.strip() else "")
    return VulnInfo(
        id=vuln["id"],
        aliases=set(vuln.get("aliases", []) or []),
        summary=summary.strip(),
        details=details.strip(),
        cvss=cvss,
        severity_source=source,
        cwe=cwe_ids[0] if cwe_ids else None,
        fixed=fixed,
    )


def is_dev_requirement_file(rel_path: str) -> bool:
    norm = (rel_path or "").replace("\\", "/").lower()
    fn = os.path.basename(norm)
    if any(k in fn for k in ("-dev", "_dev", ".dev", "dev-", "dev_", "test", "demo", "doc")):
        return True
    if any(p in norm for p in ("tests/", "test/", "dockerized_labs/", "docs/", "examples/")):
        return True
    return False


def _has_python_sources(root: Path) -> bool:
    try:
        for p in root.rglob("*.py"):
            parts = set(p.parts)
            if not (parts & SKIP_DIRS):
                return True
    except Exception:
        pass
    return False


def _combine(items: List[VulnInfo], ids: Set[str]) -> VulnInfo:
    cves = sorted(x for x in ids if x.startswith("CVE-"))
    display = cves[0] if cves else sorted(ids)[0]
    best = max(items, key=lambda v: (_SEV_PRIORITY[v.severity_source], v.cvss or 0.0))
    fixed: List[str] = []
    for v in items:
        for f in v.fixed:
            if f not in fixed:
                fixed.append(f)
    best_summary = max((v.summary for v in items if v.summary), key=len, default="")
    best_details = max((v.details for v in items if v.details), key=len, default="")
    return VulnInfo(
        id=display,
        aliases=set(ids) - {display},
        summary=best_summary,
        details=best_details,
        cvss=best.cvss,
        severity_source=best.severity_source,
        cwe=next((v.cwe for v in items if v.cwe), None),
        fixed=fixed,
    )


def merge_vulns(vulns: List[VulnInfo]) -> List[VulnInfo]:
    """OSV returns the same issue under several IDs (GHSA-..., PYSEC-..., CVE-...).
    Merge entries that share any ID/alias so each real vulnerability appears once."""
    groups: List[dict] = []
    for v in vulns:
        ids = {v.id} | v.aliases
        target = None
        for g in list(groups):
            if g["ids"] & ids:
                if target is None:
                    g["ids"] |= ids
                    g["items"].append(v)
                    target = g
                else:
                    target["ids"] |= g["ids"]
                    target["items"] += g["items"]
                    groups.remove(g)
        if target is None:
            groups.append({"ids": set(ids), "items": [v]})
    return [_combine(g["items"], g["ids"]) for g in groups]


def pick_fixed_version(fixed: Iterable[str], current: str) -> Optional[str]:
    """Nearest fixed release that is newer than the version in use."""
    try:
        cur = Version(current)
    except InvalidVersion:
        return None
    best: Optional[Tuple[Version, str]] = None
    for f in fixed:
        try:
            fv = Version(f)
        except InvalidVersion:
            continue
        if fv > cur and (best is None or fv < best[0]):
            best = (fv, f)
    return best[1] if best else None


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #
class DependencyEngine(Engine):
    name = "dependency"

    def __init__(self, offline: bool = False, session=None, cache: Optional[Cache] = None,
                 use_epss: bool = True, use_kev: bool = True, max_workers: int = 8,
                 backoff: float = 0.5, filter_unreachable: bool = True):
        self.offline = offline
        if session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": "scip-student-project/0.1"})
        self.session = session
        self.cache = cache if cache is not None else Cache()
        self.use_epss = use_epss
        self.use_kev = use_kev
        self.max_workers = max_workers
        self.backoff = backoff
        self.filter_unreachable = filter_unreachable
        self.stats: Dict[str, object] = {}

    # ---- HTTP helper ---------------------------------------------------- #
    def _ttl(self, seconds: float) -> Optional[float]:
        return None if self.offline else seconds   # offline: stale cache is better than nothing

    def _request(self, method: str, url: str, **kwargs):
        if self.offline:
            raise NetworkError("offline mode")
        last = "unknown error"
        for attempt in range(3):
            try:
                fn = self.session.post if method == "POST" else self.session.get
                resp = fn(url, timeout=TIMEOUT, **kwargs)
                if resp.status_code == 404:
                    return None
                if resp.status_code == 429 or resp.status_code >= 500:
                    last = f"HTTP {resp.status_code}"
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                resp.raise_for_status()
                return resp.json()
            except (requests.RequestException, ValueError) as e:
                last = str(e)
                time.sleep(self.backoff * (2 ** attempt))
        raise NetworkError(f"{method} {url} failed: {last}")

    # ---- OSV ------------------------------------------------------------ #
    def _query_osv(self, pairs: List[Tuple[str, str]]) -> Dict[Tuple[str, str], Set[str]]:
        result: Dict[Tuple[str, str], Set[str]] = {}
        todo: List[Tuple[str, str]] = []
        for name, ver in pairs:
            cached = self.cache.get("osv_query", f"{name}=={ver}", ttl=self._ttl(DAY))
            if cached is not None:
                result[(name, ver)] = set(cached)
            else:
                todo.append((name, ver))

        for i in range(0, len(todo), OSV_BATCH_SIZE):
            chunk = todo[i:i + OSV_BATCH_SIZE]
            ids: Dict[Tuple[str, str], Set[str]] = {p: set() for p in chunk}
            queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]
            pending = list(range(len(chunk)))
            tokens: Dict[int, str] = {}
            try:
                for _ in range(OSV_MAX_PAGES):
                    payload = {"queries": [
                        {**queries[j], **({"page_token": tokens[j]} if j in tokens else {})}
                        for j in pending
                    ]}
                    data = self._request("POST", OSV_BATCH_URL, json=payload)
                    results = (data or {}).get("results", [])
                    next_pending = []
                    for j, res in zip(pending, results):
                        for v in (res or {}).get("vulns", []) or []:
                            ids[chunk[j]].add(v["id"])
                        tok = (res or {}).get("next_page_token")
                        if tok:
                            tokens[j] = tok
                            next_pending.append(j)
                    pending = next_pending
                    if not pending:
                        break
            except NetworkError as e:
                log.error("OSV query failed for a batch of %d packages: %s", len(chunk), e)
                self.stats["osv_errors"] = int(self.stats.get("osv_errors", 0)) + 1
                continue
            for p in chunk:
                result[p] = ids[p]
                self.cache.set("osv_query", f"{p[0]}=={p[1]}", sorted(ids[p]))
        return result

    def _fetch_vulns(self, ids: Set[str]) -> Dict[str, dict]:
        def one(vid: str):
            cached = self.cache.get("osv_vuln", vid, ttl=self._ttl(7 * DAY))
            if cached is not None:
                return vid, cached
            try:
                data = self._request("GET", OSV_VULN_URL.format(id=vid))
            except NetworkError as e:
                log.warning("Could not fetch advisory %s: %s", vid, e)
                return vid, None
            if data:
                self.cache.set("osv_vuln", vid, data)
            return vid, data

        out: Dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for vid, data in ex.map(one, sorted(ids)):
                if data:
                    out[vid] = data
        missing = len(ids) - len(out)
        if missing:
            log.warning("%d advisory record(s) could not be retrieved", missing)
            self.stats["advisories_missing"] = missing
        return out

    # ---- exploitability signals ---------------------------------------- #
    def _get_epss(self, cves: Set[str]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        missing: List[str] = []
        for c in sorted(cves):
            cached = self.cache.get("epss", c, ttl=self._ttl(DAY))
            if cached is not None:
                out[c] = cached
            else:
                missing.append(c)
        for i in range(0, len(missing), EPSS_BATCH_SIZE):
            chunk = missing[i:i + EPSS_BATCH_SIZE]
            try:
                data = self._request("GET", EPSS_URL, params={"cve": ",".join(chunk)})
            except NetworkError as e:
                log.warning("EPSS lookup failed: %s", e)
                self.stats["epss_available"] = False
                continue
            rows = {r.get("cve"): r for r in (data or {}).get("data", []) or []}
            for c in chunk:
                r = rows.get(c)
                try:
                    val = ({"epss": float(r["epss"]), "percentile": float(r["percentile"])}
                           if r else {"epss": None, "percentile": None})
                except (KeyError, TypeError, ValueError):
                    val = {"epss": None, "percentile": None}
                out[c] = val
                self.cache.set("epss", c, val)
        return out

    def _get_kev(self) -> Set[str]:
        cached = self.cache.get("kev", "catalog", ttl=self._ttl(DAY))
        if cached is not None:
            return set(cached)
        try:
            data = self._request("GET", KEV_URL)
        except NetworkError as e:
            log.warning("CISA KEV download failed: %s", e)
            self.stats["kev_available"] = False
            return set()
        ids = [v.get("cveID") for v in (data or {}).get("vulnerabilities", []) or [] if v.get("cveID")]
        if ids:
            self.cache.set("kev", "catalog", ids)
        return set(ids)

    # ---- main entry ------------------------------------------------------ #
    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self.stats = {"offline": self.offline, "epss_available": True, "kev_available": True,
                      "osv_errors": 0}
        deps = collect_dependencies(root)
        pinned = [d for d in deps if d.version]
        unpinned = [d for d in deps if not d.version]
        self.stats.update(dependencies_total=len(deps), dependencies_pinned=len(pinned),
                          dependencies_unpinned=len(unpinned))
        if unpinned:
            log.info("%d dependency entries are not pinned to an exact version and were skipped "
                     "(e.g. %s)", len(unpinned), ", ".join(sorted({d.name for d in unpinned})[:5]))
        if not pinned:
            log.info("No pinned dependencies found under %s", root)
            self.stats.update(vulnerable_packages=0, vulnerabilities=0, kev_hits=0)
            return []

        # where each (name, version) appears
        locations: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
        for d in pinned:
            locations.setdefault((d.name, d.version), []).append((d.file, d.line))  # type: ignore[arg-type]
        pairs = sorted(locations)
        self.stats["unique_packages_queried"] = len(pairs)

        vuln_ids = self._query_osv(pairs)
        all_ids: Set[str] = set().union(*vuln_ids.values()) if vuln_ids else set()
        raw = self._fetch_vulns(all_ids) if all_ids else {}

        merged: Dict[Tuple[str, str], List[VulnInfo]] = {}
        for pair, ids in vuln_ids.items():
            infos = []
            for vid in sorted(ids):
                if vid in raw:
                    info = parse_osv_vuln(raw[vid], pair[0])
                    if info:
                        infos.append(info)
            if infos:
                merged[pair] = merge_vulns(infos)

        cves: Set[str] = {c for vs in merged.values() for v in vs for c in v.cves}
        epss = self._get_epss(cves) if (self.use_epss and cves) else {}
        kev = self._get_kev() if (self.use_kev and cves) else set()

        findings: List[Finding] = []
        for (name, version), vulns in merged.items():
            for v in vulns:
                findings.append(self._make_finding(name, version, v, locations[(name, version)],
                                                   epss, kev))
        # Option 1: Early reachability gating
        # When filter_unreachable is enabled and the target repository contains Python sources,
        # run AST reachability analysis and FP guards to filter out dead packages, unused
        # components, and platform-mismatched advisories before returning.
        if self.filter_unreachable and _has_python_sources(root):
            from core.risk_graph import RiskGraph
            from core.fp_detector import detect_false_positives
            rg = RiskGraph(str(root)).build()
            rg.analyze_reachability(findings)
            detect_false_positives(findings, repo_path=str(root))
            unfiltered_cnt = len(findings)
            findings = [f for f in findings if getattr(f, "fp_likelihood", None) != "HIGH"]
            self.stats["unreachable_filtered"] = unfiltered_cnt - len(findings)

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.title))
        self.stats.update(
            vulnerable_packages=len(merged),
            vulnerabilities=len(findings),
            kev_hits=sum(1 for f in findings if f.extra.get("kev")),
        )
        return findings

    def _make_finding(self, name: str, version: str, v: VulnInfo,
                      locs: List[Tuple[str, int]], epss: Dict[str, dict], kev: Set[str]) -> Finding:
        epss_vals = [epss[c]["epss"] for c in v.cves if c in epss and epss[c]["epss"] is not None]
        pct_vals = [epss[c]["percentile"] for c in v.cves
                    if c in epss and epss[c]["percentile"] is not None]
        epss_score = max(epss_vals) if epss_vals else None
        in_kev = any(c in kev for c in v.cves)
        exploitability = 1.0 if in_kev else (epss_score or 0.0)

        severity = v.cvss if v.cvss is not None else DEFAULT_SEVERITY
        source = v.severity_source if v.cvss is not None else "default"

        fixed = pick_fixed_version(v.fixed, version)
        if fixed:
            fix_hint = f"Upgrade {name} from {version} to {fixed} or later."
        else:
            fix_hint = (f"No newer fixed release of {name} is listed in OSV for {version}; "
                        f"check the advisory, pin a patched version, or replace the package.")

        desc = v.summary or "No description provided."
        if len(v.details) > len(v.summary):
            desc = (desc + "\n" + v.details)[:700]

        first_file, first_line = locs[0]
        is_dev = all(is_dev_requirement_file(f) for f, l in locs)
        return Finding(
            engine=self.name,
            title=f"{v.id}: {name}=={version} - {v.summary[:100] or 'known vulnerability'}",
            file=first_file,
            line=first_line,
            cwe=v.cwe,
            severity=round(severity, 1),
            description=desc,
            evidence=f"{name}=={version}",
            fix_hint=fix_hint,
            exploitability=round(exploitability, 4),
            extra={
                "package": name,
                "version": version,
                "vuln_id": v.id,
                "aliases": sorted(v.aliases),
                "fixed_version": fixed,
                "severity_source": source,
                "epss": epss_score,
                "epss_percentile": max(pct_vals) if pct_vals else None,
                "kev": in_kev,
                "locations": [{"file": f, "line": l} for f, l in locs],
                "dependency_scope": "dev" if is_dev else "prod",
                "advisory_url": f"https://osv.dev/vulnerability/{v.id}",
            },
        )
