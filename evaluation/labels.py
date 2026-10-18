"""Ground-truth labels: which findings are real (TP), false alarms (FP), and which known
vulnerabilities a good scanner is expected to find.

Label file format (YAML; JSON is also valid YAML):

    repo: vulpy
    findings:                                   # one entry per scanner finding a human has judged
      "bad/libuser.py:12:CWE-89": {verdict: TP, note: "login query built with format()"}
    expected:                                   # known vulnerabilities, used to measure recall
      - {file: bad/libuser.py, line: 12, tol: 2, cwe: CWE-89, note: "SQL injection in login"}

A finding's key is  "<file>:<line>:<CWE>"  (file relative to the scanned repo, '/' separators,
line 0 when unknown, CWE '-' when unknown). Dependency findings add "#<CVE/GHSA id>" so that every
vulnerability gets its own label, e.g. "requirements.txt:11:CWE-400#CVE-2024-1234".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

VERDICTS = ("TP", "FP", "UNSURE")


class LabelError(ValueError):
    """The label file is malformed (bad verdict, wrong type, ...)."""


def norm_file(path: Optional[str]) -> str:
    p = (path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


_ADVISORY_RE = re.compile(r"\b(CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+)\b", re.I)


def advisory_id(f: Dict[str, Any]) -> str:
    """Vulnerability id of a dependency finding (CVE / GHSA / PYSEC), or ''."""
    vid = (f.get("extra") or {}).get("vuln_id")
    if vid:
        return str(vid).upper()
    m = _ADVISORY_RE.search(f.get("title") or "")
    return m.group(1).upper() if m else ""


def finding_key(f: Dict[str, Any]) -> str:
    """Stable id of a finding: '<file>:<line>:<CWE>' plus '#<advisory id>' for dependency findings.

    Many CVEs can sit on the same requirements.txt line with the same CWE, so without the advisory id
    they would all share one label.
    """
    line = f.get("line")
    try:
        line = int(line) if line else 0
    except (TypeError, ValueError):
        line = 0
    cwe = (f.get("cwe") or "-").strip().upper() or "-"
    key = f"{norm_file(f.get('file'))}:{line}:{cwe}"
    vid = advisory_id(f)
    return f"{key}#{vid}" if vid else key


def _split_key(key: str):
    file_part, _, rest = key.rpartition(":")          # cwe
    file_part, _, line = file_part.rpartition(":")    # line
    return file_part, (int(line) if line.isdigit() else 0), rest


def parse_verdict(value: Any, where: str = "") -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip().upper()
    if v == "":
        return None
    if v not in VERDICTS:
        raise LabelError(f"{where}: verdict must be one of {', '.join(VERDICTS)} (or empty), got {value!r}")
    return v


@dataclass
class Expected:
    file: str
    line: int = 0
    tol: int = 3
    cwe: List[str] = field(default_factory=list)   # any of these CWEs counts; empty = any CWE
    note: str = ""

    def matches(self, f: Dict[str, Any]) -> bool:
        if norm_file(f.get("file")) != self.file:
            return False
        if self.line:
            fl = f.get("line") or 0
            if abs(int(fl) - self.line) > self.tol:
                return False
        if self.cwe and (f.get("cwe") or "").upper() not in self.cwe:
            return False
        return True


@dataclass
class Labels:
    repo: str = ""
    findings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    expected: List[Expected] = field(default_factory=list)

    def verdict_for(self, f: Dict[str, Any], line_tolerance: int = 0) -> Optional[str]:
        key = finding_key(f)
        entry = self.findings.get(key)
        if entry is not None:
            return entry.get("verdict")
        if line_tolerance > 0:
            file_, line, cwe = _split_key(key)
            hits = []
            for k, e in self.findings.items():
                kf, kl, kc = _split_key(k)
                if kf == file_ and kc == cwe and abs(kl - line) <= line_tolerance:
                    hits.append(e.get("verdict"))
            if len(hits) == 1:           # ambiguous fuzzy matches are ignored on purpose
                return hits[0]
        return None


def load_labels(path: Union[str, Path]) -> Labels:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise LabelError(f"{p}: top level must be a mapping")
    labels = Labels(repo=str(data.get("repo") or ""))

    raw_findings = data.get("findings") or {}
    if not isinstance(raw_findings, dict):
        raise LabelError(f"{p}: 'findings' must be a mapping of key -> {{verdict, note}}")
    for key, entry in raw_findings.items():
        entry = entry or {}
        if not isinstance(entry, dict):
            raise LabelError(f"{p}: entry {key!r} must be a mapping like {{verdict: TP, note: ''}}")
        labels.findings[str(key)] = {
            "verdict": parse_verdict(entry.get("verdict"), f"{p}: {key}"),
            "note": str(entry.get("note") or ""),
        }

    for i, e in enumerate(data.get("expected") or []):
        if not isinstance(e, dict) or "file" not in e:
            raise LabelError(f"{p}: expected[{i}] needs at least a 'file'")
        cwe = e.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        labels.expected.append(Expected(
            file=norm_file(e["file"]),
            line=int(e.get("line") or 0),
            tol=int(e.get("tol", 3)),
            cwe=[str(c).upper() for c in cwe],
            note=str(e.get("note") or ""),
        ))
    return labels
