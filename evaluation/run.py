"""Command line for the evaluation harness.

  python -m evaluation.run template --scan scan.json --labels evaluation/labels/vulpy.yaml
  python -m evaluation.run evaluate --scan scan.json --labels evaluation/labels/vulpy.yaml \
        --report-md docs/eval_vulpy.md --json-out eval_vulpy.json
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .labels import LabelError, finding_key, load_labels
from .metrics import DEFAULT_KS, evaluate
from .report import to_console, to_markdown


def _load_scan(path: str) -> List[Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a JSON list of findings (as written by `core.pipeline -o`)")
    return data


def _q(s: str) -> str:
    """JSON string == valid YAML double-quoted string; safe for any text."""
    return json.dumps(s, ensure_ascii=False)


def _comment(s: str, limit: int = 110) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def pick_sample(seen: Dict[str, Dict[str, Any]], keys: List[str], n: int, seed: int = 0) -> List[str]:
    """Random sample of n keys, spread over the engines in proportion to their size (at least one each).

    Deterministic for a given scan and seed, so the same sample is chosen if you re-run the command.
    """
    if n >= len(keys):
        return sorted(keys)
    groups: Dict[str, List[str]] = {}
    for k in sorted(keys):
        groups.setdefault(seen[k].get("engine", "?"), []).append(k)
    total = len(keys)
    alloc = {e: max(1, round(n * len(g) / total)) for e, g in groups.items()}
    while sum(alloc.values()) > n:                       # trim the biggest group first
        e = max((e for e in alloc if alloc[e] > 1), key=lambda e: (alloc[e], e), default=None)
        if e is None:
            break
        alloc[e] -= 1
    while sum(alloc.values()) < n:                       # top up the biggest group that has spare findings
        e = max((e for e in alloc if alloc[e] < len(groups[e])), key=lambda e: (len(groups[e]) - alloc[e], e),
                default=None)
        if e is None:
            break
        alloc[e] += 1
    rng = random.Random(seed)
    picked: List[str] = []
    for e in sorted(groups):
        picked.extend(rng.sample(groups[e], min(alloc[e], len(groups[e]))))
    return sorted(picked)


def build_template(findings: List[Dict[str, Any]], existing_path: Optional[Path], repo_name: str,
                   sample: Optional[int] = None, seed: int = 0) -> str:
    """Write the labels file. Keeps every verdict/note already there; adds new findings with empty verdicts.

    Only the scanner's masked `evidence` is shown, never raw source, so credentials cannot leak into labels.
    """
    old: Dict[str, Any] = {}
    expected: list = []
    if existing_path and existing_path.exists():
        old = yaml.safe_load(existing_path.read_text(encoding="utf-8")) or {}
        expected = old.get("expected") or []
        repo_name = repo_name or str(old.get("repo") or "")
    old_findings: Dict[str, Any] = dict(old.get("findings") or {})

    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        seen.setdefault(finding_key(f), f)

    if sample:
        # Keep everything already in the file; add a random sample of `sample` of the findings not yet in it.
        fresh = [k for k in seen if k not in old_findings]
        chosen = set(pick_sample(seen, fresh, sample, seed))
        seen = {k: f for k, f in seen.items() if k in old_findings or k in chosen}

    lines = [
        f"# SCIP evaluation labels for: {repo_name or '(repo)'}",
        "# Set `verdict` to  TP (real vulnerability) | FP (false alarm) | UNSURE  - leave \"\" to skip.",
        "# Use `note` to record WHY (this is what you explain in the viva). Re-running `template` keeps your work.",
        f"repo: {_q(repo_name)}",
        "findings:",
    ]

    def entry(key: str, f: Optional[Dict[str, Any]], old_e: Optional[Dict[str, Any]]) -> None:
        if f is not None:
            # Blind labelling: show what the scanner found, never SCIP's own risk score or FP guess,
            # otherwise the labels would just echo the tool they are meant to judge.
            lines.append(f"  # [{f.get('engine', '?')}] {_comment(f.get('title', ''), 90)}")
            ev = _comment(f.get("evidence", ""), 100)
            if ev:
                lines.append(f"  #   evidence: {ev}")
        else:
            lines.append("  # (not in the current scan - code changed or engine not run; kept for reference)")
        v = (old_e or {}).get("verdict") or ""
        n = (old_e or {}).get("note") or ""
        lines.append(f"  {_q(key)}: {{verdict: {_q(v)}, note: {_q(n)}}}")

    def _verdict(k: str) -> str:
        return ((old_findings.get(k) or {}).get("verdict") or "")

    def _sort_key(k: str):                      # file/line order: no hint of SCIP's ranking
        f = seen[k]
        return (f.get("file") or "", int(f.get("line") or 0), k)

    todo_keys = [k for k in seen if not _verdict(k)]
    done_keys = [k for k in seen if _verdict(k)]
    stale_keys = [k for k in old_findings if k not in seen]

    if todo_keys:
        lines.append("  # ===== TO LABEL: set a verdict for each of these =====")
        for k in sorted(todo_keys, key=_sort_key):
            entry(k, seen[k], old_findings.get(k))
    if done_keys:
        lines.append("  # ===== already labelled =====")
        for k in sorted(done_keys):
            entry(k, seen[k], old_findings[k])
    if stale_keys:
        lines.append("  # ===== not in the current scan =====")
    for k in sorted(stale_keys):
        entry(k, None, old_findings[k])

    lines.append("expected:")
    if expected:
        for e in expected:
            lines.append(f"  - {json.dumps(e, ensure_ascii=False)}")
    else:
        lines.append("  # - {file: bad/libuser.py, line: 12, tol: 2, cwe: CWE-89, note: \"SQL injection in login\"}")
        lines.append("  []")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="evaluation.run", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("template", help="create/update a labels file from a scan, ready for humans to label")
    t.add_argument("--scan", required=True, help="JSON written by: python -m core.pipeline <repo> -o scan.json")
    t.add_argument("--labels", required=True, help="labels file to create or update (YAML)")
    t.add_argument("--repo-name", default="", help="name stored in the file, e.g. vulpy")
    t.add_argument("--sample", type=int, metavar="N",
                   help="only add a random sample of N new findings (spread over the engines) instead of all; "
                        "findings left out are simply not part of the evaluation")
    t.add_argument("--seed", type=int, default=0, help="random seed for --sample (default 0, reproducible)")

    e = sub.add_parser("evaluate", help="score a scan against the labels")
    e.add_argument("--scan", required=True)
    e.add_argument("--labels", required=True)
    e.add_argument("--report-md", metavar="FILE", help="write a Markdown report")
    e.add_argument("--json-out", metavar="FILE", help="write all metrics as JSON")
    e.add_argument("--line-tolerance", type=int, default=0,
                   help="match a finding to a label whose line differs by up to N (same file and CWE)")
    e.add_argument("--k", type=int, action="append", help="precision@k values (default 5, 10, 20)")
    e.add_argument("--strict", action="store_true",
                   help="exit 1 if any real finding is wrongly hidden by the false-positive filter")

    args = ap.parse_args(argv)

    try:
        findings = _load_scan(args.scan)
        if args.cmd == "template":
            p = Path(args.labels)
            text = build_template(findings, p, args.repo_name, args.sample, args.seed)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8", newline="\n")
            todo = text.count('verdict: ""')
            print(f"[+] Wrote {p}  ({len(findings)} findings, {todo} still to label)")
            return 0

        labels = load_labels(args.labels)
        res = evaluate(findings, labels, ks=tuple(args.k or DEFAULT_KS), line_tolerance=args.line_tolerance)
    except (LabelError, FileNotFoundError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(to_console(res))
    if args.report_md:
        Path(args.report_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_md).write_text(to_markdown(res, labels.repo), encoding="utf-8", newline="\n")
        print(f"[+] Wrote {args.report_md}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(res, indent=2), encoding="utf-8", newline="\n")
        print(f"[+] Wrote {args.json_out}")
    if args.strict and not res["fp_filter"]["safe"]:
        print("[!] FAIL: real findings were hidden by the false-positive filter", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
