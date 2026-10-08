"""Scan pipeline: runs every engine and collects findings.

Usage:
    python -m core.pipeline <repo_path>            # readable table
    python -m core.pipeline <repo_path> --json     # full JSON
    python -m core.pipeline <repo_path> -o out.json  # full JSON saved as UTF-8 (recommended)
    python -m core.pipeline <repo_path> --offline     # dependency engine: cached data only
    python -m core.pipeline <repo_path> --no-history  # secrets engine: skip git-history scan
"""
import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional, Set

from core.dedup import deduplicate_findings
from core.finding import Finding
from core.suppression import filter_suppressions, save_baseline
from engines.bandit_engine import BanditEngine
from engines.dependency_engine import DependencyEngine
from engines.secrets_engine import SecretsEngine
from engines.semgrep_engine import SemgrepEngine
from engines.crypto_engine import CryptoEngine
from scoring import score_and_sort_findings

CONSTRUCTABLE_ENGINES: Set[str] = {"dependency", "secrets", "bandit", "semgrep", "crypto"}
KNOWN_ENGINES: Set[str] = CONSTRUCTABLE_ENGINES


def get_engines(
    offline: bool = False,
    scan_history: bool = True,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    run_crypto: bool = True,
    bandit_config: Optional[str] = None,
    semgrep_rules: Optional[str] = None,
    enabled_engines: Optional[List[str]] = None,
    include_suppressed: bool = False,
) -> list:
    all_engines = [
        DependencyEngine(offline=offline),
        SecretsEngine(scan_history=scan_history),
        BanditEngine(config_file=bandit_config, include_suppressed=include_suppressed),
        SemgrepEngine(rules_path=semgrep_rules, include_suppressed=include_suppressed),
        CryptoEngine(),
    ]
    if enabled_engines is not None:
        selected = {e.strip().lower() for e in enabled_engines}
        return [e for e in all_engines if e.name.lower() in selected]

    active = []
    for e in all_engines:
        if e.name == "bandit" and not run_bandit:
            continue
        if e.name == "semgrep" and not run_semgrep:
            continue
        if e.name == "crypto" and not run_crypto:
            continue
        active.append(e)
    return active


def run_scan(
    repo_path: str,
    engines: Optional[list] = None,
    dedup: bool = True,
    baseline_path: Optional[str] = None,
    include_suppressed: bool = False,
    is_ci: bool = False,
    scoring: bool = True,
    exclude_tests: bool = False,
) -> List[Finding]:
    engines = engines if engines is not None else get_engines(include_suppressed=include_suppressed)
    findings: List[Finding] = []
    for engine in engines:
        if hasattr(engine, "is_available") and not engine.is_available():
            print(f"[-] Skipping {engine.name} engine (not installed)", file=sys.stderr)
            engine.stats = {
                "engine": engine.name,
                "skipped": True,
                "note": "not installed / not in PATH",
                "findings_count": 0,
                "errors": [],
            }
            continue
        print(f"[+] Running {engine.name} engine...", file=sys.stderr)
        findings.extend(engine.scan(repo_path))

    # Auto-detect baseline file in repository root if not specified
    if not baseline_path:
        default_baseline = Path(repo_path).resolve() / ".scip-baseline.json"
        if default_baseline.exists():
            if is_ci:
                print(f"[!] CI mode: skipping auto-detection of {default_baseline}. "
                      f"Pass --baseline explicitly to enforce a baseline.", file=sys.stderr)
            else:
                baseline_path = str(default_baseline)
                print(f"[!] Auto-loading repository baseline: {default_baseline}", file=sys.stderr)

    # 1. Apply inline and baseline suppressions per-source before deduplication
    active, suppressed = filter_suppressions(
        findings,
        repo_path=repo_path,
        baseline_path=baseline_path,
        include_suppressed=include_suppressed,
    )
    if suppressed and not include_suppressed:
        print(f"[+] Filtered {len(suppressed)} suppressed finding(s)", file=sys.stderr)

    # 2. Correlate and deduplicate remaining active findings
    if dedup and active:
        raw_count = len(active)
        active = deduplicate_findings(active)
        merged = raw_count - len(active)
        if merged > 0:
            print(f"[+] Correlated & merged {merged} duplicate/overlapping finding(s)", file=sys.stderr)

    # 3. Calculate 0-100 risk score and sort by risk_score descending (or legacy sort if disabled)
    if scoring:
        active = score_and_sort_findings(active, repo_path=repo_path)
    else:
        active = sorted(active, key=lambda f: (-f.severity, -f.exploitability))

    # 4. Optional: filter out test fixtures
    if exclude_tests and active:
        from core.risk_graph import is_test_path
        pre_count = len(active)
        active = [f for f in active if not is_test_path(f.file) and getattr(f, "exposure", None) != "TEST"]
        test_filtered = pre_count - len(active)
        if test_filtered > 0:
            print(f"[+] Excluded {test_filtered} test fixture finding(s)", file=sys.stderr)

    return active


def _ascii(s: str) -> str:
    return s.encode("ascii", "replace").decode("ascii")


def print_table(findings: List[Finding], engines: Optional[list] = None, show_risk: bool = True) -> None:
    if not findings:
        print("No findings.")
    else:
        if show_risk and any(f.risk_score > 0 for f in findings):
            sorted_findings = sorted(findings, key=lambda f: (-f.risk_score, -f.severity, -f.exploitability))
            print(f"\n{'#':>3}  {'RISK':>6}  {'SEV':>4}  {'EXPL':>5}  {'REACH':>6}  {'ENGINE':<11} {'LOCATION':<28} TITLE")
            print("-" * 128)
            for i, f in enumerate(sorted_findings, 1):
                loc = f"{f.file}:{f.line}" if f.line else f.file
                if len(loc) > 28:
                    loc = "..." + loc[-25:]
                title = _ascii(f.title)
                if f.extra.get("seed_classification") == "SEED" or "seed" in (getattr(f, "fp_reason", "") or "").lower():
                    title = f"[SEED] {title}"
                elif getattr(f, "fp_likelihood", None) == "HIGH" or f.extra.get("fp_likelihood") == "HIGH":
                    title = f"[FP?] {title}"
                if len(title) > 55:
                    title = title[:52] + "..."
                engine_label = f"{f.engine}*" if f.extra.get("corroborated") else f.engine
                reach_str = f.exposure if f.exposure else ("YES" if f.reachable is True else ("NO" if f.reachable is False else "?"))
                print(f"{i:>3}  {f.risk_score:>6.2f}  {f.severity:>4.1f}  {f.exploitability:>5.2f}  {reach_str:>6}  {engine_label:<11} {loc:<28} {title}")
        else:
            sorted_findings = sorted(findings, key=lambda f: (-f.severity, -f.exploitability))
            print(f"\n{'#':>3}  {'SEV':>4}  {'EXPL':>5}  {'ENGINE':<11} {'LOCATION':<28} TITLE")
            print("-" * 110)
            for i, f in enumerate(sorted_findings, 1):
                loc = f"{f.file}:{f.line}" if f.line else f.file
                if len(loc) > 28:
                    loc = "..." + loc[-25:]
                title = _ascii(f.title)
                if len(title) > 60:
                    title = title[:57] + "..."
                engine_label = f"{f.engine}*" if f.extra.get("corroborated") else f.engine
                print(f"{i:>3}  {f.severity:>4.1f}  {f.exploitability:>5.2f}  {engine_label:<11} {loc:<28} {title}")
        print(f"\nTotal: {len(findings)} finding(s)")

    if engines:
        print("\nEngine Execution Summary:")
        for e in engines:
            stats = getattr(e, "stats", {})
            if stats.get("skipped"):
                print(f"  [-] {e.name:<12} SKIPPED ({stats.get('note', 'not installed')})")
            elif stats.get("errors"):
                err_count = len(stats["errors"])
                print(f"  [!] {e.name:<12} WARNING: {err_count} error(s) during scan: {stats['errors'][:2]}")
            else:
                scanned = stats.get("files_scanned")
                cnt = stats.get("findings_count", stats.get("vulnerabilities", stats.get("secrets_found", 0)))
                detail = f"scanned {scanned} files, " if scanned is not None else ""
                print(f"  [+] {e.name:<12} OK ({detail}{cnt} findings)")


def print_attack_paths(findings: List[Finding]) -> None:
    """Print detailed visual attack paths and remediation hints for reachable findings."""
    reachable = [f for f in findings if f.extra.get("attack_path") and f.exposure not in ("REPO", "HIST")]
    if not reachable:
        return

    print("\n" + "=" * 115)
    print("REACHABLE ATTACK PATHS & REMEDIATION HINTS")
    print("=" * 115)

    for i, f in enumerate(reachable, 1):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        exposure_tag = f.exposure or ("YES" if f.reachable is True else "REACHABLE")
        print(f"\n[#{i}] {f.title}")
        print(f"     Location:     {loc}")
        print(f"     Severity:     {f.severity:.1f} | Risk Score: {f.risk_score:.2f} | Exposure: {exposure_tag}")

        path = f.extra.get("attack_path", [])
        if path:
            print("     Attack Path:")
            for idx, hop in enumerate(path):
                prefix = "       |--> " if idx > 0 else "       Entry: "
                indent = "      " + (" " * (idx * 2)) if idx > 0 else ""
                print(f"{indent}{prefix}{hop}")

        hint = f.fix_hint or f.extra.get("fix_hint") or getattr(f, "fix_hint", "")
        if hint:
            print(f"     Remediation:  {hint}")
        print("-" * 115)



def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a repository")
    ap.add_argument("path", nargs="?", default=".", help="repository to scan")
    ap.add_argument("--json", action="store_true", help="print full JSON instead of a table")
    ap.add_argument("--offline", action="store_true", help="dependency engine: use cached API data only")
    ap.add_argument("--no-history", action="store_true", help="secrets engine: skip the git-history scan")
    ap.add_argument("--no-bandit", action="store_true", help="skip the Bandit security engine")
    ap.add_argument("--no-semgrep", action="store_true", help="skip the Semgrep security engine")
    ap.add_argument("--no-crypto", action="store_true", help="skip the Crypto security engine")
    ap.add_argument("--no-dedup", action="store_true", help="disable cross-tool finding deduplication")
    ap.add_argument("--no-scoring", action="store_true", help="disable composite risk scoring and preserve legacy severity sorting")
    ap.add_argument("--baseline", metavar="FILE", help="path to baseline suppression JSON file (.scip-baseline.json)")
    ap.add_argument("--make-baseline", metavar="FILE", help="record current findings into a baseline file")
    ap.add_argument("--include-suppressed", action="store_true", help="include suppressed findings in report")
    ap.add_argument("--bandit-config", metavar="FILE", help="path to custom Bandit YAML config file")
    ap.add_argument("--semgrep-rules", "--semgrep-config", metavar="PATH_OR_PRESET",
                    help="custom Semgrep rules file, directory, or preset (e.g., p/python)")
    ap.add_argument("--engines", metavar="LIST",
                    help="comma-separated list of engines to run (e.g. dependency,secrets,bandit,semgrep)")
    ap.add_argument("--ci", action="store_true",
                    help="run in CI mode: require explicit --baseline and do not auto-load repo baseline")
    ap.add_argument("--strict", action="store_true",
                    help="fail with exit code 2 if any engine is skipped or encounters errors")
    ap.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    help="exit with code 1 if active findings meet or exceed this severity")
    ap.add_argument("--exclude-tests", action="store_true",
                    help="filter out findings situated in test files and mock fixtures")
    ap.add_argument("--details", "--show-paths", action="store_true",
                    help="display detailed attack paths and remediation hints for reachable vulnerabilities")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="write full JSON to FILE (UTF-8). Use this instead of '>' in PowerShell, "
                         "which saves UTF-16 that many tools cannot read")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    # Validate requested engines
    enabled = None
    if args.engines is not None:
        enabled = [e.strip().lower() for e in args.engines.split(",") if e.strip()]
        if not enabled:
            print("Error: No engine specified in --engines.", file=sys.stderr)
            return 2
        invalid = [e for e in enabled if e not in CONSTRUCTABLE_ENGINES]
        if invalid:
            print(f"Error: Unknown or unavailable engine(s): {', '.join(invalid)}. "
                  f"Available engines are: {', '.join(sorted(CONSTRUCTABLE_ENGINES))}", file=sys.stderr)
            return 2

    # Validate explicit baseline file exists
    if args.baseline and not Path(args.baseline).exists():
        print(f"Error: Specified baseline file not found: {args.baseline}", file=sys.stderr)
        return 2

    is_ci = bool(args.ci)
    if is_ci and args.baseline:
        try:
            Path(args.baseline).resolve().relative_to(Path(args.path).resolve())
            print("[!] Security Warning: Baseline file is located inside the repository under test.", file=sys.stderr)
        except ValueError:
            pass

    engines = get_engines(
        offline=args.offline,
        scan_history=not args.no_history,
        run_bandit=not args.no_bandit,
        run_semgrep=not args.no_semgrep,
        run_crypto=not args.no_crypto,
        bandit_config=args.bandit_config,
        semgrep_rules=args.semgrep_rules,
        enabled_engines=enabled,
        include_suppressed=args.include_suppressed,
    )

    # When generating baseline, capture raw findings before suppression/dedup
    if args.make_baseline:
        raw_findings: List[Finding] = []
        for engine in engines:
            if hasattr(engine, "is_available") and not engine.is_available():
                continue
            raw_findings.extend(engine.scan(args.path))
        saved_count = save_baseline(raw_findings, Path(args.make_baseline))
        print(f"[+] Wrote {saved_count} unfiltered findings to baseline {args.make_baseline}", file=sys.stderr)
        return 0

    try:
        findings = run_scan(
            args.path,
            engines=engines,
            dedup=not args.no_dedup,
            baseline_path=args.baseline,
            include_suppressed=args.include_suppressed,
            is_ci=is_ci,
            scoring=not args.no_scoring,
            exclude_tests=args.exclude_tests,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if args.strict or is_ci:
        for e in engines:
            stats = getattr(e, "stats", {})
            if stats.get("skipped"):
                print(f"Error: Engine '{e.name}' was skipped in strict/CI mode: {stats.get('note')}", file=sys.stderr)
                return 2
            if stats.get("errors"):
                print(f"Error: Engine '{e.name}' encountered errors in strict/CI mode: {stats['errors'][:2]}", file=sys.stderr)
                return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
        print(f"[+] Wrote {len(findings)} findings to {args.output} (UTF-8)", file=sys.stderr)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        for e in engines:
            stats = getattr(e, "stats", {})
            if stats.get("errors"):
                print(f"[!] Engine {e.name} encountered errors: {stats['errors'][:3]}", file=sys.stderr)
    else:
        print_table(findings, engines=engines, show_risk=not args.no_scoring)
        if args.details:
            print_attack_paths(findings)

    # Severity failure gating
    SEV_THRESHOLDS = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
    fail_threshold = None
    if args.fail_on:
        fail_threshold = SEV_THRESHOLDS.get(args.fail_on.upper(), 7.0)
    elif is_ci:
        fail_threshold = 7.0

    if fail_threshold is not None:
        failing = [f for f in findings if f.severity >= fail_threshold and not f.extra.get("suppressed")]
        if failing:
            print(f"\n[!] Failure threshold met: {len(failing)} finding(s) with severity >= {fail_threshold}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
