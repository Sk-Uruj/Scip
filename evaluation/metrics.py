"""Pure metric functions: findings (list of dicts, as written by `core.pipeline -o`) + labels -> numbers.

Key questions answered:
  * How many reported findings are real?                       (precision)
  * How many known vulnerabilities did we find?                (recall on the `expected` list)
  * Did the false-positive filter hide any REAL finding?       (must be 0)
  * Does SCIP's risk score rank real findings above noise
    better than severity alone?                                (precision@k, average precision)
"""
from __future__ import annotations

import random
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .labels import Labels, finding_key

DEFAULT_KS = (5, 10, 20)
TIE_TRIALS = 200


def _ratio(num: int, den: int) -> Optional[float]:
    return round(num / den, 4) if den else None


def is_fp_high(f: Dict[str, Any]) -> bool:
    """Same predicate `--hide-fp` uses: these findings would be hidden from the user."""
    return (f.get("fp_likelihood") or (f.get("extra") or {}).get("fp_likelihood")) == "HIGH"


def is_fp_medium(f: Dict[str, Any]) -> bool:
    return (f.get("fp_likelihood") or (f.get("extra") or {}).get("fp_likelihood")) == "MEDIUM"


# ---------------------------------------------------------------- ranking metrics
def _precision_at(order: Sequence[bool], k: int) -> float:
    return sum(order[:k]) / k


def _average_precision(order: Sequence[bool]) -> Optional[float]:
    hits, total = 0, 0.0
    for i, rel in enumerate(order, 1):
        if rel:
            hits += 1
            total += hits / i
    return total / hits if hits else None


def ranking_metrics(items: Sequence[Tuple[bool, float]], ks: Iterable[int] = DEFAULT_KS,
                    trials: int = TIE_TRIALS, seed: int = 0) -> Dict[str, Any]:
    """items = [(is_real, score)]; higher score = ranked earlier.

    Items with equal scores have no meaningful order, so we average over random tie-breaks
    (fixed seed, fully deterministic). This keeps a coarse score such as CVSS from looking
    lucky or unlucky just because of file order.
    """
    n = len(items)
    ks = [k for k in ks if k <= n]
    groups: Dict[float, List[bool]] = defaultdict(list)
    for rel, score in items:
        groups[score].append(rel)
    any_ties = any(len(g) > 1 and len(set(g)) > 1 for g in groups.values())
    runs = trials if any_ties else 1
    p_at = {k: 0.0 for k in ks}
    ap_sum, ap_n = 0.0, 0
    for t in range(runs):
        rng = random.Random(seed + t)
        order: List[bool] = []
        for score in sorted(groups, reverse=True):
            g = list(groups[score])
            rng.shuffle(g)
            order.extend(g)
        for k in ks:
            p_at[k] += _precision_at(order, k)
        ap = _average_precision(order)
        if ap is not None:
            ap_sum += ap
            ap_n += 1
    return {
        "precision_at": {k: round(p_at[k] / runs, 4) for k in ks},
        "average_precision": round(ap_sum / ap_n, 4) if ap_n else None,
        "tie_averaged": any_ties,
    }


# ---------------------------------------------------------------- main entry
def evaluate(findings: List[Dict[str, Any]], labels: Labels, ks: Iterable[int] = DEFAULT_KS,
             line_tolerance: int = 0) -> Dict[str, Any]:
    ks = tuple(ks)
    rows = []
    for f in findings:
        rows.append({"f": f, "key": finding_key(f), "verdict": labels.verdict_for(f, line_tolerance)})

    labelled = [r for r in rows if r["verdict"] in ("TP", "FP")]
    tp = [r for r in labelled if r["verdict"] == "TP"]
    fp = [r for r in labelled if r["verdict"] == "FP"]

    coverage = {
        "findings_total": len(rows),
        "labelled": len(labelled),
        "unsure": sum(1 for r in rows if r["verdict"] == "UNSURE"),
        "unlabelled": sum(1 for r in rows if r["verdict"] is None),
        "true_positive": len(tp),
        "false_positive": len(fp),
    }
    coverage["labelled_share"] = _ratio(len(labelled), len(rows))

    # --- detection quality on what the scanner reported
    by_engine: Dict[str, Dict[str, Any]] = {}
    for r in labelled:
        e = by_engine.setdefault(r["f"].get("engine", "?"), {"tp": 0, "fp": 0})
        e["tp" if r["verdict"] == "TP" else "fp"] += 1
    for e in by_engine.values():
        e["precision"] = _ratio(e["tp"], e["tp"] + e["fp"])

    detection = {
        "precision": _ratio(len(tp), len(labelled)),
        "by_engine": dict(sorted(by_engine.items())),
    }

    # --- recall on the known-vulnerability list
    exp_rows = []
    for ex in labels.expected:
        matched = [f for f in findings if ex.matches(f)]
        visible = [f for f in matched if not is_fp_high(f)]
        status = "found" if visible else ("found_but_hidden" if matched else "missed")
        exp_rows.append({
            "file": ex.file, "line": ex.line, "cwe": ex.cwe, "note": ex.note, "status": status,
            "matched_by": sorted({finding_key(f) for f in matched}),
        })
    n_exp = len(exp_rows)
    n_found = sum(1 for e in exp_rows if e["status"] == "found")
    n_hidden = sum(1 for e in exp_rows if e["status"] == "found_but_hidden")
    recall = {
        "expected_total": n_exp,
        "found": n_found,
        "found_but_hidden_by_fp_filter": n_hidden,
        "missed": n_exp - n_found - n_hidden,
        "recall": _ratio(n_found, n_exp),
        "recall_without_fp_filter": _ratio(n_found + n_hidden, n_exp),
        "details": exp_rows,
    }

    # --- false-positive filter safety (the number that must be zero)
    wrongly_hidden = [r for r in tp if is_fp_high(r["f"])]
    tp_demoted_medium = [r for r in tp if is_fp_medium(r["f"])]
    fp_high = [r for r in fp if is_fp_high(r["f"])]
    fp_any = [r for r in fp if is_fp_high(r["f"]) or is_fp_medium(r["f"])]
    kept = [r for r in labelled if not is_fp_high(r["f"])]
    kept_tp = sum(1 for r in kept if r["verdict"] == "TP")
    fp_filter = {
        "real_findings_wrongly_hidden": len(wrongly_hidden),
        "wrongly_hidden_list": [
            {"key": r["key"], "reason": r["f"].get("fp_reason", ""), "title": r["f"].get("title", "")}
            for r in wrongly_hidden],
        "real_findings_marked_medium_fp": len(tp_demoted_medium),
        "false_alarms_caught_high": len(fp_high),
        "false_alarm_catch_rate_high": _ratio(len(fp_high), len(fp)),
        "false_alarm_catch_rate_high_or_medium": _ratio(len(fp_any), len(fp)),
        "precision_before_hide_fp": detection["precision"],
        "precision_after_hide_fp": _ratio(kept_tp, len(kept)),
        "safe": len(wrongly_hidden) == 0,
    }

    # --- ranking: SCIP risk score vs severity alone (labelled findings only)
    scip_items = [(r["verdict"] == "TP", float(r["f"].get("risk_score") or 0.0)) for r in labelled]
    sev_items = [(r["verdict"] == "TP", float(r["f"].get("severity") or 0.0)) for r in labelled]
    base_rate = detection["precision"]
    ranking: Dict[str, Any] = {"labelled_findings": len(labelled), "base_rate": base_rate,
                               "ks": [k for k in ks if k <= len(labelled)]}
    if labelled and tp and fp:
        scip = ranking_metrics(scip_items, ks)
        sev = ranking_metrics(sev_items, ks)
        ranking["scip_risk_score"] = scip
        ranking["severity_only"] = sev
        ranking["ap_improvement"] = (
            round(scip["average_precision"] - sev["average_precision"], 4)
            if scip["average_precision"] is not None and sev["average_precision"] is not None else None)
        ranking["note"] = "ties are averaged over random orderings (deterministic seed)"
    else:
        ranking["note"] = ("ranking needs at least one real (TP) and one false (FP) labelled finding; "
                           "label more findings")

    return {
        "coverage": coverage,
        "detection": detection,
        "recall": recall,
        "fp_filter": fp_filter,
        "ranking": ranking,
    }
