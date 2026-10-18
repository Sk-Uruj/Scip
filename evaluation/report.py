"""Render evaluation results as Markdown (for the report/viva) and a short console summary."""
from __future__ import annotations

from typing import Any, Dict, Optional


def _pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def to_markdown(res: Dict[str, Any], repo: str = "") -> str:
    c, d, r, fp, rk = res["coverage"], res["detection"], res["recall"], res["fp_filter"], res["ranking"]
    out = [f"# SCIP evaluation{(' - ' + repo) if repo else ''}", ""]

    out += ["## 1. Label coverage", "",
            "| Findings reported | Labelled (TP/FP) | Unsure | Unlabelled | Real (TP) | False alarm (FP) |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {c['findings_total']} | {c['labelled']} ({_pct(c['labelled_share'])}) | {c['unsure']} | "
            f"{c['unlabelled']} | {c['true_positive']} | {c['false_positive']} |", "",
            "Metrics below use labelled findings only. Unlabelled findings are not counted either way.", ""]

    out += ["## 2. Detection precision", "",
            f"Of the labelled findings SCIP reported, **{_pct(d['precision'])}** are real.", ""]
    if d["by_engine"]:
        out += ["| Engine | Real | False alarm | Precision |", "|---|---:|---:|---:|"]
        for name, e in d["by_engine"].items():
            out.append(f"| {name} | {e['tp']} | {e['fp']} | {_pct(e['precision'])} |")
        out.append("")

    out += ["## 3. Recall on known vulnerabilities", ""]
    if r["expected_total"]:
        out += [f"SCIP found **{r['found']} of {r['expected_total']}** known vulnerabilities "
                f"(recall {_pct(r['recall'])}).",
                f"{r['found_but_hidden_by_fp_filter']} more were found but flagged HIGH false-positive "
                f"(hidden by `--hide-fp`); {r['missed']} were missed.", "",
                "| Status | Location | CWE | Note |", "|---|---|---|---|"]
        for e in r["details"]:
            loc = f"{e['file']}:{e['line']}" if e["line"] else e["file"]
            out.append(f"| {e['status']} | {loc} | {', '.join(e['cwe']) or 'any'} | {e['note']} |")
        out.append("")
        out.append("Recall is measured against the `expected` list only. It is a floor, not the true recall.")
    else:
        out.append("No `expected` list in the labels file, so recall was not measured.")
    out.append("")

    out += ["## 4. False-positive filter safety", ""]
    flag = "PASS" if fp["safe"] else "FAIL"
    out += [f"**Real findings wrongly hidden: {fp['real_findings_wrongly_hidden']}  ->  {flag}** "
            "(this number must be 0).", ""]
    for w in fp["wrongly_hidden_list"]:
        out.append(f"- `{w['key']}` hidden because: {w['reason'] or 'unspecified'}")
    if fp["wrongly_hidden_list"]:
        out.append("")
    out += ["| Measure | Value |", "|---|---:|",
            f"| False alarms flagged HIGH (hidden by --hide-fp) | {fp['false_alarms_caught_high']}"
            + ("" if fp['false_alarm_catch_rate_high'] is None
               else f" ({_pct(fp['false_alarm_catch_rate_high'])} of all FPs)") + " |",
            f"| False alarms flagged HIGH or MEDIUM (demoted) | {_pct(fp['false_alarm_catch_rate_high_or_medium'])} |",
            f"| Real findings marked MEDIUM (damped, still shown) | {fp['real_findings_marked_medium_fp']} |",
            f"| Precision before --hide-fp | {_pct(fp['precision_before_hide_fp'])} |",
            f"| Precision after --hide-fp | {_pct(fp['precision_after_hide_fp'])} |", ""]

    out += ["## 5. Ranking quality: SCIP risk score vs severity alone", ""]
    if "scip_risk_score" in rk:
        out += [f"Base rate (precision if findings were in random order): {_pct(rk['base_rate'])}.", "",
                "| Ordering | " + " | ".join(f"P@{k}" for k in rk["ks"]) + " | Average precision |",
                "|---|" + "---:|" * (len(rk["ks"]) + 1)]
        for label, key in (("SCIP risk score", "scip_risk_score"), ("Severity only", "severity_only")):
            m = rk[key]
            cells = " | ".join(_pct(m["precision_at"][k]) for k in rk["ks"])
            out.append(f"| {label} | {cells} | {_pct(m['average_precision'])} |")
        out += ["", f"Average-precision change from using SCIP's score: "
                    f"**{rk['ap_improvement']:+.4f}**" if rk.get("ap_improvement") is not None else "",
                f"_P@k = share of the top k findings that are real. {rk['note']}._"]
    else:
        out.append(rk["note"])
    out.append("")
    return "\n".join(out)


def to_console(res: Dict[str, Any]) -> str:
    c, d, r, fp = res["coverage"], res["detection"], res["recall"], res["fp_filter"]
    lines = [
        f"Findings: {c['findings_total']}  labelled: {c['labelled']}  (TP {c['true_positive']}, FP {c['false_positive']}, "
        f"unsure {c['unsure']}, unlabelled {c['unlabelled']})",
        f"Precision: {_pct(d['precision'])}",
    ]
    if r["expected_total"]:
        lines.append(f"Recall on known list: {r['found']}/{r['expected_total']} ({_pct(r['recall'])})")
    lines.append(f"Real findings wrongly hidden by FP filter: {fp['real_findings_wrongly_hidden']}  "
                 f"[{'PASS' if fp['safe'] else 'FAIL'}]")
    rk = res["ranking"]
    if "scip_risk_score" in rk:
        lines.append(f"Ranking AP: SCIP {_pct(rk['scip_risk_score']['average_precision'])} "
                     f"vs severity-only {_pct(rk['severity_only']['average_precision'])}")
    return "\n".join(lines)
