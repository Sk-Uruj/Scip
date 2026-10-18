"""Tests for the evaluation harness (labels, metrics, template, CLI)."""
import json

import pytest

from evaluation.labels import (Expected, LabelError, Labels, finding_key, load_labels, norm_file,
                               parse_verdict)
from evaluation.metrics import evaluate, ranking_metrics
from evaluation.report import to_console, to_markdown
from evaluation.run import build_template, main, pick_sample


def F(file="a.py", line=1, cwe="CWE-89", engine="bandit", risk=50.0, sev=5.0, fp=None, **kw):
    d = {"engine": engine, "title": "t", "file": file, "line": line, "cwe": cwe,
         "risk_score": risk, "severity": sev}
    if fp:
        d["fp_likelihood"] = fp
        d["fp_reason"] = "why"
    d.update(kw)
    return d


def L(findings=None, expected=None):
    return Labels(repo="r",
                  findings={k: {"verdict": v, "note": ""} for k, v in (findings or {}).items()},
                  expected=expected or [])


# ------------------------------------------------------------------ labels
def test_finding_key_normalises_path_line_and_cwe():
    assert finding_key({"file": ".\\src\\a.py", "line": 7, "cwe": "cwe-89"}) == "src/a.py:7:CWE-89"
    assert finding_key({"file": "a.py"}) == "a.py:0:-"
    assert norm_file("./x/y.py") == "x/y.py"


def test_parse_verdict_accepts_empty_and_rejects_typos():
    assert parse_verdict("") is None and parse_verdict(None) is None
    assert parse_verdict("tp") == "TP"
    with pytest.raises(LabelError):
        parse_verdict("TRUE")


def test_load_labels_roundtrip_and_expected_cwe_forms(tmp_path):
    p = tmp_path / "l.yaml"
    p.write_text(
        'repo: demo\n'
        'findings:\n'
        '  "a.py:1:CWE-89": {verdict: TP, note: "x"}\n'
        '  "b.py:2:CWE-79": {verdict: "", note: ""}\n'
        'expected:\n'
        '  - {file: a.py, line: 1, cwe: CWE-89}\n'
        '  - {file: b.py, cwe: [cwe-1, CWE-2], tol: 5}\n', encoding="utf-8")
    labels = load_labels(p)
    assert labels.findings["a.py:1:CWE-89"]["verdict"] == "TP"
    assert labels.findings["b.py:2:CWE-79"]["verdict"] is None
    assert labels.expected[0].cwe == ["CWE-89"]
    assert labels.expected[1].cwe == ["CWE-1", "CWE-2"] and labels.expected[1].tol == 5


def test_load_labels_bad_verdict_raises_with_location(tmp_path):
    p = tmp_path / "l.yaml"
    p.write_text('findings:\n  "a.py:1:CWE-1": {verdict: MAYBE}\n', encoding="utf-8")
    with pytest.raises(LabelError, match="a.py:1:CWE-1"):
        load_labels(p)


def test_verdict_for_line_tolerance_and_ambiguity():
    labels = L({"a.py:10:CWE-89": "TP"})
    assert labels.verdict_for(F(line=12)) is None                       # exact only by default
    assert labels.verdict_for(F(line=12), line_tolerance=2) == "TP"
    assert labels.verdict_for(F(line=12, cwe="CWE-79"), line_tolerance=2) is None   # other CWE
    amb = L({"a.py:10:CWE-89": "TP", "a.py:12:CWE-89": "FP"})
    assert amb.verdict_for(F(line=11), line_tolerance=2) is None        # ambiguous -> ignored


# ------------------------------------------------------------------ metrics
def test_coverage_precision_and_per_engine():
    fs = [F(line=1, engine="secrets"), F(line=2, engine="secrets"), F(line=3), F(line=4), F(line=5)]
    labels = L({"a.py:1:CWE-89": "TP", "a.py:2:CWE-89": "FP", "a.py:3:CWE-89": "TP",
                "a.py:4:CWE-89": "UNSURE"})
    r = evaluate(fs, labels)
    assert r["coverage"] == {"findings_total": 5, "labelled": 3, "unsure": 1, "unlabelled": 1,
                             "true_positive": 2, "false_positive": 1, "labelled_share": 0.6}
    assert r["detection"]["precision"] == pytest.approx(0.6667, abs=1e-3)
    assert r["detection"]["by_engine"]["secrets"]["precision"] == 0.5
    assert r["detection"]["by_engine"]["bandit"]["precision"] == 1.0


def test_wrongly_hidden_real_finding_is_reported_and_fails_safety():
    fs = [F(line=1, fp="HIGH"), F(line=2, fp="HIGH"), F(line=3, fp="MEDIUM")]
    labels = L({"a.py:1:CWE-89": "TP", "a.py:2:CWE-89": "FP", "a.py:3:CWE-89": "TP"})
    fpf = evaluate(fs, labels)["fp_filter"]
    assert fpf["real_findings_wrongly_hidden"] == 1
    assert fpf["wrongly_hidden_list"][0]["key"] == "a.py:1:CWE-89"
    assert fpf["safe"] is False
    assert fpf["real_findings_marked_medium_fp"] == 1
    assert fpf["false_alarm_catch_rate_high"] == 1.0
    assert fpf["precision_after_hide_fp"] == 1.0      # only the MEDIUM real one remains


def test_safe_when_no_real_finding_is_hidden():
    fs = [F(line=1), F(line=2, fp="HIGH")]
    labels = L({"a.py:1:CWE-89": "TP", "a.py:2:CWE-89": "FP"})
    fpf = evaluate(fs, labels)["fp_filter"]
    assert fpf["safe"] is True
    assert fpf["precision_before_hide_fp"] == 0.5 and fpf["precision_after_hide_fp"] == 1.0


def test_fp_flag_can_come_from_extra_like_the_pipeline_does():
    f = F(line=1)
    f["extra"] = {"fp_likelihood": "HIGH"}
    r = evaluate([f], L({"a.py:1:CWE-89": "TP"}))
    assert r["fp_filter"]["real_findings_wrongly_hidden"] == 1


def test_recall_found_hidden_and_missed():
    fs = [F("a.py", 10, "CWE-89"), F("b.py", 5, "CWE-798", fp="HIGH")]
    exp = [Expected("a.py", 11, 2, ["CWE-89"]),          # found (within tolerance)
           Expected("b.py", 5, 2, ["CWE-798"]),          # only found by a HIGH-FP finding
           Expected("c.py", 1, 2, ["CWE-89"]),           # missed
           Expected("a.py", 10, 2, ["CWE-79"])]          # right place, wrong CWE -> missed
    rec = evaluate(fs, L(expected=exp))["recall"]
    assert [d["status"] for d in rec["details"]] == ["found", "found_but_hidden", "missed", "missed"]
    assert rec["found"] == 1 and rec["recall"] == 0.25 and rec["recall_without_fp_filter"] == 0.5


def test_expected_without_cwe_or_line_matches_by_file_only():
    assert Expected("a.py").matches(F("a.py", 99, "CWE-1"))
    assert not Expected("a.py").matches(F("b.py"))


def test_ranking_better_order_scores_higher_and_ties_are_deterministic():
    # 3 real findings all have the same severity as 3 false ones, so severity alone cannot separate them.
    items_scip = [(True, 90.0), (True, 80.0), (True, 70.0), (False, 30.0), (False, 20.0), (False, 10.0)]
    items_sev = [(rel, 5.0) for rel, _ in items_scip]
    a, b = ranking_metrics(items_scip, ks=(3,)), ranking_metrics(items_sev, ks=(3,))
    assert a["precision_at"][3] == 1.0 and a["average_precision"] == 1.0 and not a["tie_averaged"]
    assert b["tie_averaged"] is True
    assert 0.35 < b["precision_at"][3] < 0.65           # ~ base rate 0.5 under random tie-breaks
    assert ranking_metrics(items_sev, ks=(3,)) == b      # deterministic


def test_ranking_skips_k_larger_than_labelled_count_and_handles_no_fp():
    fs = [F(line=i, risk=i, sev=i) for i in range(1, 4)]
    labels = L({f"a.py:{i}:CWE-89": "TP" for i in range(1, 4)})
    rk = evaluate(fs, labels)["ranking"]
    assert "scip_risk_score" not in rk and "at least one real" in rk["note"]
    labels2 = L({"a.py:1:CWE-89": "TP", "a.py:2:CWE-89": "FP", "a.py:3:CWE-89": "TP"})
    rk2 = evaluate(fs, labels2, ks=(2, 10))["ranking"]
    assert rk2["ks"] == [2] and list(rk2["scip_risk_score"]["precision_at"]) == [2]


def test_scip_score_beats_severity_when_it_separates_noise():
    fs, lab = [], {}
    for i in range(6):                                   # real: high risk score, mediocre severity
        fs.append(F(line=i + 1, risk=80 - i, sev=5.0)); lab[f"a.py:{i + 1}:CWE-89"] = "TP"
    for i in range(6):                                   # noise: high severity, low risk score
        fs.append(F(line=i + 20, risk=10 + i, sev=5.0)); lab[f"a.py:{i + 20}:CWE-89"] = "FP"
    rk = evaluate(fs, L(lab))["ranking"]
    assert rk["scip_risk_score"]["average_precision"] == 1.0
    assert rk["ap_improvement"] > 0.2


def test_empty_inputs_do_not_crash():
    r = evaluate([], L())
    assert r["detection"]["precision"] is None and r["recall"]["recall"] is None
    assert r["fp_filter"]["safe"] is True
    assert "n/a" in to_markdown(r)


def test_markdown_and_console_mention_key_numbers():
    fs = [F(line=1, fp="HIGH"), F(line=2)]
    labels = L({"a.py:1:CWE-89": "TP", "a.py:2:CWE-89": "FP"},
               [Expected("a.py", 2, 1, ["CWE-89"], "demo")])
    r = evaluate(fs, labels)
    md, con = to_markdown(r, "demo"), to_console(r)
    assert "FAIL" in md and "wrongly hidden" in md and "a.py:1:CWE-89" in md
    assert "FAIL" in con and "Precision" in con


# ------------------------------------------------------------------ template + CLI
def test_template_keeps_existing_verdicts_adds_new_and_keeps_stale(tmp_path):
    labels_path = tmp_path / "l.yaml"
    scan1 = [F("a.py", 1, risk=10), F("b.py", 2, risk=90)]
    labels_path.write_text(build_template(scan1, None, "demo"), encoding="utf-8")
    data = load_labels(labels_path)
    assert set(data.findings) == {"a.py:1:CWE-89", "b.py:2:CWE-89"}
    assert all(v["verdict"] is None for v in data.findings.values())

    # a human labels one finding, then the code changes: a.py:1 disappears, c.py:3 appears
    txt = labels_path.read_text(encoding="utf-8").replace(
        '"a.py:1:CWE-89": {verdict: "", note: ""}', '"a.py:1:CWE-89": {verdict: "TP", note: "real"}')
    labels_path.write_text(txt, encoding="utf-8")
    txt2 = build_template([F("b.py", 2), F("c.py", 3)], labels_path, "")
    labels_path.write_text(txt2, encoding="utf-8")
    data2 = load_labels(labels_path)
    assert data2.findings["a.py:1:CWE-89"]["verdict"] == "TP"            # kept although stale
    assert data2.findings["a.py:1:CWE-89"]["note"] == "real"
    assert "c.py:3:CWE-89" in data2.findings and data2.findings["c.py:3:CWE-89"]["verdict"] is None
    assert "TO LABEL" in txt2 and "not in the current scan" in txt2
    assert data2.repo == "demo"
    # unlabelled findings stay under TO LABEL; the stale labelled one is listed last
    assert txt2.index("TO LABEL") < txt2.index('"c.py:3:CWE-89"') < txt2.index('"a.py:1:CWE-89"')
    # idempotent: regenerating from the same scan changes nothing
    assert build_template([F("b.py", 2), F("c.py", 3)], labels_path, "") == txt2


def test_template_moves_labelled_findings_out_of_the_to_label_section(tmp_path):
    p = tmp_path / "l.yaml"
    p.write_text(build_template([F("a.py", 1), F("b.py", 2)], None, "demo"), encoding="utf-8")
    p.write_text(p.read_text(encoding="utf-8").replace(
        '"a.py:1:CWE-89": {verdict: "", note: ""}', '"a.py:1:CWE-89": {verdict: "FP", note: "n"}'), encoding="utf-8")
    txt = build_template([F("a.py", 1), F("b.py", 2)], p, "")
    assert txt.index("TO LABEL") < txt.index('"b.py:2:CWE-89"') < txt.index("already labelled") \
        < txt.index('"a.py:1:CWE-89"')


def test_template_never_reads_source_files_or_leaks_beyond_masked_evidence(tmp_path):
    secret_file = tmp_path / "s.py"
    secret_file.write_text("PASSWORD = 'hunter2-real-secret'\n", encoding="utf-8")
    f = F(str(secret_file), 1, "CWE-798", engine="secrets", evidence="PASSWORD = '********'")
    text = build_template([f], None, "demo")
    assert "hunter2" not in text and "********" in text


def test_template_is_blind_it_does_not_show_scip_risk_or_fp_guess():
    f = F("a.py", 1, risk=87.65, sev=9.9, fp="HIGH")
    text = build_template([f], None, "demo")
    assert "87.65" not in text and "9.9" not in text and "HIGH" not in text and "SCIP says" not in text


def test_template_handles_hostile_text_safely(tmp_path):
    f = F('we"ird\\file.py', 1, title="x\nnewline: {broken}", evidence="a\nb # c")
    f["title"] = "x\nnewline: {broken}"
    p = tmp_path / "l.yaml"
    p.write_text(build_template([f], None, 'na"me'), encoding="utf-8")
    assert len(load_labels(p).findings) == 1             # still valid YAML


def _write(tmp_path, findings, labels_text):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(findings), encoding="utf-8")
    lab = tmp_path / "labels.yaml"
    lab.write_text(labels_text, encoding="utf-8")
    return str(scan), str(lab)


def test_cli_evaluate_writes_reports_and_strict_fails_on_wrongly_hidden(tmp_path, capsys):
    scan, lab = _write(tmp_path, [F(line=1, fp="HIGH")],
                       'repo: demo\nfindings:\n  "a.py:1:CWE-89": {verdict: TP}\nexpected: []\n')
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    assert main(["evaluate", "--scan", scan, "--labels", lab, "--report-md", str(md),
                 "--json-out", str(js)]) == 0
    assert "wrongly hidden" in md.read_text(encoding="utf-8")
    assert json.loads(js.read_text(encoding="utf-8"))["fp_filter"]["real_findings_wrongly_hidden"] == 1
    assert main(["evaluate", "--scan", scan, "--labels", lab, "--strict"]) == 1


def test_cli_returns_2_for_bad_inputs(tmp_path, capsys):
    scan, lab = _write(tmp_path, [F()], 'findings:\n  "a.py:1:CWE-89": {verdict: NOPE}\n')
    assert main(["evaluate", "--scan", scan, "--labels", lab]) == 2
    assert main(["evaluate", "--scan", str(tmp_path / "missing.json"), "--labels", lab]) == 2
    assert "Error" in capsys.readouterr().err


def test_cli_template_command_creates_file(tmp_path, capsys):
    scan, _ = _write(tmp_path, [F(line=1), F(line=2)], "")
    out = tmp_path / "sub" / "labels.yaml"
    assert main(["template", "--scan", scan, "--labels", str(out), "--repo-name", "demo"]) == 0
    assert out.exists() and "2 still to label" in capsys.readouterr().out


def test_shipped_vulpy_labels_file_is_valid():
    from pathlib import Path
    labels = load_labels(Path(__file__).resolve().parent.parent / "evaluation" / "labels" / "vulpy.yaml")
    assert labels.repo == "vulpy" and labels.expected
    assert any(v["verdict"] == "TP" for v in labels.findings.values())


# ------------------------------------------------------------------ dependency keys and sampling
def test_each_cve_on_the_same_line_gets_its_own_key():
    a = F("requirements.txt", 11, "CWE-400", engine="dependency", title="CVE-2024-0001: django==4.2 - DoS")
    b = F("requirements.txt", 11, "CWE-400", engine="dependency", title="CVE-2024-0002: django==4.2 - DoS")
    assert finding_key(a) == "requirements.txt:11:CWE-400#CVE-2024-0001"
    assert finding_key(a) != finding_key(b)
    c = F("requirements.txt", 11, "CWE-400", engine="dependency", title="x", extra={"vuln_id": "ghsa-aaaa-bbbb-cccc"})
    assert finding_key(c).endswith("#GHSA-AAAA-BBBB-CCCC")        # extra.vuln_id wins, upper-cased
    d = F("a.py", 3, "CWE-89", title="Bandit B608: Possible SQL injection")
    assert finding_key(d) == "a.py:3:CWE-89"                        # code findings keep the old key


def test_labels_for_one_cve_do_not_leak_to_another():
    a = F("requirements.txt", 11, "CWE-400", engine="dependency", title="CVE-2024-0001: django==4.2 - x")
    b = F("requirements.txt", 11, "CWE-400", engine="dependency", title="CVE-2024-0002: django==4.2 - x")
    labels = L({finding_key(a): "TP", finding_key(b): "FP"})
    r = evaluate([a, b], labels)
    assert r["coverage"]["true_positive"] == 1 and r["coverage"]["false_positive"] == 1


def _many(n_dep=40, n_code=10):
    fs = [F("requirements.txt", 11, "CWE-400", engine="dependency", title=f"CVE-2024-{i:04d}: x")
          for i in range(n_dep)]
    fs += [F("a.py", i + 1, "CWE-89", engine="bandit") for i in range(n_code)]
    return fs


def test_sample_picks_n_spread_over_engines_and_is_reproducible(tmp_path):
    fs = _many()
    t1 = build_template(fs, None, "demo", sample=10, seed=1)
    p = tmp_path / "l.yaml"
    p.write_text(t1, encoding="utf-8")
    data = load_labels(p)
    assert len(data.findings) == 10
    engines = [k for k in data.findings if "#CVE" in k]
    assert 0 < len(engines) < 10                     # both dependency and code findings present
    assert build_template(fs, None, "demo", sample=10, seed=1) == t1          # same seed -> same sample
    assert build_template(fs, None, "demo", sample=10, seed=2) != t1          # other seed -> other sample


def test_sample_keeps_existing_labels_and_only_adds_new_ones(tmp_path):
    fs = _many()
    p = tmp_path / "l.yaml"
    p.write_text(build_template(fs, None, "demo", sample=6), encoding="utf-8")
    first = set(load_labels(p).findings)
    p.write_text(p.read_text(encoding="utf-8").replace(
        'verdict: ""', 'verdict: "TP"', 1), encoding="utf-8")
    p.write_text(build_template(fs, p, "", sample=4), encoding="utf-8")
    second = set(load_labels(p).findings)
    assert first <= second and len(second) == 10


def test_sample_larger_than_available_takes_everything():
    fs = _many(3, 2)
    assert build_template(fs, None, "demo", sample=100).count('verdict: ""') == 5


def test_findings_left_out_of_the_sample_are_ignored_by_evaluate(tmp_path):
    fs = _many(30, 10)
    p = tmp_path / "l.yaml"
    p.write_text(build_template(fs, None, "demo", sample=8), encoding="utf-8")
    p.write_text(p.read_text(encoding="utf-8").replace('verdict: ""', 'verdict: "TP"'), encoding="utf-8")
    r = evaluate(fs, load_labels(p))
    assert r["coverage"]["labelled"] == 8 and r["coverage"]["unlabelled"] == 32


def test_cli_sample_option(tmp_path, capsys):
    scan, _ = _write(tmp_path, _many(), "")
    out = tmp_path / "labels.yaml"
    assert main(["template", "--scan", scan, "--labels", str(out), "--sample", "7", "--seed", "3"]) == 0
    assert "7 still to label" in capsys.readouterr().out
