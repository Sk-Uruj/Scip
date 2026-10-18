# SCIP evaluation - vulpy

## 1. Label coverage

| Findings reported | Labelled (TP/FP) | Unsure | Unlabelled | Real (TP) | False alarm (FP) |
|---:|---:|---:|---:|---:|---:|
| 50 | 38 (76.0%) | 12 | 0 | 35 | 3 |

Metrics below use labelled findings only. Unlabelled findings are not counted either way.

## 2. Detection precision

Of the labelled findings SCIP reported, **92.1%** are real.

| Engine | Real | False alarm | Precision |
|---|---:|---:|---:|
| bandit | 28 | 0 | 100.0% |
| secrets | 4 | 0 | 100.0% |
| semgrep | 3 | 3 | 50.0% |

## 3. Recall on known vulnerabilities

SCIP found **7 of 7** known vulnerabilities (recall 100.0%).
0 more were found but flagged HIGH false-positive (hidden by `--hide-fp`); 0 were missed.

| Status | Location | CWE | Note |
|---|---|---|---|
| found | bad/libuser.py:12 | CWE-89 | SQL injection: login query built with str.format() |
| found | bad/libuser.py:25 | CWE-89 | SQL injection: INSERT built with % formatting |
| found | bad/libuser.py:53 | CWE-89 | SQL injection: UPDATE built with str.format() |
| found | bad/vulpy.py:55 | CWE-489, CWE-94 | app.run(debug=True) exposes the Werkzeug debugger |
| found | bad/vulpy-ssl.py:29 | CWE-489, CWE-94 | app.run(debug=True) exposes the Werkzeug debugger |
| found | bad/vulpy-ssl.py:13 | CWE-798 | hard-coded SECRET_KEY 'aaaaaaa' |
| found | bad/libapi.py:14 | CWE-330 | API key derived from non-cryptographic random.getrandbits |

Recall is measured against the `expected` list only. It is a floor, not the true recall.

## 4. False-positive filter safety

**Real findings wrongly hidden: 0  ->  PASS** (this number must be 0).

| Measure | Value |
|---|---:|
| False alarms flagged HIGH (hidden by --hide-fp) | 1 (33.3% of all FPs) |
| False alarms flagged HIGH or MEDIUM (demoted) | 66.7% |
| Real findings marked MEDIUM (damped, still shown) | 24 |
| Precision before --hide-fp | 92.1% |
| Precision after --hide-fp | 94.6% |

## 5. Ranking quality: SCIP risk score vs severity alone

Base rate (precision if findings were in random order): 92.1%.

| Ordering | P@5 | P@10 | P@20 | Average precision |
|---|---:|---:|---:|---:|
| SCIP risk score | 80.0% | 80.0% | 90.0% | 87.2% |
| Severity only | 49.8% | 70.0% | 85.0% | 81.6% |

Average-precision change from using SCIP's score: **+0.0555**
_P@k = share of the top k findings that are real. ties are averaged over random orderings (deterministic seed)._
