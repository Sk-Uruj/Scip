# SCIP evaluation - pygoat

## 1. Label coverage

| Findings reported | Labelled (TP/FP) | Unsure | Unlabelled | Real (TP) | False alarm (FP) |
|---:|---:|---:|---:|---:|---:|
| 276 | 53 (19.2%) | 7 | 216 | 19 | 34 |

Metrics below use labelled findings only. Unlabelled findings are not counted either way.

## 2. Detection precision

Of the labelled findings SCIP reported, **35.9%** are real.

| Engine | Real | False alarm | Precision |
|---|---:|---:|---:|
| bandit | 6 | 0 | 100.0% |
| dependency | 6 | 29 | 17.1% |
| secrets | 6 | 5 | 54.5% |
| semgrep | 1 | 0 | 100.0% |

## 3. Recall on known vulnerabilities

No `expected` list in the labels file, so recall was not measured.

## 4. False-positive filter safety

**Real findings wrongly hidden: 0  ->  PASS** (this number must be 0).

| Measure | Value |
|---|---:|
| False alarms flagged HIGH (hidden by --hide-fp) | 2 (5.9% of all FPs) |
| False alarms flagged HIGH or MEDIUM (demoted) | 5.9% |
| Real findings marked MEDIUM (damped, still shown) | 3 |
| Precision before --hide-fp | 35.9% |
| Precision after --hide-fp | 37.2% |

## 5. Ranking quality: SCIP risk score vs severity alone

Base rate (precision if findings were in random order): 35.9%.

| Ordering | P@5 | P@10 | P@20 | Average precision |
|---|---:|---:|---:|---:|
| SCIP risk score | 60.0% | 30.0% | 45.0% | 45.8% |
| Severity only | 80.0% | 60.0% | 45.0% | 55.3% |

Average-precision change from using SCIP's score: **-0.0953**
_P@k = share of the top k findings that are real. ties are averaged over random orderings (deterministic seed)._
