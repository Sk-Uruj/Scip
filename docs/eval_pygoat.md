# SCIP evaluation - pygoat

## 1. Label coverage

| Findings reported | Labelled (TP/FP) | Unsure | Unlabelled | Real (TP) | False alarm (FP) |
|---:|---:|---:|---:|---:|---:|
| 243 | 47 (19.3%) | 7 | 189 | 18 | 29 |

Metrics below use labelled findings only. Unlabelled findings are not counted either way.

## 2. Detection precision

Of the labelled findings SCIP reported, **38.3%** are real.

| Engine | Real | False alarm | Precision |
|---|---:|---:|---:|
| bandit | 7 | 0 | 100.0% |
| dependency | 6 | 29 | 17.1% |
| secrets | 5 | 0 | 100.0% |

## 3. Recall on known vulnerabilities

No `expected` list in the labels file, so recall was not measured.

## 4. False-positive filter safety

**Real findings wrongly hidden: 0  ->  PASS** (this number must be 0).

| Measure | Value |
|---|---:|
| False alarms flagged HIGH (hidden by --hide-fp) | 29 (100.0% of all FPs) |
| False alarms flagged HIGH or MEDIUM (demoted) | 100.0% |
| Real findings marked MEDIUM (damped, still shown) | 3 |
| Precision before --hide-fp | 38.3% |
| Precision after --hide-fp | 100.0% |

## 5. Ranking quality: SCIP risk score vs severity alone

Base rate (precision if findings were in random order): 38.3%.

| Ordering | P@5 | P@10 | P@20 | Average precision |
|---|---:|---:|---:|---:|
| SCIP risk score | 100.0% | 100.0% | 90.0% | 100.0% |
| Severity only | 49.3% | 46.7% | 45.0% | 53.5% |

Average-precision change from using SCIP's score: **+0.4648**
_P@k = share of the top k findings that are real. ties are averaged over random orderings (deterministic seed)._
