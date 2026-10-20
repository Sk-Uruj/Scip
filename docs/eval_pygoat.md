# SCIP evaluation - pygoat

## 1. Label coverage

| Findings reported | Labelled (TP/FP) | Unsure | Unlabelled | Real (TP) | False alarm (FP) |
|---:|---:|---:|---:|---:|---:|
| 150 | 18 (12.0%) | 7 | 125 | 18 | 0 |

Metrics below use labelled findings only. Unlabelled findings are not counted either way.

## 2. Detection precision

Of the labelled findings SCIP reported, **100.0%** are real.

| Engine | Real | False alarm | Precision |
|---|---:|---:|---:|
| bandit | 7 | 0 | 100.0% |
| dependency | 6 | 0 | 100.0% |
| secrets | 5 | 0 | 100.0% |

## 3. Recall on known vulnerabilities

No `expected` list in the labels file, so recall was not measured.

## 4. False-positive filter safety

**Real findings wrongly hidden: 0  ->  PASS** (this number must be 0).

| Measure | Value |
|---|---:|
| False alarms flagged HIGH (hidden by --hide-fp) | 0 |
| False alarms flagged HIGH or MEDIUM (demoted) | n/a |
| Real findings marked MEDIUM (damped, still shown) | 3 |
| Precision before --hide-fp | 100.0% |
| Precision after --hide-fp | 100.0% |

## 5. Ranking quality: SCIP risk score vs severity alone

ranking needs at least one real (TP) and one false (FP) labelled finding; label more findings
