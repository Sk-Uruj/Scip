# Evaluating SCIP

The evaluation harness answers one question with numbers: **how good are SCIP's findings and ranking?**
It compares a scan against human-made labels ("ground truth") and reports:

| Measure | Question it answers |
|---|---|
| Precision | Of the findings SCIP reported, how many are real? |
| Recall on known vulnerabilities | Of the vulnerabilities we *know* are in the repo, how many did SCIP find? |
| **Real findings wrongly hidden** | Did the false-positive filter hide anything real? **Must be 0.** |
| False alarms caught | How much noise does the false-positive filter remove? |
| Ranking quality (P@k, average precision) | Does SCIP's risk score put real findings above noise better than severity alone? |

## Workflow

Run from the project root (PowerShell shown; use `/` paths on Linux/macOS).

**1. Pin the test repo and scan it.** Labels refer to file and line, so the repo must not change under you.
```
git -C test_repos\vulpy rev-parse HEAD            # note this commit in the labels file name below
python -m core.pipeline test_repos\vulpy -o eval_scans\vulpy_findings.json
```
Do **not** use `--hide-fp` here: the harness needs the false-positive flags in the data.
Files named `*findings*.json` are git-ignored, so scans are never committed.

**2. Create or update the labels file.**
```
python -m evaluation.run template --scan eval_scans\vulpy_findings.json --labels evaluation\labels\vulpy.yaml --repo-name vulpy@<commit>
```
Findings still needing a verdict are listed under `TO LABEL`. Re-running this command later keeps every
verdict and note you already wrote, and adds only new findings.

**3. Label.** For each finding open the file and judge the code, then set `verdict`:

* `TP` - a real weakness in the code as written (a scanner is right).
* `FP` - a false alarm (the scanner is wrong about this code).
* `UNSURE` - a judgement call; it is excluded from the numbers. Say why in `note`.

Rules that keep the evaluation honest:
* **Label blind.** The template deliberately hides SCIP's risk score and false-positive guess. Do not run
  SCIP's output next to the labelling. Judge only the code.
* **Two people, independently, on a sample.** Where you disagree, discuss and use `UNSURE` if unresolved.
* **Write the reason in `note`.** In the viva you must be able to defend each label.
* A hard-coded secret in a repo's "good" or fixed folder is still a real secret. Do not label by folder name.

**4. Add known vulnerabilities (for recall).** In the `expected:` section list vulnerabilities you know exist,
for example from the repo's own README or documentation, whether or not SCIP found them:
```yaml
expected:
  - {file: bad/libuser.py, line: 12, tol: 2, cwe: CWE-89, note: "SQL injection in login"}
  - {file: bad/vulpy.py, line: 55, tol: 2, cwe: [CWE-489, CWE-94], note: "debug=True"}   # any listed CWE counts
```
Recall is measured against this list only, so it is a floor, not the true recall.

**5. Evaluate.**
```
python -m evaluation.run evaluate --scan eval_scans\vulpy_findings.json --labels evaluation\labels\vulpy.yaml ^
        --report-md docs\eval_vulpy.md --json-out eval_scans\vulpy_eval.json --strict
```
`--strict` makes the command exit with code 1 if any real finding was hidden by the false-positive filter,
so it can also run in CI. `--line-tolerance 2` lets a label still match after small edits shift lines.

## Large repos: label a random sample

A repo like pygoat produces hundreds of findings, and most are dependency CVEs. You do not need to label them all.
A random sample gives an honest estimate and is much less work:

    python -m evaluation.run template --scan eval_scans\pygoat_findings.json --labels evaluation\labels\pygoat.yaml --repo-name pygoat --sample 60

* The sample is spread over the engines in proportion to their size and is reproducible (`--seed`).
* Run it again with `--sample 30` later to add 30 more new findings; existing labels are always kept.
* Findings that are not in the labels file are simply not part of the evaluation. Never label only the top of
  the ranking, because that would make the ranking look better than it is.
* Several people can label different parts: split the file by line range and merge in Git.

## How to label dependency findings (CVEs)

The version number is almost always really vulnerable, so "is the CVE real?" is not the question. Ask instead:
**is the vulnerable part actually used by this project?**

* `TP`: the app uses the affected library feature, or plausibly could (for example Django's request handling).
* `FP`: the affected component is not used (for example a GeoDjango CVE when the project has no GIS code).
* `UNSURE`: you cannot tell from the code.

Every CVE has its own label key (`requirements.txt:11:CWE-400#CVE-2024-1234`), so labelling one never affects another.

## How to read the results

* **Precision / recall** are only as good as the labels. Report how many findings are labelled
  (the "Label coverage" table) and never quote precision from a handful of labels.
* **Ranking.** Many findings share the same severity, so severity alone cannot order them. Ties are averaged
  over random orderings with a fixed seed, so the comparison is fair and reproducible.
* **Wrongly hidden > 0** means the false-positive filter is unsafe on that repo. Fix the rule first.
* Always report results per repo, with the engines that were actually installed (for example without
  Bandit and Semgrep, SQL injection and debug-mode findings cannot appear and recall will be low).

## Suggested evaluation set

| Repo | Why |
|---|---|
| vulpy (`bad/` vs `good/`) | Small, documents its own vulnerabilities, has a fixed version to compare |
| pygoat | Large, intentionally vulnerable Django app (pin the commit; use `--training-path` consciously and report it) |
| One or two real Flask/Django projects | Shows false-alarm behaviour on non-training code, which is what matters in practice |

## What is not covered yet

Ablation (turning scoring factors off one at a time) and a comparison with gitleaks, Bandit alone and
osv-scanner are separate roadmap items. This harness gives them the common measuring stick.
