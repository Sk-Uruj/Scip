# SCIP - Secure Codebase Intelligence Platform

**Detect -> Prioritize -> Improve.** SCIP scans a Python repository, finds security problems, and
ranks them by *real-world risk* instead of by severity alone, so a developer knows what to fix first.

Most scanners print hundreds of "critical" alerts. SCIP asks three more questions about each one:
is it being exploited in the wild (EPSS, CISA KEV), can an attacker actually reach this code
(call graph from web/CLI/worker entry points), and how much of the system depends on it.

## What it detects

| Engine | Finds | Notes |
|---|---|---|
| `dependency` | Known-vulnerable pinned packages | OSV + EPSS + CISA KEV + computed CVSS |
| `secrets` | Hard-coded credentials, including ones deleted from the code but still in **git history** | values are always masked |
| `crypto` | Weak hashes, ECB, DES/RC4, static IV, disabled TLS verification, weak randomness, cleartext HTTP | AST rules |
| `bandit`, `semgrep` | General static-analysis findings | wrappers; Semgrep is optional |

Findings are then de-duplicated across tools, scored 0-100 (`scoring/risk_score.py`), and explained.

## Setup

```bash
python -m venv venv
# Windows:  venv\Scripts\activate        Linux/Mac:  source venv/bin/activate
pip install -r requirements.txt
pytest                      # should pass
```
Scan targets are not stored in the repo: `scripts\clone_test_repos.bat` (or `bash scripts/clone_test_repos.sh`).
If `pip install` fails on `semgrep`, install the rest; the Semgrep engine skips itself when missing.

## Try it, one stage at a time

```bash
# severity-only ordering (what most scanners give you)
python -m core.pipeline samples/vuln_deps_app --offline --no-history --engines dependency --no-scoring
# the same findings ranked by real-world risk
python -m core.pipeline samples/vuln_deps_app --offline --no-history --engines dependency
# attack paths and fix hints
python -m core.pipeline samples/vuln_deps_app --offline --no-history --no-semgrep --details
# secrets, including deleted ones in git history
python scripts/make_secrets_demo.py && python -m core.pipeline test_repos/secrets_demo --no-semgrep --no-bandit
```
Save a full report as UTF-8 JSON with `-o report.json` (do not use `>` in PowerShell: it writes UTF-16).
`--offline` uses cached vulnerability data and needs a previous online run (the cache is local, not committed).

### Reading the table

| Column | Meaning |
|---|---|
| RISK | final 0-100 score |
| SEV / EXPL | severity (CVSS for dependencies) / exploitability 0-1 (1.00 = actively exploited, CISA KEV) |
| REACH | `HTTP` `WORKER` `CLI` `STARTUP` reachable from an entry point, `INTNL` no ingress path, `DEAD` no references found, `UNKNOWN` could not be analysed, `TEST`, `REPO`/`HIST` for secrets |

`UNKNOWN` and `null` mean "not analysed", **never** "safe": SCIP does not remove findings because of them.

## Useful options

| Option | Purpose |
|---|---|
| `--engines dependency,secrets` / `--no-bandit` ... | choose engines |
| `--details` | print attack paths and remediation hints |
| `-o FILE`, `--json` | UTF-8 JSON report (includes the score `explanation`) |
| `--sarif-out FILE` | export findings in SARIF v2.1.0 format for GitHub Code Scanning / CI |
| `--summary` | output formatted markdown summary table (auto-written to `$GITHUB_STEP_SUMMARY` in CI) |
| `--hide-fp` | hide HIGH-likelihood false positives. Opt-in; prints what was hidden and saves it to `<output>.hidden-fp.json` |
| `--training-path PATH` | declare a folder as training/example code (strongly demoted). Never inferred from the repo |
| `--baseline FILE`, `--make-baseline FILE` | accept known findings |
| `--ci`, `--fail-on HIGH`, `--strict` | CI gating |

## CI/CD & GitHub Code Scanning

SCIP includes native SARIF v2.1.0 output and is packaged as a **reusable GitHub Action** (`action.yml`) that any repository can use.

When integrated into pull requests, SCIP acts like an automated security reviewer (CodeRabbit style):
* **Sticky Executive Summary**: Updates in-place with risk score badges, findings breakdown, and native Mermaid attack path graphs.
* **1-Click Code Suggestions**: Formats remediation patches into GitHub's native ````suggestion```` diff blocks so reviewers/authors can commit fixes with one click.
* **PR-Scoped Scanning**: Focuses only on files touched in the PR, filtering out legacy noise in unmodified files.
* **GitHub Security Tab**: Results are uploaded as SARIF v2.1.0 to **Security > Code Scanning** with CWE badges and CVSS ratings.
* **100% Serverless & Private**: Runs entirely within your own GitHub Actions runners; code never leaves GitHub.

### Quick Start in Any Repository

Create `.github/workflows/scip.yml` in your repository:

```yaml
name: SCIP Security Review

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write   # to post sticky summary and 1-click code suggestions
  security-events: write # to upload SARIF to GitHub Code Scanning

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: SCIP Security Review
        uses: roshankumar0036singh/Scip@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          diff-only: 'true'
          enable-suggestions: 'true'
```

## Trust model: the scanned repository is untrusted input

A scan target can contain anything, including files that look like SCIP configuration.
Therefore **nothing inside the scanned repo changes how SCIP behaves**:

* scoring weights come only from SCIP's own `.env` or environment variables, validated (a hostile `.env`
  used to be able to reverse the ranking);
* a `.scip-baseline.json` inside the target is ignored unless you pass `--trust-repo-baseline`;
* "this is training code" is declared with `--training-path`, not guessed from folder names or comments;
* credential values are never printed: wrapped scanners' output is redacted (`core/redact.py`);
* "dead code" / "false positive" labels need positive evidence: a repo with no entry points is `UNKNOWN`,
  dead code is at most MEDIUM likelihood, weak hashing of password-like data is never an "ETag false positive",
  and a CISA-KEV bug or a provider-format token can never be demoted.

## Layout

| Folder | Purpose |
|---|---|
| `engines/` | detection engines |
| `core/` | Finding schema, pipeline, risk graph (`risk_graph.py`), false-positive detector, redaction, package aliases |
| `scoring/` | composite risk score and explanation |
| `remediation/` | dependency-upgrade remediation: plan, patch on a copy, verify (see `docs/REMEDIATION.md`) |
| `api/` | dashboard backend: `python -m api` serves `dashboard/` and runs scan, remediation and evaluation as jobs |
| `evaluation/` | evaluation harness: labels, precision/recall, false-positive filter safety, ranking quality (see `docs/EVALUATION.md`) |
| `tests/` | pytest suite (CI runs it on every push and PR) |
| `docs/` | roadmap, contributions |

See `docs/ROADMAP.md` for status and `CONTRIBUTING.md` for the workflow.
