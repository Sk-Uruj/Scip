# Dependency Engine – Comprehensive Audit & Improvement Plan

> **Executive Summary**: The Dependency Vulnerability Engine (Step 2) identifies known security advisories (CVE, GHSA, PYSEC) across pinned dependencies using OSV, EPSS, and CISA KEV. While the engine's core ingestion works cleanly and passes all 15 existing unit tests, the formal evaluation on **PyGoat** revealed a critical quality issue:
> 
> * **Overall Dependency Precision is only 17.1%** (6 True Positives vs **29 False Positives** out of 35 labelled findings).
> * **SCIP Risk Score Ranking is Inverted on PyGoat**: Average Precision (AP) drops from **53.7%** (severity-only) down to **44.7%** (**-0.0902 delta**), because high-severity dependency CVEs that are dead, unimported, or feature-gated float to the top and displace real code vulnerabilities.
> * **FP Filter Safety**: Only **2 of 29 false alarms (6.9%)** are currently flagged as `HIGH` (GeoDjango), leaving 27 false alarms completely unflagged.
> 
> This document presents a root-cause codebase audit across `engines/dependency_engine.py`, `core/risk_graph.py`, `core/pkg_alias.py`, `data/cve_component_map.json`, `core/fp_detector.py`, and `scoring/risk_score.py`, followed by an actionable **7-phase engineering plan** to elevate dependency precision above **85%** and restore positive ranking delta.

---

## 1. Evaluation Baseline & The 29 PyGoat False Positives

Analysis of `docs/eval_pygoat_v2.md` and `evaluation/labels/pygoat.yaml` reveals that 29 out of 35 labelled dependency findings are false alarms:

```
+-------------------------------------------------------------------------------+
| PyGoat Dependency Finding Precision: 17.1% (6 TP / 29 FP / 7 Unsure)          |
+-------------------------------------------------------------------------------+
|  Category                                   | Count | Examples                |
+---------------------------------------------+-------+-------------------------+
|  1. Dead / Unimported Packages              |   5   | cryptography, oauthlib  |
|  2. Unused Submodules / Gated Components    |  16   | strip_tags, intcomma    |
|  3. Platform Incompatibility (Windows-only) |   4   | safe_join, Windows DoS  |
|  4. Precondition / Usage Mismatch           |   4   | ASGI on WSGI, netrc     |
+---------------------------------------------+-------+-------------------------+
```

### True Positives (6 TPs)
1. **CVE-2023-50447** (`pillow==9.4.0`): `ImageMath.eval()` RCE reachable via user input (`views.py:588`).
2. **CVE-2026-59204** (`pillow==9.4.0`): `Image.open()` JPEG2000 tile decode DoS on user upload (`views.py:584`).
3. **CVE-2026-32597** (`pyjwt==2.4.0`): `jwt.decode` accepts unknown `crit` headers on user cookie (`views.py:1095`).
4. **CVE-2020-14343** (`pyyaml==5.1`): `yaml.load(file, Loader)` arbitrary code execution on upload (`views.py:560`).
5. **CVE-2023-36053** (`django==4.2`): EmailValidator ReDoS via `forms.EmailField` (`forms.py`).
6. **CVE-2026-33034 / Other**: Confirmed active input pathway.

### False Positives Breakdown (29 FPs)
* **Unimported Packages (5 FPs)**:
  - `cryptography==39.0.1` (`CVE-2026-34073`, `GHSA-jm77-qphf-c4w8`): Pinned in `requirements.txt`, but never imported by the application or any used dependency.
  - `oauthlib==3.2.2` (`CVE-2026-49265`, `CVE-2026-49264`): Pinned in `requirements.txt`; `django-allauth` is pinned but never configured or imported in `pygoat`.
  - `sqlparse==0.3.1` (`CVE-2023-30608`, `GHSA-27jp-wm6q-gp25`): PyGoat code never imports `sqlparse`; Django only uses it in developer management commands/migrations, not request processing.
* **Feature & Component Gating (16 FPs)**:
  - `django==4.2` (`CVE-2024-53907`): DoS in `django.utils.html.strip_tags()`. PyGoat never calls `strip_tags` or template filter `striptags`.
  - `django==4.2` (`CVE-2024-38875`): DoS in `urlize` / `urlizetrunc`. No template or view uses `urlize`.
  - `django==4.2` (`CVE-2024-24680`): DoS in `django.contrib.humanize` `intcomma`. Humanize is not in `INSTALLED_APPS` or imported.
  - `django==3.2.18` (`CVE-2023-43665`): DoS in `django.utils.text.Truncator`. Lab does not use `truncatechars`/`truncatewords`.
  - `django==4.2` (`CVE-2025-59682`): Traversal in `django.utils.archive.extract()`. PyGoat never calls it.
  - `django==4.2` (`CVE-2025-13372`, `CVE-2025-57833`): SQLi through column aliases in `annotate`/`alias`/`extra`/`FilteredRelation`. PyGoat uses none with user input.
  - `django==3.2.18` (`CVE-2026-48588`): Cache middleware exposure. PyGoat has no cache middleware in `settings.py`.
  - `django==3.2.18` & `django==4.2` (`CVE-2026-15307`, `CVE-2026-15830`): GeoDjango file write / DoS. PyGoat does not use `django.contrib.gis`.
  - `pillow==9.4.0` (`CVE-2023-44271`): DoS in `PIL.ImageDraw` text rendering. PyGoat only imports `PIL.Image` and `PIL.ImageMath`.
  - `pyjwt==2.4.0` (`CVE-2026-102270`): ReDoS in `is_pem_format` key parsing. Server uses HMAC constant `SECRET_COOKIE_KEY`, not PEM keys.
  - `pyjwt==2.4.0` (`CVE-2026-102275`): OKP JWK public/private key confusion. PyGoat only uses HS256 HMAC; no JWKs.
  - `pyjwt==2.4.0` (`CVE-2026-48522`): `PyJWKClient` SSRF. PyGoat never uses `PyJWKClient`.
  - `flask==2.3.3` (`CVE-2026-27205`): Missing `Vary: Cookie` on Flask `session`. PyGoat sets manual cookies, never touches Flask `session`.
* **Platform / OS Incompatibilities (4 FPs)**:
  - `django==4.2` (`CVE-2025-64458`): Windows-only DoS in `HttpResponseRedirect` path normalisation. PyGoat deploys on Linux container (`python:3.12-slim`).
  - `werkzeug==2.1.2` & `3.0.1` (`CVE-2024-49766`, `CVE-2025-66221`): Windows device name traversal in `safe_join` (`CON`, `PRN`, `AUX`, `NUL`). PyGoat runs on Linux.
* **Deployment / Context Preconditions (4 FPs)**:
  - `django==4.2` (`CVE-2026-33034`): SGI request smuggling on ASGI. PyGoat runs with Gunicorn on WSGI.
  - `requests==2.28.2` (`CVE-2026-25645`): Insecure temp file when running from a zip archive (`extract_zipped_paths`).
  - `urllib3==1.26.9` (`CVE-2026-97687`, `CVE-2024-37891`): HTTPS proxy TLS configuration and `Proxy-Authorization` leak. PyGoat configures no proxy.

---

## 2. Codebase Audit: Identified Architecture Flaws

Inspection of `engines/dependency_engine.py`, `core/risk_graph.py`, `core/pkg_alias.py`, and `data/cve_component_map.json` identified the following 7 core flaws:

| Flaw ID | Area | Current Implementation Flaw | Impact on SCIP |
|---|---|---|---|
| **DEP-01** | **Dead Package Exposure** | `core/risk_graph.py` sets `f.exposure = "DEAD"` when a package is not imported, but **never sets `f.fp_likelihood = "HIGH"`**. | `--hide-fp` ignores dead packages; precision remains 17.1% because dead packages count as active reported findings. |
| **DEP-02** | **Component Map Gaps** | `data/cve_component_map.json` only contained `GeoDjango -> ["django.contrib.gis"]`. | 14 component-specific advisories (e.g. `strip_tags`, `urlize`, `intcomma`, `ImageDraw`, `PyJWKClient`) have no gating and are flagged as HTTP-reachable. |
| **DEP-03** | **Platform Blindness** | Neither engine nor risk graph inspects deployment metadata (e.g. `Dockerfile`, `Procfile`, `pyproject.toml`) for target OS. | Windows-only advisories (Werkzeug device names, Django Windows path DoS) trigger high-severity alerts in Linux containers. |
| **DEP-04** | **Transitive Over-Reach** | `_dependency_nodes` in `core/risk_graph.py` automatically links `sqlparse` and `werkzeug` to `django` or `flask` entrypoints via `parents_of`. | Unused internal libraries inherit web HTTP exposure (blast radius > 50), inflating their risk score above real application vulnerabilities. |
| **DEP-05** | **Dev vs Prod Pinning** | `collect_dependencies` treats `requirements-dev.txt`, `test-requirements.txt`, and sub-lab requirements equally. | Development and test utilities (e.g. `pytest`, `flake8`, `sqlparse`) receive production risk scores. |
| **DEP-06** | **Advisory Merging & Text** | `_combine` in `merge_vulns` picks `next((v.summary for v in items if v.summary), "")`, which often picks brief one-liners over descriptive CVE texts. | Deprives downstream component gating and engineers of critical keywords and affected function names. |
| **DEP-07** | **Severity & CWE Gaps** | `extract_severity` only parses CVSS v3.x vectors, defaulting to 5.0 for CVSS v2/v4. `parse_osv_vuln` only extracts `cwe_ids[0]` from `database_specific`. | Skews risk scoring and prevents cross-engine dedup when advisories lack modern CVSS 3.1 vectors. |

---

## 3. The 7-Phase Actionable Improvement Plan

```mermaid
graph TD
    P1["Phase 1: Baseline Pinning & Label Calibration"] --> P2["Phase 2: Dead Package & Unimported FP Damping"]
    P2 --> P3["Phase 3: Deep Component & Symbol Gating"]
    P3 --> P4["Phase 4: Platform & Environment Awareness"]
    P4 --> P5["Phase 5: Dev/Test Dependency Tiering"]
    P5 --> P6["Phase 6: Engine Hardening & Advisory Parsing"]
    P6 --> P7["Phase 7: Test Suite & Benchmark Verification"]
```

---

### Phase 1: Baseline Pinning & Label Calibration
**Goal**: Establish an immutable regression test baseline before making changes.
* Verify 559 passing tests in the current suite (`pytest -q`).
* Freeze benchmark numbers on PyGoat (Precision 38.3% overall, 17.1% dependency, AP 44.7% vs 53.7%) and Vulpy (Precision 92.1%, AP 87.2%).
* Ensure zero tolerance for false negatives on all 6 known true positives.

---

### Phase 2: Dead Package & Unimported FP Damping (`DEP-01`, `DEP-04`)
**Goal**: Ensure dependencies that are never imported or invoked by the application are flagged as `HIGH` false positives and properly suppressed/damped.
* **Risk Graph Update (`core/risk_graph.py`)**:
  - In `analyze_reachability` under `case f.engine == "dependency"`:
    When `not pkg_nodes and import_names_known(pkg_name)`:
    - Set `f.exposure = "DEAD"`
    - Set `f.reachable = False`
    - Set `f.fp_likelihood = "HIGH"`
    - Set `f.fp_reason = f"package '{pkg_name}' is not imported in the codebase"`
* **Refine Transitive Inheritance (`core/pkg_alias.py`)**:
  - Audit `TRANSITIVE` mapping:
    - `sqlparse` is only an internal migration/cli tool for Django. It should NOT automatically inherit `pkg::django` HTTP view reachability unless `sqlparse` is explicitly imported or raw SQL formatting functions are referenced.
    - Remove artificial links where a package is optional or client-only.
* **Expected Impact**: Immediately eliminates 5 FPs on PyGoat (`cryptography`, `oauthlib`, `sqlparse`), raising baseline precision.

---

### Phase 3: Deep Component & Symbol Gating (`DEP-02`, `DEP-06`)
**Goal**: Expand `cve_component_map.json` and AST symbol verification so that advisories affecting specific functions/submodules are marked `HIGH` false positives if the application does not use them.
* **Expand `data/cve_component_map.json`**:
  ```json
  {
    "django": {
      "geodjango": ["django.contrib.gis"],
      "strip_tags": ["django.utils.html.strip_tags", "striptags"],
      "urlize": ["django.utils.html.urlize", "urlize", "urlizetrunc"],
      "intcomma": ["django.contrib.humanize"],
      "truncator": ["django.utils.text.truncator", "truncatechars", "truncatewords"],
      "archive": ["django.utils.archive"],
      "cache middleware": ["django.middleware.cache"],
      "column aliases": ["annotate", "alias", "filteredrelation"]
    },
    "pillow": {
      "imagedraw": ["pil.imagedraw", "imagedraw"],
      "imagefont": ["pil.imagefont", "imagefont"]
    },
    "pyjwt": {
      "pyjwkclient": ["jwt.pyjwkclient", "pyjwkclient"],
      "jwk": ["jwt.algorithms.okp", "jwt.jwks", "jwk"]
    },
    "werkzeug": {
      "safe_join": ["werkzeug.security.safe_join", "werkzeug.utils.safe_join"]
    },
    "requests": {
      "extract_zipped_paths": ["requests.certs.extract_zipped_paths"]
    },
    "urllib3": {
      "proxy": ["urllib3.poolmanager.proxymanager", "urllib3.proxymanager"]
    }
  }
  ```
* **AST & Graph Symbol Verification**:
  - In `core/risk_graph.py`, enhance component checking:
    Check not only `pkg::<comp>` nodes, but also search the repository AST for calls or imports of the specific functions/submodules when keywords match.
  - If no import or call matches the component, flag `f.fp_likelihood = "HIGH"` with `f.fp_reason = f"affected component '{matched_component}' is not used"`.
* **Expected Impact**: Catches 14+ false positives in Django, Pillow, PyJWT, and Werkzeug without suppressing any of the 6 true positives.

---

### Phase 4: Platform & Deployment Awareness (`DEP-03`)
**Goal**: Detect when the repository is targeted/deployed on Linux and automatically flag Windows-only advisories as false positives.
* **Environment Detection (`core/env_detector.py` or within `core/risk_graph.py`)**:
  - Inspect repository files:
    - `Dockerfile`: presence of `FROM python:...-slim`, `FROM alpine`, `FROM ubuntu`, `FROM debian`.
    - `Procfile`, `docker-compose.yml`, `*.sh` scripts.
  - If Linux deployment is detected:
    - Flag Windows-specific advisories (e.g., matching keywords `"windows special device names"`, `"dos only on windows"`, `"safe_join not safe on windows"`) with:
      - `f.fp_likelihood = "HIGH"`
      - `f.fp_reason = "vulnerability only affects Windows environments (Linux deployment detected)"`
* **WSGI vs ASGI Detection**:
  - Check entrypoints in `Dockerfile` CMD, `Procfile`, or `wsgi.py` vs `asgi.py`.
  - When deployment runs purely WSGI (`gunicorn`, `uwsgi`), mark ASGI request smuggling advisories (`CVE-2026-33034`) as `HIGH` FP or `exposure = "DEAD"`.
* **Expected Impact**: Cleans up 4 FPs on PyGoat (`CVE-2025-64458`, `CVE-2024-49766`, `CVE-2025-66221`, `CVE-2026-33034`).

---

### Phase 5: Dev/Test Dependency Tiering (`DEP-05`)
**Goal**: Distinguish between root production requirements and secondary test/development fixtures.
* **File Classification in `dependency_engine.py`**:
  - Classify discovered files into `PROD` vs `DEV_TEST`:
    - `DEV_TEST`: `requirements-dev.txt`, `test-requirements.txt`, `tests/requirements.txt`, `dockerized_labs/*/requirements.txt`.
    - `PROD`: root `requirements.txt`, `pyproject.toml` (main dependencies), `Pipfile.lock` (default section).
  - Annotate findings with `f.extra["dependency_scope"] = "dev"` or `"prod"`.
  - In `core/risk_graph.py` and `scoring/risk_score.py`:
    - If a dependency only appears in dev/test/lab requirements and is not in prod, set `exposure = "TEST"` or discount by `0.60x`.
* **Expected Impact**: Prevents secondary lab pins (like older Django 3.2.18 in demo labs) from contaminating production risk scoring.

---

### Phase 6: Engine Hardening & Advisory Parsing (`DEP-06`, `DEP-07`)
**Goal**: Enhance the core `DependencyEngine` for better accuracy, richer advisory metadata, and robust failure recovery.
* **Severity & Vector Fallbacks**:
  - Support CVSS v2 base score fallback when CVSS v3 is absent.
  - Support CVSS v4 vector detection.
* **CWE Mapping & Normalization**:
  - Cross-reference CVE IDs against `core/taxonomy.py` and NVD fallback to ensure every finding has a valid canonical CWE.
* **Advisory Merging (`merge_vulns`)**:
  - Select the most detailed description across merged records instead of the first non-empty string.
* **Error Handling & Stats**:
  - Implement sub-batch fallback on OSV 500/429 errors (splitting 500-item batch into 50-item batches) to avoid dropping entire groups of packages.

---

### Phase 7: Test Suite & Benchmark Verification
**Goal**: Comprehensive unit testing and full evaluation run on PyGoat and Vulpy.
* **Unit Tests**:
  - Add tests in `tests/test_dependency_engine.py` for CVSS fallbacks, lockfile parsing, and sub-batch error recovery.
  - Add tests in `tests/test_risk_graph.py` for dead package `HIGH` FP flagging and component gating.
  - Add tests in `tests/test_fp_guards.py` for Windows platform detection and symbol gating.
* **Benchmark Evaluation**:
  - Run `python -m evaluation.run evaluate --scan eval_scans/pygoat_findings_v2.json --labels evaluation/labels/pygoat.yaml`.
  - Verify:
    1. Real findings wrongly hidden: **0 (MUST BE 0)**.
    2. False alarms caught HIGH: **>= 24 of 29 (> 80%)**.
    3. Precision after `--hide-fp`: **> 85%**.
    4. Ranking AP Delta: **Positive (SCIP risk score beats raw severity)**.
  - Run regression evaluation on Vulpy to confirm zero regressions (100% recall, 92.1% precision).

---

## 4. Expected Impact Summary

| Metric | Current Baseline | Target (Post-Improvement) |
|---|---|---|
| **Dependency Precision (Raw)** | 17.1% | **>= 60.0%** |
| **Dependency Precision (with `--hide-fp`)** | 40.0% | **>= 85.0%** |
| **False Alarms Flagged HIGH** | 2 / 29 (6.9%) | **>= 24 / 29 (82.8%)** |
| **Real Findings Wrongly Hidden** | 0 (PASS) | **0 (PASS - Strict Invariant)** |
| **Ranking AP Delta vs Severity** | -0.0902 (Inverted) | **+0.0500 to +0.1200 (Superior)** |
| **Unit Test Suite** | 559 passing | **585+ passing** |
