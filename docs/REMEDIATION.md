# Remediation (slice 1: dependency upgrades)

SCIP turns dependency findings into a **reviewed, verified upgrade patch**. It never edits your repository.

## How it works

1. **Plan** (`remediation/plan.py`). For each pinned line such as `Django==4.2`, take every vulnerability found on it
   and choose the *lowest version that fixes all of them* (the highest of the per-CVE fixed versions).
   * `patch`/`minor` jumps are planned automatically.
   * `major` jumps (for example 3.x -> 4.x) are listed as **needs manual review** and not applied unless `--allow-major`.
   * Pins with no known fixed version are listed under **no known fix**, never hidden.
2. **Apply to a copy** (`remediation/apply.py`). The repo is copied to `remediation_out/workspace` (without `.git`,
   virtualenvs or caches). Only the version number on `name==version` lines of `requirements*.txt` is changed;
   comments, extras, markers and line endings are kept. Hash-pinned lines, unexpected lines and other file
   types are skipped with a reason. The output is `dependency_upgrades.patch`.
3. **Verify** (`remediation/verify.py`):
   * **Re-scan** the patched copy: targeted vulnerabilities must be gone and no new ones may appear.
   * **Tests** (optional): run your test command inside a *fresh virtualenv built from the upgraded requirements*.

| Status | Meaning |
|---|---|
| `verified` | re-scan clean **and** your tests passed in a fresh venv with the upgraded packages |
| `scan_only` | re-scan clean, but no tests (or tests ran against the OLD installed packages). Not proven safe |
| `needs_review` | some vulnerabilities remain, or the new version has its own advisories |
| `tests_failed` | your tests failed with the upgraded packages |
| `nothing_applied` | no edit was safe to make |

## Commands

```
python -m core.pipeline <repo> -o scan.json
python -m remediation.run <repo> --scan scan.json                     # plan + patch only
python -m remediation.run <repo> --scan scan.json --verify            # + re-scan the patched copy (needs network)
python -m remediation.run <repo> --scan scan.json --verify --test-cmd "pytest -q" --venv
git apply remediation_out/dependency_upgrades.patch                   # after you have read the patch
```

## Honest limits

* Only `requirements*.txt` pins are edited automatically (pyproject, Poetry and Pipfile locks are reported, not edited).
* `verified` means "scan clean and your own tests pass". It is only as strong as your test suite; a project with no
  tests can reach `scan_only` at best.
* The target version is the highest *fixed* version OSV lists; the new version may have new advisories, which is why the
  re-scan checks for introduced vulnerabilities.
* Fixes for secrets and code patterns (weak hash, `debug=True`) are not automated yet; see the roadmap.
