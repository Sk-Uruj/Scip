# PR: feat(risk-graph,fp-hardening): Code Risk Graph, Precision FP Heuristics, and Hardened Exposure Modeling

## Summary

This PR delivers comprehensive precision and architectural hardening across the **Code & Risk Graph engine**, **False Positive Detector**, and **Secrets Exposure Model**:

1. **AST-Based SQL Identifier & DDL Verification**: Resolves SQL interpolated variables via an AST backward walk to verify provenance from string constants, literal dict/set lookups, or Enums, rejecting request/user inputs.
2. **Weak-Hash S3 ETag Precision**: Restricts RFC 7232 compliance damping to weak-hash findings (B324, CWE-327/328) with nearby/enclosing ETag signals, dropping naive filename matching.
3. **Mandatory Seed Guards & In-Memory Cross-Check**: Enforces mandatory environment and cross-file safety (`required = g_env and g_cross`) for credential damping, searches secret values in-memory (never emitted), respects `SKIP_DIRS`, and scopes gating checks to enclosing seed blocks.
4. **Provider-Format Test Exemption**: Exempts live provider-formatted keys (`AKIA...`, `ghp_...`, `sk_live_...`) in test suites from blanket FP damping.
5. **PRNG Security Precedence**: Protects OTP, PIN, verification, and reset codes from being discounted as reference IDs.
6. **Class-Method & Object Reachability**: Traces `Class.method` and `obj.method()` instance calls, FastAPI `Depends(...)` parameters, and startup/lifespan hooks.
7. **Analyzer Cache Invalidation & $O(1)$ Graph Ingress**: Adds `ANALYZER_VERSION = "2.0"` to SQLite cache keys and optimizes reachability with ancestor membership checks.
8. **Disentangled Exposure Knobs**: Separates `WORKER` ($0.70\times$) from `HIST` ($0.50\times$), assigns distinct `INTNL` ($0.20\times$) and `UNKNOWN` ($0.50\times$) reachability scores in `ScoringConfig`.
9. **Leak-Free Structural Fingerprints & End-to-End Scan Test**: Fingerprints include scope, column offset, and occurrence index without leaking line shifts or collisions; end-to-end test scans a fixture repo with `SecretsEngine` ensuring raw secrets, hashes, and length hints never leak into JSON.
10. **Resilient Failure Handling**: Per-finding `try...except` in `detect_false_positives` preventing malformed findings from aborting the pipeline; gitignores generated report artifacts.

---

## Detailed Changes

### 1. AST Backward Walk for SQL Injection & DDL (`core/fp_detector.py`)
- Replaced name-based literal pattern matching (`{entered_col}`, `{col_name}`, naive `ALTER TABLE`) with `check_ast_sql_variable_safety`.
- Walks backward through statements in the enclosing AST scope to ensure all interpolated variables derive from string literal constants, literal dict/tuple/list mappings, or Enum attributes.
- Fails closed on any variable originating from request parameters (`request.args`, `request.json`), external calls, or function parameters.
- Added adversarial test `test_sql_fp_adversarial_request_field`.

### 2. S3 ETag Heuristic Precision (`core/fp_detector.py`)
- Requires a weak-hash finding (`CWE-327`, `CWE-328`, `B324`, or `crypto`/`bandit` hash findings).
- Requires an ETag signal in the enclosing function, nearby source code lines ($\pm 10$ lines), or finding title/description.
- Dropped blanket `"metadata"` in filename check.

### 3. Fail-Closed Seed Guard Model (`core/fp_detector.py`)
- Restricted seed branch strictly to credential CWEs (`CWE-259`, `CWE-798`, `CWE-1188`, `B105-B107`, `secrets`).
- Made environment and cross-file guards mandatory:
  ```python
  required = g_env and g_cross
  if required and g_demo and g_gate:
      damp = 0.20
  elif required and (g_demo or g_gate):
      damp = 0.60
  else:
      damp = 1.0  # NOT_SEED
  ```
- **In-Memory Value Cross-Check**: Searches candidate secret values ($\ge 6$ chars) across non-fixture production files while pruning `SKIP_DIRS` (`.git`, `venv`, `node_modules`). Fails closed if no value can be extracted, and never logs or emits the candidate value.
- **Scoped Gating Guard**: Restricts `--seed` / `DEBUG` / `SELECT COUNT` regex checks to the enclosing statement block/function instead of searching the entire file.

### 4. Test-Path Secret Exemption & PRNG Disambiguation (`core/fp_detector.py`)
- Exempts known provider prefixes (`AKIA`, `ASIA`, `ghp_`, `sk_live_`, `xoxb-`, etc.) and high-confidence provider rules in test directories; damps only generic passwords.
- Added `otp`, `pin`, `password`, `reset`, `verify`, `code`, `token`, `secret`, `key` to `SECURITY_PRNG_PATTERNS`.
- Strict precedence: any match against security patterns immediately overrides reference-ID heuristics.

### 5. Call Graph & Reachability Enhancements (`core/risk_graph.py`, `engines/blast_radius_engine.py`)
- `find_enclosing_function` tracks enclosing classes to return `Class.method`, aligning with node IDs in `RiskGraph`.
- `RiskGraphASTVisitor` resolves `obj.method()` instance calls using local variable type tracking (`var_types`) and imported class methods.
- Added support for FastAPI `@app.on_event("startup")` / `lifespan` handlers and `Depends(...)` dependencies.
- Added `ANALYZER_VERSION = "2.0"` to `SQLiteGraphStore.for_repo` cache key to invalidate cached graphs across AST visitor changes.
- Optimized reachability evaluation using $O(1)$ `ep in ancestors` checks before path reconstruction.

### 6. Scoring Disentanglement & Fingerprints (`scoring/risk_score.py`, `engines/secrets_engine.py`)
- Disentangled `WORKER` ($0.70\times$) from `HIST` ($0.50\times$), `INTNL` ($0.20\times$), and `UNKNOWN` ($0.50\times$).
- Consolidated all dampening factors and reachability weights into `ScoringConfig` with bounded validation.
- Structural fingerprints incorporate rule ID, file, enclosing scope, line, column, and occurrence index: `sha256(f"{rule}:{file}:{scope}:{line}:{col}:{occ_idx}")[:16]`.
- Omitted `"entropy"` from finding extra data to prevent secret length leakage.
- Excluded repository-level secrets (`REPO`, `HIST`) from the call-graph "REACHABLE ATTACK PATHS" section.

---

## Verification & Test Results

- **Complete Test Suite**: **290 / 290 tests passing** (100% pass rate).
  ```text
  tests/test_bandit_engine.py ......................                       [  7%]
  tests/test_blast_radius.py .....                                         [  9%]
  tests/test_crypto_engine.py ....................                         [ 16%]
  tests/test_cvss.py ......                                                [ 18%]
  tests/test_dedup.py ..................                                   [ 24%]
  tests/test_dependency_engine.py .................................        [ 35%]
  tests/test_fp_detector.py ..............                                 [ 40%]
  tests/test_pipeline.py ..............                                    [ 45%]
  tests/test_risk_graph.py ........                                        [ 48%]
  tests/test_risk_score.py ............                                    [ 52%]
  tests/test_secrets_engine.py ........................................... [ 67%]
  ..............................................................           [ 88%]
  tests/test_semgrep_engine.py ..............                              [ 93%]
  tests/test_suppression.py ...................                            [100%]
  ============================ 290 passed in 13.03s =============================
  ```

- **Target Repository Scan**: Verified on `test_repos/metering_billing_engine` using `python -m core.pipeline test_repos/metering_billing_engine`:
  - `tiering_engine.py:179` correctly identified as FP via AST backward walk ($56.40 \rightarrow 11.28$).
  - `helpers.py:76` and `add_object_metadata.py:31` correctly identified as RFC 7232 ETag compliance FP.
  - `main.py:404` properly classified as `[REF-ID]`.
  - Zero raw secrets, hashes, or length hints emitted in finding outputs.
