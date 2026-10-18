"""Never print the VALUE of a credential that a code scanner found.

The secrets engine already masks what it finds. Wrapped scanners do not: Bandit's
B105/B106/B107 put the literal password in the title, the description and the code
snippet ("Possible hardcoded password: 'hunter2'"), which would leak real credentials
into reports, CI logs and any LLM prompt built from them.

``redact_finding`` is applied at the engine boundary (so baseline fingerprints stay
consistent) and once more just before output as a safety net. It is idempotent.
"""
from __future__ import annotations

import re
from typing import Any, List, Set

from core.finding import Finding
from engines.secrets_engine import is_placeholder, mask_secret, scrub_tokens

CREDENTIAL_CWES = {"CWE-259", "CWE-798", "CWE-321", "CWE-522", "CWE-312"}
CREDENTIAL_TEST_IDS = {"B105", "B106", "B107"}
_CREDENTIAL_TITLE = re.compile(
    r"(?i)hard-?coded|password|passwd|secret|api[_ -]?key|credential|private key|access token|auth token")
# Bandit: "Possible hardcoded password: 'hunter2'"
_BANDIT_LITERAL = re.compile(r"""(?i)hardcoded (?:password|secret|token|key)[^:'"]*:\s*(['"])(.*)\1""")
_QUOTED = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\\n]){4,200}?)\1""")
# any credential-named assignment / keyword argument / dict entry, however short the value:
#   password = "x"    connect(passwd="y")    {"api_key": "z"}
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential|private[_-]?key)\w*['"\]]*\s*[:=]\s*"""
    r"""[bBrRuUfF]?(['"])((?:\\.|(?!\1)[^\\\n]){1,200}?)\1""")


def _is_credential_finding(f: Finding) -> bool:
    test_id = str((f.extra or {}).get("test_id", "")).upper()
    return (test_id in CREDENTIAL_TEST_IDS
            or (f.cwe or "").upper() in CREDENTIAL_CWES
            or bool(_CREDENTIAL_TITLE.search(f.title or "")))


def _literals(f: Finding) -> Set[str]:
    found: Set[str] = set()
    for text in (f.description, f.title):
        m = _BANDIT_LITERAL.search(text or "")
        if m and m.group(2):
            found.add(m.group(2))
    # Code snippets include NEIGHBOURING lines (Bandit prints context), so any credential-named
    # assignment in the evidence is masked, whatever kind of finding this is.
    for m in _CREDENTIAL_ASSIGNMENT.finditer(f.evidence or ""):
        if not is_placeholder(m.group(2)):
            found.add(m.group(2))
    if _is_credential_finding(f):
        for m in _QUOTED.finditer(f.evidence or ""):
            lit = m.group(2)
            if not is_placeholder(lit):
                found.add(lit)
    return found


def _mask_quoted(text: str, literals: List[str]) -> str:
    """Replace 'literal' / "literal" with the masked form, keeping the quotes and the code around."""
    for lit in literals:
        mask = mask_secret(lit)
        for q in ("'", '"'):
            text = text.replace(f"{q}{lit}{q}", f"{q}{mask}{q}")
    return text


def _mask_any(value: Any, literals: List[str]) -> Any:
    """Recursively mask in structured data (e.g. Semgrep metavars), matching whole tokens only."""
    if isinstance(value, str):
        for lit in literals:
            if len(lit) >= 3:
                value = re.sub(r"(?<![A-Za-z0-9_])" + re.escape(lit) + r"(?![A-Za-z0-9_])", mask_secret(lit), value)
        return value
    if isinstance(value, list):
        return [_mask_any(v, literals) for v in value]
    if isinstance(value, dict):
        return {k: _mask_any(v, literals) for k, v in value.items()}
    return value


def redact_finding(f: Finding) -> Finding:
    """Mask credential values in-place and return the finding. Secrets-engine findings are skipped."""
    if f.engine == "secrets":
        return f
    before = (f.title, f.description, f.evidence, f.fix_hint)
    # longest first so a literal that contains another one is masked as a whole
    literals = sorted(_literals(f), key=len, reverse=True)
    if literals:
        f.title = _mask_quoted(f.title or "", literals)
        f.description = _mask_quoted(f.description or "", literals)
        f.evidence = _mask_quoted(f.evidence or "", literals)
        f.fix_hint = _mask_quoted(f.fix_hint or "", literals)
        if f.extra:
            f.extra = _mask_any(f.extra, literals)
    # defence in depth: never echo a long random-looking token that sits next to a finding
    f.evidence = scrub_tokens(f.evidence or "")
    if (f.title, f.description, f.evidence, f.fix_hint) != before:
        f.extra = dict(f.extra or {})
        f.extra["redacted"] = True
    return f
