"""Secrets engine (Step 3).

Finds hard-coded credentials in two places:
  1. the current files of the repository (working tree), and
  2. the full git history -- a secret that was committed and later deleted is
     still recoverable by anyone with a copy of the repo.

Detection layers (strongest first):
  * provider rules  - tokens with a recognisable shape (AWS, GitHub, Stripe, private keys...)
  * generic rules   - a string literal assigned to a variable called password / secret / token ...
  * entropy rule    - long random-looking string literals (conservative, low confidence)

Safety: the raw secret is NEVER stored in a Finding. Only a masked preview and a
truncated SHA-256 fingerprint (used to recognise the same secret in several places)
leave this module.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from core.finding import Finding
from engines.base import Engine

log = logging.getLogger("scip.secrets")

# --------------------------------------------------------------------------- #
# Tunables
# --------------------------------------------------------------------------- #
MAX_FILE_SIZE = 1_000_000          # bytes; larger files are skipped
MAX_LINE = 1000                    # characters; longer lines are minified blobs, skipped
MAX_HUNK_LINES = 20_000            # skip absurdly large added blocks in history (vendored data)
MAX_OCCURRENCES = 25               # history occurrences kept per secret
IGNORE_MARKERS = ("scip:ignore", "pragma: allowlist secret", "gitleaks:allow")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".idea", ".vscode",
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo", ".o", ".a",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".map", ".db", ".sqlite", ".sqlite3",
}
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Cargo.lock", "go.sum",
}
NO_ENTROPY_EXTS = {".json", ".ipynb", ".csv", ".tsv", ".lock", ".sum", ".xml", ".html", ".htm"}
CONFIG_EXTS = {".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".sh", ".bash", ".zsh"}


def should_skip_path(rel_path: str) -> bool:
    p = Path(rel_path)
    if any(part in SKIP_DIRS for part in p.parts[:-1]):
        return True
    name = p.name
    if name in SKIP_NAMES or name.endswith((".min.js", ".min.css")):
        return True
    return p.suffix.lower() in SKIP_EXTS


def is_test_path(rel_path: str) -> bool:
    p = Path(rel_path.lower())
    if any(part in {"test", "tests", "__tests__", "spec", "specs", "fixtures"} for part in p.parts[:-1]):
        return True
    return p.name.startswith("test_") or p.stem.endswith("_test")


def is_doc_file(rel_path: str) -> bool:
    p = Path(rel_path)
    return p.suffix.lower() in {".md", ".rst", ".txt", ".adoc"} or p.name == "METADATA"


def is_config_file(rel_path: str) -> bool:
    p = Path(rel_path)
    name = p.name.lower()
    return (p.suffix.lower() in CONFIG_EXTS or name.startswith(".env") or name.endswith(".env")
            or name in {"dockerfile", "docker-compose.yml"})


# --------------------------------------------------------------------------- #
# Small helpers: entropy, masking, placeholders
# --------------------------------------------------------------------------- #
def shannon_entropy(s: str) -> float:
    """Bits of entropy per character (0 = all same char, ~log2(alphabet) = random)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_KNOWN_PROVIDER_PREFIXES = (
    "AKIA", "ASIA", "ABIA", "ACCA",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "sk_live_", "pk_live_", "sk_test_", "pk_test_",
    "xoxb-", "xoxp-", "xoxr-", "xoxa-",
    "sq0atp-", "sq0csp-",
    "AIza",
)


def mask_secret(s: str) -> str:
    """Mask sensitive secret values without leaking initial characters or exact string length."""
    if not s:
        return "********"
    for prefix in _KNOWN_PROVIDER_PREFIXES:
        if s.startswith(prefix):
            return f"{prefix}****"
    return "********"


def fingerprint(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


_PLACEHOLDER_EXACT = {
    "password", "passwd", "pass", "pwd", "secret", "token", "apikey", "api_key", "api-key",
    "none", "null", "nil", "true", "false", "string", "str", "empty", "undefined",
    "changeme", "change_me", "change-me", "default", "required", "optional",
    "string?", "str?", "int", "integer", "number", "boolean", "bool", "object", "array", "bytes",
}
_PLACEHOLDER_SUBSTR = (
    "example", "your_", "your-", "yourpass", "yoursecret", "yourtoken", "yourkey", "xxxx",
    "placeholder", "dummy", "sample", "insert", "replace", "redacted", "todo", "fixme",
    "<", "{{", "${", "%(", "{%", "os.environ", "getenv", "environ[",
)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    low = v.lower()
    if not v:
        return True
    # filler such as 'xxxx', '****', '....', '0000'. NOT 'aaaaaaa': that is a real (weak) secret.
    if re.fullmatch(r"([xX*#._\-0])\1{3,}", v) or re.fullmatch(r"[*xX#._\-]{4,}", v):
        return True
    if v[0] in "$%{<[|>!&*":
        return True
    if low in _PLACEHOLDER_EXACT:
        return True
    return any(w in low for w in _PLACEHOLDER_SUBSTR)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: "re.Pattern[str]"
    hints: Tuple[str, ...]       # cheap lowercase substring pre-filter
    severity: float
    exploit: float               # heuristic 0-1 (no live validation is done)
    cwe: str = "CWE-798"
    group: int = 1
    confidence: str = "high"


def _r(id_, title, pattern, hints, severity, exploit, cwe="CWE-798", group=1, flags=0):
    return Rule(id_, title, re.compile(pattern, flags), tuple(h.lower() for h in hints),
                severity, exploit, cwe, group)


# Order = priority when two rules hit the same secret (earlier wins).
PROVIDER_RULES: List[Rule] = [
    _r("private-key", "Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       ("private key",), 9.0, 0.9, cwe="CWE-321", group=0),
    _r("aws-access-key-id", "AWS access key ID", r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
       ("akia", "asia", "abia", "acca"), 8.0, 0.8),
    _r("aws-secret-access-key", "AWS secret access key",
       r"(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
       ("secret",), 9.5, 0.9),
    _r("github-token", "GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b",
       ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), 9.0, 0.9),
    _r("gitlab-token", "GitLab personal access token", r"\b(glpat-[A-Za-z0-9_\-]{20})\b",
       ("glpat-",), 9.0, 0.9),
    _r("slack-token", "Slack token", r"\b(xox[abprs]-[A-Za-z0-9\-]{10,72})\b",
       ("xox",), 8.5, 0.8),
    _r("slack-webhook", "Slack webhook URL",
       r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
       ("hooks.slack.com",), 7.5, 0.7),
    _r("stripe-live-key", "Stripe live secret key", r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b",
       ("_live_",), 9.0, 0.9),
    _r("google-api-key", "Google API key", r"\b(AIza[0-9A-Za-z_\-]{35})\b",
       ("aiza",), 7.5, 0.7),
    _r("sendgrid-key", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
       ("sg.",), 8.5, 0.8),
    _r("pypi-token", "PyPI upload token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
       ("pypi-",), 9.0, 0.9),
    _r("npm-token", "npm access token", r"\b(npm_[A-Za-z0-9]{36})\b",
       ("npm_",), 9.0, 0.9),
    _r("anthropic-key", "Anthropic API key", r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b",
       ("sk-ant-",), 9.0, 0.9),
    _r("openai-key", "OpenAI API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{40,})\b",
       ("sk-",), 9.0, 0.9),
    _r("db-url-password", "Database URL with embedded password",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s:@/'\"]*:([^\s@/'\"]{3,})@[^\s'\"]+",
       ("://",), 8.0, 0.8),
    _r("jwt", "JSON Web Token", r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
       ("eyj",), 6.0, 0.4),
    _r("huggingface-token", "Hugging Face access token", r"\b(hf_[A-Za-z0-9]{34,})\b",
       ("hf_",), 9.0, 0.9),
    _r("discord-bot-token", "Discord bot token",
       r"(?i)\b(?:discord(?:[_\-]?bot)?|bot)[\"']?\s*[:=]\s*[\"']?([MN][A-Za-z\d]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b",
       ("discord", "bot"), 8.5, 0.8),
    _r("twilio-api-key", "Twilio API key", r"\b(SK[0-9a-fA-F]{32})\b",
       ("sk",), 8.0, 0.8),
    _r("vault-token", "HashiCorp Vault token", r"\b(hvs\.[A-Za-z0-9_\-]{24,})\b",
       ("hvs.",), 8.5, 0.8),
    _r("gcp-service-account", "GCP service account private key",
       r"\"private_key\"\s*:\s*\"(-----BEGIN (?:RSA )?PRIVATE KEY[^\"]+)\"",
       ("private_key",), 9.0, 0.9, cwe="CWE-321"),
]

_KEYWORDS = (r"(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?key"
             r"|private[_\-]?key|client[_\-]?secret|credential)")
_GENERIC_HINTS = ("password", "passwd", "pwd", "secret", "token", "api_key", "api-key", "apikey",
                  "access_key", "access-key", "auth_key", "auth-key", "private_key", "private-key",
                  "credential", "getenv", "environ")
GENERIC_QUOTED = re.compile(
    r"(?P<key>[A-Za-z0-9_.\-]*" + _KEYWORDS + r"[A-Za-z0-9_.\-]*)[\"']?\]?\s*(?::|=)\s*"
    r"(?:[bBrRuUfF]{1,2})?(?P<q>[\"'])(?P<val>[^\"'\n\\]{4,200})(?P=q)", re.I)
GENERIC_GETENV = re.compile(
    r"(?:(?P<lhs>[A-Za-z0-9_.\-]*" + _KEYWORDS + r"[A-Za-z0-9_.\-]*)\s*=\s*)?"
    r"(?:os\.)?(?:environ\.get|getenv)\s*\(\s*[\"'](?P<key>[^\"']+)[\"']\s*,\s*"
    r"(?:[bBrRuUfF]{1,2})?(?P<q>[\"'])(?P<val>[^\"'\n\\]{4,200})(?P=q)\s*\)", re.I)
GENERIC_UNQUOTED = re.compile(
    r"^\s*(?:export\s+|ENV\s+|set\s+)?(?P<key>[A-Za-z0-9_.\-]*" + _KEYWORDS + r"[A-Za-z0-9_.\-]*)\s*(?::|=)\s*"
    r"(?P<val>[^\s#\"'$%{<\[|>!&*][^\s#]{5,})\s*(?:#.*)?$", re.I)
ENTROPY_RE = re.compile(r"[\"']([A-Za-z0-9+/=_\-]{32,200})[\"']")

_KEY_SUFFIX_IGNORE = {
    "url", "uri", "path", "file", "name", "field", "label", "type", "header", "prefix", "endpoint",
    "msg", "message", "error", "regex", "pattern", "help", "text", "title", "env", "var", "id", "expiry",
    "expires", "length", "min", "max", "required", "validator", "form", "param", "params", "key_name",
}
_ENTROPY_LINE_SKIP = ("sha1", "sha256", "sha384", "sha512", "integrity", "checksum", "digest", "hash",
                      "md5", "uuid", "data:", "base64,", "font", "csrf", "nonce")


def looks_like_alphabet(s: str) -> bool:
    """True for strings such as 'ABCDEFGHIJKL...' or '0123456789abcdef' (sequential characters).
    Random secrets have almost no consecutive characters; alphabets are mostly consecutive."""
    if len(s) < 8:
        return False
    runs = sum(1 for a, b in zip(s, s[1:]) if ord(b) - ord(a) == 1)
    return runs / (len(s) - 1) > 0.3


def looks_like_identifier(v: str) -> bool:
    """CamelCase / snake_case / kebab-case NAMES (e.g. 'challengePassword', 'do_stuff') are labels,
    not credentials. Random mixed-case strings have far more case flips than real identifiers."""
    if re.search(r"[^A-Za-z_\-]", v):
        return False
    if re.fullmatch(r"[a-z]+|[A-Z]+|[A-Z][a-z]+", v):
        return False                       # single plain word: could be a weak password, keep it
    flips = len(re.findall(r"[a-z][A-Z]", v))
    seps = len(re.findall(r"[_\-]", v))
    if seps:
        return all(re.fullmatch(r"[A-Za-z][a-z]*|[A-Z]+", seg) for seg in re.split(r"[_\-]", v) if seg)
    return flips / len(v) <= 0.2


_CRED_END = re.compile(
    r"(?:password|passwd|pwd|secret|token|api_?key|apikey|access_?key|auth_?key|private_?key|secret_?key"
    r"|client_?secret|credentials?)s?(?:_?\d+)?(?:_base)?$")
_NLP_TOKEN_PREFIX = ("bos", "eos", "pad", "unk", "cls", "sep", "mask", "special", "start", "end",
                     "max", "min", "num", "n", "total", "stop", "image", "video", "audio", "text")


def credential_key(key: str) -> Optional[str]:
    """The assigned name must END with a credential word (db_password, apiKey, SECRET_KEY...).
    This drops parser/NLP 'token' variables such as token.markup, tokentype, TOKEN_COMMENT."""
    seg = key.split(".")[-1]
    seg = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", seg).lower().replace("-", "_")
    if not _CRED_END.search(seg):
        return None
    if seg.endswith(("token", "tokens")) and seg.split("_")[0] in _NLP_TOKEN_PREFIX and seg != "token":
        return None
    return seg


def _generic_title_cwe(key: str) -> Tuple[str, str, str]:
    k = key.lower()
    if any(x in k for x in ("password", "passwd", "pwd")):
        return "generic-password", "Hard-coded password", "CWE-259"
    return "generic-secret", "Hard-coded secret / API key / token", "CWE-798"


# --------------------------------------------------------------------------- #
# Line scanning (shared by working-tree scan and git-history scan)
# --------------------------------------------------------------------------- #
@dataclass
class Match:
    rule_id: str
    title: str
    fingerprint: str
    masked: str
    masked_line: str
    line: int
    entropy: float
    severity: float
    exploit: float
    cwe: str
    confidence: str
    variable: Optional[str] = None


def _classify_generic(value: str) -> Tuple[str, float, float, float]:
    """(confidence, severity, exploitability, entropy) for a generic assignment."""
    ent = shannon_entropy(value)
    if len(value) >= 16 and ent >= 4.0:
        return "high", 7.5, 0.7, ent
    mixed = bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value)) or bool(
        re.search(r"[^A-Za-z0-9]", value))
    if len(value) >= 8 and (ent >= 3.0 or mixed):
        return "medium", 6.0, 0.5, ent
    return "low", 4.5, 0.3, ent


_WHOLE_LINE_STRING = re.compile(r"""[(\[]?\s*[bBrRuU]?["'][^"']+["']\s*[,)\]]*\s*""")
_COLOR = re.compile(r"#[0-9a-fA-F]{3,8}")
_MAX_ENTROPY_PER_FILE = 5
_PRIVATE_KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
_LOCAL_HOST = re.compile(r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?![\w.-])", re.I)
_LONG_LINE = 400            # generic/entropy rules ignore lines longer than this (minified code)


_TOKENISH = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")      # "=" only as base64 padding, so "name=value" keeps its name


def scrub_tokens(s: str) -> str:
    """Defence in depth for the evidence snippet: even if no rule recognised a value, never echo
    back a long random-looking token that happens to sit on the same line as a finding
    (e.g. a cookie string such as 'csrftoken=5fVO...; jwt=<detected>')."""
    def repl(m: "re.Match[str]") -> str:
        t = m.group(0)
        if "*" in t or not (re.search(r"[A-Za-z]", t) and re.search(r"\d", t)):
            return t
        if shannon_entropy(t) < 3.5:
            return t
        return mask_secret(t)
    return _TOKENISH.sub(repl, s)


def _mask_spans(text: str, spans: List[Tuple[int, int, str]]) -> str:
    """Replace only the exact secret positions with their masks (not every occurrence of the text)."""
    lead = len(text) - len(text.lstrip())
    out = text.strip()
    last_start = len(out) + 1
    for a, b, mask in sorted(spans, key=lambda x: -x[0]):
        a, b = a - lead, b - lead
        if a < 0 or b > len(out) or b > last_start:
            continue
        out = out[:a] + mask + out[b:]
        last_start = a
    # Normalize intra-line whitespace padding around values to prevent column alignment length leaks
    out = re.sub(r"[ \t]{2,}", " ", out)
    return scrub_tokens(out)[:160]


def scan_lines(lines: List[Tuple[int, str]], filename: str = "", use_entropy: bool = True) -> List[Match]:
    """Scan (line_number, text) pairs. Returns Matches carrying NO raw secrets."""
    out: List[Match] = []
    config = is_config_file(filename) if filename else False
    entropy_ok = use_entropy and Path(filename).suffix.lower() not in NO_ENTROPY_EXTS
    n = len(lines)

    for idx, (lineno, text) in enumerate(lines):
        if len(text) > MAX_LINE or not text.strip():
            continue
        low = text.lower()
        if any(m in low for m in IGNORE_MARKERS):
            continue
        stripped = text.lstrip()
        if stripped.startswith((">>>", "...")):              # doctest examples
            continue

        # fingerprint -> (priority, Match, span-to-mask | None)
        found: Dict[str, Tuple[int, Match, Optional[Tuple[int, int]]]] = {}

        def add(prio: int, m: Match, span: Optional[Tuple[int, int]]) -> None:
            cur = found.get(m.fingerprint)
            if cur is None or prio < cur[0]:
                found[m.fingerprint] = (prio, m, span)

        # 1) provider rules --------------------------------------------------
        for prio, rule in enumerate(PROVIDER_RULES):
            if not any(h in low for h in rule.hints):
                continue
            for mt in rule.pattern.finditer(text):
                secret = mt.group(rule.group)
                sev, exp, conf = rule.severity, rule.exploit, rule.confidence
                if rule.id == "private-key":
                    nxt = lines[idx + 1][1].strip() if idx + 1 < n else ""
                    has_body = (_PRIVATE_KEY_BODY.search(text[mt.end():]) is not None
                                or re.fullmatch(r"[A-Za-z0-9+/=]{40,}", nxt) is not None
                                or nxt.startswith(("Proc-Type:", "DEK-Info:")))
                    if not has_body:                         # just a marker string in code/docs
                        continue
                    fp = fingerprint(secret + "\n" + nxt[:80])
                    masked, span = secret + " [key body redacted]", None
                else:
                    if is_placeholder(secret):
                        continue
                    fp, masked, span = fingerprint(secret), mask_secret(secret), mt.span(rule.group)
                    if rule.id == "db-url-password" and _LOCAL_HOST.search(text):
                        sev, exp, conf = 4.5, 0.3, "low"    # local dev database
                    elif rule.id != "db-url-password" and (looks_like_alphabet(secret)
                                                          or shannon_entropy(secret) < 3.0):
                        # right shape but not random ('sk_live_abcdefgh...', '..._1234567890'):
                        # almost certainly a documentation / training dummy
                        sev, exp, conf = min(sev, 4.0), min(exp, 0.2), "low"
                add(prio, Match(rule.id, rule.title, fp, masked, "", lineno, shannon_entropy(secret),
                                sev, exp, rule.cwe, conf), span)

        # 2) generic assignments ---------------------------------------------
        if len(text) <= _LONG_LINE and any(h in low for h in _GENERIC_HINTS):
            candidates = []
            for mt in GENERIC_QUOTED.finditer(text):
                pm = re.search(r"(?<![A-Za-z0-9_])([bBrRuUfF]{1,2})$", text[:mt.start("q")])
                if pm and "f" in pm.group(1).lower():         # f-string -> interpolation, not a literal
                    continue
                candidates.append((mt.group("key"), mt.group("val"), mt.span("val")))
            for mt in GENERIC_GETENV.finditer(text):
                pm = re.search(r"(?<![A-Za-z0-9_])([bBrRuUfF]{1,2})$", text[:mt.start("q")])
                if pm and "f" in pm.group(1).lower():
                    continue
                k = mt.group("key") if credential_key(mt.group("key")) else (mt.group("lhs") or mt.group("key"))
                candidates.append((k, mt.group("val"), mt.span("val")))
            if config:
                mt = GENERIC_UNQUOTED.match(text)
                if mt:
                    candidates.append((mt.group("key"), mt.group("val"), mt.span("val")))
            for key, val, span in candidates:
                kw = credential_key(key)
                if kw is None or kw.split("_")[-1] in _KEY_SUFFIX_IGNORE or is_placeholder(val):
                    continue
                if re.search(r"[\s{}]", val) or re.match(r"(?i)https?://", val) or "%s" in val:
                    continue
                nval = re.sub(r"\W", "", val).lower()
                if looks_like_identifier(val) or nval in (re.sub(r"\W", "", key).lower(),
                                                          re.sub(r"\W", "", key.split(".")[-1]).lower()):
                    continue            # value just repeats the variable name: user_token = "user_token"
                if _COLOR.fullmatch(val):
                    continue
                if kw.endswith(("token", "tokens")) and (val.isdigit() or val.isalpha()):
                    continue          # numbers / plain words assigned to a 'token' are labels, not secrets
                conf, sev, exp, ent = _classify_generic(val)
                if is_doc_file(filename):                    # prose / documentation examples
                    conf, sev, exp = "low", min(sev, 4.0), min(exp, 0.2)
                rid, title, cwe = _generic_title_cwe(key)
                add(100, Match(rid, title, fingerprint(val), mask_secret(val), "", lineno, ent,
                               sev, exp, cwe, conf, variable=key.split(".")[-1]), span)

        # 3) standalone high-entropy strings ---------------------------------
        if (entropy_ok and 34 <= len(text) <= _LONG_LINE
                and not any(w in low for w in _ENTROPY_LINE_SKIP)):
            for mt in ENTROPY_RE.finditer(text):
                val = mt.group(1)
                if re.fullmatch(r"[0-9a-fA-F]+", val) or re.fullmatch(r"[0-9]+", val):
                    continue
                if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", val):
                    continue
                if re.fullmatch(r"[A-Za-z_\-]+", val) or "//" in val or looks_like_alphabet(val):
                    continue
                if _WHOLE_LINE_STRING.fullmatch(text.strip()):   # a data table / blob, not an assignment
                    continue
                ent = shannon_entropy(val)
                if ent >= 4.5:
                    add(200, Match("high-entropy-string", "High-entropy string (possible secret)",
                                   fingerprint(val), mask_secret(val), "", lineno, ent,
                                   4.5, 0.3, "CWE-798", "low"), mt.span(1))

        if found:
            spans = [(sp[0], sp[1], m.masked) for _, m, sp in found.values() if sp]
            masked_line = _mask_spans(text, spans)
            for _, m, _ in found.values():
                m.masked_line = masked_line
                out.append(m)
    # A file with many 'random-looking strings' is a data table / embedded blob, not a leak.
    if sum(1 for m in out if m.rule_id == "high-entropy-string") > _MAX_ENTROPY_PER_FILE:
        out = [m for m in out if m.rule_id != "high-entropy-string"]
    return out


# --------------------------------------------------------------------------- #
# Aggregation of one secret across files / commits
# --------------------------------------------------------------------------- #
@dataclass
class _Agg:
    match: Match
    tree: List[Tuple[str, int]] = field(default_factory=list)
    history: List[dict] = field(default_factory=list)
    is_test: bool = True


class SecretsEngine(Engine):
    name = "secrets"

    def __init__(self, scan_history: bool = True, max_commits: int = 5000, use_entropy: bool = True,
                 max_file_size: int = MAX_FILE_SIZE):
        self.scan_history = scan_history
        self.max_commits = max_commits
        self.use_entropy = use_entropy
        self.max_file_size = max_file_size
        self.stats: Dict[str, object] = {}

    @staticmethod
    def _register(aggs: Dict[str, _Agg], m: Match) -> _Agg:
        """One entry per distinct secret. If the same secret shows up in several places, the
        finding keeps the MOST severe interpretation (e.g. a prod DB password that is also used
        in a localhost URL must not be rated as a harmless local credential)."""
        agg = aggs.get(m.fingerprint)
        if agg is None:
            agg = aggs[m.fingerprint] = _Agg(m)
        elif (m.severity, m.exploit) > (agg.match.severity, agg.match.exploit):
            agg.match = m
        return agg

    # ---- working tree ---------------------------------------------------- #
    def _iter_files(self, root: Path) -> Iterator[Tuple[Path, str]]:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                full = Path(dirpath) / fn
                rel = full.relative_to(root).as_posix()
                if should_skip_path(rel):
                    continue
                yield full, rel

    def _scan_tree(self, root: Path, aggs: Dict[str, _Agg]) -> None:
        scanned = skipped = 0
        for full, rel in self._iter_files(root):
            try:
                if full.stat().st_size > self.max_file_size:
                    skipped += 1
                    continue
                data = full.read_bytes()
            except OSError:
                skipped += 1
                continue
            if b"\x00" in data[:4096]:          # binary
                skipped += 1
                continue
            scanned += 1
            text = data.decode("utf-8", errors="replace")
            lines = list(enumerate(text.splitlines(), 1))
            for m in scan_lines(lines, rel, self.use_entropy):
                agg = self._register(aggs, m)
                if (rel, m.line) not in agg.tree:
                    agg.tree.append((rel, m.line))
                agg.is_test = agg.is_test and is_test_path(rel)
        self.stats.update(files_scanned=scanned, files_skipped=skipped)

    # ---- git history ----------------------------------------------------- #
    @staticmethod
    def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace")

    def _scan_history(self, root: Path, aggs: Dict[str, _Agg]) -> None:
        self.stats["history_scanned"] = False
        try:
            probe = self._git(root, "rev-parse", "--is-inside-work-tree")
        except FileNotFoundError:
            self.stats["history_note"] = "git executable not found"
            log.info("git not installed; skipping history scan")
            return
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            self.stats["history_note"] = "not a git repository"
            log.info("%s is not a git repository; skipping history scan", root)
            return

        cmd = ["git", "-C", str(root), "-c", "core.quotepath=off", "log", "--all", "--reverse",
               "-p", "-U0", "--relative", "--no-color", "--no-ext-diff", "--no-textconv",
               f"--max-count={self.max_commits}",
               "--format=@@COMMIT@@%H%x1f%an%x1f%aI", "--", "."]
        errfile = tempfile.TemporaryFile()
        commits = 0
        hist_matches = 0
        truncated_lines = 0
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errfile, text=True,
                                    encoding="utf-8", errors="replace")
        except OSError as e:
            self.stats["history_note"] = f"could not run git: {e}"
            return

        commit = {"commit": "", "author": "", "date": ""}
        cur_file: Optional[str] = None
        in_header = False
        hunk: List[Tuple[int, str]] = []
        new_no = 0
        file_lines_scanned = 0

        def flush() -> None:
            nonlocal hunk, hist_matches
            if hunk and cur_file and not should_skip_path(cur_file):
                for m in scan_lines(hunk, cur_file, self.use_entropy):
                    agg = self._register(aggs, m)
                    agg.is_test = agg.is_test and is_test_path(cur_file)
                    occ = {"commit": commit["commit"][:8], "date": commit["date"][:10],
                           "author": commit["author"], "file": cur_file, "line": m.line}
                    if occ not in agg.history and len(agg.history) < MAX_OCCURRENCES:
                        agg.history.append(occ)
                        hist_matches += 1
            hunk = []

        hunk_re = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n").rstrip("\r")
            if line.startswith("@@COMMIT@@"):
                flush()
                parts = line[len("@@COMMIT@@"):].split("\x1f")
                commit = {"commit": parts[0], "author": parts[1] if len(parts) > 1 else "",
                          "date": parts[2] if len(parts) > 2 else ""}
                cur_file, in_header = None, False
                file_lines_scanned = 0
                commits += 1
                continue
            if line.startswith("diff --git "):
                flush()
                cur_file, in_header = None, True
                file_lines_scanned = 0
                continue
            if in_header:
                if line.startswith("+++ "):
                    path = line[4:]
                    cur_file = None if path == "/dev/null" else (path[2:] if path.startswith("b/") else path)
                elif line.startswith("@@ "):
                    in_header = False
                    mt = hunk_re.match(line)
                    new_no = int(mt.group(1)) if mt else 0
                continue
            if line.startswith("@@ "):
                flush()
                mt = hunk_re.match(line)
                new_no = int(mt.group(1)) if mt else 0
                continue
            if line.startswith("+"):
                if file_lines_scanned < MAX_HUNK_LINES:
                    hunk.append((new_no, line[1:]))
                    file_lines_scanned += 1
                    if len(hunk) >= 5000:
                        flush()
                else:
                    truncated_lines += 1
                new_no += 1
        flush()
        proc.wait()
        errfile.seek(0)
        err = errfile.read().decode("utf-8", "replace").strip()
        errfile.close()
        if proc.returncode != 0 and "does not have any commits" not in err:
            self.stats["history_note"] = f"git log failed: {err[:200]}"
            log.warning("git log failed for %s: %s", root, err[:200])
            return
        self.stats.update(
            history_scanned=True,
            commits_scanned=commits,
            truncated_diff_lines=truncated_lines,
        )

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self._current_root = root
        self.stats = {"history_scanned": False}
        aggs: Dict[str, _Agg] = {}
        self._scan_tree(root, aggs)
        if self.scan_history:
            self._scan_history(root, aggs)

        loc_counts: Dict[Tuple[str, str, int], int] = {}
        findings: List[Finding] = []
        for a in aggs.values():
            m = a.match
            f_path, f_line = a.tree[0] if a.tree else (a.history[0]["file"], a.history[0]["line"])
            loc_key = (m.rule_id, f_path, f_line)
            occ_idx = loc_counts.get(loc_key, 0)
            loc_counts[loc_key] = occ_idx + 1
            findings.append(self._make_finding(a, occ_idx=occ_idx))

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats.update(
            secrets_found=len(findings),
            in_current_files=sum(1 for f in findings if f.extra["in_working_tree"]),
            history_only=sum(1 for f in findings if not f.extra["in_working_tree"]),
        )
        return findings

    def _make_finding(self, a: _Agg, occ_idx: int = 0) -> Finding:
        m = a.match
        in_tree, in_hist = bool(a.tree), bool(a.history)
        first = a.history[0] if in_hist else None

        if in_tree:
            file, line = a.tree[0]
            title = f"Hard-coded secret: {m.title}"
            desc = (f"{m.title} found in {file}:{line}. Anyone who can read this repository "
                    f"-- including its git history -- can use it.")
            if in_hist and first:
                desc += (f" First committed in {first['commit']} on {first['date']} "
                         f"by {first['author']}.")
            hint = ("Remove the secret from source and load it at runtime from an environment variable "
                    "or a secrets manager. Then rotate/revoke the exposed credential, because it is "
                    "already in the repository history.") if in_hist else (
                    "Remove the secret from source and load it from an environment variable or a "
                    "secrets manager before committing. Rotate it if it was ever shared.")
        else:
            assert first is not None
            file, line = first["file"], first["line"]
            title = f"Secret in git history (no longer in current files): {m.title}"
            desc = (f"{m.title} was committed in {first['commit']} on {first['date']} by "
                    f"{first['author']} ({file}:{line}) and later removed from the current files, "
                    f"but it remains retrievable from git history.")
            hint = ("Treat this credential as compromised: rotate/revoke it now. Deleting the file "
                    "does not help; purging history (git filter-repo / BFG) is only a partial measure "
                    "once the repository has been cloned or pushed anywhere.")

        scope = "global"
        full_path = (self._current_root / file) if hasattr(self, "_current_root") and self._current_root else None
        if full_path and full_path.is_file() and line:
            try:
                from engines.blast_radius_engine import find_enclosing_function
                enc = find_enclosing_function(str(full_path), line)
                if enc:
                    scope = enc
            except Exception:
                pass
        if scope == "global" and m.variable:
            scope = m.variable

        col = getattr(m, "col_offset", 0) or 0
        loc_fp = hashlib.sha256(f"{m.rule_id}:{file}:{scope}:{line}:{col}:{occ_idx}".encode("utf-8")).hexdigest()[:16]
        return Finding(
            engine=self.name,
            title=title,
            file=file,
            line=line,
            cwe=m.cwe,
            severity=m.severity,
            description=desc,
            evidence=m.masked_line,
            fix_hint=hint,
            exploitability=m.exploit,
            extra={
                "rule": m.rule_id,
                "rule_title": m.title,
                "confidence": m.confidence,
                "fingerprint": loc_fp,
                "variable": m.variable,
                "masked_value": m.masked,
                "in_working_tree": in_tree,
                "in_history": in_hist,
                "first_seen": first,
                "history_occurrences": a.history,
                "locations": [{"file": f, "line": l} for f, l in a.tree],
                "is_test_file": a.is_test,
                "exploitability_basis": "heuristic (secret validity is not checked)",
            },
        )
