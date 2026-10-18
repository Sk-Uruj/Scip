"""Bandit static security analysis engine for Python.

Scans Python code for common security issues (AST-based analysis), such as
insecure cryptography, unsafe deserialization (yaml/pickle), command injection,
and dangerous built-ins.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.finding import Finding
from core.redact import redact_finding
from core.taxonomy import normalize_cwe
from engines.base import Engine, rel_path

_rel_path = rel_path

log = logging.getLogger("scip.bandit")

DEFAULT_CONFIG = Path(__file__).resolve().parent / "configs" / "bandit_default.yaml"
TIMEOUT = 60

# Severity and confidence multipliers for composite 0-10 score
SEV_MAP = {"HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.5}
CONF_ADJUST = {"HIGH": 0.5, "MEDIUM": 0.0, "LOW": -0.5}

# Calibrated vulnerability base severities (1.0 - 10.0 scale)
RULE_SEVERITY_BASE: Dict[str, float] = {
    # RCE & Eval / Command Injection (Critical impact 8.8 - 9.5)
    "B102": 9.2,  # exec_used
    "B307": 9.2,  # eval
    "B506": 9.0,  # yaml_load (arbitrary object creation / RCE)
    "B602": 9.0,  # subprocess shell=True
    "B605": 8.8,  # start_process_with_a_shell
    "B609": 8.5,  # wildcard injection
    "B601": 8.5,  # paramiko calls
    "B612": 9.0,  # logging listen pickle RCE
    "B614": 8.8,  # pytorch_load weights RCE
    "B615": 8.8,  # huggingface unsafe download
    "B301": 8.5,  # pickle deserialization
    "B302": 8.5,  # marshal deserialization
    "B403": 7.5,  # import pickle
    "B404": 7.5,  # import subprocess
    # Passwords & Hardcoded Secrets (2.5 base matching Bandit LOW severity)
    "B105": 2.5, "B106": 2.5, "B107": 2.5,
    # SQL Injection (8.5 base)
    "B608": 8.5, "B610": 8.5, "B611": 8.5,
    # XXE (8.0 base)
    "B313": 8.0, "B314": 8.0, "B315": 8.0, "B316": 8.0,
    "B317": 8.0, "B318": 8.0, "B319": 8.0, "B320": 8.0,
    # Dangerous Web Settings & Path Traversal (6.8 - 7.5)
    "B201": 7.5,  # flask debug=True (Werkzeug debugger console)
    "B202": 7.5,  # tarfile path traversal
    "B308": 6.8,  # django mark_safe (XSS)
    "B701": 6.8,  # jinja2 autoescape false (XSS)
    "B702": 6.8,  # mako templates (XSS)
    "B703": 6.8,  # django mark_safe (XSS)
    "B704": 6.8,  # markupsafe markup XSS
    "B310": 7.5,  # urllib urlopen SSRF / file scheme
    # Broken Cryptography & Insecure Hashes (6.5 - 8.0)
    "B303": 8.0,  # md5 / sha1 (High base)
    "B324": 7.5,  # hashlib insecure functions
    "B304": 7.5,  # weak ciphers (DES, ARC4)
    "B305": 6.5,  # weak cipher mode (ECB)
    "B501": 6.5,  # verify=False
    "B502": 6.5, "B503": 6.5, "B504": 6.5, "B505": 6.5,
    "B309": 6.5, "B323": 6.5, "B507": 6.5,
    # Network Bindings, Cleartext & Weak Randomness (4.0 - 5.5)
    "B104": 4.5,  # bind 0.0.0.0
    "B311": 4.0,  # pseudo-random generator
    "B312": 5.5,  # telnetlib
    "B321": 5.5,  # ftplib
    "B508": 5.0,  # snmp insecure version
    # Temporary files & race conditions (4.5 - 5.5)
    "B108": 4.5,  # hardcoded tmp directory
    "B306": 5.0,  # mktemp race condition
    "B325": 5.0,  # tempnam race condition
    "B103": 5.0,  # bad file permissions
    # Hygiene & Timeouts (2.5 - 4.0)
    "B113": 4.0,  # request without timeout
    "B101": 2.5,  # assert used
    "B110": 2.5,  # try_except_pass
    "B112": 2.5,  # try_except_continue
    "B603": 3.0,  # subprocess without shell=True
    "B606": 3.0,  # process no shell
    "B607": 3.5,  # partial path
}

# Calibrated vulnerability exploitability baseline (0.05 - 1.0 scale)
RULE_EXPLOIT_BASE: Dict[str, float] = {
    # RCE / Code Execution (0.80 - 0.88)
    "B102": 0.88,  # exec
    "B307": 0.88,  # eval
    "B506": 0.85,  # yaml.load
    "B602": 0.85,  # subprocess shell=True
    "B605": 0.80,  # system shell
    "B609": 0.75,  # wildcard injection
    "B301": 0.80,  # pickle
    "B302": 0.80,  # marshal
    "B612": 0.85,  # logging listen
    "B614": 0.80,  # pytorch load
    "B615": 0.80,  # huggingface download
    # SQL Injection (0.80)
    "B608": 0.80, "B610": 0.80, "B611": 0.80,
    # Debuggers & Web Configuration (0.65 - 0.70)
    "B201": 0.70,  # flask debug=True
    "B202": 0.65,  # tarfile path traversal
    "B308": 0.60, "B701": 0.60, "B702": 0.60, "B703": 0.60, "B704": 0.60,  # XSS
    "B310": 0.65,  # SSRF
    # Secrets & Hardcoded Passwords (0.60)
    "B105": 0.60, "B106": 0.60, "B107": 0.60,
    # XXE (0.55)
    "B313": 0.55, "B314": 0.55, "B315": 0.55, "B316": 0.55,
    "B317": 0.55, "B318": 0.55, "B319": 0.55, "B320": 0.55,
    # Network & Cleartext (0.40 - 0.50)
    "B104": 0.45,  # 0.0.0.0 bind
    "B312": 0.50, "B321": 0.50, "B508": 0.45,
    # Broken Crypto & Hashes (0.35 - 0.45)
    "B303": 0.35, "B324": 0.35,  # md5/sha1
    "B304": 0.45, "B305": 0.40,
    "B501": 0.50, "B502": 0.45, "B503": 0.45, "B504": 0.45, "B505": 0.45,
    # Temp files & Hygiene (0.20 - 0.30)
    "B108": 0.30, "B306": 0.35, "B325": 0.35,
    "B311": 0.20,  # pseudo-random
    "B113": 0.25,  # timeout
    "B101": 0.10, "B110": 0.10, "B112": 0.10,
    "B603": 0.15, "B606": 0.15, "B607": 0.20,
}

COMMON_FIX_HINTS: Dict[str, str] = {
    "B506": "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution.",
    "B301": "Pickle is insecure for untrusted inputs. Use json, protocol buffers, or cryptographic signing.",
    "B303": "Use a secure cryptographic hash (e.g. hashlib.sha256()) instead of MD5/SHA1.",
    "B304": "Avoid weak ciphers (e.g. DES, ARC4). Use AES-GCM or ChaCha20-Poly1305 from cryptography library.",
    "B305": "Avoid weak cipher modes. Use authenticated cipher modes like AES-GCM.",
    "B113": "Add a timeout parameter to requests call (e.g., requests.get(url, timeout=10)).",
    "B501": "Do not set verify=False on HTTPS requests. Ensure valid certificates are trusted.",
    "B602": "Avoid shell=True in subprocess calls. Pass arguments as a list and validate input.",
    "B603": "Ensure arguments passed to subprocess are strictly validated or use an allowlist.",
    "B608": "Use parameterized SQL queries with placeholders instead of string formatting or concatenation.",
    "B324": "Specify usedforsecurity=False if hashing with MD5/SHA1 strictly for non-cryptographic checksums.",
    "B306": "Use tempfile.NamedTemporaryFile() or mkstemp() instead of deprecated, race-prone mktemp().",
}

SKIP_DIRS = {".git", ".hg", "venv", ".venv", "node_modules", "__pycache__", ".tox"}


def _calculate_severity(
    issue_sev: str,
    issue_conf: str,
    test_id: Optional[str] = None,
) -> float:
    if test_id and test_id.upper() in RULE_SEVERITY_BASE:
        base = RULE_SEVERITY_BASE[test_id.upper()]
    else:
        base = SEV_MAP.get(issue_sev.upper(), 5.0)
    adjust = CONF_ADJUST.get(issue_conf.upper(), 0.0)
    return round(max(1.0, min(10.0, base + adjust)), 1)


def _calculate_exploitability(
    issue_sev: str,
    issue_conf: str,
    test_id: Optional[str] = None,
) -> float:
    if test_id and test_id.upper() in RULE_EXPLOIT_BASE:
        base = RULE_EXPLOIT_BASE[test_id.upper()]
    else:
        base = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}.get(issue_sev.upper(), 0.3)
    conf_mult = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}.get(issue_conf.upper(), 0.7)
    return round(max(0.05, min(1.0, base * conf_mult)), 2)


class BanditEngine(Engine):
    name = "bandit"

    def __init__(
        self,
        config_file: Optional[str] = None,
        tests: Optional[List[str]] = None,
        skips: Optional[List[str]] = None,
        severity_min: Optional[str] = None,
        confidence_min: Optional[str] = None,
        timeout: int = TIMEOUT,
        include_suppressed: bool = False,
    ):
        if config_file:
            self.config_file = str(Path(config_file).resolve())
        elif DEFAULT_CONFIG.exists():
            self.config_file = str(DEFAULT_CONFIG.resolve())
        else:
            self.config_file = None
        self.tests = tests
        self.skips = skips
        self.severity_min = severity_min
        self.confidence_min = confidence_min
        self.timeout = timeout
        self.include_suppressed = include_suppressed
        self.stats: Dict[str, Any] = {}

    def is_available(self) -> bool:
        """Check if Bandit is installed in current Python environment or on PATH."""
        return importlib.util.find_spec("bandit") is not None or shutil.which("bandit") is not None

    def _has_python_files(self, root: Path) -> bool:
        for p in root.rglob("*.py"):
            try:
                rel_parts = p.relative_to(root).parts
            except ValueError:
                rel_parts = p.parts
            if not any(part in SKIP_DIRS for part in rel_parts):
                return True
        return False

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self.stats = {
            "engine": self.name,
            "target": str(root),
            "findings_count": 0,
            "skipped": False,
            "errors": [],
        }

        if not root.exists():
            log.warning("Target directory does not exist: %s", root)
            self.stats["errors"].append("Directory does not exist")
            return []

        if not self.is_available():
            log.warning("Bandit is not installed in the environment. Skipping Bandit engine.")
            self.stats.update(skipped=True, note="Bandit package not found")
            return []

        # Fast check if there are any non-ignored Python files to scan
        if not self._has_python_files(root):
            log.info("No Python files found under %s", root)
            self.stats["files_scanned"] = 0
            return []

        # Run via current Python environment module if available, otherwise fallback to PATH executable
        if importlib.util.find_spec("bandit") is not None:
            cmd = [sys.executable, "-m", "bandit", "-r", "-f", "json"]
        elif shutil.which("bandit") is not None:
            cmd = ["bandit", "-r", "-f", "json"]
        else:
            self.stats.update(skipped=True, note="Bandit executable not found")
            return []

        if self.config_file and os.path.exists(self.config_file):
            cmd.extend(["-c", str(self.config_file)])
        if self.tests:
            cmd.extend(["-t", ",".join(self.tests)])
        if self.skips:
            cmd.extend(["-s", ",".join(self.skips)])
            self.stats["skipped_rules"] = list(self.skips)
        if self.severity_min:
            flag = {"low": "-l", "medium": "-ll", "high": "-lll"}.get(self.severity_min.lower())
            if flag:
                cmd.append(flag)
        if self.confidence_min:
            flag = {"low": "-i", "medium": "-ii", "high": "-iii"}.get(self.confidence_min.lower())
            if flag:
                cmd.append(flag)
        if self.include_suppressed:
            cmd.append("--ignore-nosec")

        # Pass target path with '--' to prevent flag injection.
        # Run with cwd=root and relative target '.' to prevent parent directories (e.g. /env/)
        # from inadvertently matching exclude_dirs substrings.
        cmd.extend(["--", "."])

        log.info("Running Bandit: %s (cwd=%s)", " ".join(cmd), root)
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(root),
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("Bandit scan timed out after %ds on %s", self.timeout, root)
            self.stats["errors"].append(f"Timed out after {self.timeout}s")
            return []
        except Exception as e:
            log.warning("Failed to invoke Bandit: %s", e)
            self.stats["errors"].append(str(e))
            return []

        data = self._load_json(proc.stdout)
        if data is None:
            err_msg = proc.stderr.strip()[:300] or f"exit code {proc.returncode}, no JSON"
            log.warning("Bandit execution failed: %s", err_msg)
            self.stats["errors"].append(err_msg)
            return []

        return self._parse_output(data, root)

    def _parse_output(self, data_or_stdout: Any, root: Path) -> List[Finding]:
        if isinstance(data_or_stdout, str):
            data = self._load_json(data_or_stdout)
            if data is None:
                return []
        elif isinstance(data_or_stdout, dict):
            data = data_or_stdout
        else:
            return []

        metrics = data.get("metrics", {})
        totals = metrics.get("_totals", {})
        self.stats.update(
            files_scanned=len(metrics) - 1 if "_totals" in metrics else len(metrics),
            loc=totals.get("loc", 0),
            nosec=totals.get("nosec", 0),
        )

        # Capture Bandit file/syntax errors into engine stats
        for err in data.get("errors", []):
            filename = err.get("filename", "unknown")
            reason = err.get("reason", "error")
            self.stats["errors"].append(f"{filename}: {reason}"[:200])

        results = data.get("results", [])
        findings: List[Finding] = []

        for r in results:
            findings.append(self._make_finding(r, root))

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats["findings_count"] = len(findings)
        return findings

    def _make_finding(self, r: Dict[str, Any], root: Path) -> Finding:
        test_id = r.get("test_id", "UNKNOWN")
        test_name = r.get("test_name", "")
        raw_text = (r.get("issue_text") or "").strip()
        # Sentence splitting using regex instead of naive '.'
        sentences = re.split(r"\.\s+", raw_text)
        summary = sentences[0] if sentences and sentences[0] else test_name
        issue_sev = r.get("issue_severity", "MEDIUM")
        issue_conf = r.get("issue_confidence", "MEDIUM")

        severity = _calculate_severity(issue_sev, issue_conf, test_id=test_id)

        # CWE Extraction using canonical taxonomy mapping
        cwe_data = r.get("issue_cwe") or {}
        raw_cwe_id = cwe_data.get("id")
        cwe_str = normalize_cwe(raw_cwe_id, test_id=test_id)

        # File & Line
        raw_filename = r.get("filename", "")
        normalized_file = rel_path(raw_filename, root)
        line = r.get("line_number")

        # Exploitability heuristic based on rule calibration and confidence
        exploitability = _calculate_exploitability(issue_sev, issue_conf, test_id=test_id)

        # Fix hint
        fix_hint = COMMON_FIX_HINTS.get(
            test_id,
            f"Review Bandit rule {test_id} ({r.get('more_info', '')}) and refactor the code to eliminate this pattern.",
        )

        # Evidence
        code_snippet = (r.get("code") or "").strip()

        return redact_finding(Finding(
            engine=self.name,
            title=f"Bandit {test_id}: {summary}",
            file=normalized_file,
            line=line,
            cwe=cwe_str,
            severity=severity,
            description=raw_text,
            evidence=code_snippet,
            fix_hint=fix_hint,
            exploitability=exploitability,
            extra={
                "test_id": test_id,
                "test_name": test_name,
                "issue_severity": issue_sev,
                "issue_confidence": issue_conf,
                "line_range": r.get("line_range", []),
                "col_offset": r.get("col_offset"),
                "end_col_offset": r.get("end_col_offset"),
                "more_info": r.get("more_info", ""),
            },
        ))
