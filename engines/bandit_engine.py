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


def _calculate_severity(issue_sev: str, issue_conf: str) -> float:
    base = SEV_MAP.get(issue_sev.upper(), 5.0)
    adjust = CONF_ADJUST.get(issue_conf.upper(), 0.0)
    return round(max(1.0, min(10.0, base + adjust)), 1)


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

        severity = _calculate_severity(issue_sev, issue_conf)

        # CWE Extraction using canonical taxonomy mapping
        cwe_data = r.get("issue_cwe") or {}
        raw_cwe_id = cwe_data.get("id")
        cwe_str = normalize_cwe(raw_cwe_id, test_id=test_id)

        # File & Line
        raw_filename = r.get("filename", "")
        normalized_file = rel_path(raw_filename, root)
        line = r.get("line_number")

        # Exploitability heuristic based on severity and confidence
        exploit_base = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}.get(issue_sev.upper(), 0.3)
        exploit_conf = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}.get(issue_conf.upper(), 0.7)
        exploitability = round(exploit_base * exploit_conf, 2)

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
