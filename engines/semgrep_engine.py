"""Semgrep rule-driven static analysis engine for SCIP.

Scans source code using semantic pattern rules (bundled default rules or user-provided
rulesets) to detect OWASP Top 10 vulnerabilities, framework misconfigurations,
insecure deserialization, and injection patterns.
"""
from __future__ import annotations
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.finding import Finding
from core.redact import redact_finding
from core.taxonomy import normalize_cwe
from engines.base import Engine, rel_path

_rel_path = rel_path

log = logging.getLogger("scip.semgrep")

DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "semgrep" / "default_rules.yaml"
TIMEOUT = 60

SEV_MAP = {
    "ERROR": 8.5,
    "WARNING": 5.5,
    "INFO": 2.5,
}

EXPLOIT_MAP = {
    "ERROR": 0.75,
    "WARNING": 0.40,
    "INFO": 0.15,
}


def _extract_cwe(metadata: Dict[str, Any]) -> Optional[str]:
    raw_cwe = metadata.get("cwe")
    if not raw_cwe:
        return None
    if isinstance(raw_cwe, list) and raw_cwe:
        target = str(raw_cwe[0])
    else:
        target = str(raw_cwe)
    return normalize_cwe(target)


def _clean_check_id(check_id: str) -> str:
    """Strip local path prefix from Semgrep check IDs (e.g. engines.rules.semgrep.scip...)."""
    m = re.search(r"(scip\.[A-Za-z0-9._-]+)", check_id)
    if m:
        return m.group(1)
    if "rules." in check_id:
        return check_id.split("rules.", 1)[-1]
    return check_id


def _read_source_snippet(file_path: Path, start_line: Optional[int], end_line: Optional[int]) -> str:
    """Read the snippet directly from the source file when Semgrep OSS redacts extra.lines."""
    if not start_line or not file_path.exists() or not file_path.is_file():
        return ""
    try:
        raw = file_path.read_text(encoding="utf-8-sig", errors="replace")
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        s = max(0, start_line - 1)
        e = min(len(lines), end_line or start_line)
        return "\n".join(lines[s:e]).strip()
    except OSError:
        return ""


class SemgrepEngine(Engine):
    name = "semgrep"

    def __init__(
        self,
        rules_path: Optional[str] = None,
        timeout: int = TIMEOUT,
        max_target_bytes: int = 1_000_000,
        exclude_dirs: Optional[List[str]] = None,
        include_suppressed: bool = False,
    ):
        if rules_path:
            p = Path(rules_path)
            self.rules_path = str(p.resolve()) if p.exists() else str(rules_path)
        elif DEFAULT_RULES.exists():
            self.rules_path = str(DEFAULT_RULES.resolve())
        else:
            self.rules_path = None
        self.timeout = timeout
        self.max_target_bytes = max_target_bytes
        self.exclude_dirs = exclude_dirs or [".git", "venv", ".venv", "node_modules", ".tox"]
        self.include_suppressed = include_suppressed
        self.stats: Dict[str, Any] = {}

    def is_available(self) -> bool:
        """Check if semgrep executable is installed and reachable."""
        return shutil.which("semgrep") is not None

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self.stats = {
            "engine": self.name,
            "target": str(root),
            "rules_used": str(self.rules_path),
            "findings_count": 0,
            "skipped": False,
            "errors": [],
        }

        if not root.exists():
            log.warning("Target path does not exist: %s", root)
            self.stats["errors"].append("Directory does not exist")
            return []

        if not self.is_available():
            log.warning("Semgrep CLI is not installed or not in PATH. Skipping Semgrep engine.")
            self.stats.update(skipped=True, note="Semgrep CLI not found in PATH")
            return []

        if not self.rules_path:
            log.warning("No Semgrep rules specified and default rules not found.")
            self.stats.update(skipped=True, note="No rules configuration found")
            return []

        cmd = [
            "semgrep",
            "scan",
            "--config",
            str(self.rules_path),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--max-target-bytes",
            str(self.max_target_bytes),
        ]
        if self.include_suppressed:
            cmd.append("--disable-nosem")

        for exc in self.exclude_dirs:
            cmd.extend(["--exclude", exc])

        # Use '--' to guard target path
        cmd.extend(["--", str(root)])

        log.info("Running Semgrep with config: %s", self.rules_path)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("Semgrep scan timed out after %ds on %s", self.timeout, root)
            self.stats["errors"].append(f"Timed out after {self.timeout}s")
            return []
        except Exception as e:
            log.warning("Failed to execute Semgrep: %s", e)
            self.stats["errors"].append(str(e))
            return []

        data = self._load_json(proc.stdout)
        if data is None:
            err = proc.stderr.strip()[:300] or f"exit code {proc.returncode}, no JSON"
            log.warning("Semgrep execution failed: %s", err)
            self.stats["errors"].append(err)
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

        raw_results = data.get("results", [])
        paths_scanned = data.get("paths", {}).get("scanned", [])
        self.stats.update(
            files_scanned=len(paths_scanned),
            rules_skipped=len(data.get("skipped_rules", [])),
        )

        # Capture Semgrep rule or file syntax errors into engine stats
        for err in data.get("errors", []):
            msg = err.get("message") or err.get("spans", [{}])[0].get("file") or str(err)
            self.stats["errors"].append(str(msg)[:200])

        findings: List[Finding] = []
        for r in raw_results:
            findings.append(self._make_finding(r, root))

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats["findings_count"] = len(findings)
        return findings

    def _make_finding(self, r: Dict[str, Any], root: Path) -> Finding:
        raw_check_id = r.get("check_id", "semgrep.rule")
        check_id = _clean_check_id(raw_check_id)
        short_id = check_id.split(".")[-1]

        extra = r.get("extra", {})
        message = (extra.get("message") or "Semgrep security finding").strip()
        metadata = extra.get("metadata", {})
        raw_sev = extra.get("severity", "WARNING").upper()

        severity = SEV_MAP.get(raw_sev, 5.0)
        exploitability = EXPLOIT_MAP.get(raw_sev, 0.4)

        cwe = _extract_cwe(metadata)

        raw_path = r.get("path", "")
        normalized_file = rel_path(raw_path, root)
        start = r.get("start", {})
        end = r.get("end", {})
        line = start.get("line")
        end_line = end.get("line") or line
        line_range = list(range(line, end_line + 1)) if line else []

        # First sentence splitting using regex
        sentences = re.split(r"\.\s+", message)
        first_sentence = sentences[0] if sentences and sentences[0] else check_id
        title = f"Semgrep {short_id}: {first_sentence}"

        # Fix hint
        fix_content = extra.get("fix") or metadata.get("fix")
        if fix_content:
            fix_hint = f"Suggested fix: {fix_content}"
        else:
            fix_hint = f"Review rule {check_id} and refactor code to remediate this issue."

        # Evidence: handle "requires login" redaction in Semgrep OSS
        raw_lines = extra.get("lines")
        if raw_lines and raw_lines != "requires login":
            evidence = raw_lines.strip()
        else:
            # Read snippet directly from file
            target_file = root / normalized_file
            evidence = _read_source_snippet(target_file, line, end.get("line"))

        # Fingerprint: drop placeholder "requires login"
        fingerprint = extra.get("fingerprint")
        if fingerprint == "requires login":
            fingerprint = None

        return redact_finding(Finding(
            engine=self.name,
            title=title,
            file=normalized_file,
            line=line,
            cwe=cwe,
            severity=severity,
            description=message,
            evidence=evidence,
            fix_hint=fix_hint,
            exploitability=exploitability,
            extra={
                "check_id": check_id,
                "rule_severity": raw_sev,
                "confidence": metadata.get("confidence", "MEDIUM"),
                "owasp": metadata.get("owasp"),
                "references": metadata.get("references", []),
                "fingerprint": fingerprint,
                "start": start,
                "end": end,
                "line_range": line_range,
            },
        ))
