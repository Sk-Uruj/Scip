import functools
import subprocess
from pathlib import Path
from typing import List, Dict
from core.finding import Finding
from engines.base import Engine


@functools.lru_cache(maxsize=32)
def get_git_churn(repo_path: str) -> Dict[str, int]:
    try:
        resolved_path = str(Path(repo_path).resolve())
        cmd = ["git", "log", "--name-only", "--format="]
        output = subprocess.check_output(cmd, cwd=resolved_path, text=True, stderr=subprocess.DEVNULL)
        
        churn_counts: Dict[str, int] = {}
        for line in output.splitlines():
            line = line.strip()
            if line:
                # Standardize paths to use forward slashes
                normalized_path = line.replace('\\', '/')
                churn_counts[normalized_path] = churn_counts.get(normalized_path, 0) + 1
                
        return churn_counts
    except Exception:
        return {}


def normalize_churn(churn_counts: Dict[str, int]) -> Dict[str, float]:
    if not churn_counts:
        return {}
    
    max_churn = max(churn_counts.values())
    if max_churn == 0:
        return {k: 0.0 for k in churn_counts}
        
    return {k: v / max_churn for k, v in churn_counts.items()}


class ChurnEngine(Engine):
    name = "churn"

    def scan(self, repo_path: str) -> List[Finding]:
        churn_counts = get_git_churn(repo_path)
        normalized = normalize_churn(churn_counts)
        
        findings = []
        for file_path, churn_val in normalized.items():
            if churn_val >= 0.9:
                findings.append(Finding(
                    engine=self.name,
                    title="High Code Churn",
                    file=file_path,
                    severity=3.0,
                    description=f"File is modified very frequently (normalized churn score: {churn_val:.2f}). This often correlates with a higher defect rate.",
                    churn=churn_val,
                ))
                
        return findings
