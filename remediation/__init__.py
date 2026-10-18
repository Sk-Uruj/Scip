"""Remediation: turn dependency and code findings into verified patches.

Pipeline:
  - Dependency: plan (plan.py) -> apply to a COPY (apply.py) -> verify (verify.py)
  - Code patterns: code_patcher (code_patcher.py) for automated rule-based fixes (B506, B303, B201, B306, B113, etc.)

The original repository is never modified directly.
"""
from .code_patcher import apply_code_patches, can_auto_patch, generate_file_patch, patch_line

__all__ = [
    "apply_code_patches",
    "can_auto_patch",
    "generate_file_patch",
    "patch_line",
]
