"""Remediation: turn dependency and code findings into verified patches.

Pipeline:
  - Dependency: plan (plan.py) -> apply to a COPY (apply.py) -> verify (verify.py)
  - Code patterns: code_patcher (code_patcher.py) for AST-verified rule-based fixes

The original repository is never modified directly.
"""
from .code_patcher import (
    RULE_PATCHERS,
    PatchStatus,
    PatchTier,
    apply_code_patches,
    can_auto_patch,
    generate_file_patch,
    patch_file_content,
    patch_single_snippet,
)

__all__ = [
    "RULE_PATCHERS",
    "PatchStatus",
    "PatchTier",
    "apply_code_patches",
    "can_auto_patch",
    "generate_file_patch",
    "patch_file_content",
    "patch_single_snippet",
]
