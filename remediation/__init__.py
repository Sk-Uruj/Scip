"""Remediation: turn dependency findings into verified upgrade patches.

Pipeline:  plan (plan.py)  ->  apply to a COPY of the repo (apply.py)  ->  verify (verify.py)
The original repository is never modified. The result is a normal .patch file a human reviews and applies.
"""
