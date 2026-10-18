"""Evaluation harness: measures how good SCIP's findings and ranking actually are.

Workflow (see docs/EVALUATION.md):
    1. scan a repo            python -m core.pipeline test_repos/vulpy --offline -o scan.json
    2. make a label template  python -m evaluation.run template --scan scan.json --labels evaluation/labels/vulpy.yaml
    3. humans fill `verdict`  TP (real), FP (false alarm) or UNSURE
    4. evaluate               python -m evaluation.run evaluate --scan scan.json --labels evaluation/labels/vulpy.yaml
"""
