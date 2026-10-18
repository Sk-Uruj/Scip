"""Tests for taxonomy normalization and compatibility groups."""
import pytest
from core.taxonomy import (
    BANDIT_TO_CWE,
    CWE_DEFINITIONS,
    COMPATIBILITY_FAMILIES,
    normalize_cwe,
    is_compatible_cwe,
)


def test_bandit_to_cwe_mappings():
    """Verify that every Bandit test ID in BANDIT_TO_CWE maps to a valid canonical CWE."""
    assert len(BANDIT_TO_CWE) >= 60
    for test_id, cwe in BANDIT_TO_CWE.items():
        assert test_id.startswith("B"), f"Test ID {test_id} does not start with B"
        assert cwe.startswith("CWE-"), f"CWE {cwe} does not start with CWE-"
        assert normalize_cwe(None, test_id=test_id) == cwe


@pytest.mark.parametrize(
    "raw,test_id,expected",
    [
        ("CWE-502", None, "CWE-502"),
        ("cwe-89", None, "CWE-89"),
        (89, None, "CWE-89"),
        ("89", None, "CWE-89"),
        ("invalid", None, None),
        ("", None, None),
        (None, None, None),
        (None, "B104", "CWE-605"),
        (None, "B308", "CWE-79"),
        (None, "B310", "CWE-918"),
        (None, "B311", "CWE-330"),
        (None, "B609", "CWE-78"),
        (None, "B701", "CWE-79"),
        (None, "b506", "CWE-502"),
    ],
)
def test_normalize_cwe(raw, test_id, expected):
    assert normalize_cwe(raw, test_id=test_id) == expected


def test_cwe_definitions_coverage():
    """Verify that every mapped CWE in BANDIT_TO_CWE has a defined severity and description."""
    for test_id, cwe in BANDIT_TO_CWE.items():
        assert cwe in CWE_DEFINITIONS, f"CWE {cwe} (from {test_id}) is missing from CWE_DEFINITIONS"
        desc, sev = CWE_DEFINITIONS[cwe]
        assert isinstance(desc, str) and len(desc) > 0
        assert 1.0 <= sev <= 10.0


@pytest.mark.parametrize(
    "cwe1,cwe2,expected",
    [
        ("CWE-78", "CWE-78", True),
        ("CWE-78", "CWE-95", True),
        ("CWE-78", "CWE-94", True),
        ("CWE-327", "CWE-328", True),
        ("CWE-326", "CWE-327", True),
        ("CWE-259", "CWE-798", True),
        ("CWE-200", "CWE-605", True),
        ("CWE-605", "CWE-668", True),
        ("CWE-79", "CWE-116", True),
        ("CWE-78", "CWE-89", False),
        ("CWE-89", "CWE-79", False),
        ("CWE-502", "CWE-78", False),
        (None, "CWE-78", False),
        ("UNKNOWN", "CWE-78", False),
    ],
)
def test_is_compatible_cwe(cwe1, cwe2, expected):
    assert is_compatible_cwe(cwe1, cwe2) == expected
