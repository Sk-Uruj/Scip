"""Taxonomy and canonical vulnerability definitions.

Normalizes vulnerability identifiers (Bandit test IDs, Semgrep rule IDs,
OSV advisories, and CWE strings) into canonical CWE identifiers.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Set, Tuple

# Mapping of Bandit test IDs to canonical CWEs
BANDIT_TO_CWE: Dict[str, str] = {
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-95",   # exec_used -> Eval Injection (CWE-95)
    "B103": "CWE-276",  # set_bad_file_permissions
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B113": "CWE-400",  # request_without_timeout
    "B201": "CWE-489",  # flask_debug_true
    "B301": "CWE-502",  # pickle -> Deserialization
    "B302": "CWE-502",  # marshal -> Deserialization
    "B303": "CWE-327",  # md5/sha1
    "B304": "CWE-327",  # ciphers (des, arc4)
    "B305": "CWE-327",  # cipher_modes (ecb)
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-95",   # eval -> Eval Injection (CWE-95)
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatreader
    "B316": "CWE-611",  # xml_bad_expatbuilder
    "B317": "CWE-611",  # xml_bad_sax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree
    "B324": "CWE-327",  # hashlib_new_insecure_functions
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B506": "CWE-502",  # yaml_load -> Deserialization (CWE-502)
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
}

# Canonical CWE Names and Default Severities
CWE_DEFINITIONS: Dict[str, Tuple[str, float]] = {
    "CWE-20": ("Improper Input Validation", 5.0),
    "CWE-78": ("OS Command Injection", 9.0),
    "CWE-79": ("Cross-site Scripting (XSS)", 6.5),
    "CWE-89": ("SQL Injection", 9.0),
    "CWE-95": ("Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", 9.0),
    "CWE-200": ("Exposure of Sensitive Information", 5.5),
    "CWE-259": ("Use of Hard-coded Password", 7.5),
    "CWE-276": ("Incorrect Default Permissions", 5.0),
    "CWE-295": ("Improper Certificate Validation", 6.5),
    "CWE-319": ("Cleartext Transmission of Sensitive Information", 5.0),
    "CWE-326": ("Inadequate Encryption Strength", 6.0),
    "CWE-327": ("Use of a Broken or Risky Cryptographic Algorithm", 7.5),
    "CWE-328": ("Use of Weak Hash", 7.0),
    "CWE-330": ("Use of Insufficiently Random Values", 6.5),
    "CWE-377": ("Insecure Temporary File", 5.5),
    "CWE-400": ("Uncontrolled Resource Consumption", 4.5),
    "CWE-489": ("Active Debug Code", 5.0),
    "CWE-502": ("Deserialization of Untrusted Data", 8.5),
    "CWE-611": ("Improper Restriction of XML External Entity Reference (XXE)", 8.0),
    "CWE-703": ("Improper Check or Handling of Exceptional Conditions", 3.5),
    "CWE-798": ("Use of Hard-coded Credentials", 8.5),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", 8.5),
}

# Vulnerability Family Compatibility Groups (narrowed to prevent cross-class false merges)
COMPATIBILITY_FAMILIES = [
    {"CWE-78", "CWE-95"},                    # Command & Eval Injection (B102, B307, B602 & Semgrep injection)
    {"CWE-326", "CWE-327", "CWE-328"},      # Cryptographic issues (weak algorithms, hashes & key lengths)
    {"CWE-259", "CWE-798"},                  # Hardcoded passwords & credentials (Bandit B105 & Secrets engine)
]


def normalize_cwe(raw: Optional[str | int], test_id: Optional[str] = None) -> Optional[str]:
    """Normalize a raw CWE identifier string or Bandit test ID to canonical format (e.g. 'CWE-502')."""
    if test_id and test_id.upper() in BANDIT_TO_CWE:
        return BANDIT_TO_CWE[test_id.upper()]

    if not raw:
        return None

    target = str(raw).strip()
    m = re.search(r"CWE-(\d+)", target, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"

    # If raw is a plain integer e.g. 502 or "502"
    if target.isdigit():
        return f"CWE-{target}"

    return None


def is_compatible_cwe(cwe1: Optional[str], cwe2: Optional[str]) -> bool:
    """Check if two CWEs represent the same or closely related vulnerability class."""
    if not cwe1 or not cwe2:
        return False
    norm1, norm2 = normalize_cwe(cwe1), normalize_cwe(cwe2)
    # Both must be recognized canonical CWEs; do not merge unrecognized/junk CWEs
    if not norm1 or not norm2:
        return False
    if norm1 == norm2:
        return True

    for family in COMPATIBILITY_FAMILIES:
        if norm1 in family and norm2 in family:
            return True

    return False
