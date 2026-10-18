"""Taxonomy and canonical vulnerability definitions.

Normalizes vulnerability identifiers (Bandit test IDs, Semgrep rule IDs,
OSV advisories, and CWE strings) into canonical CWE identifiers.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Set, Tuple

# Mapping of Bandit test IDs to canonical CWEs
BANDIT_TO_CWE: Dict[str, str] = {
    # B1xx: Miscellaneous & General
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-95",   # exec_used -> Eval Injection
    "B103": "CWE-276",  # set_bad_file_permissions
    "B104": "CWE-605",  # hardcoded_bind_all_interfaces
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B113": "CWE-400",  # request_without_timeout
    # B2xx: Web & Frameworks
    "B201": "CWE-489",  # flask_debug_true
    "B202": "CWE-22",   # tarfile_unsafe_members (Path Traversal)
    # B3xx: Blacklist Calls & Insecure Functions
    "B301": "CWE-502",  # pickle -> Deserialization
    "B302": "CWE-502",  # marshal -> Deserialization
    "B303": "CWE-327",  # md5/sha1 -> Broken Cryptographic Algorithm
    "B304": "CWE-327",  # ciphers (des, arc4)
    "B305": "CWE-327",  # cipher_modes (ecb)
    "B306": "CWE-377",  # mktemp_q -> Insecure Temporary File
    "B307": "CWE-95",   # eval -> Eval Injection
    "B308": "CWE-79",   # mark_safe -> Cross-site Scripting
    "B309": "CWE-295",  # httpsconnection -> Improper Certificate Validation
    "B310": "CWE-918",  # urllib_urlopen -> SSRF / URL scheme injection
    "B311": "CWE-330",  # random -> Insufficiently Random Values
    "B312": "CWE-319",  # telnetlib -> Cleartext Transmission
    "B313": "CWE-611",  # xml_bad_cElementTree -> XXE
    "B314": "CWE-611",  # xml_bad_ElementTree -> XXE
    "B315": "CWE-611",  # xml_bad_expatreader -> XXE
    "B316": "CWE-611",  # xml_bad_expatbuilder -> XXE
    "B317": "CWE-611",  # xml_bad_sax -> XXE
    "B318": "CWE-611",  # xml_bad_minidom -> XXE
    "B319": "CWE-611",  # xml_bad_pulldom -> XXE
    "B320": "CWE-611",  # xml_bad_etree -> XXE
    "B321": "CWE-319",  # ftplib -> Cleartext Transmission
    "B323": "CWE-295",  # unverified_context -> Improper Certificate Validation
    "B324": "CWE-327",  # hashlib_new_insecure_functions
    "B325": "CWE-377",  # tempnam -> Insecure Temporary File
    # B4xx: Blacklist Imports
    "B401": "CWE-319",  # import_telnetlib
    "B402": "CWE-319",  # import_ftplib
    "B403": "CWE-502",  # import_pickle
    "B404": "CWE-78",   # import_subprocess
    "B405": "CWE-611",  # import_xml_etree
    "B406": "CWE-611",  # import_xml_sax
    "B407": "CWE-611",  # import_xml_expat
    "B408": "CWE-611",  # import_xml_minidom
    "B409": "CWE-611",  # import_xml_pulldom
    "B410": "CWE-611",  # import_lxml
    "B411": "CWE-611",  # import_xmlrpc
    "B412": "CWE-284",  # import_httpoxy
    "B413": "CWE-327",  # import_pycrypto
    "B415": "CWE-319",  # import_pyghmi
    # B5xx: Cryptography & SSL/TLS Configuration
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-326",  # ssl_with_bad_version
    "B503": "CWE-326",  # ssl_with_bad_defaults
    "B504": "CWE-326",  # ssl_with_no_version
    "B505": "CWE-326",  # weak_cryptographic_key
    "B506": "CWE-502",  # yaml_load -> Deserialization
    "B507": "CWE-295",  # ssh_no_host_key_verification
    "B508": "CWE-319",  # snmp_insecure_version
    "B509": "CWE-326",  # snmp_weak_cryptography
    # B6xx: Command, Process & SQL Injection
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    "B610": "CWE-89",   # django_extra_used
    "B611": "CWE-89",   # django_rawsql_used
    "B612": "CWE-502",  # logging_config_insecure_listen
    "B613": "CWE-94",   # trojansource
    "B614": "CWE-502",  # pytorch_load
    "B615": "CWE-502",  # huggingface_unsafe_download
    # B7xx: Template Injection & XSS
    "B701": "CWE-79",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
    "B704": "CWE-79",   # markupsafe_markup_xss
}

# Canonical CWE Names and Default Severities
CWE_DEFINITIONS: Dict[str, Tuple[str, float]] = {
    "CWE-20": ("Improper Input Validation", 5.0),
    "CWE-22": ("Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", 7.5),
    "CWE-78": ("OS Command Injection", 9.0),
    "CWE-79": ("Cross-site Scripting (XSS)", 6.5),
    "CWE-89": ("SQL Injection", 9.0),
    "CWE-94": ("Improper Control of Generation of Code ('Code Injection')", 9.0),
    "CWE-95": ("Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", 9.0),
    "CWE-200": ("Exposure of Sensitive Information", 5.5),
    "CWE-259": ("Use of Hard-coded Password", 7.5),
    "CWE-276": ("Incorrect Default Permissions", 5.0),
    "CWE-284": ("Improper Access Control", 6.5),
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
    "CWE-605": ("Multiple Binds to the Same Port", 4.5),
    "CWE-611": ("Improper Restriction of XML External Entity Reference (XXE)", 8.0),
    "CWE-668": ("Exposure of Resource to Wrong Sphere", 5.0),
    "CWE-703": ("Improper Check or Handling of Exceptional Conditions", 3.5),
    "CWE-798": ("Use of Hard-coded Credentials", 8.5),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", 8.5),
}

# Vulnerability Family Compatibility Groups (narrowed to prevent cross-class false merges)
COMPATIBILITY_FAMILIES = [
    {"CWE-78", "CWE-94", "CWE-95"},          # Command, Code & Eval Injection
    {"CWE-326", "CWE-327", "CWE-328"},      # Cryptographic issues (weak algorithms, hashes & key lengths)
    {"CWE-259", "CWE-798"},                  # Hardcoded passwords & credentials (Bandit B105 & Secrets engine)
    {"CWE-200", "CWE-605", "CWE-668"},      # Information / interface exposure (B104 & network exposure)
    {"CWE-79", "CWE-116"},                   # Cross-site Scripting & Output Encoding
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
