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
from typing import Any, Dict, List, Optional, Tuple

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

# Unified rule calibration table: (base_severity, base_exploitability)
# Systematically covers all 79 rules in core.taxonomy.BANDIT_TO_CWE.
BANDIT_RULE_CALIBRATION: Dict[str, Tuple[float, float]] = {
    # B1xx: General & Code Hygiene
    "B101": (2.0, 0.10),   # assert_used
    "B102": (8.5, 0.80),   # exec_used
    "B103": (4.5, 0.30),   # set_bad_file_permissions
    "B104": (4.5, 0.40),   # hardcoded_bind_all_interfaces
    "B105": (2.5, 0.30),   # hardcoded_password_string (Bandit regex noise level)
    "B106": (2.5, 0.30),   # hardcoded_password_funcarg
    "B107": (2.5, 0.30),   # hardcoded_password_default
    "B108": (4.0, 0.25),   # hardcoded_tmp_directory
    "B110": (2.0, 0.10),   # try_except_pass
    "B112": (2.0, 0.10),   # try_except_continue
    "B113": (3.5, 0.20),   # request_without_timeout

    # B2xx: Web & Frameworks
    "B201": (7.5, 0.65),   # flask_debug_true
    "B202": (7.0, 0.60),   # tarfile_unsafe_members

    # B3xx: Blacklist Calls & Insecure Functions
    "B301": (8.0, 0.70),   # pickle deserialization
    "B302": (8.0, 0.70),   # marshal deserialization
    "B303": (6.5, 0.30),   # md5/sha1 hash (calibrated for non-security checksums)
    "B304": (7.0, 0.45),   # ciphers (DES, ARC4)
    "B305": (6.5, 0.40),   # cipher_modes (ECB)
    "B306": (4.5, 0.30),   # mktemp_q
    "B307": (8.5, 0.80),   # eval
    "B308": (6.5, 0.55),   # django mark_safe (XSS)
    "B309": (6.5, 0.50),   # httpsconnection
    "B310": (7.0, 0.60),   # urllib_urlopen (SSRF)
    "B311": (3.5, 0.20),   # random pseudo-random generator
    "B312": (5.0, 0.40),   # telnetlib
    "B313": (7.5, 0.55),   # xml_bad_cElementTree (XXE)
    "B314": (7.5, 0.55),   # xml_bad_ElementTree (XXE)
    "B315": (7.5, 0.55),   # xml_bad_expatreader (XXE)
    "B316": (7.5, 0.55),   # xml_bad_expatbuilder (XXE)
    "B317": (7.5, 0.55),   # xml_bad_sax (XXE)
    "B318": (7.5, 0.55),   # xml_bad_minidom (XXE)
    "B319": (7.5, 0.55),   # xml_bad_pulldom (XXE)
    "B320": (7.5, 0.55),   # xml_bad_etree (XXE)
    "B321": (5.0, 0.40),   # ftplib
    "B323": (6.5, 0.50),   # unverified_context
    "B324": (6.5, 0.30),   # hashlib_new_insecure_functions
    "B325": (4.5, 0.30),   # tempnam

    # B4xx: Blacklist Imports (bare imports: low severity, strictly below call rules)
    "B401": (2.5, 0.10),   # import_telnetlib
    "B402": (2.5, 0.10),   # import_ftplib
    "B403": (2.5, 0.10),   # import_pickle
    "B404": (2.5, 0.10),   # import_subprocess
    "B405": (2.5, 0.10),   # import_xml_etree
    "B406": (2.5, 0.10),   # import_xml_sax
    "B407": (2.5, 0.10),   # import_xml_expat
    "B408": (2.5, 0.10),   # import_xml_minidom
    "B409": (2.5, 0.10),   # import_xml_pulldom
    "B410": (2.5, 0.10),   # import_lxml
    "B411": (2.5, 0.10),   # import_xmlrpc
    "B412": (2.5, 0.10),   # import_httpoxy
    "B413": (2.5, 0.10),   # import_pycrypto
    "B415": (2.5, 0.10),   # import_pyghmi

    # B5xx: Cryptography & SSL/TLS Configuration
    "B501": (6.5, 0.50),   # request_with_no_cert_validation
    "B502": (6.0, 0.40),   # ssl_with_bad_version
    "B503": (6.0, 0.40),   # ssl_with_bad_defaults
    "B504": (6.0, 0.40),   # ssl_with_no_version
    "B505": (6.0, 0.40),   # weak_cryptographic_key
    "B506": (8.0, 0.75),   # yaml_load (calibrated: pattern vs data flow)
    "B507": (6.5, 0.50),   # ssh_no_host_key_verification
    "B508": (4.5, 0.35),   # snmp_insecure_version
    "B509": (5.0, 0.35),   # snmp_weak_cryptography

    # B6xx: Command, Process & SQL Injection
    "B601": (7.5, 0.65),   # paramiko_calls
    "B602": (8.5, 0.75),   # subprocess_popen_with_shell_equals_true
    "B603": (3.0, 0.15),   # subprocess_without_shell_equals_true
    "B604": (8.0, 0.70),   # any_other_function_with_shell_equals_true
    "B605": (8.0, 0.70),   # start_process_with_a_shell
    "B606": (3.0, 0.15),   # start_process_no_shell
    "B607": (3.5, 0.20),   # start_process_with_partial_path
    "B608": (8.5, 0.75),   # hardcoded_sql_expressions
    "B609": (7.5, 0.65),   # linux_commands_wildcard_injection
    "B610": (8.5, 0.75),   # django_extra_used
    "B611": (8.5, 0.75),   # django_rawsql_used
    "B612": (7.0, 0.55),   # logging_config_insecure_listen (reachable port dependent)
    "B613": (6.0, 0.40),   # trojansource
    "B614": (8.0, 0.70),   # pytorch_load
    "B615": (5.5, 0.30),   # huggingface_unsafe_download (supply-chain risk)

    # B7xx: Template Injection & XSS
    "B701": (6.5, 0.55),   # jinja2_autoescape_false
    "B702": (6.5, 0.55),   # use_of_mako_templates
    "B703": (6.5, 0.55),   # django_mark_safe
    "B704": (6.5, 0.55),   # markupsafe_markup_xss
}

# Synchronized derived views guaranteeing key parity
RULE_SEVERITY_BASE: Dict[str, float] = {k: v[0] for k, v in BANDIT_RULE_CALIBRATION.items()}
RULE_EXPLOIT_BASE: Dict[str, float] = {k: v[1] for k, v in BANDIT_RULE_CALIBRATION.items()}

COMMON_FIX_HINTS: Dict[str, str] = {
    # B1xx: General & Hardcoded Credentials / Misc
    "B101": "Use explicit error handling or validation checks instead of assert in production code.",
    "B102": "Avoid exec(). Refactor code to use safe alternatives, dispatch tables, or ast.literal_eval().",
    "B103": "Avoid overly permissive file permissions (e.g. 0o777). Use restricted permissions like 0o600 or 0o700.",
    "B104": "Avoid binding to all interfaces (0.0.0.0). Bind explicitly to 127.0.0.1 or a specific internal IP.",
    "B105": "Store passwords and secrets in environment variables or a secrets manager, not hardcoded in source code.",
    "B106": "Pass credentials via environment variables or a secure vault instead of hardcoding in function arguments.",
    "B107": "Do not use hardcoded secret values as default parameter values. Use None and load from environment.",
    "B108": "Avoid hardcoded /tmp paths. Use tempfile.NamedTemporaryFile() or tempfile.mkdtemp().",
    "B110": "Avoid empty except: pass blocks. Log the exception or handle specific error types explicitly.",
    "B112": "Avoid try-except-continue blocks that silently ignore errors. Log the exception before continuing.",
    "B113": "Add a timeout parameter to requests call (e.g., requests.get(url, timeout=10)).",

    # B2xx: Web & Framework
    "B201": "Do not run Flask with debug=True in production. Set debug=False and use an environment variable.",
    "B202": "Extract tar files safely by validating member paths against directory traversal (or use filter='data' in Python 3.12+).",

    # B3xx: Crypto, Serialization & Input Injection
    "B301": "Pickle is insecure for untrusted inputs. Use json, protocol buffers, or cryptographic signing.",
    "B302": "Avoid marshal serialization for untrusted data. Use json or protobuf instead.",
    "B303": "Use a secure cryptographic hash (e.g. hashlib.sha256()) instead of MD5/SHA1.",
    "B304": "Avoid weak ciphers (e.g. DES, ARC4). Use AES-GCM or ChaCha20-Poly1305 from cryptography library.",
    "B305": "Avoid weak cipher modes. Use authenticated cipher modes like AES-GCM.",
    "B306": "Use tempfile.NamedTemporaryFile() or mkstemp() instead of deprecated, race-prone mktemp().",
    "B307": "Avoid eval(). Use ast.literal_eval() for parsing literals or refactor logic without dynamic evaluation.",
    "B308": "Avoid django.utils.safestring.mark_safe() on untrusted user input to prevent Cross-Site Scripting (XSS).",
    "B309": "Avoid HTTPSConnection without SSL certificate verification. Use requests or http.client with a verified SSLContext.",
    "B310": "Audit urllib.request.urlopen() URLs. Restrict allowed URL schemes to ('http', 'https') to prevent file:// and SSRF.",
    "B311": "Do not use random for security or cryptographic purposes. Use secrets module or os.urandom().",
    "B312": "Avoid telnetlib as Telnet transmits data in plaintext. Use paramiko or SSH/TLS-based protocols.",
    "B313": "xml.etree.cElementTree is vulnerable to XML attacks. Use defusedxml.ElementTree for parsing untrusted XML.",
    "B314": "xml.etree.ElementTree is vulnerable to XML attacks. Use defusedxml.ElementTree for untrusted XML.",
    "B315": "xml.parsers.expat expatreader is vulnerable to XML entity expansion. Use defusedxml.expatreader.",
    "B316": "xml.parsers.expat expatbuilder is vulnerable to XML attacks. Use defusedxml.expatbuilder.",
    "B317": "xml.sax is vulnerable to entity expansion and external entities. Use defusedxml.sax.",
    "B318": "xml.dom.minidom is vulnerable to entity expansion and XML attacks. Use defusedxml.minidom.",
    "B319": "xml.dom.pulldom is vulnerable to entity expansion and XML attacks. Use defusedxml.pulldom.",
    "B320": "lxml.etree is vulnerable to XML entity attacks. Use defusedxml.lxml or resolve_entities=False.",
    "B321": "ftplib transmits credentials and data in cleartext. Use SFTP (paramiko) or FTPS with TLS.",
    "B323": "Do not use ssl._create_unverified_context(). Use ssl.create_default_context() to enforce certificate validation.",
    "B324": "Specify usedforsecurity=False if hashing with MD5/SHA1 strictly for non-cryptographic checksums.",
    "B325": "tempnam and tmpnam are insecure and deprecated. Use tempfile.NamedTemporaryFile() instead.",

    # B4xx: Import Audits
    "B401": "Telnet is an insecure plaintext protocol. Replace telnetlib with SSH (paramiko) or TLS-encrypted connections.",
    "B402": "FTP is an insecure plaintext protocol. Replace ftplib with SFTP via paramiko or FTPS.",
    "B403": "pickle is vulnerable to arbitrary code execution during deserialization. Use json or protobuf for untrusted inputs.",
    "B404": "Audit subprocess usage. Ensure commands are executed without shell=True and with validated arguments.",
    "B405": "Standard xml.etree is vulnerable to XML entity attacks. Consider importing defusedxml.ElementTree.",
    "B406": "Standard xml.sax is vulnerable to XML entity attacks. Consider importing defusedxml.sax.",
    "B407": "Standard xml.parsers.expat is vulnerable to XML attacks. Consider importing defusedxml.expatbuilder.",
    "B408": "Standard xml.dom.minidom is vulnerable to XML attacks. Consider importing defusedxml.minidom.",
    "B409": "Standard xml.dom.pulldom is vulnerable to XML attacks. Consider importing defusedxml.pulldom.",
    "B410": "lxml can be vulnerable to XML external entity attacks. Ensure XMLParser has resolve_entities=False or use defusedxml.",
    "B411": "xmlrpclib is vulnerable to XML attacks and insecure communication. Use modern JSON-RPC over HTTPS.",
    "B412": "wsgiref server may be vulnerable to HTTPoxy attacks. Do not trust the HTTP_PROXY header in CGI/WSGI environments.",
    "B413": "pycrypto is unmaintained and contains known vulnerabilities. Migrate to the cryptography library.",
    "B415": "pyghmi may expose sensitive IPMI operations over plaintext. Verify secure TLS transport and credential management.",

    # B5xx: SSL / TLS / Cryptography
    "B501": "Do not set verify=False on HTTPS requests. Ensure valid certificates are trusted.",
    "B502": "Avoid deprecated SSL/TLS protocols (SSLv2, SSLv3, TLSv1, TLSv1.1). Use ssl.PROTOCOL_TLS_CLIENT with TLSv1.2+.",
    "B503": "Do not create SSL contexts without SNI and certificate verification. Use ssl.create_default_context().",
    "B504": "Do not disable certificate revocation checks. Ensure CRL/OCSP checking is properly configured if used.",
    "B505": "Weak cryptographic key size detected. Use RSA keys of at least 2048 bits or ECC with curves P-256+.",
    "B506": "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution.",
    "B507": "Do not disable SSH host key verification (AutoAddPolicy). Use RejectPolicy and manage known_hosts.",
    "B508": "SNMP v1 and v2c send credentials in plaintext. Upgrade to SNMPv3 with authPriv privacy.",
    "B509": "Weak SNMP encryption/authentication used. Use SHA for authentication and AES-128+ for privacy in SNMPv3.",

    # B6xx: Shell & SQL Injection
    "B601": "Avoid calling paramiko.SSHClient.exec_command() with unsanitized shell inputs. Validate parameters strictly.",
    "B602": "Avoid shell=True in subprocess calls. Pass arguments as a list and validate input.",
    "B603": "Ensure arguments passed to subprocess are strictly validated or use an allowlist.",
    "B604": "Function call with shell=True detected. Set shell=False and pass arguments as a list.",
    "B605": "Starting a process with a shell can lead to shell injection. Avoid os.system() and use subprocess.run(..., shell=False).",
    "B606": "Process started without shell. Ensure executable path and argument list are properly validated.",
    "B607": "Starting process with partial path is vulnerable to PATH manipulation. Use an absolute path or shutil.which().",
    "B608": "Use parameterized SQL queries with placeholders instead of string formatting or concatenation.",
    "B609": "Wildcard injection vulnerability in Linux command. Avoid using '*' with tar, chown, or chmod in shell calls.",
    "B610": "Django extra() is prone to SQL injection. Refactor query to use standard ORM methods (filter, annotate).",
    "B611": "Django RawSQL is prone to SQL injection. Use parameterized queries with params argument or standard ORM.",
    "B612": "logging.config.listen() can execute arbitrary code over the network. Bind to localhost or require authentication.",
    "B613": "Trojan Source bidirectional Unicode control characters detected. Remove hidden direction control characters.",
    "B614": "torch.load() uses pickle by default and can execute arbitrary code. Specify weights_only=True in torch.load().",
    "B615": "Hugging Face model download without revision pin or from untrusted repo. Pin revision commit SHA.",

    # B7xx: Template Injection & XSS
    "B701": "Jinja2 autoescape is disabled or set to False. Enable autoescape=True (or select_autoescape()) to prevent XSS.",
    "B702": "Mako templates do not autoescape by default. Apply ${val | h} escaping or enable default_filters=['h'].",
    "B703": "Django mark_safe() bypasses HTML escaping. Avoid calling mark_safe() on unescaped or user-controlled input.",
    "B704": "markupsafe.Markup() bypasses escaping and can introduce XSS. Use escape() before wrapping in Markup().",
}

# Structured remediation templates for auto-patching and high-value fixes (Step 9 Integration)
REMEDIATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # Top 5 Auto-Fixable Rules
    "B506": {
        "safe_alternative": "yaml.safe_load",
        "import_required": "yaml",
        "auto_fixable": True,
        "replacement_pattern": "yaml.safe_load({arg})",
        "description": "Replace unsafe yaml.load() with yaml.safe_load().",
    },
    "B303": {
        "safe_alternative": "hashlib.sha256",
        "import_required": "hashlib",
        "auto_fixable": True,
        "replacement_pattern": "hashlib.sha256({arg})",
        "description": "Replace weak MD5/SHA1 hash with hashlib.sha256().",
    },
    "B201": {
        "safe_alternative": "debug=False",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "app.run(..., debug=False)",
        "description": "Disable debug mode in Flask app.run().",
    },
    "B306": {
        "safe_alternative": "tempfile.NamedTemporaryFile",
        "import_required": "tempfile",
        "auto_fixable": True,
        "replacement_pattern": "tempfile.NamedTemporaryFile()",
        "description": "Replace insecure tempfile.mktemp() with tempfile.NamedTemporaryFile().",
    },
    "B113": {
        "safe_alternative": "timeout=10",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "requests.{method}(..., timeout=10)",
        "description": "Add explicit timeout parameter to HTTP requests call.",
    },

    # Additional high-value structured guidance
    "B102": {
        "safe_alternative": "ast.literal_eval",
        "import_required": "ast",
        "auto_fixable": False,
        "replacement_pattern": "ast.literal_eval({arg})",
        "description": "Refactor dynamic exec() to safe evaluation or dispatch table.",
    },
    "B307": {
        "safe_alternative": "ast.literal_eval",
        "import_required": "ast",
        "auto_fixable": False,
        "replacement_pattern": "ast.literal_eval({arg})",
        "description": "Replace eval() with ast.literal_eval() for literal evaluation.",
    },
    "B324": {
        "safe_alternative": "usedforsecurity=False",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "hashlib.new(..., usedforsecurity=False)",
        "description": "Specify usedforsecurity=False for non-cryptographic hashing.",
    },
    "B501": {
        "safe_alternative": "verify=True",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "requests.{method}(..., verify=True)",
        "description": "Enable TLS certificate verification on HTTPS request.",
    },
    "B602": {
        "safe_alternative": "shell=False",
        "import_required": "shlex",
        "auto_fixable": False,
        "replacement_pattern": "subprocess.run(shlex.split({cmd}), shell=False)",
        "description": "Pass arguments as a list and set shell=False.",
    },
    "B604": {
        "safe_alternative": "shell=False",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "func(..., shell=False)",
        "description": "Set shell=False in function call.",
    },
    "B614": {
        "safe_alternative": "weights_only=True",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "torch.load(..., weights_only=True)",
        "description": "Specify weights_only=True in torch.load().",
    },
    "B701": {
        "safe_alternative": "autoescape=True",
        "import_required": None,
        "auto_fixable": True,
        "replacement_pattern": "Environment(..., autoescape=True)",
        "description": "Enable autoescape in Jinja2 environment.",
    },
}


def get_remediation_metadata(test_id: Optional[str]) -> Dict[str, Any]:
    """Return structured remediation guidance for a Bandit test_id."""
    t_id = test_id.upper() if test_id else "UNKNOWN"
    if t_id in REMEDIATION_TEMPLATES:
        return dict(REMEDIATION_TEMPLATES[t_id])
    hint = COMMON_FIX_HINTS.get(
        t_id,
        f"Review Bandit rule {t_id} and refactor the code to eliminate this pattern.",
    )
    return {
        "safe_alternative": None,
        "import_required": None,
        "auto_fixable": False,
        "replacement_pattern": None,
        "description": hint,
    }


def patch_code_snippet(code: str, test_id: str) -> Optional[str]:
    """Generate an automated code fix for known auto-fixable Bandit rules.

    Returns the patched string if a transformation is applied, or None if no fix applies.
    """
    t_id = test_id.upper() if test_id else ""
    if not code or not t_id:
        return None

    patched = code
    if t_id == "B506":
        # yaml.load(...) -> yaml.safe_load(...)
        if "yaml.load" in patched:
            patched = re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", patched)
            patched = re.sub(r",\s*Loader\s*=\s*yaml\.[A-Za-z0-9_]+", "", patched)
    elif t_id == "B303":
        # hashlib.md5 / sha1 -> hashlib.sha256
        patched = re.sub(r"\bhashlib\.(?:md5|sha1)\s*\(", "hashlib.sha256(", patched)
        patched = re.sub(r"\b(?:Crypto\.Hash\.)?MD5\.new\s*\(", "Crypto.Hash.SHA256.new(", patched)
    elif t_id == "B201":
        # app.run(..., debug=True) -> app.run(..., debug=False)
        patched = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", patched)
    elif t_id == "B306":
        # tempfile.mktemp() -> tempfile.NamedTemporaryFile()
        patched = re.sub(r"\btempfile\.mktemp\s*\(", "tempfile.NamedTemporaryFile(", patched)
        patched = re.sub(r"(?<!tempfile\.)\bmktemp\s*\(", "tempfile.NamedTemporaryFile(", patched)
    elif t_id == "B113":
        # Add timeout=10 to requests calls missing a timeout
        if "timeout" not in patched:
            pattern = re.compile(
                r"\b((?:requests|session)\.(?:get|post|put|delete|patch|head|options|request))\((.*?)\)",
                re.DOTALL,
            )
            def _add_timeout(m: re.Match) -> str:
                call_name = m.group(1)
                args = m.group(2).strip()
                if not args:
                    return f"{call_name}(timeout=10)"
                return f"{call_name}({args}, timeout=10)"
            patched = pattern.sub(_add_timeout, patched)
    elif t_id == "B501":
        # verify=False -> verify=True
        patched = re.sub(r"\bverify\s*=\s*False\b", "verify=True", patched)
    elif t_id == "B604":
        # shell=True -> shell=False
        patched = re.sub(r"\bshell\s*=\s*True\b", "shell=False", patched)
    elif t_id == "B614":
        # torch.load(..., weights_only=True)
        if "weights_only" not in patched and "torch.load" in patched:
            patched = re.sub(r"\btorch\.load\((.*?)\)", r"torch.load(\1, weights_only=True)", patched)
    elif t_id == "B701":
        # autoescape=False -> autoescape=True
        patched = re.sub(r"\bautoescape\s*=\s*False\b", "autoescape=True", patched)

    return patched if patched != code else None

SKIP_DIRS = {".git", ".hg", "venv", ".venv", "node_modules", "__pycache__", ".tox"}


def _calculate_severity(
    issue_sev: str,
    issue_conf: str,
    test_id: Optional[str] = None,
) -> float:
    t_id = test_id.upper() if test_id else None
    if t_id and t_id in RULE_SEVERITY_BASE:
        base = RULE_SEVERITY_BASE[t_id]
    else:
        base = SEV_MAP.get((issue_sev or "").upper(), 5.0)
    adjust = CONF_ADJUST.get((issue_conf or "").upper(), 0.0)
    return round(max(1.0, min(10.0, base + adjust)), 1)


def _calculate_exploitability(
    issue_sev: str,
    issue_conf: str,
    test_id: Optional[str] = None,
) -> float:
    t_id = test_id.upper() if test_id else None
    if t_id and t_id in RULE_EXPLOIT_BASE:
        base = RULE_EXPLOIT_BASE[t_id]
    else:
        base = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}.get((issue_sev or "").upper(), 0.3)
    conf_mult = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}.get((issue_conf or "").upper(), 0.7)
    return round(max(0.05, min(1.0, base * conf_mult)), 2)


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

        severity = _calculate_severity(issue_sev, issue_conf, test_id=test_id)

        # CWE Extraction using canonical taxonomy mapping
        cwe_data = r.get("issue_cwe") or {}
        raw_cwe_id = cwe_data.get("id")
        cwe_str = normalize_cwe(raw_cwe_id, test_id=test_id)

        # File & Line
        raw_filename = r.get("filename", "")
        normalized_file = rel_path(raw_filename, root)
        line = r.get("line_number")

        # Exploitability heuristic based on rule calibration and confidence
        exploitability = _calculate_exploitability(issue_sev, issue_conf, test_id=test_id)

        # Fix hint & structured remediation metadata (Step 9 Integration)
        fix_hint = COMMON_FIX_HINTS.get(
            test_id,
            f"Review Bandit rule {test_id} ({r.get('more_info', '')}) and refactor the code to eliminate this pattern.",
        )
        remediation_meta = get_remediation_metadata(test_id)

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
                "remediation": remediation_meta,
            },
        ))
