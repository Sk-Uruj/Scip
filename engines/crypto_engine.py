"""Crypto and network misuse engine (Step 4).

AST-based detection of cryptographic weaknesses and insecure network configurations
in Python source files without third-party dependencies:
  * Weak hash functions: MD5, SHA-1 (with usedforsecurity=False exception)
  * Insecure PRNG for credentials/tokens: random module used for security-sensitive values
  * Broken / weak ciphers: DES, 3DES, RC4, Blowfish
  * Insecure cipher modes: Electronic Codebook (ECB)
  * Static / predictable IVs or nonces
  * Weak asymmetric key lengths (< 2048 bits for RSA/DSA)
  * Insecure TLS / network misuse: verify=False, unverified SSL contexts, deprecated protocols
"""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.finding import Finding
from engines.base import Engine, rel_path

log = logging.getLogger("scip.crypto")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "venv", ".venv", "env", "node_modules", "__pycache__",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".idea", ".vscode",
}

# Variable name patterns suggesting a security-sensitive credential or token
_SECURITY_NAME_KEYWORDS = (
    "token", "secret", "password", "passwd", "pwd", "key", "auth", "session",
    "csrf", "nonce", "salt", "api_key", "apikey", "credential"
)


def _is_security_sensitive_name(name: str) -> bool:
    low = name.lower().replace("-", "_")
    return any(k in low for k in _SECURITY_NAME_KEYWORDS)


def _get_call_func_name(node: ast.AST) -> str:
    """Extract dotted name representation of a function call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _get_call_func_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _get_constant_val(node: Optional[ast.AST]) -> Any:
    """Helper to safely extract constant values."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    return getattr(node, "value", None)


class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        # alias -> canonical module or qualified name
        self.imports: Dict[str, str] = {}
        # variable_name -> literal constant (for scope-local constant tracking)
        self.local_constants: Dict[str, Any] = {}

    def _get_evidence(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:160]
        return ""

    def _canonical_name(self, raw_name: str) -> str:
        """Resolve aliased names using collected imports."""
        if not raw_name:
            return ""
        parts = raw_name.split(".")
        root = parts[0]
        if root in self.imports:
            resolved_root = self.imports[root]
            if len(parts) > 1:
                return f"{resolved_root}.{'.'.join(parts[1:])}"
            return resolved_root
        return raw_name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imports[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            target = f"{mod}.{alias.name}" if mod else alias.name
            asname = alias.asname or alias.name
            self.imports[asname] = target
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Track literal assignments for IV / key checking
        val = _get_constant_val(node.value)
        if val is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.local_constants[target.id] = val

        # Check PRNG assignments to security sensitive names: token = random.randint(...)
        if isinstance(node.value, ast.Call):
            call_name = self._canonical_name(_get_call_func_name(node.value.func))
            if any(call_name.startswith(p) for p in (
                "random.random", "random.randint", "random.choice", "random.choices",
                "random.randrange", "random.sample", "random.getrandbits"
            )):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _is_security_sensitive_name(target.id):
                        self.findings.append(Finding(
                            engine="crypto",
                            title=f"Insecure PRNG used for security-sensitive variable '{target.id}'",
                            file=self.file_path,
                            line=node.lineno,
                            cwe="CWE-338",
                            severity=6.5,
                            description=(
                                f"Standard pseudo-random number generator ({call_name}) used to generate "
                                f"'{target.id}'. Standard PRNGs are predictable and insecure for cryptography/tokens."
                            ),
                            evidence=self._get_evidence(node),
                            fix_hint="Use secrets module (e.g. secrets.token_hex(), secrets.token_urlsafe()) or os.urandom().",
                            exploitability=0.5,
                            extra={"rule": "insecure-prng", "variable": target.id, "call": call_name},
                        ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._canonical_name(_get_call_func_name(node.func))

        # 1. Weak Hash Algorithms (MD5, SHA1) - CWE-328
        self._check_weak_hashes(node, func_name)

        # 2. Insecure Ciphers & Modes (DES, 3DES, RC4, ECB mode) - CWE-327
        self._check_ciphers_and_modes(node, func_name)

        # 3. Weak Key Lengths (< 2048 bits) - CWE-326
        self._check_key_lengths(node, func_name)

        # 4. Insecure TLS / Network Misuse - CWE-295, CWE-319
        self._check_network_misuse(node, func_name)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Check deprecated SSL protocol versions: ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_TLSv1, etc.
        attr_name = self._canonical_name(_get_call_func_name(node))
        if any(attr_name.startswith(p) for p in (
            "ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_TLSv1",
            "ssl.PROTOCOL_TLSv1_1", "ssl.TLSVersion.TLSv1", "ssl.TLSVersion.TLSv1_1"
        )):
            self.findings.append(Finding(
                engine="crypto",
                title=f"Deprecated or insecure TLS/SSL protocol version: {node.attr}",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-327",
                severity=7.5,
                description=(
                    f"Use of deprecated SSL/TLS protocol ({node.attr}). Legacy protocols are vulnerable to "
                    "POODLE, BEAST, and eavesdropping attacks."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Enforce TLS 1.2 or TLS 1.3 minimum (e.g. ssl.PROTOCOL_TLS_CLIENT with TLSv1_2 minimum).",
                exploitability=0.6,
                extra={"rule": "insecure-tls-version", "protocol": node.attr},
            ))

        # Check ECB mode attribute access: AES.MODE_ECB, DES.MODE_ECB
        if node.attr == "MODE_ECB":
            self.findings.append(Finding(
                engine="crypto",
                title="Use of insecure Electronic Codebook (ECB) cipher mode",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-327",
                severity=8.0,
                description=(
                    "Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical "
                    "ciphertext blocks, leaking data patterns without providing confidentiality."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Use an authenticated encryption mode such as AES-GCM or ChaCha20-Poly1305.",
                exploitability=0.7,
                extra={"rule": "insecure-mode-ecb"},
            ))

        self.generic_visit(node)

    def _has_usedforsecurity_false(self, node: ast.Call) -> bool:
        """Check if call has usedforsecurity=False (Python 3.9+)."""
        for kw in node.keywords:
            if kw.arg == "usedforsecurity" and _get_constant_val(kw.value) is False:
                return True
        return False

    def _check_weak_hashes(self, node: ast.Call, func_name: str) -> None:
        if self._has_usedforsecurity_false(node):
            return

        is_md5 = False
        is_sha1 = False

        if (
            func_name in ("hashlib.md5", "md5")
            or func_name.endswith((".hashlib.md5", "Crypto.Hash.MD5.new", "MD5.new", "hashes.MD5"))
        ):
            is_md5 = True
        elif (
            func_name in ("hashlib.sha1", "sha1")
            or func_name.endswith((".hashlib.sha1", "Crypto.Hash.SHA.new", "Crypto.Hash.SHA1.new", "SHA.new", "SHA1.new", "hashes.SHA1"))
        ):
            is_sha1 = True
        elif func_name in ("hashlib.new",) or func_name.endswith(".hashlib.new"):
            name_arg = None
            if node.args:
                name_arg = _get_constant_val(node.args[0])
            for kw in node.keywords:
                if kw.arg == "name":
                    name_arg = _get_constant_val(kw.value)
            if isinstance(name_arg, str):
                low_name = name_arg.lower()
                if low_name == "md5":
                    is_md5 = True
                elif low_name in ("sha1", "sha-1"):
                    is_sha1 = True

        if is_md5:
            self.findings.append(Finding(
                engine="crypto",
                title="Use of broken hash algorithm MD5",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-328",
                severity=7.0,
                description=(
                    "MD5 is cryptographically broken and vulnerable to collision and preimage attacks. "
                    "Do not use it for authentication, signatures, password hashing, or integrity verification."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Use SHA-256 (hashlib.sha256) or SHA-3, or pass usedforsecurity=False if computing a non-security checksum.",
                exploitability=0.6,
                extra={"rule": "weak-hash-md5", "algorithm": "MD5"},
            ))
        elif is_sha1:
            self.findings.append(Finding(
                engine="crypto",
                title="Use of weak hash algorithm SHA-1",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-328",
                severity=6.0,
                description=(
                    "SHA-1 is deprecated and vulnerable to practical collision attacks (SHAttered). "
                    "It should not be used for security purposes."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Use SHA-256 (hashlib.sha256), SHA-3, or BLAKE2.",
                exploitability=0.5,
                extra={"rule": "weak-hash-sha1", "algorithm": "SHA-1"},
            ))

    def _check_ciphers_and_modes(self, node: ast.Call, func_name: str) -> None:
        if any(func_name.endswith(x) or func_name == x for x in (
            "Crypto.Cipher.DES.new", "DES.new", "algorithms.TripleDES",
            "Crypto.Cipher.DES3.new", "DES3.new"
        )):
            self.findings.append(Finding(
                engine="crypto",
                title="Use of broken cipher DES/3DES",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-327",
                severity=7.5,
                description="DES and 3DES have inadequate key lengths or block sizes (64-bit) vulnerable to Sweet32 attacks.",
                evidence=self._get_evidence(node),
                fix_hint="Migrate to AES-256-GCM or ChaCha20-Poly1305.",
                exploitability=0.6,
                extra={"rule": "insecure-cipher-des", "cipher": "DES/3DES"},
            ))
        elif any(func_name.endswith(x) or func_name == x for x in (
            "Crypto.Cipher.ARC4.new", "ARC4.new", "Crypto.Cipher.RC4.new", "RC4.new", "algorithms.ARC4"
        )):
            self.findings.append(Finding(
                engine="crypto",
                title="Use of broken stream cipher RC4",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-327",
                severity=7.5,
                description="RC4 has severe cryptographic biases and vulnerabilities and is prohibited in modern security protocols.",
                evidence=self._get_evidence(node),
                fix_hint="Migrate to AES-GCM or ChaCha20-Poly1305.",
                exploitability=0.6,
                extra={"rule": "insecure-cipher-rc4", "cipher": "RC4"},
            ))

        if func_name.endswith("modes.ECB"):
            self.findings.append(Finding(
                engine="crypto",
                title="Use of insecure Electronic Codebook (ECB) cipher mode",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-327",
                severity=8.0,
                description="ECB mode leaks plaintext pattern structure in ciphertext. It does not provide semantic security.",
                evidence=self._get_evidence(node),
                fix_hint="Use an authenticated encryption mode such as modes.GCM or modes.CBC with a random IV.",
                exploitability=0.7,
                extra={"rule": "insecure-mode-ecb"},
            ))

        self._check_static_iv(node, func_name)

    def _check_static_iv(self, node: ast.Call, func_name: str) -> None:
        # Gate behind cipher constructor or cipher mode call sites
        is_cipher_call = any(func_name.endswith(c) or func_name == c for c in (
            "AES.new", "DES.new", "DES3.new", "Blowfish.new", "ARC4.new",
            "Cipher", "Cipher.new",
            "modes.CBC", "modes.CTR", "modes.CFB", "modes.OFB", "modes.GCM"
        ))
        if not is_cipher_call:
            return

        iv_val = None
        for kw in node.keywords:
            if kw.arg in ("iv", "nonce", "initial_value"):
                iv_val = _get_constant_val(kw.value)
                if iv_val is None and isinstance(kw.value, ast.Name):
                    iv_val = self.local_constants.get(kw.value.id)

        if any(func_name.endswith(m) for m in ("modes.CBC", "modes.CTR", "modes.CFB", "modes.OFB", "modes.GCM")):
            if node.args:
                iv_val = _get_constant_val(node.args[0])
                if iv_val is None and isinstance(node.args[0], ast.Name):
                    iv_val = self.local_constants.get(node.args[0].id)

        if iv_val is not None and isinstance(iv_val, (bytes, str, int)):
            self.findings.append(Finding(
                engine="crypto",
                title="Hardcoded or static Initialization Vector (IV) in cipher",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-329",
                severity=7.5,
                description=(
                    "A static, constant, or hardcoded IV/nonce was provided to a block cipher mode. "
                    "Reusing IVs destroys ciphertext confidentiality and authenticity."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Generate a fresh cryptographic IV for every encryption call using os.urandom(16).",
                exploitability=0.6,
                extra={"rule": "static-iv"},
            ))

    def _check_key_lengths(self, node: ast.Call, func_name: str) -> None:
        key_size: Optional[int] = None
        if any(func_name.endswith(x) for x in ("RSA.generate", "DSA.generate")):
            if node.args:
                key_size = _get_constant_val(node.args[0])
            for kw in node.keywords:
                if kw.arg in ("bits", "key_size"):
                    key_size = _get_constant_val(kw.value)
        elif func_name.endswith("rsa.generate_private_key"):
            for kw in node.keywords:
                if kw.arg == "key_size":
                    key_size = _get_constant_val(kw.value)

        if isinstance(key_size, int) and key_size < 2048:
            self.findings.append(Finding(
                engine="crypto",
                title=f"Asymmetric key size is less than 2048 bits ({key_size} bits)",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-326",
                severity=7.0,
                description=(
                    f"RSA/DSA key size of {key_size} bits is cryptographically weak and factorable. "
                    "Modern standards require a minimum key size of 2048 bits (3072+ recommended)."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Increase key size to at least 2048 bits (e.g. 3072 or 4096), or use Ed25519.",
                exploitability=0.5,
                extra={"rule": "weak-key-size", "key_size": key_size},
            ))

    def _check_network_misuse(self, node: ast.Call, func_name: str) -> None:
        if func_name in ("ssl._create_unverified_context", "_create_unverified_context") or func_name.endswith(".ssl._create_unverified_context"):
            self.findings.append(Finding(
                engine="crypto",
                title="TLS certificate verification globally bypassed with _create_unverified_context()",
                file=self.file_path,
                line=node.lineno,
                cwe="CWE-295",
                severity=8.5,
                description=(
                    "ssl._create_unverified_context() disables all TLS certificate verification, "
                    "making HTTPS connections vulnerable to Man-in-the-Middle (MitM) attacks."
                ),
                evidence=self._get_evidence(node),
                fix_hint="Use ssl.create_default_context() and ensure CA certificates are configured.",
                exploitability=0.7,
                extra={"rule": "tls-verify-disabled"},
            ))

        # Gate verify=False and cert_reqs behind known HTTP client calls
        is_http_call = any(func_name.startswith(p) for p in (
            "requests.", "httpx.", "urllib3.", "aiohttp.", "urllib.request."
        )) or any(func_name.endswith(s) or func_name == s for s in (
            ".get", ".post", ".put", ".delete", ".patch", ".head", ".request",
            ".Session", ".Client", ".AsyncClient", ".PoolManager",
            "get", "post", "put", "delete", "request"
        ))
        if is_http_call:
            for kw in node.keywords:
                if kw.arg == "verify" and _get_constant_val(kw.value) is False:
                    self.findings.append(Finding(
                        engine="crypto",
                        title="TLS certificate verification disabled (verify=False)",
                        file=self.file_path,
                        line=node.lineno,
                        cwe="CWE-295",
                        severity=8.0,
                        description=(
                            "Setting verify=False disables TLS certificate and hostname validation, allowing "
                            "attackers on the same network or DNS to intercept and decrypt traffic."
                        ),
                        evidence=self._get_evidence(node),
                        fix_hint="Remove verify=False or provide a trusted CA bundle path.",
                        exploitability=0.7,
                        extra={"rule": "tls-verify-disabled", "call": func_name},
                    ))
                elif kw.arg == "cert_reqs" and _get_constant_val(kw.value) in ("CERT_NONE", 0, "none"):
                    self.findings.append(Finding(
                        engine="crypto",
                        title="TLS certificate requirements disabled (cert_reqs=CERT_NONE)",
                        file=self.file_path,
                        line=node.lineno,
                        cwe="CWE-295",
                        severity=8.0,
                        description="Setting cert_reqs='CERT_NONE' bypasses TLS server certificate verification.",
                        evidence=self._get_evidence(node),
                        fix_hint="Enforce ssl.CERT_REQUIRED.",
                        exploitability=0.7,
                        extra={"rule": "tls-verify-disabled", "call": func_name},
                    ))

        if any(func_name.startswith(p) for p in (
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "httpx.get", "httpx.post", "urllib.request.urlopen"
        )):
            if node.args:
                url_val = _get_constant_val(node.args[0])
                if isinstance(url_val, str) and url_val.startswith("http://"):
                    if not any(loc in url_val for loc in ("localhost", "127.0.0.1", "0.0.0.0", "::1")):
                        self.findings.append(Finding(
                            engine="crypto",
                            title="Cleartext HTTP URL used in network transmission",
                            file=self.file_path,
                            line=node.lineno,
                            cwe="CWE-319",
                            severity=5.5,
                            description=(
                                f"Network request made to unencrypted cleartext HTTP endpoint: '{url_val[:60]}'. "
                                "Sensitive payload data and headers are exposed in transit."
                            ),
                            evidence=self._get_evidence(node),
                            fix_hint="Use HTTPS (https://) instead of cleartext HTTP.",
                            exploitability=0.4,
                            extra={"rule": "cleartext-http", "url": url_val[:100]},
                        ))


class CryptoEngine(Engine):
    name = "crypto"

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        findings: List[Finding] = []
        files_scanned = 0
        files_skipped = 0
        errors: List[str] = []

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS]
            for fn in sorted(filenames):
                if not fn.endswith(".py"):
                    continue
                full_path = Path(dirpath) / fn
                rpath = rel_path(full_path, root)

                try:
                    code = full_path.read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    files_skipped += 1
                    errors.append(f"Cannot read {rpath}: {e}")
                    continue

                try:
                    tree = ast.parse(code, filename=rpath)
                except SyntaxError as e:
                    files_skipped += 1
                    errors.append(f"Syntax error in {rpath}:{e.lineno}")
                    continue

                files_scanned += 1
                source_lines = code.splitlines()
                visitor = CryptoVisitor(file_path=rpath, source_lines=source_lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats = {
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "findings_count": len(findings),
            "errors": errors,
        }
        return findings
