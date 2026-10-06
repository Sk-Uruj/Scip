"""Unit tests for the Crypto & Network Misuse Engine (CryptoEngine)."""
from pathlib import Path
import pytest

from core.pipeline import get_engines, run_scan
from engines.crypto_engine import CryptoEngine


def write_py(tmp_path: Path, filename: str, code: str) -> Path:
    p = tmp_path / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return p


def scan(tmp_path: Path):
    return CryptoEngine().scan(str(tmp_path))


def rules(findings):
    return {f.extra.get("rule") for f in findings}


# --------------------------------------------------------------------------- #
# 1. Weak Hashes
# --------------------------------------------------------------------------- #
def test_md5_detected(tmp_path):
    write_py(tmp_path, "a.py", "import hashlib\nh = hashlib.md5(b'pass').hexdigest()\n")
    found = scan(tmp_path)
    assert "weak-hash-md5" in rules(found)
    assert found[0].cwe == "CWE-328"
    assert found[0].severity == 7.0


def test_sha1_detected(tmp_path):
    write_py(tmp_path, "a.py", "import hashlib\nh = hashlib.sha1(b'pass').hexdigest()\n")
    found = scan(tmp_path)
    assert "weak-hash-sha1" in rules(found)
    assert found[0].cwe == "CWE-328"


def test_hashlib_new_detected(tmp_path):
    code = (
        "import hashlib\n"
        "h1 = hashlib.new('MD5', b'data')\n"
        "h2 = hashlib.new('sha1', b'data')\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "weak-hash-md5" in rules(found)
    assert "weak-hash-sha1" in rules(found)


def test_usedforsecurity_false_ignored(tmp_path):
    code = "import hashlib\nh = hashlib.md5(b'data', usedforsecurity=False)\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert not any(f.extra.get("rule") == "weak-hash-md5" for f in found)


def test_import_alias_resolved(tmp_path):
    code = "from hashlib import md5 as my_hash\nh = my_hash(b'data')\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "weak-hash-md5" in rules(found)


# --------------------------------------------------------------------------- #
# 2. Insecure PRNG for Credentials / Tokens
# --------------------------------------------------------------------------- #
def test_insecure_prng_for_token_detected(tmp_path):
    code = (
        "import random\n"
        "auth_token = random.randint(100000, 999999)\n"
        "session_key = random.choice(['a', 'b', 'c'])\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "insecure-prng" in rules(found)
    assert all(f.cwe == "CWE-338" for f in found if f.extra.get("rule") == "insecure-prng")


def test_random_for_normal_variables_ignored(tmp_path):
    code = (
        "import random\n"
        "dice_roll = random.randint(1, 6)\n"
        "player_index = random.choice([0, 1, 2])\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert not any(f.extra.get("rule") == "insecure-prng" for f in found)


# --------------------------------------------------------------------------- #
# 3. Broken Ciphers & Modes
# --------------------------------------------------------------------------- #
def test_des_and_rc4_detected(tmp_path):
    code = (
        "from Crypto.Cipher import DES, ARC4\n"
        "c1 = DES.new(key, DES.MODE_ECB)\n"
        "c2 = ARC4.new(key)\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "insecure-cipher-des" in rules(found)
    assert "insecure-cipher-rc4" in rules(found)
    assert "insecure-mode-ecb" in rules(found)


def test_ecb_mode_attribute_detected(tmp_path):
    code = "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB)\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "insecure-mode-ecb" in rules(found)
    assert found[0].severity == 8.0


def test_static_iv_detected(tmp_path):
    code = (
        "from Crypto.Cipher import AES\n"
        "fixed_iv = b'0123456789abcdef'\n"
        "c = AES.new(key, AES.MODE_CBC, iv=fixed_iv)\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "static-iv" in rules(found)
    assert any(f.cwe == "CWE-329" for f in found)


# --------------------------------------------------------------------------- #
# 4. Weak Key Sizes (< 2048 bits)
# --------------------------------------------------------------------------- #
def test_weak_rsa_key_detected(tmp_path):
    code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "weak-key-size" in rules(found)
    assert found[0].cwe == "CWE-326"


def test_strong_rsa_key_not_flagged(tmp_path):
    code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(4096)\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert not any(f.extra.get("rule") == "weak-key-size" for f in found)


# --------------------------------------------------------------------------- #
# 5. Network & TLS Misuse
# --------------------------------------------------------------------------- #
def test_tls_verify_disabled_detected(tmp_path):
    code = (
        "import requests\n"
        "resp = requests.get('https://example.com/api', verify=False)\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "tls-verify-disabled" in rules(found)
    assert found[0].cwe == "CWE-295"


def test_unverified_context_detected(tmp_path):
    code = "import ssl\nctx = ssl._create_unverified_context()\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "tls-verify-disabled" in rules(found)


def test_insecure_tls_version_detected(tmp_path):
    code = "import ssl\nproto = ssl.PROTOCOL_TLSv1\n"
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "insecure-tls-version" in rules(found)


def test_cleartext_http_detected(tmp_path):
    code = (
        "import requests\n"
        "r1 = requests.get('http://api.production-service.com/users')\n"
        "r2 = requests.get('http://localhost:8000/test')\n"  # local dev allowed
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert "cleartext-http" in rules(found)
    assert len([f for f in found if f.extra.get("rule") == "cleartext-http"]) == 1


# --------------------------------------------------------------------------- #
# 6. Syntax Error Resilience & Engine Properties
# --------------------------------------------------------------------------- #
def test_syntax_error_handled_gracefully(tmp_path):
    write_py(tmp_path, "broken.py", "def invalid_syntax(\n")
    engine = CryptoEngine()
    found = engine.scan(str(tmp_path))
    assert found == []
    assert engine.stats["files_skipped"] == 1
    assert any("Syntax error" in err for err in engine.stats["errors"])


def test_pipeline_runs_crypto_engine(tmp_path):
    code = "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n"
    write_py(tmp_path, "app.py", code)
    engines = get_engines(enabled_engines=["crypto"])
    assert len(engines) == 1
    assert engines[0].name == "crypto"
    findings = run_scan(str(tmp_path), engines=engines)
    assert len(findings) == 1
    assert findings[0].engine == "crypto"


def test_unrelated_call_with_verify_kwarg_ignored(tmp_path):
    code = (
        "class Form:\n"
        "    def check(self, data, verify=True): pass\n"
        "f = Form()\n"
        "f.check(data, verify=False)\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert not any(f.extra.get("rule") == "tls-verify-disabled" for f in found)


def test_unrelated_call_with_initial_value_ignored(tmp_path):
    code = (
        "def accumulate(items, initial_value=0): return items\n"
        "res = accumulate([1, 2], initial_value=0)\n"
    )
    write_py(tmp_path, "a.py", code)
    found = scan(tmp_path)
    assert not any(f.extra.get("rule") == "static-iv" for f in found)

