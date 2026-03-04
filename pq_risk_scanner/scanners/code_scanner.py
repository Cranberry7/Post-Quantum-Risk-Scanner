"""Source code cryptographic usage scanner.

Lightweight pattern matcher that detects well-known cryptographic library
calls in Python, Java, and JavaScript/TypeScript source files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, NamedTuple

from pq_risk_scanner.models import (
    AlgorithmFamily,
    CryptographicFinding,
    UsageContext,
)


class _Pattern(NamedTuple):
    regex: re.Pattern[str]
    algorithm: str
    family: AlgorithmFamily
    key_size: int | None


# ---------------------------------------------------------------------------
# Detection patterns per language ecosystem
# ---------------------------------------------------------------------------

_PATTERNS: List[_Pattern] = [
    # ── Python ──────────────────────────────────────────────────────────
    _Pattern(re.compile(r"hashlib\.md5", re.I), "MD5", AlgorithmFamily.HASH, None),
    _Pattern(re.compile(r"hashlib\.sha1", re.I), "SHA-1", AlgorithmFamily.HASH, None),
    _Pattern(re.compile(r"hashlib\.sha256", re.I), "SHA-256", AlgorithmFamily.HASH, None),
    _Pattern(re.compile(r"hashlib\.sha384", re.I), "SHA-384", AlgorithmFamily.HASH, None),
    _Pattern(re.compile(r"hashlib\.sha512", re.I), "SHA-512", AlgorithmFamily.HASH, None),
    _Pattern(re.compile(r"hashlib\.sha3_256", re.I), "SHA3-256", AlgorithmFamily.HASH, None),
    _Pattern(
        re.compile(r"rsa\.generate_private_key\s*\(.*?key_size\s*=\s*(\d+)", re.I | re.S),
        "RSA", AlgorithmFamily.ASYMMETRIC, None,  # key_size captured from group
    ),
    _Pattern(re.compile(r"ec\.SECP256R1", re.I), "ECDSA", AlgorithmFamily.SIGNATURE, 256),
    _Pattern(re.compile(r"ec\.SECP384R1", re.I), "ECDSA", AlgorithmFamily.SIGNATURE, 384),
    _Pattern(re.compile(r"ec\.SECP521R1", re.I), "ECDSA", AlgorithmFamily.SIGNATURE, 521),
    _Pattern(re.compile(r"Ed25519PrivateKey|Ed25519PublicKey", re.I), "Ed25519", AlgorithmFamily.SIGNATURE, 256),
    _Pattern(
        re.compile(r"algorithms\.AES\b", re.I),
        "AES-256", AlgorithmFamily.SYMMETRIC, 256,
    ),
    _Pattern(
        re.compile(r"algorithms\.TripleDES\b", re.I),
        "3DES", AlgorithmFamily.SYMMETRIC, 168,
    ),
    # ── Java ────────────────────────────────────────────────────────────
    _Pattern(
        re.compile(r'Cipher\.getInstance\s*\(\s*"AES', re.I),
        "AES-128", AlgorithmFamily.SYMMETRIC, 128,
    ),
    _Pattern(
        re.compile(r'Cipher\.getInstance\s*\(\s*"DESede', re.I),
        "3DES", AlgorithmFamily.SYMMETRIC, 168,
    ),
    _Pattern(
        re.compile(r'Cipher\.getInstance\s*\(\s*"RSA', re.I),
        "RSA", AlgorithmFamily.ASYMMETRIC, None,
    ),
    _Pattern(
        re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-256"', re.I),
        "SHA-256", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-1"', re.I),
        "SHA-1", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r'MessageDigest\.getInstance\s*\(\s*"MD5"', re.I),
        "MD5", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"EC"', re.I),
        "ECDSA", AlgorithmFamily.SIGNATURE, None,
    ),
    # ── JavaScript / TypeScript ─────────────────────────────────────────
    _Pattern(
        re.compile(r"crypto\.createHash\s*\(\s*['\"]sha256['\"]", re.I),
        "SHA-256", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r"crypto\.createHash\s*\(\s*['\"]sha1['\"]", re.I),
        "SHA-1", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r"crypto\.createHash\s*\(\s*['\"]md5['\"]", re.I),
        "MD5", AlgorithmFamily.HASH, None,
    ),
    _Pattern(
        re.compile(r"crypto\.createSign\s*\(\s*['\"]RSA-SHA256['\"]", re.I),
        "RSA", AlgorithmFamily.SIGNATURE, None,
    ),
    _Pattern(
        re.compile(r"crypto\.createCipheriv\s*\(\s*['\"]aes-256-gcm['\"]", re.I),
        "AES-256", AlgorithmFamily.SYMMETRIC, 256,
    ),
    _Pattern(
        re.compile(r"crypto\.createCipheriv\s*\(\s*['\"]aes-128-gcm['\"]", re.I),
        "AES-128", AlgorithmFamily.SYMMETRIC, 128,
    ),
]

_SUPPORTED_EXTENSIONS = {".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".c", ".cpp", ".cs"}


def scan_source_file(file_path: Path) -> List[CryptographicFinding]:
    """Scan a source file for cryptographic library usages."""
    if file_path.suffix.lower() not in _SUPPORTED_EXTENSIONS:
        return []

    text = file_path.read_text(errors="replace")
    source = str(file_path)
    findings: List[CryptographicFinding] = []
    seen: set[tuple[str, int | None]] = set()

    for line_num, line in enumerate(text.splitlines(), start=1):
        for pat in _PATTERNS:
            m = pat.regex.search(line)
            if not m:
                continue

            key_size = pat.key_size
            # Special handling: RSA key size captured from regex group
            if pat.algorithm == "RSA" and m.lastindex and m.lastindex >= 1:
                try:
                    key_size = int(m.group(1))
                except (ValueError, IndexError):
                    pass

            dedup = (pat.algorithm, key_size)
            if dedup in seen:
                continue
            seen.add(dedup)

            findings.append(
                CryptographicFinding(
                    algorithm=pat.algorithm,
                    key_size=key_size,
                    source_file=source,
                    usage_context=UsageContext.GENERAL,
                    algorithm_family=pat.family,
                    line_number=line_num,
                    raw_match=line.strip(),
                )
            )

    return findings
