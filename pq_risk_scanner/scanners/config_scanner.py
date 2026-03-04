"""Configuration file scanner for TLS and SSH settings.

Uses regex patterns to extract cryptographic algorithms, cipher suites,
and key exchange methods from text-based configuration files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from pq_risk_scanner.models import (
    AlgorithmFamily,
    CryptographicFinding,
    UsageContext,
)

# ---------------------------------------------------------------------------
# TLS configuration patterns
# ---------------------------------------------------------------------------

_TLS_CIPHER_DIRECTIVES = re.compile(
    r"(?:ssl_ciphers|SSLCipherSuite|CipherString)\s+['\"]?([^;'\"]+)",
    re.IGNORECASE,
)

_TLS_PROTOCOL_DIRECTIVES = re.compile(
    r"(?:ssl_protocols|SSLProtocol|Protocol)\s+([^;]+)",
    re.IGNORECASE,
)

# Individual cipher/kex tokens we recognise inside a cipher string
_CIPHER_TOKENS = re.compile(
    r"(AES(?:128|256)(?:-(?:CBC|GCM|CTR))?|"
    r"CHACHA20-POLY1305|"
    r"3DES(?:-CBC)?|"
    r"DES-CBC3|"
    r"RC4|"
    r"ECDHE?|"
    r"DHE?|"
    r"RSA|"
    r"ECDSA|"
    r"SHA(?:256|384|512|1)?|"
    r"ED25519|ED448)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SSH configuration patterns
# ---------------------------------------------------------------------------

_SSH_CIPHERS = re.compile(r"Ciphers\s+(.+)", re.IGNORECASE)
_SSH_KEXALGORITHMS = re.compile(r"KexAlgorithms\s+(.+)", re.IGNORECASE)
_SSH_HOSTKEY = re.compile(r"HostKeyAlgorithms\s+(.+)", re.IGNORECASE)
_SSH_MACS = re.compile(r"MACs\s+(.+)", re.IGNORECASE)


def _family_for_token(token: str) -> AlgorithmFamily:
    """Guess the algorithm family from a cipher-string token."""
    t = token.upper()
    if t in {"ECDHE", "DHE", "DH", "ECDH", "X25519"}:
        return AlgorithmFamily.KEY_EXCHANGE
    if t in {"RSA", "ECDSA", "DSA", "ED25519", "ED448"}:
        return AlgorithmFamily.SIGNATURE
    if t.startswith(("AES", "CHACHA", "3DES", "DES", "RC4")):
        return AlgorithmFamily.SYMMETRIC
    if t.startswith("SHA") or t == "MD5":
        return AlgorithmFamily.HASH
    return AlgorithmFamily.UNKNOWN


def _key_size_hint(token: str) -> int | None:
    """Extract a key-size hint from a token like 'AES256'."""
    m = re.search(r"(\d+)", token)
    return int(m.group(1)) if m else None


def scan_config_file(file_path: Path) -> List[CryptographicFinding]:
    """Scan a TLS or SSH configuration file for cryptographic primitives."""
    text = file_path.read_text(errors="replace")
    source = str(file_path)
    findings: List[CryptographicFinding] = []
    seen: set[tuple[str, str]] = set()

    is_ssh = _is_ssh_config(text, file_path)
    context = UsageContext.SSH if is_ssh else UsageContext.TLS

    for line_num, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        tokens = _extract_tokens(stripped, is_ssh)
        for token in tokens:
            dedup_key = (token.upper(), context.value)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                CryptographicFinding(
                    algorithm=token,
                    key_size=_key_size_hint(token),
                    source_file=source,
                    usage_context=context,
                    algorithm_family=_family_for_token(token),
                    line_number=line_num,
                    raw_match=stripped,
                )
            )

    return findings


def _is_ssh_config(text: str, path: Path) -> bool:
    """Heuristic: decide whether a config file is SSH or TLS."""
    name = path.name.lower()
    if "ssh" in name:
        return True
    if any(kw in text.lower() for kw in ("kexalgorithms", "hostkey", "authorizedkeys")):
        return True
    return False


def _extract_tokens(line: str, is_ssh: bool) -> List[str]:
    """Pull cryptographic tokens from a single config line."""
    if is_ssh:
        for pattern in (_SSH_CIPHERS, _SSH_KEXALGORITHMS, _SSH_HOSTKEY, _SSH_MACS):
            m = pattern.match(line)
            if m:
                return [t.strip() for t in m.group(1).split(",") if t.strip()]
        return []

    # TLS — first check directive matches
    for pattern in (_TLS_CIPHER_DIRECTIVES, _TLS_PROTOCOL_DIRECTIVES):
        m = pattern.match(line)
        if m:
            return [t.group(0) for t in _CIPHER_TOKENS.finditer(m.group(1))]

    return []
