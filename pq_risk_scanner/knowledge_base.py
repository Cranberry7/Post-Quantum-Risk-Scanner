"""Post-quantum cryptographic knowledge base.

Static mappings from algorithm names to risk categories, quantum
vulnerability details, and recommended post-quantum replacements.
All data is sourced from NIST standards and current public research.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from pq_risk_scanner.models import AlgorithmFamily, RiskCategory


@dataclass(frozen=True)
class AlgorithmProfile:
    """Complete profile of a cryptographic algorithm's post-quantum posture."""

    canonical_name: str
    family: AlgorithmFamily
    risk_category: RiskCategory
    vulnerable_to: str  # "shor" | "grover" | "none"
    post_quantum_replacement: Optional[str]
    replacement_standard: Optional[str]
    effective_pq_bits: Optional[int]
    notes: str = ""


# ---------------------------------------------------------------------------
# Algorithm knowledge base
# ---------------------------------------------------------------------------

_ALGORITHM_DB: Dict[str, AlgorithmProfile] = {
    # ── Asymmetric / Public-Key (broken by Shor's) ──────────────────────
    "rsa": AlgorithmProfile(
        canonical_name="RSA",
        family=AlgorithmFamily.ASYMMETRIC,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-KEM (Kyber)",
        replacement_standard="NIST FIPS 203",
        effective_pq_bits=0,
        notes="Integer factorization solved in polynomial time by Shor's algorithm.",
    ),
    "dsa": AlgorithmProfile(
        canonical_name="DSA",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-DSA (Dilithium)",
        replacement_standard="NIST FIPS 204",
        effective_pq_bits=0,
        notes="Discrete logarithm problem solved by Shor's algorithm.",
    ),
    "ecdsa": AlgorithmProfile(
        canonical_name="ECDSA",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-DSA (Dilithium)",
        replacement_standard="NIST FIPS 204",
        effective_pq_bits=0,
        notes="Elliptic curve discrete logarithm solved by Shor's algorithm.",
    ),
    "ed25519": AlgorithmProfile(
        canonical_name="Ed25519",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-DSA (Dilithium)",
        replacement_standard="NIST FIPS 204",
        effective_pq_bits=0,
        notes="EdDSA over Curve25519; ECDLP solved by Shor's algorithm.",
    ),
    "ed448": AlgorithmProfile(
        canonical_name="Ed448",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-DSA (Dilithium)",
        replacement_standard="NIST FIPS 204",
        effective_pq_bits=0,
        notes="EdDSA over Curve448; ECDLP solved by Shor's algorithm.",
    ),
    "dh": AlgorithmProfile(
        canonical_name="Diffie-Hellman",
        family=AlgorithmFamily.KEY_EXCHANGE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-KEM (Kyber)",
        replacement_standard="NIST FIPS 203",
        effective_pq_bits=0,
        notes="Discrete logarithm problem solved by Shor's algorithm.",
    ),
    "ecdh": AlgorithmProfile(
        canonical_name="ECDH",
        family=AlgorithmFamily.KEY_EXCHANGE,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="shor",
        post_quantum_replacement="ML-KEM (Kyber)",
        replacement_standard="NIST FIPS 203",
        effective_pq_bits=0,
        notes="ECDLP solved by Shor's algorithm.",
    ),
    # ── Symmetric (weakened by Grover's) ────────────────────────────────
    "aes-128": AlgorithmProfile(
        canonical_name="AES-128",
        family=AlgorithmFamily.SYMMETRIC,
        risk_category=RiskCategory.QUANTUM_WEAKENED,
        vulnerable_to="grover",
        post_quantum_replacement="AES-256",
        replacement_standard="NIST SP 800-131A",
        effective_pq_bits=64,
        notes="Grover's reduces effective security from 128 to 64 bits.",
    ),
    "aes-192": AlgorithmProfile(
        canonical_name="AES-192",
        family=AlgorithmFamily.SYMMETRIC,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=96,
        notes="Grover's reduces to 96 bits; still considered adequate.",
    ),
    "aes-256": AlgorithmProfile(
        canonical_name="AES-256",
        family=AlgorithmFamily.SYMMETRIC,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=128,
        notes="Grover's reduces to 128 bits; considered quantum-safe.",
    ),
    "3des": AlgorithmProfile(
        canonical_name="3DES",
        family=AlgorithmFamily.SYMMETRIC,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="grover",
        post_quantum_replacement="AES-256",
        replacement_standard="NIST SP 800-131A",
        effective_pq_bits=56,
        notes="Already weak classically (112-bit); Grover's halves to ~56 bits.",
    ),
    "chacha20": AlgorithmProfile(
        canonical_name="ChaCha20",
        family=AlgorithmFamily.SYMMETRIC,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=128,
        notes="256-bit key; Grover's reduces to 128 bits; quantum-safe.",
    ),
    # ── Hash Functions (weakened by Grover's) ───────────────────────────
    "sha-1": AlgorithmProfile(
        canonical_name="SHA-1",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="grover",
        post_quantum_replacement="SHA-3-256 or SHA-256",
        replacement_standard="NIST SP 800-131A",
        effective_pq_bits=80,
        notes="Already deprecated classically; Grover's further weakens collision resistance.",
    ),
    "sha-256": AlgorithmProfile(
        canonical_name="SHA-256",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=128,
        notes="Grover's reduces collision resistance to 128 bits; adequate.",
    ),
    "sha-384": AlgorithmProfile(
        canonical_name="SHA-384",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=192,
        notes="Grover's reduces collision resistance to 192 bits; quantum-safe.",
    ),
    "sha-512": AlgorithmProfile(
        canonical_name="SHA-512",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=256,
        notes="Grover's reduces collision resistance to 256 bits; quantum-safe.",
    ),
    "sha3-256": AlgorithmProfile(
        canonical_name="SHA3-256",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="grover",
        post_quantum_replacement=None,
        replacement_standard=None,
        effective_pq_bits=128,
        notes="SHA-3 with 256-bit output; quantum-safe.",
    ),
    "md5": AlgorithmProfile(
        canonical_name="MD5",
        family=AlgorithmFamily.HASH,
        risk_category=RiskCategory.QUANTUM_UNSAFE,
        vulnerable_to="grover",
        post_quantum_replacement="SHA-3-256 or SHA-256",
        replacement_standard="NIST SP 800-131A",
        effective_pq_bits=64,
        notes="Broken classically; Grover's further weakens it.",
    ),
    # ── Post-Quantum Algorithms (quantum-safe) ──────────────────────────
    "ml-kem": AlgorithmProfile(
        canonical_name="ML-KEM (Kyber)",
        family=AlgorithmFamily.KEY_EXCHANGE,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="none",
        post_quantum_replacement=None,
        replacement_standard="NIST FIPS 203",
        effective_pq_bits=192,
        notes="NIST-standardized post-quantum key encapsulation mechanism.",
    ),
    "ml-dsa": AlgorithmProfile(
        canonical_name="ML-DSA (Dilithium)",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="none",
        post_quantum_replacement=None,
        replacement_standard="NIST FIPS 204",
        effective_pq_bits=192,
        notes="NIST-standardized post-quantum digital signature.",
    ),
    "slh-dsa": AlgorithmProfile(
        canonical_name="SLH-DSA (SPHINCS+)",
        family=AlgorithmFamily.SIGNATURE,
        risk_category=RiskCategory.QUANTUM_SAFE,
        vulnerable_to="none",
        post_quantum_replacement=None,
        replacement_standard="NIST FIPS 205",
        effective_pq_bits=128,
        notes="Hash-based post-quantum signature; NIST-standardized.",
    ),
}

# Alias lookup table — maps common alternate names to canonical DB keys.
_ALIASES: Dict[str, str] = {
    "rsa-sha256": "rsa",
    "rsa-sha384": "rsa",
    "rsa-sha512": "rsa",
    "rsa-sha1": "rsa",
    "rsa2048": "rsa",
    "rsa4096": "rsa",
    "ec": "ecdsa",
    "ecc": "ecdsa",
    "ecdsa-sha2-nistp256": "ecdsa",
    "ecdsa-sha2-nistp384": "ecdsa",
    "ecdsa-sha2-nistp521": "ecdsa",
    "diffie-hellman": "dh",
    "diffie-hellman-group14-sha1": "dh",
    "diffie-hellman-group14-sha256": "dh",
    "diffie-hellman-group16-sha512": "dh",
    "diffie-hellman-group-exchange-sha256": "dh",
    "curve25519-sha256": "ecdh",
    "x25519": "ecdh",
    "ssh-rsa": "rsa",
    "ssh-dss": "dsa",
    "ssh-ed25519": "ed25519",
    "ssh-ed448": "ed448",
    "aes128": "aes-128",
    "aes-128-cbc": "aes-128",
    "aes-128-ctr": "aes-128",
    "aes-128-gcm": "aes-128",
    "aes128-cbc": "aes-128",
    "aes128-ctr": "aes-128",
    "aes128-gcm@openssh.com": "aes-128",
    "aes192": "aes-192",
    "aes-192-cbc": "aes-192",
    "aes-192-ctr": "aes-192",
    "aes256": "aes-256",
    "aes-256-cbc": "aes-256",
    "aes-256-ctr": "aes-256",
    "aes-256-gcm": "aes-256",
    "aes256-cbc": "aes-256",
    "aes256-ctr": "aes-256",
    "aes256-gcm@openssh.com": "aes-256",
    "chacha20-poly1305": "chacha20",
    "chacha20-poly1305@openssh.com": "chacha20",
    "tripledes": "3des",
    "des-ede3": "3des",
    "3des-cbc": "3des",
    "sha1": "sha-1",
    "sha2-256": "sha-256",
    "sha2-384": "sha-384",
    "sha2-512": "sha-512",
    "sha256": "sha-256",
    "sha384": "sha-384",
    "sha512": "sha-512",
    "sha3_256": "sha3-256",
    "sha-3-256": "sha3-256",
    "kyber": "ml-kem",
    "dilithium": "ml-dsa",
    "sphincs+": "slh-dsa",
    "sphincs": "slh-dsa",
}


def lookup_algorithm(name: str) -> Optional[AlgorithmProfile]:
    """Look up an algorithm profile by name (case-insensitive).

    Checks canonical names first, then aliases.
    Returns ``None`` if the algorithm is not in the knowledge base.
    """
    key = name.strip().lower()
    if key in _ALGORITHM_DB:
        return _ALGORITHM_DB[key]
    resolved = _ALIASES.get(key)
    if resolved is not None:
        return _ALGORITHM_DB[resolved]
    return None


def all_profiles() -> Dict[str, AlgorithmProfile]:
    """Return a copy of the full algorithm database."""
    return dict(_ALGORITHM_DB)
