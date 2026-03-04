"""PEM certificate and key scanner.

Uses the ``cryptography`` library to parse PEM-encoded X.509 certificates
and public/private keys, extracting algorithm and key-size information.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from pq_risk_scanner.models import (
    AlgorithmFamily,
    CryptographicFinding,
    UsageContext,
)


def _identify_public_key(pub_key: object) -> tuple[str, int | None]:
    """Return (algorithm_name, key_size) for a public key object."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "ECDSA", pub_key.key_size
    if isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return "Unknown", None


def _identify_private_key(priv_key: object) -> tuple[str, int | None]:
    """Return (algorithm_name, key_size) for a private key object."""
    if isinstance(priv_key, rsa.RSAPrivateKey):
        return "RSA", priv_key.key_size
    if isinstance(priv_key, ec.EllipticCurvePrivateKey):
        return "ECDSA", priv_key.key_size
    if isinstance(priv_key, dsa.DSAPrivateKey):
        return "DSA", priv_key.key_size
    if isinstance(priv_key, ed25519.Ed25519PrivateKey):
        return "Ed25519", 256
    if isinstance(priv_key, ed448.Ed448PrivateKey):
        return "Ed448", 448
    return "Unknown", None


def scan_pem_file(file_path: Path) -> List[CryptographicFinding]:
    """Parse a PEM file and return cryptographic findings.

    Attempts to load as certificate first, then public key, then private key.
    Multiple PEM blocks in one file are supported via certificate iteration.
    """
    findings: List[CryptographicFinding] = []
    raw = file_path.read_bytes()
    source = str(file_path)

    # --- Try X.509 certificates ----------------------------------------
    if b"BEGIN CERTIFICATE" in raw:
        for cert in _load_certificates(raw):
            algo, size = _identify_public_key(cert.public_key())
            findings.append(
                CryptographicFinding(
                    algorithm=algo,
                    key_size=size,
                    source_file=source,
                    usage_context=UsageContext.PKI,
                    algorithm_family=AlgorithmFamily.ASYMMETRIC,
                    raw_match=f"X.509 certificate ({algo})",
                )
            )
        return findings

    # --- Try public key ------------------------------------------------
    if b"BEGIN PUBLIC KEY" in raw:
        try:
            pub = load_pem_public_key(raw)
            algo, size = _identify_public_key(pub)
            findings.append(
                CryptographicFinding(
                    algorithm=algo,
                    key_size=size,
                    source_file=source,
                    usage_context=UsageContext.PKI,
                    algorithm_family=AlgorithmFamily.ASYMMETRIC,
                    raw_match=f"PEM public key ({algo})",
                )
            )
        except Exception:
            pass
        return findings

    # --- Try private key -----------------------------------------------
    if b"BEGIN" in raw and b"PRIVATE KEY" in raw:
        try:
            priv = load_pem_private_key(raw, password=None)
            algo, size = _identify_private_key(priv)
            findings.append(
                CryptographicFinding(
                    algorithm=algo,
                    key_size=size,
                    source_file=source,
                    usage_context=UsageContext.PKI,
                    algorithm_family=AlgorithmFamily.ASYMMETRIC,
                    raw_match=f"PEM private key ({algo})",
                )
            )
        except Exception:
            pass

    return findings


def _load_certificates(raw: bytes) -> list:
    """Load one or more X.509 certificates from PEM bytes."""
    certs: list = []
    try:
        cert = x509.load_pem_x509_certificate(raw)
        certs.append(cert)
    except Exception:
        pass
    return certs
