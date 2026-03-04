"""Shor's algorithm impact explainer.

Provides educational, standards-referenced explanations of how Shor's
algorithm threatens public-key cryptography.  Does *not* simulate
quantum computation.
"""

from __future__ import annotations

from pq_risk_scanner.models import QuantumExplanation

# ---------------------------------------------------------------------------
# Static explanation templates keyed by algorithm family
# ---------------------------------------------------------------------------

_SHOR_EXPLANATIONS = {
    "RSA": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="RSA is completely broken by a sufficiently large quantum computer.",
        detailed_explanation=(
            "Shor's algorithm solves the integer factorization problem in polynomial time "
            "O((log N)^3). Since RSA security depends entirely on the hardness of factoring "
            "the product of two large primes, a fault-tolerant quantum computer running "
            "Shor's algorithm would recover the private key from the public key, regardless "
            "of key size. This renders all RSA key sizes equally vulnerable."
        ),
    ),
    "DSA": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="DSA is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "DSA relies on the hardness of the discrete logarithm problem in a prime-order "
            "subgroup of Z_p*. Shor's algorithm solves the discrete logarithm problem in "
            "polynomial time, allowing full private key recovery from the public key."
        ),
    ),
    "ECDSA": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="ECDSA is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "ECDSA security depends on the Elliptic Curve Discrete Logarithm Problem (ECDLP). "
            "Shor's algorithm, adapted for elliptic curves, solves the ECDLP in polynomial "
            "time. This means all ECDSA key sizes (P-256, P-384, P-521) are equally "
            "vulnerable to a sufficiently large quantum computer."
        ),
    ),
    "Ed25519": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="Ed25519 is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "Ed25519 is an EdDSA signature scheme on Curve25519. Like all elliptic-curve "
            "schemes, it is vulnerable to Shor's algorithm solving the ECDLP. The private "
            "key can be recovered from the public key in polynomial time."
        ),
    ),
    "Ed448": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="Ed448 is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "Ed448 is an EdDSA signature scheme on Curve448 (Goldilocks). It is vulnerable "
            "to the same quantum attack as Ed25519 — Shor's algorithm on the ECDLP."
        ),
    ),
    "DH": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="Diffie-Hellman key exchange is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "The Diffie-Hellman protocol relies on the hardness of the discrete logarithm "
            "problem. Shor's algorithm solves this in polynomial time, allowing an adversary "
            "to compute the shared secret from the publicly exchanged values."
        ),
    ),
    "ECDH": QuantumExplanation(
        quantum_algorithm="Shor's algorithm",
        impact_summary="ECDH key exchange is completely broken by Shor's algorithm.",
        detailed_explanation=(
            "Elliptic Curve Diffie-Hellman relies on the ECDLP. Shor's algorithm solves "
            "this in polynomial time, enabling passive eavesdroppers with quantum computing "
            "capabilities to derive the shared secret."
        ),
    ),
}


def explain(algorithm_name: str) -> QuantumExplanation | None:
    """Return a Shor's algorithm explanation for the given algorithm.

    Returns ``None`` if the algorithm is not affected by Shor's.
    """
    return _SHOR_EXPLANATIONS.get(algorithm_name)
