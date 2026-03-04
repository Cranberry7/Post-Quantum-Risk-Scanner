"""Grover's algorithm impact explainer.

Provides educational explanations of how Grover's algorithm affects
symmetric encryption and hash functions.  Does *not* simulate
quantum computation.
"""

from __future__ import annotations

from pq_risk_scanner.models import QuantumExplanation

# ---------------------------------------------------------------------------
# Static explanation templates for symmetric/hash algorithms
# ---------------------------------------------------------------------------

_GROVER_EXPLANATIONS = {
    "AES-128": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="AES-128 is weakened to an effective 64-bit security level.",
        detailed_explanation=(
            "Grover's algorithm provides a quadratic speedup for brute-force key search. "
            "For AES-128, this reduces the effective security from 128 bits to 64 bits, "
            "which is below the generally accepted minimum threshold of 128 bits for "
            "long-term security. Migration to AES-256 is recommended."
        ),
    ),
    "AES-192": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="AES-192 is reduced to an effective 96-bit security level.",
        detailed_explanation=(
            "Grover's algorithm halves the effective security of AES-192 from 192 bits "
            "to 96 bits. While weaker, this is generally considered adequate for most "
            "applications but does not meet the 128-bit post-quantum security target."
        ),
    ),
    "AES-256": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="AES-256 retains a 128-bit effective security level — considered quantum-safe.",
        detailed_explanation=(
            "Grover's algorithm reduces AES-256 from 256-bit to 128-bit effective "
            "security. Since 128 bits remains well above practical brute-force "
            "thresholds, AES-256 is considered quantum-safe for the foreseeable future."
        ),
    ),
    "3DES": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="3DES is critically weakened to approximately 56-bit effective security.",
        detailed_explanation=(
            "3DES has an effective classical security of approximately 112 bits. "
            "Grover's algorithm halves this to roughly 56 bits, well below any "
            "acceptable security threshold. 3DES should be replaced immediately "
            "even without quantum threat considerations."
        ),
    ),
    "ChaCha20": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="ChaCha20 retains a 128-bit effective security level — considered quantum-safe.",
        detailed_explanation=(
            "ChaCha20 uses a 256-bit key. Grover's algorithm reduces its effective "
            "security to 128 bits, which is adequate for post-quantum security."
        ),
    ),
    "SHA-1": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="SHA-1 collision resistance is further weakened by Grover's algorithm.",
        detailed_explanation=(
            "SHA-1 is already considered broken classically due to demonstrated "
            "collision attacks. Grover's algorithm further reduces preimage resistance "
            "from 160 bits to 80 bits. SHA-1 should not be used for any security purpose."
        ),
    ),
    "SHA-256": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="SHA-256 retains 128-bit collision resistance — considered quantum-safe.",
        detailed_explanation=(
            "Grover's algorithm reduces SHA-256 preimage resistance from 256 to 128 bits "
            "and collision resistance from 128 to approximately 85 bits (via BHT algorithm). "
            "SHA-256 remains adequate for most post-quantum applications."
        ),
    ),
    "SHA-384": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="SHA-384 retains strong post-quantum security margins.",
        detailed_explanation=(
            "SHA-384 offers 192-bit collision resistance classically. Under quantum "
            "attacks this reduces but remains well above practical thresholds."
        ),
    ),
    "SHA-512": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="SHA-512 retains very strong post-quantum security margins.",
        detailed_explanation=(
            "SHA-512 offers 256-bit collision resistance classically. Even with "
            "Grover's quadratic speedup, the effective security remains 256 bits "
            "for preimage and approximately 170 bits for collision, which is quantum-safe."
        ),
    ),
    "SHA3-256": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="SHA3-256 retains 128-bit effective security — considered quantum-safe.",
        detailed_explanation=(
            "SHA-3 (Keccak) with 256-bit output has similar quantum resilience to SHA-256. "
            "Grover's reduces preimage resistance to 128 bits; collision resistance "
            "remains adequate."
        ),
    ),
    "MD5": QuantumExplanation(
        quantum_algorithm="Grover's algorithm",
        impact_summary="MD5 is critically broken classically and further weakened by Grover's.",
        detailed_explanation=(
            "MD5 has been broken for over a decade with practical collision attacks. "
            "Grover's algorithm further halves its already inadequate preimage "
            "resistance (128 bits → 64 bits). MD5 must not be used for any "
            "security-relevant purpose."
        ),
    ),
}


def explain(algorithm_name: str) -> QuantumExplanation | None:
    """Return a Grover's algorithm explanation for the given algorithm.

    Returns ``None`` if the algorithm is not affected by Grover's.
    """
    return _GROVER_EXPLANATIONS.get(algorithm_name)
