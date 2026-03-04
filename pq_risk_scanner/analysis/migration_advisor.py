"""Migration advisor — generates post-quantum migration guidance.

Produces conceptual, standards-based recommendations for migrating
away from quantum-vulnerable cryptographic primitives.
"""

from __future__ import annotations

from typing import List, Optional

from pq_risk_scanner.knowledge_base import lookup_algorithm
from pq_risk_scanner.models import (
    AnalysisResult,
    MigrationGuidance,
    RiskCategory,
)


def advise(result: AnalysisResult) -> AnalysisResult:
    """Attach migration guidance to a classified result.

    Only produces guidance for findings that are quantum-unsafe
    or quantum-weakened.  Quantum-safe findings are returned as-is.
    """
    if result.risk_category in (RiskCategory.QUANTUM_SAFE, RiskCategory.UNKNOWN):
        return result

    guidance = _build_guidance(result)
    if guidance is None:
        return result

    return AnalysisResult(
        finding=result.finding,
        risk_category=result.risk_category,
        quantum_explanation=result.quantum_explanation,
        migration_guidance=guidance,
        effective_post_quantum_bits=result.effective_post_quantum_bits,
    )


def advise_batch(results: List[AnalysisResult]) -> List[AnalysisResult]:
    """Attach migration guidance to a batch of results."""
    return [advise(r) for r in results]


def _build_guidance(result: AnalysisResult) -> Optional[MigrationGuidance]:
    """Construct migration guidance from the knowledge base."""
    profile = lookup_algorithm(result.finding.algorithm)
    if profile is None or profile.post_quantum_replacement is None:
        return None

    rationale = (
        f"{profile.canonical_name} is classified as {result.risk_category.value} "
        f"because it is vulnerable to {_human_quantum_algo(profile.vulnerable_to)}. "
        f"Migrating to {profile.post_quantum_replacement} provides "
        f"post-quantum security."
    )

    return MigrationGuidance(
        recommended_replacement=profile.post_quantum_replacement,
        rationale=rationale,
        standard_reference=profile.replacement_standard or "N/A",
    )


def _human_quantum_algo(key: str) -> str:
    """Convert internal key to a human-readable quantum algorithm name."""
    return {
        "shor": "Shor's algorithm",
        "grover": "Grover's algorithm",
    }.get(key, key)
