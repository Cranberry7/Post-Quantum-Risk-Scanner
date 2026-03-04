"""Quantum reasoning orchestrator.

Enriches ``AnalysisResult`` objects with ``QuantumExplanation`` by
dispatching to the appropriate explainer (Shor or Grover) based on
the algorithm's vulnerability profile.
"""

from __future__ import annotations

from typing import List

from pq_risk_scanner.knowledge_base import lookup_algorithm
from pq_risk_scanner.models import AnalysisResult
from pq_risk_scanner.quantum.grover_explainer import explain as grover_explain
from pq_risk_scanner.quantum.shor_explainer import explain as shor_explain


def enrich(result: AnalysisResult) -> AnalysisResult:
    """Attach a quantum explanation to a single analysis result.

    Looks up whether the algorithm is vulnerable to Shor's or Grover's
    and fetches the corresponding educational explanation.
    """
    profile = lookup_algorithm(result.finding.algorithm)
    if profile is None:
        return result

    explanation = None
    if profile.vulnerable_to == "shor":
        explanation = shor_explain(profile.canonical_name)
    elif profile.vulnerable_to == "grover":
        explanation = grover_explain(profile.canonical_name)

    if explanation is None:
        return result

    return AnalysisResult(
        finding=result.finding,
        risk_category=result.risk_category,
        quantum_explanation=explanation,
        migration_guidance=result.migration_guidance,
        effective_post_quantum_bits=result.effective_post_quantum_bits,
    )


def enrich_batch(results: List[AnalysisResult]) -> List[AnalysisResult]:
    """Attach quantum explanations to a batch of analysis results."""
    return [enrich(r) for r in results]
