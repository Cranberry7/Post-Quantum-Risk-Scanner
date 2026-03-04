"""Risk classifier — maps cryptographic findings to post-quantum risk categories.

This is the core of the Analysis Layer. It consults the knowledge base
to classify each finding, never inventing risk scores or making
speculative claims.
"""

from __future__ import annotations

from typing import List

from pq_risk_scanner.knowledge_base import lookup_algorithm
from pq_risk_scanner.models import (
    AnalysisResult,
    CryptographicFinding,
    RiskCategory,
)


def classify_finding(finding: CryptographicFinding) -> AnalysisResult:
    """Classify a single cryptographic finding against the knowledge base.

    Returns an ``AnalysisResult`` with the risk category populated.
    Quantum explanation and migration guidance are *not* attached here;
    those are added by subsequent pipeline stages.
    """
    profile = lookup_algorithm(finding.algorithm)

    if profile is None:
        return AnalysisResult(
            finding=finding,
            risk_category=RiskCategory.UNKNOWN,
        )

    return AnalysisResult(
        finding=finding,
        risk_category=profile.risk_category,
        effective_post_quantum_bits=profile.effective_pq_bits,
    )


def classify_findings(findings: List[CryptographicFinding]) -> List[AnalysisResult]:
    """Classify a batch of cryptographic findings."""
    return [classify_finding(f) for f in findings]
