"""Domain models for the PQ Risk Scanner pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskCategory(Enum):
    """Post-quantum risk classification for a cryptographic primitive."""

    QUANTUM_UNSAFE = "quantum-unsafe"
    QUANTUM_WEAKENED = "quantum-weakened"
    QUANTUM_SAFE = "quantum-safe"
    UNKNOWN = "unknown"


class UsageContext(Enum):
    """Context in which a cryptographic primitive is used."""

    TLS = "TLS"
    SSH = "SSH"
    JWT = "JWT"
    PKI = "PKI"
    GENERAL = "General"
    UNKNOWN = "Unknown"


class AlgorithmFamily(Enum):
    """Broad family of a cryptographic algorithm."""

    ASYMMETRIC = "asymmetric"
    SYMMETRIC = "symmetric"
    HASH = "hash"
    KEY_EXCHANGE = "key-exchange"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CryptographicFinding:
    """A single detected cryptographic primitive — output of the Scanner Layer.

    This is purely factual; no risk evaluation is attached.
    """

    algorithm: str
    key_size: Optional[int]
    source_file: str
    usage_context: UsageContext = UsageContext.UNKNOWN
    algorithm_family: AlgorithmFamily = AlgorithmFamily.UNKNOWN
    line_number: Optional[int] = None
    raw_match: str = ""


@dataclass(frozen=True)
class QuantumExplanation:
    """Educational explanation of quantum impact — output of the Quantum Reasoning Layer."""

    quantum_algorithm: str  # e.g. "Shor's algorithm"
    impact_summary: str
    detailed_explanation: str


@dataclass(frozen=True)
class MigrationGuidance:
    """Conceptual migration recommendation toward post-quantum alternatives."""

    recommended_replacement: str
    rationale: str
    standard_reference: str  # e.g. "NIST FIPS 203"


@dataclass(frozen=True)
class AnalysisResult:
    """Fully enriched result for a single finding — final pipeline output.

    Combines the raw finding with its risk classification, quantum
    explanation, and migration guidance.
    """

    finding: CryptographicFinding
    risk_category: RiskCategory
    quantum_explanation: Optional[QuantumExplanation] = None
    migration_guidance: Optional[MigrationGuidance] = None
    effective_post_quantum_bits: Optional[int] = None
