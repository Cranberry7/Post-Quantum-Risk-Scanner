# System Architecture

## Overview
The system is designed as a modular, static analysis pipeline that separates cryptographic detection, risk analysis, quantum reasoning, and reporting into distinct components. This separation ensures clarity, extensibility, and deterministic behavior.

---

## High-Level Flow
Input artifacts are processed through the following stages:
1. Cryptographic detection
2. Post-quantum risk classification
3. Quantum impact explanation
4. Report generation

Each stage operates independently and communicates via well-defined data structures.

---

## Component Breakdown

### Scanner Layer
The scanner layer is responsible for detecting cryptographic primitives and their usage contexts. It performs no risk evaluation and produces a factual cryptographic inventory.

Responsibilities:
- Parse configuration files and artifacts
- Identify cryptographic algorithms and parameters
- Output structured detection results

---

### Analysis Layer
The analysis layer evaluates detected primitives against the defined threat model and knowledge base.

Responsibilities:
- Map detected primitives to post-quantum risk categories
- Apply threat model assumptions
- Generate migration guidance aligned with current research and standards

---

### Quantum Reasoning Layer
The quantum reasoning layer provides theoretical justification for cryptographic risk classifications.

Responsibilities:
- Explain the impact of Shor’s algorithm on public-key cryptography
- Explain the impact of Grover’s algorithm on symmetric cryptography
- Provide educational context without simulation claims

This layer exists to justify conclusions, not to perform quantum computation.

---

### Reporting Layer
The reporting layer transforms analysis results into user-facing artifacts.

Responsibilities:
- Generate console output
- Generate structured markdown reports
- Ensure clarity and traceability of conclusions

---

## Data Flow
- Input artifacts are scanned to produce a cryptographic inventory
- The inventory is passed to the analysis layer for classification
- Classified results are enriched with quantum explanations
- Final results are rendered by the reporting layer

---

## Design Principles
- Separation of concerns
- Deterministic outputs
- Standards-based reasoning
- Minimal assumptions
- Explicit non-goals

---

## Extensibility Considerations
The architecture allows for future extensions such as:
- Additional cryptographic scanners
- Integration with large language models for summarization
- Web-based user interfaces
- Containerized deployment

These extensions are intentionally excluded from the current implementation.

---

## Architectural Constraints
The system explicitly avoids:
- Hard-coded security scoring systems
- Black-box decision-making
- Speculative claims
- Over-engineered abstractions
