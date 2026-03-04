# Project Scope

## Objective
The objective of this project is to build a static analysis tool that inventories cryptographic usage in software systems and evaluates the associated risk under post-quantum threat models.

---

## In Scope
The following functionality is explicitly included:
- Static detection of cryptographic primitives in configuration files and artifacts
- Identification of cryptographic usage contexts (TLS, SSH, JWT, PKI)
- Classification of primitives as quantum-unsafe, quantum-weakened, or quantum-resistant
- Standards-based explanation of quantum impact
- Generation of human-readable risk assessment reports
- Conceptual migration guidance toward post-quantum alternatives

---

## Out of Scope
The following are explicitly excluded from this project:
- Live network scanning or traffic inspection
- Exploit development or vulnerability exploitation
- Runtime instrumentation
- Performance benchmarking
- Compliance certification or regulatory auditing
- Prediction of quantum computing timelines
- Automated remediation or code modification

---

## Supported Inputs
The tool supports analysis of the following input artifacts:
- PEM-encoded certificates and keys
- Text-based configuration files (e.g., TLS, SSH)
- Limited source code snippets for cryptographic usage detection

Inputs are analyzed statically and offline.

---

## Supported Outputs
The tool produces:
- A cryptographic inventory of detected primitives
- Post-quantum risk classification for each primitive
- Explanation of quantum-related weaknesses or strengths
- Conceptual migration recommendations aligned with current standards

---

## Non-Goals
This project is not:
- A vulnerability scanner
- A penetration testing tool
- A compliance assessment platform
- A real-time security monitoring system

The tool provides analytical insight, not security guarantees.
