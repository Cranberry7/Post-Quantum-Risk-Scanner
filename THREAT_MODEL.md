# Threat Model

## Purpose
This project evaluates cryptographic systems under the assumption of a future adversary equipped with a large-scale, fault-tolerant quantum computer. The goal is to assess post-quantum cryptographic risk based on well-established quantum algorithms, not to perform penetration testing or exploit development.

---

## Assets Under Consideration
The assets evaluated by this system are strictly cryptographic in nature:
- Asymmetric private keys used for authentication and key exchange
- Symmetric keys used for encryption and integrity
- Digital signature schemes ensuring authenticity and non-repudiation
- Cryptographic trust guarantees provided by PKI and token-based systems

No physical, network, or application-layer assets are modeled.

---

## Adversary Model
The adversary is assumed to possess the following capabilities:
- Access to a large-scale, fault-tolerant quantum computer
- Ability to execute Shor’s algorithm for integer factorization and discrete logarithms
- Ability to execute Grover’s algorithm for accelerated brute-force search

The adversary is explicitly assumed **not** to:
- Exploit side-channel vulnerabilities
- Compromise endpoint systems
- Exploit software implementation bugs
- Perform active network attacks

---

## Attacks Considered

### Shor’s Algorithm
Shor’s algorithm enables polynomial-time attacks against cryptosystems based on integer factorization and discrete logarithms. This directly compromises:
- RSA
- DSA
- ECDSA
- Diffie–Hellman and Elliptic Curve Diffie–Hellman

### Grover’s Algorithm
Grover’s algorithm provides a quadratic speedup for brute-force search, effectively reducing the security strength of symmetric primitives and hash functions. This impacts:
- Symmetric encryption algorithms (e.g., AES)
- Cryptographic hash functions (e.g., SHA-2, SHA-3)

---

## Attacks Out of Scope
The following attack classes are explicitly excluded:
- Side-channel attacks (timing, power, EM)
- Fault injection attacks
- Implementation vulnerabilities
- Zero-day exploits
- Network-based attacks
- Classical cryptanalysis

---

## Assumptions
- Cryptographic primitives are implemented correctly and according to standards
- Configuration files accurately reflect deployed systems
- No attempt is made to predict real-world quantum computing timelines
- Post-quantum algorithms are evaluated based on current public research

---

## Security Goals
- Accurately classify cryptographic primitives by post-quantum risk category
- Provide standards-based reasoning for each classification
- Avoid false claims of security guarantees or timelines
