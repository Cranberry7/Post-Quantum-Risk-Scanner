# Post-Quantum Risk Assessment Report

*Generated: 2026-03-17 03:54 UTC*

---

## Summary

- 🔴 **12** finding(s) classified as **quantum-unsafe**
- 🟡 **2** finding(s) classified as **quantum-weakened**
- 🟢 **7** finding(s) classified as **quantum-safe**
- ⚪ **6** finding(s) classified as **unknown**

**Total findings:** 27

---

## Cryptographic Inventory

| Algorithm | Key Size | Context | Risk | PQ Bits | Source |
|-----------|----------|---------|------|---------|--------|
| RSA | 2048 | General | 🔴 quantum-unsafe | 0 | tests\samples\crypto_usage.py |
| ECDSA | 256 | General | 🔴 quantum-unsafe | 0 | tests\samples\crypto_usage.py |
| SHA-256 | — | General | 🟢 quantum-safe | 128 | tests\samples\crypto_usage.py |
| MD5 | — | General | 🔴 quantum-unsafe | 64 | tests\samples\crypto_usage.py |
| SHA-1 | — | General | 🔴 quantum-unsafe | 80 | tests\samples\crypto_usage.py |
| AES-256 | 256 | General | 🟢 quantum-safe | 128 | tests\samples\crypto_usage.py |
| ECDHE | — | TLS | ⚪ unknown | — | tests\samples\nginx_tls.conf |
| RSA | — | TLS | 🔴 quantum-unsafe | 0 | tests\samples\nginx_tls.conf |
| AES256-GCM | 256 | TLS | ⚪ unknown | — | tests\samples\nginx_tls.conf |
| SHA384 | 384 | TLS | 🟢 quantum-safe | 192 | tests\samples\nginx_tls.conf |
| AES128-GCM | 128 | TLS | ⚪ unknown | — | tests\samples\nginx_tls.conf |
| SHA256 | 256 | TLS | 🟢 quantum-safe | 128 | tests\samples\nginx_tls.conf |
| DHE | — | TLS | ⚪ unknown | — | tests\samples\nginx_tls.conf |
| ssh-ed25519 | 25519 | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| ssh-rsa | — | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| ecdsa-sha2-nistp256 | 2 | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| curve25519-sha256 | 25519 | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| diffie-hellman-group14-sha256 | 14 | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| diffie-hellman-group16-sha512 | 16 | SSH | 🔴 quantum-unsafe | 0 | tests\samples\sshd_config |
| aes256-gcm@openssh.com | 256 | SSH | 🟢 quantum-safe | 128 | tests\samples\sshd_config |
| aes128-gcm@openssh.com | 128 | SSH | 🟡 quantum-weakened | 64 | tests\samples\sshd_config |
| chacha20-poly1305@openssh.com | 20 | SSH | 🟢 quantum-safe | 128 | tests\samples\sshd_config |
| aes256-ctr | 256 | SSH | 🟢 quantum-safe | 128 | tests\samples\sshd_config |
| aes128-ctr | 128 | SSH | 🟡 quantum-weakened | 64 | tests\samples\sshd_config |
| hmac-sha2-256 | 2 | SSH | ⚪ unknown | — | tests\samples\sshd_config |
| hmac-sha2-512 | 2 | SSH | ⚪ unknown | — | tests\samples\sshd_config |
| RSA | 2048 | PKI | 🔴 quantum-unsafe | 0 | tests\samples\test_rsa2048.pem |

---

## Quantum Impact Analysis

### RSA

**RSA is completely broken by a sufficiently large quantum computer.**

Shor's algorithm solves the integer factorization problem in polynomial time O((log N)^3). Since RSA security depends entirely on the hardness of factoring the product of two large primes, a fault-tolerant quantum computer running Shor's algorithm would recover the private key from the public key, regardless of key size. This renders all RSA key sizes equally vulnerable.

### ECDSA

**ECDSA is completely broken by Shor's algorithm.**

ECDSA security depends on the Elliptic Curve Discrete Logarithm Problem (ECDLP). Shor's algorithm, adapted for elliptic curves, solves the ECDLP in polynomial time. This means all ECDSA key sizes (P-256, P-384, P-521) are equally vulnerable to a sufficiently large quantum computer.

### SHA-256

**SHA-256 retains 128-bit collision resistance — considered quantum-safe.**

Grover's algorithm reduces SHA-256 preimage resistance from 256 to 128 bits and collision resistance from 128 to approximately 85 bits (via BHT algorithm). SHA-256 remains adequate for most post-quantum applications.

### MD5

**MD5 is critically broken classically and further weakened by Grover's.**

MD5 has been broken for over a decade with practical collision attacks. Grover's algorithm further halves its already inadequate preimage resistance (128 bits → 64 bits). MD5 must not be used for any security-relevant purpose.

### SHA-1

**SHA-1 collision resistance is further weakened by Grover's algorithm.**

SHA-1 is already considered broken classically due to demonstrated collision attacks. Grover's algorithm further reduces preimage resistance from 160 bits to 80 bits. SHA-1 should not be used for any security purpose.

### AES-256

**AES-256 retains a 128-bit effective security level — considered quantum-safe.**

Grover's algorithm reduces AES-256 from 256-bit to 128-bit effective security. Since 128 bits remains well above practical brute-force thresholds, AES-256 is considered quantum-safe for the foreseeable future.

### RSA

**RSA is completely broken by a sufficiently large quantum computer.**

Shor's algorithm solves the integer factorization problem in polynomial time O((log N)^3). Since RSA security depends entirely on the hardness of factoring the product of two large primes, a fault-tolerant quantum computer running Shor's algorithm would recover the private key from the public key, regardless of key size. This renders all RSA key sizes equally vulnerable.

### SHA384

**SHA-384 retains strong post-quantum security margins.**

SHA-384 offers 192-bit collision resistance classically. Under quantum attacks this reduces but remains well above practical thresholds.

### SHA256

**SHA-256 retains 128-bit collision resistance — considered quantum-safe.**

Grover's algorithm reduces SHA-256 preimage resistance from 256 to 128 bits and collision resistance from 128 to approximately 85 bits (via BHT algorithm). SHA-256 remains adequate for most post-quantum applications.

### ssh-ed25519

**Ed25519 is completely broken by Shor's algorithm.**

Ed25519 is an EdDSA signature scheme on Curve25519. Like all elliptic-curve schemes, it is vulnerable to Shor's algorithm solving the ECDLP. The private key can be recovered from the public key in polynomial time.

### ssh-rsa

**RSA is completely broken by a sufficiently large quantum computer.**

Shor's algorithm solves the integer factorization problem in polynomial time O((log N)^3). Since RSA security depends entirely on the hardness of factoring the product of two large primes, a fault-tolerant quantum computer running Shor's algorithm would recover the private key from the public key, regardless of key size. This renders all RSA key sizes equally vulnerable.

### ecdsa-sha2-nistp256

**ECDSA is completely broken by Shor's algorithm.**

ECDSA security depends on the Elliptic Curve Discrete Logarithm Problem (ECDLP). Shor's algorithm, adapted for elliptic curves, solves the ECDLP in polynomial time. This means all ECDSA key sizes (P-256, P-384, P-521) are equally vulnerable to a sufficiently large quantum computer.

### curve25519-sha256

**ECDH key exchange is completely broken by Shor's algorithm.**

Elliptic Curve Diffie-Hellman relies on the ECDLP. Shor's algorithm solves this in polynomial time, enabling passive eavesdroppers with quantum computing capabilities to derive the shared secret.

### aes256-gcm@openssh.com

**AES-256 retains a 128-bit effective security level — considered quantum-safe.**

Grover's algorithm reduces AES-256 from 256-bit to 128-bit effective security. Since 128 bits remains well above practical brute-force thresholds, AES-256 is considered quantum-safe for the foreseeable future.

### aes128-gcm@openssh.com

**AES-128 is weakened to an effective 64-bit security level.**

Grover's algorithm provides a quadratic speedup for brute-force key search. For AES-128, this reduces the effective security from 128 bits to 64 bits, which is below the generally accepted minimum threshold of 128 bits for long-term security. Migration to AES-256 is recommended.

### chacha20-poly1305@openssh.com

**ChaCha20 retains a 128-bit effective security level — considered quantum-safe.**

ChaCha20 uses a 256-bit key. Grover's algorithm reduces its effective security to 128 bits, which is adequate for post-quantum security.

### aes256-ctr

**AES-256 retains a 128-bit effective security level — considered quantum-safe.**

Grover's algorithm reduces AES-256 from 256-bit to 128-bit effective security. Since 128 bits remains well above practical brute-force thresholds, AES-256 is considered quantum-safe for the foreseeable future.

### aes128-ctr

**AES-128 is weakened to an effective 64-bit security level.**

Grover's algorithm provides a quadratic speedup for brute-force key search. For AES-128, this reduces the effective security from 128 bits to 64 bits, which is below the generally accepted minimum threshold of 128 bits for long-term security. Migration to AES-256 is recommended.

### RSA

**RSA is completely broken by a sufficiently large quantum computer.**

Shor's algorithm solves the integer factorization problem in polynomial time O((log N)^3). Since RSA security depends entirely on the hardness of factoring the product of two large primes, a fault-tolerant quantum computer running Shor's algorithm would recover the private key from the public key, regardless of key size. This renders all RSA key sizes equally vulnerable.

---

## Migration Recommendations

| Current Algorithm | Recommended Replacement | Standard |
|-------------------|-------------------------|----------|
| RSA | ML-KEM (Kyber) | NIST FIPS 203 |
| ECDSA | ML-DSA (Dilithium) | NIST FIPS 204 |
| MD5 | SHA-3-256 or SHA-256 | NIST SP 800-131A |
| SHA-1 | SHA-3-256 or SHA-256 | NIST SP 800-131A |
| ssh-ed25519 | ML-DSA (Dilithium) | NIST FIPS 204 |
| ssh-rsa | ML-KEM (Kyber) | NIST FIPS 203 |
| ecdsa-sha2-nistp256 | ML-DSA (Dilithium) | NIST FIPS 204 |
| curve25519-sha256 | ML-KEM (Kyber) | NIST FIPS 203 |
| diffie-hellman-group14-sha256 | ML-KEM (Kyber) | NIST FIPS 203 |
| diffie-hellman-group16-sha512 | ML-KEM (Kyber) | NIST FIPS 203 |
| aes128-gcm@openssh.com | AES-256 | NIST SP 800-131A |
| aes128-ctr | AES-256 | NIST SP 800-131A |

### Rationale

- **RSA:** RSA is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-KEM (Kyber) provides post-quantum security.
- **ECDSA:** ECDSA is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-DSA (Dilithium) provides post-quantum security.
- **MD5:** MD5 is classified as quantum-unsafe because it is vulnerable to Grover's algorithm. Migrating to SHA-3-256 or SHA-256 provides post-quantum security.
- **SHA-1:** SHA-1 is classified as quantum-unsafe because it is vulnerable to Grover's algorithm. Migrating to SHA-3-256 or SHA-256 provides post-quantum security.
- **ssh-ed25519:** Ed25519 is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-DSA (Dilithium) provides post-quantum security.
- **ssh-rsa:** RSA is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-KEM (Kyber) provides post-quantum security.
- **ecdsa-sha2-nistp256:** ECDSA is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-DSA (Dilithium) provides post-quantum security.
- **curve25519-sha256:** ECDH is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-KEM (Kyber) provides post-quantum security.
- **diffie-hellman-group14-sha256:** Diffie-Hellman is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-KEM (Kyber) provides post-quantum security.
- **diffie-hellman-group16-sha512:** Diffie-Hellman is classified as quantum-unsafe because it is vulnerable to Shor's algorithm. Migrating to ML-KEM (Kyber) provides post-quantum security.
- **aes128-gcm@openssh.com:** AES-128 is classified as quantum-weakened because it is vulnerable to Grover's algorithm. Migrating to AES-256 provides post-quantum security.
- **aes128-ctr:** AES-128 is classified as quantum-weakened because it is vulnerable to Grover's algorithm. Migrating to AES-256 provides post-quantum security.

---

*This report provides analytical insight based on current public research and NIST standards. It does not constitute a security guarantee or compliance assessment.*
