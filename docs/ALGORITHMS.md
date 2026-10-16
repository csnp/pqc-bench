# PQC Algorithm Reference

Comprehensive reference for post-quantum cryptographic algorithms supported by PQC-Bench.

---

## Table of Contents

- [Overview](#overview)
- [Key Encapsulation Mechanisms (KEMs)](#key-encapsulation-mechanisms-kems)
  - [ML-KEM-512](#ml-kem-512)
  - [ML-KEM-768](#ml-kem-768)
  - [ML-KEM-1024](#ml-kem-1024)
- [Digital Signatures](#digital-signatures)
  - [ML-DSA-44](#ml-dsa-44)
  - [ML-DSA-65](#ml-dsa-65)
  - [ML-DSA-87](#ml-dsa-87)
  - [Falcon-512 (FN-DSA-512)](#falcon-512-fn-dsa-512)
  - [Falcon-1024 (FN-DSA-1024)](#falcon-1024-fn-dsa-1024)
  - [SLH-DSA-SHA2-128f](#slh-dsa-sha2-128f)
- [Algorithm Comparison](#algorithm-comparison)
- [Hybrid Modes](#hybrid-modes)
- [Selection Guide](#selection-guide)

---

## Overview

### NIST Post-Quantum Standards

| Standard | Algorithm Family | Type | Status |
|----------|-----------------|------|--------|
| FIPS 203 | ML-KEM (Kyber) | KEM | Finalized (Aug 2024) |
| FIPS 204 | ML-DSA (Dilithium) | Signature | Finalized (Aug 2024) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Signature | Finalized (Aug 2024) |
| FIPS 206 | FN-DSA (Falcon) | Signature | Draft (Expected 2025) |

### Security Levels

| NIST Level | Classical Equivalent | Quantum Equivalent | Use Case |
|------------|---------------------|-------------------|----------|
| 1 | AES-128 | Grover's on AES-128 | Short-term, constrained |
| 2 | SHA-256 collisions | - | General applications |
| 3 | AES-192 | Grover's on AES-192 | Long-term, general |
| 5 | AES-256 | Grover's on AES-256 | Highest security, CNSA 2.0 |

---

## Key Encapsulation Mechanisms (KEMs)

KEMs are used for key exchange, replacing ECDH and RSA key transport.

### ML-KEM-512

**NIST FIPS 203 | Security Level 1**

```bash
pqc-bench explain ml-kem-512
```

| Property | Value |
|----------|-------|
| Public Key | 800 bytes |
| Ciphertext | 768 bytes |
| Shared Secret | 32 bytes |
| Key Generation | ~0.01 ms |
| Encapsulation | ~0.01 ms |
| Decapsulation | ~0.01 ms |

**Use Cases:**
- Constrained IoT devices
- High-throughput systems where Level 1 is acceptable
- Automotive V2X with latency requirements

**Considerations:**
- Lowest security level (but still quantum-resistant)
- Smallest sizes and fastest performance
- Not suitable for long-term data protection

---

### ML-KEM-768

**NIST FIPS 203 | Security Level 3**

```bash
pqc-bench explain ml-kem-768
```

| Property | Value |
|----------|-------|
| Public Key | 1,184 bytes |
| Ciphertext | 1,088 bytes |
| Shared Secret | 32 bytes |
| Key Generation | ~0.02 ms |
| Encapsulation | ~0.02 ms |
| Decapsulation | ~0.02 ms |

**Use Cases:**
- General-purpose TLS
- Web applications
- Cloud services
- Most enterprise applications

**Considerations:**
- **Recommended default** for most applications
- Good balance of security and performance
- Widely deployed (Chrome, Cloudflare, AWS)
- ~2x size of ML-KEM-512 with higher security

---

### ML-KEM-1024

**NIST FIPS 203 | Security Level 5**

```bash
pqc-bench explain ml-kem-1024
```

| Property | Value |
|----------|-------|
| Public Key | 1,568 bytes |
| Ciphertext | 1,568 bytes |
| Shared Secret | 32 bytes |
| Key Generation | ~0.03 ms |
| Encapsulation | ~0.03 ms |
| Decapsulation | ~0.03 ms |

**Use Cases:**
- CNSA 2.0 compliance (required for NSS)
- Healthcare with 50+ year data retention
- Government classified systems
- Long-term secure messaging (Signal uses this)

**Considerations:**
- Highest security level
- Required for CNSA 2.0 compliance
- Still very fast, size is manageable
- Recommended for high-value, long-term data

---

## Digital Signatures

Digital signatures replace RSA and ECDSA for authentication and integrity.

### ML-DSA-44

**NIST FIPS 204 | Security Level 2**

```bash
pqc-bench explain ml-dsa-44
```

| Property | Value |
|----------|-------|
| Public Key | 1,312 bytes |
| Signature | 2,420 bytes |
| Sign | ~0.1 ms |
| Verify | ~0.03 ms |

**Use Cases:**
- API authentication tokens (JWT)
- High-volume signing operations
- Constrained devices with FPU
- Short-lived certificates

**Considerations:**
- Fastest ML-DSA variant
- Signature size may impact bandwidth-constrained protocols
- Good for high-throughput scenarios
- Not suitable for CNSA 2.0 compliance

---

### ML-DSA-65

**NIST FIPS 204 | Security Level 3**

```bash
pqc-bench explain ml-dsa-65
```

| Property | Value |
|----------|-------|
| Public Key | 1,952 bytes |
| Signature | 3,293 bytes |
| Sign | ~0.15 ms |
| Verify | ~0.05 ms |

**Use Cases:**
- General-purpose code signing
- TLS certificates
- Document signing
- Enterprise PKI

**Considerations:**
- **Recommended default** for most signature use cases
- Balanced security and performance
- Suitable for certificate chains
- Good library support

---

### ML-DSA-87

**NIST FIPS 204 | Security Level 5**

```bash
pqc-bench explain ml-dsa-87
```

| Property | Value |
|----------|-------|
| Public Key | 2,592 bytes |
| Signature | 4,595 bytes |
| Sign | ~0.2 ms |
| Verify | ~0.07 ms |

**Use Cases:**
- CNSA 2.0 compliance
- Root CA certificates
- Long-term archival signatures
- Government/defense systems

**Considerations:**
- Required for CNSA 2.0 compliance
- Larger signatures impact certificate chain size
- Still performant for most applications
- Use for high-security, long-term scenarios

---

### Falcon-512 (FN-DSA-512)

**NIST FIPS 206 (Draft) | Security Level 1**

```bash
pqc-bench explain falcon-512
```

| Property | Value |
|----------|-------|
| Public Key | 897 bytes |
| Signature | 666 bytes |
| Sign | ~0.3 ms |
| Verify | ~0.05 ms |

**Use Cases:**
- Bandwidth-constrained environments
- Certificate chains where size matters
- IoT with signature verification only

**Considerations:**
- **Smallest signatures** among NIST candidates
- Requires floating-point unit (FPU)
- Signing is slower than ML-DSA
- Not constant-time (timing side-channel concerns)
- FIPS 206 not yet finalized

---

### Falcon-1024 (FN-DSA-1024)

**NIST FIPS 206 (Draft) | Security Level 5**

```bash
pqc-bench explain falcon-1024
```

| Property | Value |
|----------|-------|
| Public Key | 1,793 bytes |
| Signature | 1,280 bytes |
| Sign | ~0.6 ms |
| Verify | ~0.1 ms |

**Use Cases:**
- High-security with signature size constraints
- Long-term archival with space constraints

**Considerations:**
- Smaller than ML-DSA-87 signatures
- Requires FPU
- Slower signing than ML-DSA
- Wait for FIPS 206 finalization for production

---

### SLH-DSA-SHA2-128f

**NIST FIPS 205 | Security Level 1**

```bash
pqc-bench explain slh-dsa-128f
```

| Property | Value |
|----------|-------|
| Public Key | 32 bytes |
| Signature | 17,088 bytes |
| Sign | ~3 ms |
| Verify | ~1 ms |

**Use Cases:**
- Ultra-conservative security requirements
- When lattice assumptions concern you
- Long-term archival (hash-based, well-understood)

**Considerations:**
- **Smallest public keys** but **largest signatures**
- Based on hash functions (well-understood security)
- Stateless (unlike XMSS/LMS)
- Very slow compared to ML-DSA
- "f" = fast variant; "s" variants are even slower but smaller

---

## Algorithm Comparison

### KEM Comparison

| Algorithm | Security | Public Key | Ciphertext | Speed |
|-----------|----------|------------|------------|-------|
| ML-KEM-512 | Level 1 | 800 B | 768 B | Fastest |
| ML-KEM-768 | Level 3 | 1,184 B | 1,088 B | Fast |
| ML-KEM-1024 | Level 5 | 1,568 B | 1,568 B | Fast |
| RSA-2048* | ~112 bits | 256 B | 256 B | Slow |
| ECDH-P256* | ~128 bits | 64 B | 64 B | Fast |

*Classical algorithms shown for reference (vulnerable to quantum attacks)

### Signature Comparison

| Algorithm | Security | Public Key | Signature | Sign | Verify |
|-----------|----------|------------|-----------|------|--------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,420 B | Fast | Fastest |
| ML-DSA-65 | Level 3 | 1,952 B | 3,293 B | Fast | Fast |
| ML-DSA-87 | Level 5 | 2,592 B | 4,595 B | Fast | Fast |
| Falcon-512 | Level 1 | 897 B | 666 B | Slow | Fast |
| Falcon-1024 | Level 5 | 1,793 B | 1,280 B | Slow | Fast |
| SLH-DSA-128f | Level 1 | 32 B | 17,088 B | Slowest | Slow |
| RSA-2048* | ~112 bits | 256 B | 256 B | Fast | Fast |
| ECDSA-P256* | ~128 bits | 64 B | 64 B | Fast | Fast |

*Classical algorithms shown for reference

---

## Hybrid Modes

Hybrid cryptography combines classical and post-quantum algorithms for defense-in-depth.

### X25519MLKEM768

**Components:** X25519 (classical) + ML-KEM-768 (PQC)

TLS supported group 4588 (0x11EC), defined in RFC 10024. The two shared secrets are concatenated, ML-KEM-768 first, and the result enters the TLS 1.3 key schedule:

```
Shared Secret = ML-KEM-768_shared || X25519_shared
```

**Deployed in:**
- Chrome/Chromium browsers (since Chrome 131, replacing the draft Kyber group 0x6399)
- Cloudflare edge
- AWS TLS

**Use case:** TLS 1.3 key exchange during transition period

---

### ECDSA-P256 + ML-DSA-44

**Components:** ECDSA-P256 (classical) + ML-DSA-44 (PQC)

**Use case:** Certificate signatures where both classical and PQC verification are needed

**Note:** Results in two signatures per certificate, increasing chain size

---

## Selection Guide

### Quick Decision Tree

```
Is this for CNSA 2.0 / government classified?
├── Yes → ML-KEM-1024, ML-DSA-87
└── No
    ├── Is this a constrained device (<512KB RAM)?
    │   ├── Yes → ML-KEM-512, ML-DSA-44
    │   └── No → ML-KEM-768, ML-DSA-65 (defaults)
    │
    ├── Is signature size critical (bandwidth-constrained)?
    │   ├── Yes → Consider Falcon-512 (requires FPU)
    │   └── No → ML-DSA-65
    │
    └── Is data retention > 30 years?
        ├── Yes → ML-KEM-1024, ML-DSA-87
        └── No → ML-KEM-768, ML-DSA-65
```

### By Use Case

| Use Case | KEM | Signature | Notes |
|----------|-----|-----------|-------|
| Web TLS | ML-KEM-768 | ML-DSA-65 | Use hybrid mode |
| Mobile app | ML-KEM-768 | ML-DSA-65 | Standard choice |
| IoT sensor | ML-KEM-512 | ML-DSA-44 | Size-constrained |
| Government | ML-KEM-1024 | ML-DSA-87 | CNSA 2.0 required |
| Healthcare | ML-KEM-1024 | ML-DSA-87 | Long retention |
| V2X automotive | ML-KEM-512 | ML-DSA-44 or Falcon | Latency critical |
| Archival | - | SLH-DSA | Conservative |

---

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
