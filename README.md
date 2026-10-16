# PQC-Bench

**Post-Quantum Cryptography Recommendation Engine**

*"What post-quantum crypto should I use?"* Finally, there's a tool for that.

[![CI](https://github.com/csnp/pqc-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/pqc-bench/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

[Quick Start](#quick-start) • [What it does](#what-it-does) • [Documentation](#documentation)

---

## Quick Start

### Installation

Requires Python 3.10+ ([install Python](https://www.python.org/downloads/))

```bash
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e .
```

### Basic Usage

```bash
# Get a recommendation
pqc-bench recommend "REST API with JWT auth"

# Explain an algorithm
pqc-bench explain ml-kem-768

# Compare algorithms
pqc-bench compare ml-dsa-44 falcon-512

# Check compliance requirements
pqc-bench compliance cnsa_2_0

# Get sector-specific guidance
pqc-bench sector healthcare
```

### Try It Out

```bash
# Try some queries
pqc-bench recommend "mobile banking app"
# → ML-KEM-768 for key exchange, ML-DSA-65 for signatures

pqc-bench recommend "embedded sensor with 256KB RAM"
# → ML-KEM-512 (smallest NIST-approved KEM)

pqc-bench threat --data-type healthcare_records
# → ⚠ AT RISK
```

---

## What it does

### Natural Language Recommendations

Ask in plain English, get specific answers with reasoning:

```bash
$ pqc-bench recommend "REST API with JWT auth, running on AWS Lambda"

╭─ Recommendation ─────────────────────────────────────────────────────────────╮
│ ML-DSA-44 (FIPS 204)                                                         │
│                                                                              │
│ Why this algorithm:                                                          │
│ • Fast signing/verification for API workloads                                │
│ • NIST standardized with constant-time implementation                        │
│ • Excellent AWS-LC support for Lambda                                        │
│ • Level 2 security appropriate for authentication tokens                     │
│                                                                              │
│ Signature: 2,420 bytes | Verify: ~0.03ms on x86_64                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### 7 Critical Infrastructure Sectors

Sector-specific guidance based on real regulations:

| Sector | Urgency | Key Regulation | Unique Constraint |
|--------|---------|----------------|-------------------|
| Space & Aerospace | CRITICAL | CNSA 2.0 | No software updates post-launch |
| Healthcare | CRITICAL | FDA 524B | 100-year data lifespan |
| Financial Services | CRITICAL | SWIFT CSP, DORA | Network-wide coordination |
| Automotive | HIGH | ISO/SAE 21434 | V2X 100ms latency |
| Industrial OT | HIGH | IEC 62443 | 30-year equipment lifecycle |
| Energy & Utilities | HIGH | NERC CIP | Grid reliability requirements |
| Telecommunications | HIGH | GSMA PQ.03 | Multi-generation networks |

### SNDL Threat Assessment

Quantify your "Store Now, Decrypt Later" risk:

```bash
$ pqc-bench threat --data-type healthcare_records
...
⚠ AT RISK

CRITICAL: Data needs 102 years of protection, but quantum threat expected in 15
years. You are 87 years behind.
...
Recommended Action:
  Prioritize PQC for data at rest and in transit
```

### Library Production-Readiness

Not all PQC libraries are ready for production:

```bash
$ pqc-bench libraries

╭─ Production Ready ───────────────────────────────────────────────────────────╮
│ ✓ AWS-LC         - FIPS 140-3 validated, ML-KEM, ML-DSA                     │
│ ✓ BoringSSL      - Google's fork, hybrid TLS support                        │
│ ✓ OpenSSL 3.5+   - ML-KEM, ML-DSA (provider model)                          │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─ NOT Production Ready ───────────────────────────────────────────────────────╮
│ ✗ liboqs         - Research library, NOT for production                     │
│ ✗ pqcrypto       - Academic implementations                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Protocol Impact Analysis

Understand what PQC means for TLS, certificates, and bandwidth:

```bash
$ pqc-bench impact ml-kem-768

Protocol Impact: ML-KEM-768
...
  Baseline: ECDSA P-256 + X25519
...
  ClientHello       +1,152 bytes
  ServerHello       +1,056 bytes
  Total Handshake   +2,208 bytes
...
  Fragmentation risk: high
  Middlebox compatibility: poor
```

### Algorithms Covered

#### NIST Post-Quantum Standards

| Algorithm | Type | Standard | Security Level | Primary Use Case |
|-----------|------|----------|----------------|------------------|
| ML-KEM-512 | KEM | FIPS 203 | 1 | Constrained devices |
| ML-KEM-768 | KEM | FIPS 203 | 3 | General purpose (recommended) |
| ML-KEM-1024 | KEM | FIPS 203 | 5 | High security, long-term |
| ML-DSA-44 | Signature | FIPS 204 | 2 | Fast signing, small keys |
| ML-DSA-65 | Signature | FIPS 204 | 3 | General purpose (recommended) |
| ML-DSA-87 | Signature | FIPS 204 | 5 | CNSA 2.0 compliance |
| SLH-DSA-* | Signature | FIPS 205 | 1-5 | Conservative, hash-based |
| FN-DSA (Falcon) | Signature | FIPS 206* | 1,5 | Compact signatures |

*FIPS 206 pending finalization

#### Hybrid Modes

| Mode | Components | Deployed In |
|------|------------|-------------|
| X25519MLKEM768 | X25519 + ML-KEM-768 | Chrome, Cloudflare, AWS |
| ECDSA-P256+ML-DSA-44 | ECDSA + ML-DSA | Certificate chains |

---

## Documentation

- [User Guide](docs/USER_GUIDE.md): every command, output formats, and usage instructions
- [Use Cases](docs/USE_CASES.md): the quantum risk, why PQC-Bench, and scenario walkthroughs
- [Algorithm Reference](docs/ALGORITHMS.md): a deep dive on each algorithm
- [Sector Guide](docs/SECTORS.md): critical infrastructure details
- [Contributing](docs/CONTRIBUTING.md): development setup and running the tests

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice-Based Key-Encapsulation Mechanism
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Algorithm
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) — Stateless Hash-Based Digital Signature Algorithm

### Additional Resources

- [NSA CNSA 2.0 Algorithm Guidance](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## About CSNP

PQC-Bench is developed by the **[Cybersecurity Non-Profit (CSNP)](https://csnp.org)**, a 501(c)(3) organization dedicated to making cybersecurity knowledge accessible to everyone through education, community, and practical resources.

### Our Mission

- **Accessibility**: Cybersecurity knowledge should be available to everyone
- **Community**: Supportive communities help people learn and grow together
- **Education**: Practical resources empower people to implement better security
- **Integrity**: The highest ethical standards in all operations

### QRAMM Toolkit

PQC-Bench is part of the **[Quantum Readiness Assurance Maturity Model (QRAMM)](https://qramm.org)** toolkit—a suite of open-source tools for post-quantum migration:

| Tool | Description |
|------|-------------|
| **[CryptoScan](https://github.com/csnp/qramm-cryptoscan)** | Cryptographic discovery scanner |
| **PQC-Bench** | Algorithm recommendation engine (this project) |
| **TLS-Analyzer** | TLS/SSL configuration analysis (coming soon) |
| **CryptoCBOM** | Cryptographic Bill of Materials generator (coming soon) |

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025 Cybersecurity Non-Profit (CSNP)

---

Built with purpose by **[CSNP](https://csnp.org)** — Advancing cybersecurity for everyone

[QRAMM](https://qramm.org) • [CSNP](https://csnp.org) • [Issues](https://github.com/csnp/pqc-bench/issues)

---

**Data last updated:** December 2024 | **Next update:** When NIST finalizes FIPS 206 (Falcon)
