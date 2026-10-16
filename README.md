# PQC-Bench

**Post-Quantum Cryptography Recommendation Engine**

*"What post-quantum crypto should I use?"* Finally, there's a tool for that.

[![CI](https://github.com/csnp/pqc-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/pqc-bench/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

[Why PQC-Bench](#why-pqc-bench) • [Quick Start](#quick-start) • [Features](#features) • [Documentation](#documentation) • [Contributing](#contributing)

---

## The Quantum Computing Challenge

Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade. NIST has finalized new standards (FIPS 203, 204, 205). But developers face a maze:

- 4 NIST standards with 15+ parameter variants
- Performance varies 10-50x by platform
- Key sizes vary 10-100x from classical
- Every benchmark says "it depends"
- Academic papers assume PhD knowledge
- No guidance for specific industries

**The real risk?** Adversaries are harvesting encrypted data *today* to decrypt when quantum computers arrive. This "Store Now, Decrypt Later" (SNDL) attack means your sensitive data may already be compromised.

---

## Why PQC-Bench

PQC-Bench gives you **answers**, not data dumps:

| Capability | PQC-Bench | Reading NIST Docs | Academic Papers |
|------------|-----------|-------------------|-----------------|
| Natural language queries | ✓ | ✗ | ✗ |
| Sector-specific guidance | ✓ | Partial | ✗ |
| Compliance deadline tracking | ✓ | Manual | ✗ |
| Library production-readiness | ✓ | ✗ | ✗ |
| SNDL threat assessment | ✓ | ✗ | ✗ |
| Protocol impact analysis | ✓ | Partial | Varies |
| Actionable recommendations | ✓ | ✗ | ✗ |
| Open source | ✓ | N/A | Varies |
| Price | Free | Free | Often paywalled |

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
pqc-bench compliance cnsa-2.0

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

pqc-bench threat --data-type "patient records" --retention "50 years"
# → EXTREME risk, immediate migration recommended
```

---

## Features

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
$ pqc-bench threat --data-type "patient health records" --retention "50 years"

Risk Level: EXTREME
Effective data lifespan: 100+ years
Recommendation: Begin migration immediately
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
$ pqc-bench impact ml-kem-768 --protocol tls

TLS Handshake Impact:
• Key size: +1,184 bytes (vs ECDH)
• Additional TCP segments: ~2
• Middlebox compatibility: Monitor for ossification
• MTU considerations: May fragment on constrained networks
```

---

## Algorithms Covered

### NIST Post-Quantum Standards

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

### Hybrid Modes

| Mode | Components | Deployed In |
|------|------------|-------------|
| X25519MLKEM768 | X25519 + ML-KEM-768 | Chrome, Cloudflare, AWS |
| ECDSA-P256+ML-DSA-44 | ECDSA + ML-DSA | Certificate chains |

---

## Commands Reference

| Command | Description |
|---------|-------------|
| `pqc-bench recommend "<query>"` | Natural language recommendation |
| `pqc-bench explain <algorithm>` | Deep dive on algorithm |
| `pqc-bench compare <a> <b>` | Side-by-side comparison |
| `pqc-bench list` | List all algorithms |
| `pqc-bench migrate --from <alg>` | Migration path from classical |
| `pqc-bench compliance <framework>` | CNSA 2.0, FIPS 140-3 requirements |
| `pqc-bench libraries` | Library production-readiness |
| `pqc-bench hybrid` | Hybrid mode guidance |
| `pqc-bench threat` | SNDL threat assessment |
| `pqc-bench impact <algorithm>` | Protocol impact analysis |
| `pqc-bench sector <name>` | Sector-specific guidance |

### Output Formats

```bash
pqc-bench recommend "query"           # Rich terminal output (default)
pqc-bench recommend "query" --verbose # Detailed with citations
pqc-bench recommend "query" --json    # Machine-readable JSON
```

---

## Documentation

- [User Guide](docs/USER_GUIDE.md) — Comprehensive usage instructions
- [Use Cases](docs/USE_CASES.md) — Detailed scenario walkthroughs
- [Algorithm Reference](docs/ALGORITHMS.md) — Deep dive on each algorithm
- [Sector Guide](docs/SECTORS.md) — Critical infrastructure details

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e ".[dev]"
pytest  # Run 227 tests
```

---

## About CSNP

PQC-Bench is developed by the **[Cybersecurity Non-Profit (CSNP)](https://csnp.org)**, a 501(c)(3) organization dedicated to making cybersecurity knowledge accessible to everyone through education, community, and practical resources.

### Our Mission

- **Accessibility**: Cybersecurity knowledge should be available to everyone
- **Community**: Supportive communities help people learn and grow together
- **Education**: Practical resources empower people to implement better security
- **Integrity**: The highest ethical standards in all operations

---

## QRAMM Toolkit

PQC-Bench is part of the **[Quantum Readiness Assurance Maturity Model (QRAMM)](https://qramm.org)** toolkit—a suite of open-source tools for post-quantum migration:

| Tool | Description |
|------|-------------|
| **[CryptoScan](https://github.com/csnp/qramm-cryptoscan)** | Cryptographic discovery scanner |
| **PQC-Bench** | Algorithm recommendation engine (this project) |
| **TLS-Analyzer** | TLS/SSL configuration analysis (coming soon) |
| **CryptoCBOM** | Cryptographic Bill of Materials generator (coming soon) |

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

---

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice-Based Key-Encapsulation Mechanism
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice-Based Digital Signature Algorithm
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) — Stateless Hash-Based Digital Signature Algorithm

### Additional Resources

- [NSA CNSA 2.0 Algorithm Guidance](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025 Cybersecurity Non-Profit (CSNP)

---

Built with purpose by **[CSNP](https://csnp.org)** — Advancing cybersecurity for everyone

[QRAMM](https://qramm.org) • [CSNP](https://csnp.org) • [Issues](https://github.com/csnp/pqc-bench/issues)

---

**Data last updated:** December 2024 | **Next update:** When NIST finalizes FIPS 206 (Falcon)
