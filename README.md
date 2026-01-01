# PQC-Bench

**Post-Quantum Cryptography Benchmarking and Recommendation Engine**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## The Problem

Developers know they should adopt post-quantum cryptography, but existing resources fail them:

```
Developer thinks: "I should use post-quantum crypto"

Developer finds:
├── 4 NIST standards with 15+ parameter variants
├── Performance varies 10-50x by platform
├── Key sizes vary 10-100x from classical
├── Every benchmark says "it depends"
└── Academic papers assume PhD knowledge

Developer does: Keeps using RSA-2048
```

## The Solution

PQC-Bench provides **answers**, not data dumps:

```bash
$ pqc-bench "REST API with JWT auth, running on AWS Lambda"

  Recommendation: ML-DSA-44

  Why: Fast signing/verification, NIST standardized (FIPS 204),
  constant-time implementation, excellent AWS-LC support.
  Level 2 security appropriate for authentication tokens.

  Signature: 2,420 bytes | Verify: ~0.03ms on x86_64

  Run `pqc-bench explain ml-dsa-44` for details.
```

## Features

### Core Recommendations
- **Natural language queries**: Describe your use case, get recommendations
- **Intelligent reasoning**: Understands context (e.g., "fintech" implies compliance needs)
- **Comprehensive coverage**: All NIST PQC standards, major platforms, common use cases
- **Compliance mapping**: FIPS 140-3, CNSA 2.0, PCI-DSS, HIPAA, and more
- **Migration guidance**: Clear paths from RSA, ECDSA, and other classical algorithms

### Expert-Level Analysis (v0.2.0+)
- **Library maturity database**: Know which libraries are production-ready (CRITICAL: liboqs is NOT)
- **Hybrid cryptography**: X25519Kyber768 guidance (already deployed in Chrome/Cloudflare)
- **Protocol impact analysis**: TLS handshake sizes, certificate chain calculations, TCP segments
- **SNDL threat model**: "Store Now, Decrypt Later" prioritization based on data lifespan
- **Ossification risks**: Middlebox compatibility, fragmentation analysis

### Philosophy
- **Honest engineering**: Every claim cited, caveats surfaced, uncertainty acknowledged

## Installation

```bash
pip install pqc-bench
```

Or from source:

```bash
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e ".[dev]"
```

## Quick Start

```bash
# Get a recommendation
pqc-bench "mobile banking app with TLS and JWT"

# Learn about a specific algorithm
pqc-bench explain ml-kem-768

# Compare algorithms
pqc-bench compare ml-dsa-44 falcon-512

# Migration guidance
pqc-bench migrate --from ecdsa-p256

# Compliance requirements
pqc-bench compliance cnsa-2.0 --use-case tls
```

## Commands

### Recommendations & Research

| Command | Description |
|---------|-------------|
| `pqc-bench recommend "<query>"` | Get algorithm recommendation for your use case |
| `pqc-bench explain <algorithm>` | Deep dive on a specific algorithm |
| `pqc-bench compare <a> <b>` | Side-by-side comparison |
| `pqc-bench list` | List all available algorithms |

### Migration & Compliance

| Command | Description |
|---------|-------------|
| `pqc-bench migrate --from <classical>` | Migration path from classical crypto |
| `pqc-bench compliance <framework>` | Framework-specific requirements |
| `pqc-bench libraries` | Production-ready library recommendations |
| `pqc-bench hybrid` | Hybrid cryptography modes (X25519+ML-KEM) |

### Threat & Impact Analysis

| Command | Description |
|---------|-------------|
| `pqc-bench threat` | SNDL (Store Now, Decrypt Later) threat assessment |
| `pqc-bench impact <algorithm>` | Protocol impact analysis (TLS, certificates) |

## Output Formats

```bash
# Quick answer (default)
pqc-bench "your query"

# Detailed with citations
pqc-bench "your query" --verbose

# Machine-readable JSON
pqc-bench "your query" --json
```

## Algorithms Covered

### NIST Standards

| Algorithm | Type | FIPS | Use Case |
|-----------|------|------|----------|
| ML-KEM-512/768/1024 | KEM | FIPS 203 | Key exchange, encryption |
| ML-DSA-44/65/87 | Signature | FIPS 204 | Digital signatures |
| SLH-DSA-* | Signature | FIPS 205 | Stateless hash-based signatures |
| FN-DSA (Falcon) | Signature | FIPS 206 (pending) | Compact signatures |

### Compliance Frameworks

- NIST FIPS 140-3
- NSA CNSA 2.0
- Common Criteria
- PCI-DSS 4.0 implications

## Philosophy

1. **Security as foundation**: Defaults favor safety over speed
2. **Intelligence, not pattern matching**: Context-aware recommendations
3. **Comprehensiveness as credibility**: The definitive source
4. **Honest engineering**: Every claim cited, limitations surfaced

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## About CSNP

[CSNP](https://csnp.org) (Cyber Security Non-Profit) advances cybersecurity through education, research, and open-source tools. PQC-Bench is part of the [QRAMM](https://qramm.org) quantum readiness toolkit.

---

*"Don't give developers data. Give them answers."*
