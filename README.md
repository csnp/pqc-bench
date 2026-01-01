# PQC-Bench

**Post-Quantum Cryptography Benchmarking and Recommendation Engine**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-227%20passed-brightgreen.svg)](#)

A command-line tool that translates developer constraints into actionable post-quantum cryptography recommendations with full reasoning and citations.

---

## Why PQC-Bench?

### The Problem

Quantum computers will break RSA, ECDSA, and ECDH. NIST has finalized new standards. But developers face a maze:

```
Developer thinks: "I should use post-quantum crypto"

Developer finds:
├── 4 NIST standards with 15+ parameter variants
├── Performance varies 10-50x by platform
├── Key sizes vary 10-100x from classical
├── Every benchmark says "it depends"
├── Academic papers assume PhD knowledge
└── No guidance for their specific industry

Developer does: Keeps using RSA-2048 and hopes for the best
```

**The real risk?** Adversaries are harvesting encrypted data *today* to decrypt when quantum computers arrive. This "Store Now, Decrypt Later" (SNDL) attack means your sensitive data may already be compromised.

### The Solution

PQC-Bench provides **answers**, not data dumps:

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

---

## Real-World Use Cases

### For Application Developers

**"I'm building a mobile banking app. What crypto should I use?"**

```bash
$ pqc-bench recommend "mobile banking app with TLS and transaction signing"

# Returns: ML-KEM-768 for key exchange, ML-DSA-65 for signatures
# Explains: FIPS compliance for financial services, hybrid mode for transition
```

**"My IoT devices have only 256KB RAM"**

```bash
$ pqc-bench recommend "embedded sensor with 256KB RAM, battery powered"

# Returns: ML-KEM-512 (smallest NIST-approved KEM)
# Explains: Size/performance tradeoffs, why ML-DSA-44 for constrained signing
```

### For Security Architects

**"What's the SNDL risk for our healthcare data?"**

```bash
$ pqc-bench threat --data-type "patient health records" --retention "50 years"

# Returns: EXTREME risk - 100-year effective data lifespan
# Recommends: Immediate migration, hybrid cryptography during transition
```

**"Show me TLS handshake impact"**

```bash
$ pqc-bench impact ml-kem-768 --protocol tls

# Returns: +1,184 bytes key, ~2 extra TCP segments
# Explains: Middlebox compatibility, ossification risks, MTU considerations
```

### For Compliance Officers

**"What does CNSA 2.0 require?"**

```bash
$ pqc-bench compliance cnsa-2.0

# Returns: Complete requirements with deadlines (2030-2033)
# Lists: Approved algorithms, key sizes, migration timeline
```

**"We're in healthcare - what regulations apply?"**

```bash
$ pqc-bench sector healthcare

# Returns: FDA 524B, HIPAA implications, NIST 2030 deprecation
# Explains: Device approval cycles, patient safety constraints
```

### For Critical Infrastructure

**"I work on SCADA systems with 30-year equipment lifecycles"**

```bash
$ pqc-bench sector industrial

# Returns: IEC 62443 guidance, equipment refresh strategy
# Explains: Focus on IT/OT boundaries, gateway-based protection
```

**"What about automotive V2X with 100ms latency requirements?"**

```bash
$ pqc-bench sector automotive

# Returns: ML-KEM-512, ML-DSA-44 for latency constraints
# Explains: CAN bus limitations, Falcon tradeoffs, AUTOCRYPT PKI
```

---

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

---

## Commands Reference

### Getting Recommendations

| Command | Description |
|---------|-------------|
| `pqc-bench recommend "<query>"` | Natural language query for recommendations |
| `pqc-bench explain <algorithm>` | Deep dive on a specific algorithm |
| `pqc-bench compare <a> <b>` | Side-by-side algorithm comparison |
| `pqc-bench list` | List all available algorithms |

```bash
# Examples
pqc-bench recommend "TLS for web server with nginx"
pqc-bench explain ml-kem-768
pqc-bench compare ml-dsa-44 falcon-512
```

### Migration & Compliance

| Command | Description |
|---------|-------------|
| `pqc-bench migrate --from <classical>` | Migration path from RSA, ECDSA, etc. |
| `pqc-bench compliance <framework>` | CNSA 2.0, FIPS 140-3 requirements |
| `pqc-bench libraries` | Production-ready library ratings |
| `pqc-bench hybrid` | Hybrid modes (X25519+Kyber, ECDSA+ML-DSA) |

```bash
# Examples
pqc-bench migrate --from rsa-2048
pqc-bench compliance cnsa-2.0 --use-case tls
pqc-bench libraries --fips-only
```

### Threat & Impact Analysis

| Command | Description |
|---------|-------------|
| `pqc-bench threat` | SNDL threat assessment |
| `pqc-bench impact <algorithm>` | Protocol impact (TLS, certificates) |

```bash
# Examples
pqc-bench threat --data-type "financial records" --retention "30 years"
pqc-bench impact ml-kem-1024 --protocol tls
```

### Critical Infrastructure Sectors

| Command | Description |
|---------|-------------|
| `pqc-bench sector --list` | Overview of all 7 sectors |
| `pqc-bench sector --deadlines` | Compliance deadline timeline |
| `pqc-bench sector <name>` | Detailed sector guidance |

```bash
# Examples
pqc-bench sector --list
pqc-bench sector space        # Space & Aerospace
pqc-bench sector automotive   # Automotive & EVs
pqc-bench sector industrial   # Industrial OT & SCADA
pqc-bench sector energy       # Energy & Utilities
pqc-bench sector healthcare   # Healthcare & Medical Devices
pqc-bench sector financial    # Financial Services
pqc-bench sector telecom      # Telecommunications & 5G
```

### Output Formats

```bash
pqc-bench recommend "your query"           # Rich terminal output (default)
pqc-bench recommend "your query" --verbose # Detailed with citations
pqc-bench recommend "your query" --json    # Machine-readable JSON
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

### Hybrid Modes (Recommended for Transition)

| Mode | Components | Deployed In |
|------|------------|-------------|
| X25519Kyber768 | X25519 + ML-KEM-768 | Chrome, Cloudflare, AWS |
| ECDSA-P256+ML-DSA-44 | ECDSA + ML-DSA | Certificate chains |

---

## Critical Infrastructure Sectors

PQC-Bench provides sector-specific guidance based on real regulations and constraints:

| Sector | Urgency | Key Regulation | Unique Constraint |
|--------|---------|----------------|-------------------|
| Space & Aerospace | CRITICAL | CNSA 2.0 | No software updates post-launch |
| Healthcare | CRITICAL | FDA 524B | 100-year data lifespan |
| Financial Services | CRITICAL | SWIFT CSP, DORA | Network-wide coordination |
| Automotive | HIGH | ISO/SAE 21434 | V2X 100ms latency |
| Industrial OT | HIGH | IEC 62443 | 30-year equipment lifecycle |
| Energy & Utilities | HIGH | NERC CIP | Grid reliability requirements |
| Telecommunications | HIGH | GSMA PQ.03 | Multi-generation networks |

---

## Library Recommendations

**CRITICAL WARNING**: Not all PQC libraries are production-ready.

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

---

## Why Trust PQC-Bench?

### Validated Against Real Deployments

Our recommendations match what security experts chose:

| Deployment | They Chose | PQC-Bench Recommends |
|------------|------------|---------------------|
| Signal PQXDH | ML-KEM-1024 | ML-KEM-1024 for messaging |
| Chrome/Cloudflare | X25519Kyber768 | Hybrid for web TLS |
| AWS TLS | ML-KEM-768 | ML-KEM-768 for cloud |

### Comprehensive Testing

- **227 unit tests** covering algorithms, parsing, recommendations
- **Edge case validation** for sector detection accuracy
- **Word boundary matching** to prevent false positives

### Based on Authoritative Sources

- NIST FIPS 203, 204, 205 standards
- NSA CNSA 2.0 requirements
- Industry regulations (IEC 62443, FDA 524B, NERC CIP, SWIFT CSP)
- Real-world deployment experience

---

## Philosophy

1. **Security as foundation**: Defaults favor safety over speed
2. **Answers, not data dumps**: Actionable recommendations with reasoning
3. **Honest engineering**: Every claim cited, limitations surfaced
4. **Comprehensive coverage**: All major sectors, regulations, use cases

---

## Documentation

- [User Guide](docs/USER_GUIDE.md) - Comprehensive usage instructions
- [Use Cases](docs/USE_CASES.md) - Detailed scenario walkthroughs
- [Algorithm Reference](docs/ALGORITHMS.md) - Deep dive on each algorithm
- [Sector Guide](docs/SECTORS.md) - Critical infrastructure details

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e ".[dev]"
pytest  # Run tests
```

---

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

## About

**[CSNP](https://csnp.org)** (Cyber Security Non-Profit) advances cybersecurity through education, research, and open-source tools.

**PQC-Bench** is part of the **[QRAMM](https://qramm.org)** (Quantum Readiness Assurance Maturity Model) toolkit for quantum-safe migration.

---

*"Quantum computers will break today's encryption. The question isn't if, but when. Start your migration now."*
