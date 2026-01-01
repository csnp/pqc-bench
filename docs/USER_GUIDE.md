# PQC-Bench User Guide

Complete guide to using PQC-Bench for post-quantum cryptography recommendations.

## Table of Contents

- [Getting Started](#getting-started)
- [Core Commands](#core-commands)
- [Understanding Recommendations](#understanding-recommendations)
- [Migration Planning](#migration-planning)
- [Compliance Requirements](#compliance-requirements)
- [Critical Infrastructure](#critical-infrastructure)
- [Output Formats](#output-formats)
- [Best Practices](#best-practices)

---

## Getting Started

### Installation

```bash
# From PyPI
pip install pqc-bench

# From source
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e .
```

### Verify Installation

```bash
pqc-bench --version
# Output: pqc-bench 0.3.0
```

### Quick Test

```bash
pqc-bench recommend "web application with user authentication"
```

---

## Core Commands

### recommend

Get algorithm recommendations based on natural language queries.

```bash
pqc-bench recommend "<your use case description>"
```

**Tips for effective queries:**
- Include your platform: "running on AWS Lambda", "embedded ARM device"
- Mention constraints: "256KB RAM", "100ms latency requirement"
- Specify the use case: "TLS", "JWT signing", "file encryption"
- Include industry context: "healthcare", "financial", "automotive"

**Examples:**
```bash
# General web application
pqc-bench recommend "REST API with TLS and JWT tokens"

# Constrained environment
pqc-bench recommend "IoT sensor with 128KB RAM, battery powered"

# Industry-specific
pqc-bench recommend "healthcare application storing patient records"

# Specific protocol
pqc-bench recommend "TLS 1.3 for nginx web server"
```

### explain

Get detailed information about a specific algorithm.

```bash
pqc-bench explain <algorithm-name>
```

**Available algorithms:**
- `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`
- `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- `falcon-512`, `falcon-1024`
- `slh-dsa-128f`

**Examples:**
```bash
pqc-bench explain ml-kem-768
pqc-bench explain ml-dsa-44
pqc-bench explain falcon-512
```

### compare

Compare two algorithms side-by-side.

```bash
pqc-bench compare <algorithm-a> <algorithm-b>
```

**Examples:**
```bash
# Compare signature algorithms
pqc-bench compare ml-dsa-44 falcon-512

# Compare KEM security levels
pqc-bench compare ml-kem-768 ml-kem-1024

# Compare signature sizes
pqc-bench compare ml-dsa-65 slh-dsa-128f
```

### list

List all available algorithms with key properties.

```bash
pqc-bench list

# Filter by type
pqc-bench list --type kem
pqc-bench list --type signature
```

---

## Understanding Recommendations

### Security Levels

PQC-Bench uses NIST security levels:

| Level | Equivalent Classical Security | Recommended For |
|-------|------------------------------|-----------------|
| 1 | AES-128 | Short-term data, constrained devices |
| 2 | SHA-256 | General applications |
| 3 | AES-192 | Long-term data, general purpose |
| 5 | AES-256 | Highest security, CNSA 2.0 compliance |

### Algorithm Selection Criteria

When making recommendations, PQC-Bench considers:

1. **Use case type**: Key exchange vs. signatures
2. **Security requirements**: Data sensitivity, retention period
3. **Performance constraints**: CPU, memory, latency
4. **Compliance requirements**: FIPS, CNSA 2.0, industry regulations
5. **Platform**: x86_64, ARM, embedded
6. **Library availability**: Production-ready implementations

### Recommendation Confidence

Recommendations include confidence indicators:

- **Strong**: Clear best choice for the use case
- **Moderate**: Good choice, but alternatives exist
- **Conditional**: Depends on specific factors explained in notes

---

## Migration Planning

### From Classical Algorithms

```bash
pqc-bench migrate --from <classical-algorithm>
```

**Supported migrations:**

| From | Recommended PQC Replacement |
|------|----------------------------|
| RSA-2048 | ML-KEM-768 (encryption), ML-DSA-65 (signatures) |
| RSA-4096 | ML-KEM-1024 (encryption), ML-DSA-87 (signatures) |
| ECDSA-P256 | ML-DSA-44 or ML-DSA-65 |
| ECDSA-P384 | ML-DSA-65 or ML-DSA-87 |
| ECDH-P256 | ML-KEM-768 |
| X25519 | ML-KEM-768 |

**Examples:**
```bash
pqc-bench migrate --from rsa-2048
pqc-bench migrate --from ecdsa-p256
pqc-bench migrate --from x25519
```

### Hybrid Cryptography

During the transition period, hybrid modes combine classical and PQC:

```bash
pqc-bench hybrid
```

**Recommended hybrid modes:**

| Mode | Components | Use Case |
|------|------------|----------|
| X25519Kyber768 | X25519 + ML-KEM-768 | TLS key exchange |
| ECDSA-P256+ML-DSA-44 | ECDSA + ML-DSA | Certificate signatures |

**Why hybrid?**
- Maintains security if either algorithm is broken
- Required during transition (devices may not support PQC)
- Already deployed in Chrome, Cloudflare, AWS

---

## Compliance Requirements

### View Framework Requirements

```bash
pqc-bench compliance <framework>
```

**Available frameworks:**
- `cnsa-2.0` - NSA Commercial National Security Algorithm Suite 2.0
- `fips-140-3` - FIPS 140-3 cryptographic module requirements
- `pci-dss` - Payment Card Industry Data Security Standard
- `hipaa` - Health Insurance Portability and Accountability Act
- `fedramp` - Federal Risk and Authorization Management Program

**Examples:**
```bash
# NSA requirements for national security systems
pqc-bench compliance cnsa-2.0

# With specific use case
pqc-bench compliance cnsa-2.0 --use-case tls
pqc-bench compliance cnsa-2.0 --use-case signatures
```

### CNSA 2.0 Timeline

| Deadline | Requirement |
|----------|-------------|
| 2025 | Begin planning PQC migration |
| 2030 | Prefer PQC for new systems |
| 2033 | Exclusively use PQC |

---

## Critical Infrastructure

### Sector-Specific Guidance

```bash
# List all sectors
pqc-bench sector --list

# View compliance deadlines
pqc-bench sector --deadlines

# Get sector-specific guidance
pqc-bench sector <sector-name>
```

**Available sectors:**
- `space` - Space & Aerospace
- `automotive` - Automotive & EVs
- `industrial` - Industrial OT & SCADA
- `energy` - Energy & Utilities
- `healthcare` - Healthcare & Medical Devices
- `financial` - Financial Services
- `telecom` - Telecommunications & 5G

**Examples:**
```bash
pqc-bench sector healthcare
pqc-bench sector automotive
pqc-bench sector space
```

### Sector Output Includes

- Migration urgency level (CRITICAL, HIGH, MEDIUM)
- SNDL (Store Now, Decrypt Later) risk assessment
- Relevant regulations and deadlines
- Technical constraints specific to the sector
- Recommended algorithms
- Migration priority order
- Special considerations

---

## Output Formats

### Terminal Output (Default)

Rich formatted output with colors and boxes:

```bash
pqc-bench recommend "your query"
```

### Verbose Output

Detailed output with citations and additional context:

```bash
pqc-bench recommend "your query" --verbose
```

### JSON Output

Machine-readable format for integration:

```bash
pqc-bench recommend "your query" --json
```

**Example JSON output:**
```json
{
  "recommendation": "ML-KEM-768",
  "confidence": "high",
  "security_level": 3,
  "rationale": ["NIST standardized", "Good performance"],
  "alternatives": ["ML-KEM-1024"],
  "warnings": []
}
```

---

## Best Practices

### 1. Start with Your Use Case

Don't ask "what's the best algorithm?" Instead, describe your specific scenario:

```bash
# Good
pqc-bench recommend "mobile banking app with biometric auth, needs FIPS compliance"

# Less helpful
pqc-bench recommend "best encryption"
```

### 2. Consider Hybrid Mode During Transition

For production systems, use hybrid cryptography:

```bash
pqc-bench hybrid
```

### 3. Check Library Availability

Before choosing an algorithm, verify library support:

```bash
pqc-bench libraries
```

**Critical warning:** liboqs is NOT production-ready. Use AWS-LC, BoringSSL, or OpenSSL 3.5+ for production.

### 4. Assess SNDL Risk

For sensitive data, understand your threat timeline:

```bash
pqc-bench threat --data-type "customer PII" --retention "10 years"
```

### 5. Plan for Your Industry

Check sector-specific requirements:

```bash
pqc-bench sector <your-industry>
```

### 6. Verify Compliance Requirements

Check relevant frameworks before finalizing:

```bash
pqc-bench compliance cnsa-2.0
pqc-bench compliance fips-140-3
```

---

## Troubleshooting

### "No recommendation found"

Your query may be too vague. Add more context:
- Platform details
- Security requirements
- Industry context

### "Algorithm not found"

Check available algorithms:
```bash
pqc-bench list
```

Use the canonical name (e.g., `ml-kem-768`, not `Kyber768`).

### "Command not found"

Verify installation:
```bash
pip install --upgrade pqc-bench
pqc-bench --version
```

---

## Getting Help

```bash
# General help
pqc-bench --help

# Command-specific help
pqc-bench recommend --help
pqc-bench sector --help
```

For issues and feature requests: [GitHub Issues](https://github.com/csnp/pqc-bench/issues)
