# PQC-Bench Use Cases

Real-world scenarios demonstrating how to use PQC-Bench for post-quantum cryptography migration.

---

## Table of Contents

- [The Quantum Computing Challenge](#the-quantum-computing-challenge)
- [Why PQC-Bench](#why-pqc-bench)
- [Web Applications](#web-applications)
- [Mobile Applications](#mobile-applications)
- [IoT and Embedded Systems](#iot-and-embedded-systems)
- [Enterprise Infrastructure](#enterprise-infrastructure)
- [Financial Services](#financial-services)
- [Healthcare](#healthcare)
- [Government and Defense](#government-and-defense)
- [Critical Infrastructure](#critical-infrastructure)

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

## Web Applications

### Scenario: E-commerce Platform

**Context:** You're building an e-commerce platform that handles credit card transactions and user authentication.

**Concerns:**
- PCI-DSS compliance
- TLS for all communications
- JWT tokens for API authentication
- Long-term storage of transaction records

**Using PQC-Bench:**

```bash
# Get overall recommendation
$ pqc-bench recommend "e-commerce platform with payment processing, TLS, JWT auth"

# Check PCI-DSS requirements
$ pqc-bench compliance pci-dss

# Understand TLS impact
$ pqc-bench impact ml-kem-768 --protocol tls

# Check library options
$ pqc-bench libraries --fips-only
```

**Recommended Approach:**
1. Use **ML-KEM-768** for TLS key exchange (via X25519MLKEM768 hybrid)
2. Use **ML-DSA-65** for JWT signing
3. Deploy with AWS-LC or BoringSSL for production
4. Plan migration timeline based on PCI-DSS updates

---

### Scenario: SaaS API Platform

**Context:** Building a multi-tenant SaaS platform with REST APIs.

**Concerns:**
- API authentication
- Webhook signatures
- Data encryption at rest
- Multi-region deployment

**Using PQC-Bench:**

```bash
# API authentication
$ pqc-bench recommend "REST API authentication with short-lived tokens"

# Webhook signing
$ pqc-bench recommend "webhook payload signing, need small signatures"

# Compare signature sizes
$ pqc-bench compare ml-dsa-44 falcon-512
```

**Recommended Approach:**
1. **ML-DSA-44** for API tokens (fast verification)
2. **Falcon-512** for webhooks if signature size is critical (666 bytes vs 2,420)
3. Use hybrid mode for TLS endpoints

---

## Mobile Applications

### Scenario: Mobile Banking App

**Context:** iOS/Android banking app with biometric auth.

**Concerns:**
- FIPS compliance for financial data
- Performance on mobile devices
- Secure key storage
- Transaction signing

**Using PQC-Bench:**

```bash
# Mobile-specific recommendation
$ pqc-bench recommend "mobile banking app, iOS and Android, transaction signing"

# Check financial sector guidance
$ pqc-bench sector financial

# FIPS requirements
$ pqc-bench compliance fips-140-3
```

**Recommended Approach:**
1. **ML-KEM-768** for key exchange
2. **ML-DSA-65** for transaction signatures
3. Use platform secure enclave for key storage
4. Implement hybrid mode during transition

---

### Scenario: Secure Messaging App

**Context:** End-to-end encrypted messaging like Signal.

**Concerns:**
- Forward secrecy
- Long-term message security
- Cross-platform support
- Battery efficiency

**Using PQC-Bench:**

```bash
# Messaging-specific
$ pqc-bench recommend "end-to-end encrypted messaging with forward secrecy"

# What Signal uses
$ pqc-bench explain ml-kem-1024
```

**Recommended Approach:**
1. **ML-KEM-1024** for initial key exchange (matches Signal PQXDH)
2. Ratcheting protocol for forward secrecy
3. Consider hybrid X3DH + PQXDH during transition

---

## IoT and Embedded Systems

### Scenario: Industrial Sensors

**Context:** Battery-powered sensors with limited compute.

**Concerns:**
- 256KB RAM constraint
- 10-year battery life
- Infrequent data transmission
- OTA update capability

**Using PQC-Bench:**

```bash
# Constrained device
$ pqc-bench recommend "embedded sensor, 256KB RAM, battery powered, 10 year lifetime"

# Compare smallest options
$ pqc-bench compare ml-kem-512 ml-kem-768

# Industrial sector guidance
$ pqc-bench sector industrial
```

**Recommended Approach:**
1. **ML-KEM-512** for key exchange (smallest)
2. **ML-DSA-44** for firmware signing
3. Pre-shared keys for sensors without PQC capability
4. Gateway-based crypto termination

---

### Scenario: Smart Home Devices

**Context:** Consumer IoT devices (thermostats, cameras).

**Concerns:**
- Cost-constrained hardware
- Cloud connectivity
- User privacy
- 5-7 year product lifecycle

**Using PQC-Bench:**

```bash
# Consumer IoT
$ pqc-bench recommend "smart home device, cloud connected, cost sensitive"

# Check threat timeline
$ pqc-bench threat --data-type "home automation data" --retention "5 years"
```

**Recommended Approach:**
1. **ML-KEM-768** for cloud TLS
2. Focus on gateway/hub first, sensors later
3. Plan for firmware updates with crypto agility

---

## Enterprise Infrastructure

### Scenario: VPN Gateway

**Context:** Corporate VPN for remote workers.

**Concerns:**
- IKEv2/IPsec compatibility
- High throughput
- FIPS compliance
- Existing infrastructure integration

**Using PQC-Bench:**

```bash
# VPN recommendation
$ pqc-bench recommend "enterprise VPN gateway, IKEv2, high throughput"

# Compare KEM performance
$ pqc-bench explain ml-kem-768
```

**Recommended Approach:**
1. **ML-KEM-768** for IKE key exchange
2. Wait for vendor PQC support in IKEv2
3. Use hybrid mode for compatibility
4. Plan phased rollout by user group

---

### Scenario: PKI Infrastructure

**Context:** Enterprise certificate authority.

**Concerns:**
- Certificate chain sizes
- HSM support
- Backwards compatibility
- Multi-year certificates

**Using PQC-Bench:**

```bash
# PKI recommendation
$ pqc-bench recommend "enterprise PKI, certificate authority, 5-year certificates"

# Check certificate impact
$ pqc-bench impact ml-dsa-65 --protocol tls

# Library HSM support
$ pqc-bench libraries
```

**Recommended Approach:**
1. **ML-DSA-65** for CA certificates
2. Dual-signed certificates during transition
3. Test certificate chain sizes (ML-DSA adds ~2.4KB per signature)
4. Verify HSM vendor PQC support

---

## Financial Services

### Scenario: Payment Processing

**Context:** Payment gateway processing credit cards.

**Concerns:**
- PCI-DSS compliance
- SWIFT network compatibility
- Transaction latency
- Fraud detection integration

**Using PQC-Bench:**

```bash
# Payment processing
$ pqc-bench recommend "payment gateway, credit card processing, PCI-DSS"

# Financial sector deep dive
$ pqc-bench sector financial

# SWIFT guidance
$ pqc-bench compliance cnsa-2.0
```

**Recommended Approach:**
1. **ML-KEM-768** for TLS
2. **ML-DSA-65** for transaction signing
3. Coordinate with SWIFT for network migration
4. Monitor DORA (EU) 2025 deadline

---

### Scenario: Trading Platform

**Context:** High-frequency trading with microsecond latency requirements.

**Concerns:**
- Ultra-low latency
- Market data protection
- Regulatory compliance
- Co-located infrastructure

**Using PQC-Bench:**

```bash
# Low-latency trading
$ pqc-bench recommend "high-frequency trading, microsecond latency, market data"

# Compare fastest algorithms
$ pqc-bench compare ml-dsa-44 ml-dsa-65
```

**Recommended Approach:**
1. **ML-KEM-512** for lowest latency (if security permits)
2. **ML-DSA-44** for fastest signing
3. Hardware acceleration essential
4. Consider SLH-DSA for archival signatures (trades must be verifiable for years)

---

## Healthcare

### Scenario: Electronic Health Records

**Context:** Hospital EHR system storing patient data.

**Concerns:**
- HIPAA compliance
- 50+ year data retention (patient lifetime)
- FDA requirements for connected devices
- Legacy system integration

**Using PQC-Bench:**

```bash
# Healthcare EHR
$ pqc-bench recommend "electronic health records, HIPAA, 50 year retention"

# Healthcare sector guidance
$ pqc-bench sector healthcare

# Assess SNDL risk
$ pqc-bench threat --data-type "patient health records" --retention "50 years"
```

**Recommended Approach:**
1. **ML-KEM-1024** for key exchange (highest security)
2. **ML-DSA-87** for document signing
3. Hybrid mode mandatory during transition
4. Network segmentation for legacy devices

---

### Scenario: Medical Device

**Context:** Connected insulin pump or pacemaker.

**Concerns:**
- FDA approval cycles (6-24 months)
- Patient safety
- Limited compute resources
- Cannot fail open

**Using PQC-Bench:**

```bash
# Medical device
$ pqc-bench recommend "medical device, FDA regulated, patient safety critical"

# Healthcare sector
$ pqc-bench sector healthcare
```

**Recommended Approach:**
1. Design crypto-agility into new devices (FDA now requires this)
2. **ML-KEM-768** for device-to-cloud
3. Plan 18-month FDA approval timeline
4. Network segmentation for legacy devices

---

## Government and Defense

### Scenario: National Security System

**Context:** Classified government communications.

**Concerns:**
- CNSA 2.0 mandatory compliance
- 2030-2033 deadline
- Interoperability with allies
- Supply chain security

**Using PQC-Bench:**

```bash
# National security
$ pqc-bench recommend "classified government system, CNSA 2.0 required"

# CNSA 2.0 requirements
$ pqc-bench compliance cnsa-2.0

# Space sector (if applicable)
$ pqc-bench sector space
```

**Recommended Approach:**
1. **ML-KEM-1024** for key establishment (CNSA 2.0 mandates Level 5)
2. **ML-DSA-87** for signatures
3. No hybrid - pure PQC for new systems
4. Begin transition immediately (2030 deadline)

---

## Critical Infrastructure

### Scenario: Power Grid SCADA

**Context:** SCADA system controlling power distribution.

**Concerns:**
- 30-year equipment lifecycle
- Real-time control requirements
- Air-gapped networks
- NERC CIP compliance

**Using PQC-Bench:**

```bash
# Power grid
$ pqc-bench recommend "SCADA power grid, 30 year lifecycle, real-time control"

# Energy sector
$ pqc-bench sector energy

# Industrial sector
$ pqc-bench sector industrial
```

**Recommended Approach:**
1. Focus on IT/OT boundary first
2. **ML-KEM-768** for gateway communications
3. Legacy protocol gateways with PQC termination
4. Equipment refresh alignment with PQC rollout

---

### Scenario: Automotive V2X

**Context:** Vehicle-to-everything (V2X) safety communications.

**Concerns:**
- 100ms latency requirement
- CAN bus bandwidth limits
- 15-year vehicle lifetime
- No ECU FPU

**Using PQC-Bench:**

```bash
# Automotive V2X
$ pqc-bench recommend "automotive V2X, 100ms latency, no FPU"

# Automotive sector
$ pqc-bench sector automotive
```

**Recommended Approach:**
1. **ML-KEM-512** for latency (smallest)
2. **ML-DSA-44** for V2X certificates
3. Consider Falcon-512 for smaller signatures (but requires FPU)
4. Hardware crypto acceleration essential

---

### Scenario: Satellite Communication

**Context:** LEO satellite constellation communication.

**Concerns:**
- No software updates after launch
- Radiation-hardened processors (slow)
- 15-25 year mission lifetime
- Bandwidth constraints

**Using PQC-Bench:**

```bash
# Satellite
$ pqc-bench recommend "satellite communication, no updates possible, 25 year mission"

# Space sector
$ pqc-bench sector space
```

**Recommended Approach:**
1. **ML-KEM-1024** for ground-to-space (highest security)
2. **ML-DSA-87** for command authentication
3. NO crypto agility possible - choose for mission lifetime
4. Ground segment can use hybrid; spacecraft commits to one
5. Avoid Falcon (requires FPU, timing variability)

---

## Summary: Quick Reference

| Use Case | Recommended KEM | Recommended Signature | Key Consideration |
|----------|-----------------|----------------------|-------------------|
| Web/SaaS | ML-KEM-768 | ML-DSA-65 | Hybrid mode for TLS |
| Mobile | ML-KEM-768 | ML-DSA-65 | Platform secure enclave |
| IoT/Embedded | ML-KEM-512 | ML-DSA-44 | Size and power |
| Financial | ML-KEM-768 | ML-DSA-65 | FIPS, SWIFT coordination |
| Healthcare | ML-KEM-1024 | ML-DSA-87 | Long-term data retention |
| Government | ML-KEM-1024 | ML-DSA-87 | CNSA 2.0 mandatory |
| Industrial | ML-KEM-768 | ML-DSA-65 | IT/OT boundary focus |
| Automotive | ML-KEM-512 | ML-DSA-44 | Latency constraints |
| Space | ML-KEM-1024 | ML-DSA-87 | No updates possible |
