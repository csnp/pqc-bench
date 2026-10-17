# Critical Infrastructure Sector Guide

Detailed PQC guidance for critical infrastructure sectors based on real-world regulations, constraints, and deployment considerations.

---

## Table of Contents

- [Overview](#overview)
- [Space & Aerospace](#space--aerospace)
- [Automotive & EVs](#automotive--evs)
- [Industrial OT & SCADA](#industrial-ot--scada)
- [Energy & Utilities](#energy--utilities)
- [Healthcare & Medical Devices](#healthcare--medical-devices)
- [Financial Services](#financial-services)
- [Telecommunications & 5G](#telecommunications--5g)
- [Compliance Deadlines](#compliance-deadlines)

---

## Overview

### Urgency Levels

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| **CRITICAL** | Immediate action needed | Begin migration now |
| **HIGH** | Start within 12 months | Planning and pilots |
| **MEDIUM** | Start within 2-3 years | Assessment phase |
| **PLANNING** | Begin planning | Awareness and budgeting |

### SNDL Risk Assessment

"Store Now, Decrypt Later" (SNDL) is the primary quantum threat. Adversaries harvest encrypted data today to decrypt when quantum computers arrive.

| Risk Level | Data Lifespan | Examples |
|------------|---------------|----------|
| **EXTREME** | 30-100+ years | Health records, classified intel, financial |
| **HIGH** | 10-30 years | Infrastructure data, corporate secrets |
| **MEDIUM** | 5-10 years | Business communications |
| **LOW** | <5 years | Session data, ephemeral keys |

---

## Space & Aerospace

```bash
pqc-bench sector space
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | CRITICAL |
| **SNDL Risk** | EXTREME |
| **Data Lifespan** | 50+ years |
| **Equipment Lifecycle** | 25 years |

### Regulatory Framework

| Regulation | Authority | Status | Deadline |
|------------|-----------|--------|----------|
| CNSA 2.0 | NSA | Mandatory | 2030-2033 |
| NASA-STD-1006A | NASA | Recommended | - |
| CCSDS SDLS | CCSDS | PQC updates expected | - |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **No software updates** | BLOCKING | Choose algorithm for entire mission lifetime |
| **Radiation-hardened CPUs** | MAJOR | 10-100x slower than commercial; algorithm performance critical |
| **High latency** | MAJOR | Deep space: minutes to hours; interactive protocols impossible |
| **Bandwidth constraints** | MAJOR | Limited RF; signature/key sizes impact mission data |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-1024 | Highest security for long missions |
| Signature | ML-DSA-87 | CNSA 2.0 Level 5 required |
| Hybrid | SecP384r1MLKEM1024 | Ground segment only; carries ML-KEM-1024 as CNSA 2.0 requires |

### Migration Priority

1. Ground station command authentication (immediate)
2. Telemetry encryption (before 2027)
3. Inter-satellite links (new missions only)
4. Legacy missions - assess data classification

### Special Considerations

- **CRYPTO-AGILITY IMPOSSIBLE** - spacecraft cannot receive updates
- **Falcon NOT suitable** - requires FPU, variable timing
- Consider SLH-DSA for ultra-long-term archival despite size
- Ground segment can use hybrid; spacecraft must commit

### Key References

- [CNSA 2.0 FAQ (NSA)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
- [NASA Quantum Communication 101](https://www.nasa.gov/wp-content/uploads/2024/07/quantum-communication-101-final.pdf)

---

## Automotive & EVs

```bash
pqc-bench sector automotive
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | HIGH |
| **SNDL Risk** | HIGH |
| **Data Lifespan** | 15 years |
| **Equipment Lifecycle** | 15 years |

### Regulatory Framework

| Regulation | Authority | Status |
|------------|-----------|--------|
| ISO/SAE 21434 | ISO/SAE | No PQC yet |
| SAE J2735 | SAE | V2X definitions, no PQC |
| UN R155/R156 | UNECE | Crypto agility implied |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **V2X 100ms latency** | BLOCKING | Large signatures may exceed budget |
| **CAN bus bandwidth** | MAJOR | 4.6KB ML-DSA won't fit in single frame |
| **ECU resources** | MAJOR | <1MB RAM, often no FPU |
| **AUTOSAR** | MINOR | No PQC schemes specified |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-512 | Smallest for latency |
| Signature | ML-DSA-44 | Fastest signing |
| Hybrid KEM | X25519MLKEM768 | Cloud/telematics |
| Hybrid Sig | ECDSA-P256+ML-DSA-44 | Dual-signed certs |

### Migration Priority

1. V2X PKI certificates (new deployments)
2. Telematics/cloud communication
3. OTA update signing
4. ECU-to-ECU authentication (long-term)

### Special Considerations

- V2X: Consider Falcon for smaller signatures (666B vs 2,420B)
- BUT Falcon requires FPU - not available on all ECUs
- Hybrid mode critical - vehicles last 15+ years
- AUTOCRYPT offers first commercial ML-DSA PKI for vehicles

### Key References

- [SAE Quantum Technologies Report](https://saemobilus.sae.org/reports/unsettled-topics-concerning-impact-quantum-technologies-automotive-cybersecurity-epr2020026)
- [AUTOCRYPT PQC PKI](https://autocrypt.io/pqc-pki-vehicle-solution/)

---

## Industrial OT & SCADA

```bash
pqc-bench sector industrial
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | HIGH |
| **SNDL Risk** | HIGH |
| **Data Lifespan** | 10 years |
| **Equipment Lifecycle** | 30 years |

### Regulatory Framework

| Regulation | Authority | Status |
|------------|-----------|--------|
| IEC 62443 | IEC | 2024 update, no PQC yet |
| NIST SP 800-82 | NIST | References PQC transition |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **30-year lifecycle** | BLOCKING | Equipment outlives threat timeline |
| **Real-time (<10ms)** | MAJOR | Crypto cannot block control |
| **Air-gapped networks** | MINOR | Reduces SNDL, complicates key distribution |
| **Legacy protocols** | MAJOR | Modbus, DNP3 have limited crypto |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-768 | Standard security |
| Signature | ML-DSA-65 | Standard security |

### Migration Priority

1. IT/OT boundary gateways (immediate)
2. SCADA master stations
3. HMI authentication
4. Field devices (with equipment refresh)

### Special Considerations

- SNDL risk reduced for air-gapped but not eliminated
- Focus on IT/OT boundaries first
- Equipment refresh cycles (30 years) extend beyond threat
- PQC-capable secure gateways for legacy protection

### Key References

- [IEC 62443-2-1:2024](https://industrialcyber.co/isa-iec-62443/iec-publishes-iec-62443-2-12024-setting-security-standards-for-industrial-automation-and-control-systems/)

---

## Energy & Utilities

```bash
pqc-bench sector energy
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | HIGH |
| **SNDL Risk** | HIGH |
| **Data Lifespan** | 20 years |
| **Equipment Lifecycle** | 25 years |

### Regulatory Framework

| Regulation | Authority | Status |
|------------|-----------|--------|
| NERC CIP | NERC | Crypto required, no PQC |
| DOE Cybersecurity | DOE | PQC recommended |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **Grid reliability** | BLOCKING | 99.99%+ uptime; migration cannot disrupt |
| **Smart meter limits** | MAJOR | Millions deployed with limited compute |
| **Substation isolation** | MINOR | Key distribution challenging |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-768 | Standard security |
| Signature | ML-DSA-65 | Standard security |

### Migration Priority

1. Energy trading platforms (high SNDL risk)
2. SCADA communications
3. Substation authentication
4. Smart meter PKI (with device refresh)

### Special Considerations

- AES-256 is quantum-resistant for symmetric encryption
- Focus PQC on asymmetric (key exchange, signatures)
- Prioritize energy trading - financial data has high SNDL
- DOE funding available for quantum security research

### Key References

- [CISA PQC Initiative](https://www.cisa.gov/quantum)
- [DOE Quantum Collaboration](https://www.energy.gov/technologytransitions/articles/us-department-energy-announces-first-its-kind-collaboration-quantum)

---

## Healthcare & Medical Devices

```bash
pqc-bench sector healthcare
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | CRITICAL |
| **SNDL Risk** | EXTREME |
| **Data Lifespan** | 100 years |
| **Equipment Lifecycle** | 10 years |

### Regulatory Framework

| Regulation | Authority | Status | Deadline |
|------------|-----------|--------|----------|
| FDA 524B | FDA | Recommended | Ongoing |
| HIPAA | HHS | No PQC yet | - |
| NIST Deprecation | NIST | Mandatory | 2030 |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **FDA approval cycles** | MAJOR | 6-24 months for crypto changes |
| **Patient safety** | BLOCKING | Crypto updates must not affect function |
| **Legacy devices** | MAJOR | Many cannot receive updates |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-768 | Standard (ML-KEM-1024 for long-term) |
| Signature | ML-DSA-65 | Standard (ML-DSA-87 for long-term) |

### Migration Priority

1. EHR systems (extreme SNDL - 100-year data)
2. Medical imaging archives (DICOM)
3. New device submissions (FDA expects crypto planning)
4. Hospital network infrastructure
5. Connected medical devices

### Special Considerations

- HIPAA 6-year retention is MINIMUM; patient data lives forever
- FDA requires crypto-agility in new submissions
- Hybrid cryptography recommended during transition
- Legacy devices: focus on network segmentation
- SNDL risk is EXTREME - health records are lifetime sensitive

### Key References

- [FDA Cybersecurity Guidance 2023](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions)
- [Medcrypt PQC Guide](https://www.medcrypt.com/blog/navigating-post-quantum-cryptography-in-medical-device-cybersecurity)

---

## Financial Services

```bash
pqc-bench sector financial
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | CRITICAL |
| **SNDL Risk** | EXTREME |
| **Data Lifespan** | 30 years |
| **Equipment Lifecycle** | 7 years |

### Regulatory Framework

| Regulation | Authority | Status | Deadline |
|------------|-----------|--------|----------|
| SWIFT CSP | SWIFT | Recommended | Ongoing |
| DORA | EU | Recommended | 2025 |
| PCI-DSS 4.0 | PCI SSC | No PQC yet | - |
| NSM-10 | US Gov | Mandatory | 2035 |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **SWIFT migration** | MAJOR | 11,000+ banks must upgrade |
| **Transaction latency** | MAJOR | PQC overhead must not impact SLAs |
| **HSM replacement** | MAJOR | Hardware refresh before migration |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-768 | Standard security |
| Signature | ML-DSA-65 | Standard security |

### Migration Priority

1. SWIFT messaging authentication (immediate)
2. HSM key generation (with hardware refresh)
3. TLS for banking APIs
4. Payment card authentication
5. Blockchain/DLT systems

### Special Considerations

- BIS Project Leap successfully tested PQC in payments
- SWIFT already using third-party quantum-resistant algorithm
- 18 EU member states issued joint statement urging action
- SNDL is PRIMARY threat for financial data
- Coordinate with SWIFT and payment networks

### Key References

- [BIS Project Leap Phase 2](https://www.bis.org/publ/othp107.htm)
- [SWIFT Security Programme](https://www.swift.com/myswift/customer-security-programme-csp)

---

## Telecommunications & 5G

```bash
pqc-bench sector telecom
```

### Profile

| Attribute | Value |
|-----------|-------|
| **Migration Urgency** | HIGH |
| **SNDL Risk** | HIGH |
| **Data Lifespan** | 10 years |
| **Equipment Lifecycle** | 15 years |

### Regulatory Framework

| Regulation | Authority | Status |
|------------|-----------|--------|
| GSMA PQ.03 | GSMA | Recommended |
| 3GPP Standards | 3GPP | PQC updates coming |

### Technical Constraints

| Constraint | Severity | Impact |
|------------|----------|--------|
| **Multi-generation** | MAJOR | 2G-5G coexist with different crypto |
| **Radio interface** | MAJOR | Larger keys impact handover/battery |
| **Interoperability** | MAJOR | Industry-wide coordination needed |

### Recommendations

| Type | Algorithm | Rationale |
|------|-----------|-----------|
| KEM | ML-KEM-768 | Standard security |
| Signature | ML-DSA-65 | Standard security |
| Hybrid | X25519MLKEM768 | 5G core |

### Migration Priority

1. 5G core network (SA architecture)
2. Backhaul encryption
3. SIM/eSIM authentication (new issuance)
4. Radio interface (long-term, 6G design)

### Special Considerations

- HPQC (Hybrid PQC) with ECC recommended
- 5G core can handle PQC overhead
- Radio interface is long-term (5G/6G transition)
- Cryptographic discovery essential first step
- Nokia, Ericsson, Huawei all developing solutions

### Key References

- [GSMA PQ.03 Guidelines](https://www.gsma.com/newsroom/wp-content/uploads//PQ.03-Post-Quantum-Cryptography-Guidelines-for-Telecom-Use-v1.0.pdf)
- [5G Americas Post-Quantum Security](https://www.5gamericas.org/post-quantum-computing-security/)

---

## Compliance Deadlines

```bash
pqc-bench sector --deadlines
```

| Year | Sector | Framework | Requirement |
|------|--------|-----------|-------------|
| **2025** | Financial | DORA | ICT risk mitigation |
| **2030** | Healthcare | NIST | Classical crypto deprecated |
| **2030** | Government | CNSA 2.0 | Exclusive PQC for software signing and networking equipment |
| **2033** | Government | CNSA 2.0 | Exclusive PQC for browsers, servers, cloud and operating systems |
| **2035** | Federal | NSM-10 | Complete PQC migration |

---

## Summary by Urgency

### CRITICAL - Start Now

| Sector | Key Driver |
|--------|------------|
| Space & Aerospace | No updates possible after launch |
| Healthcare | 100-year data lifespan |
| Financial | SNDL risk, DORA 2025 |

### HIGH - Start Within 12 Months

| Sector | Key Driver |
|--------|------------|
| Automotive | 15-year vehicle lifetime |
| Industrial OT | 30-year equipment lifecycle |
| Energy | Grid reliability requirements |
| Telecommunications | Multi-generation network complexity |

---

## Getting Sector Guidance

```bash
# List all sectors
pqc-bench sector --list

# View deadlines
pqc-bench sector --deadlines

# Get specific sector details
pqc-bench sector <sector-name>
```

Available sector names:
- `space` or `space_aerospace`
- `automotive`
- `industrial` or `industrial_ot`
- `energy` or `energy_utilities`
- `healthcare`
- `financial`
- `telecom` or `telecommunications`
