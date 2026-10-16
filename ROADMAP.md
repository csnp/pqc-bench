# PQC-Bench Roadmap

Future development plans for PQC-Bench.

---

## Current Version: v0.3.0

- Core algorithm recommendations (ML-KEM, ML-DSA, Falcon, SLH-DSA)
- Natural language query parsing
- Compliance framework guidance (CNSA 2.0, FIPS 140-3, etc.)
- Critical infrastructure sector profiles (7 sectors)
- Library production-readiness ratings
- SNDL threat assessment
- Protocol impact analysis

---

## v0.4.0 - Extended Coverage

### Additional Algorithms
- [ ] Remaining SLH-DSA variants (192f, 256f, 128s, 192s, 256s)
- [ ] XMSS/LMS stateful hash-based signatures (NIST SP 800-208)
- [ ] HQC (if NIST finalizes Round 4)

### Additional Compliance Frameworks
- [ ] DORA (EU Digital Operational Resilience Act) - 2025 deadline
- [ ] NIS2 (EU Network and Information Security Directive)
- [ ] ISO 27001 PQC implications
- [ ] SOC 2 considerations

### Additional Libraries
- [ ] Bouncy Castle (Java/C#)
- [ ] NSS (Mozilla)
- [ ] Go crypto/x/crypto
- [ ] Rust pqcrypto crates

---

## v0.5.0 - Live Data Updates

### Data Update Mechanism
- [ ] `pqc-bench update` command to fetch latest data
- [ ] Public data repository (GitHub-hosted JSON/YAML)
- [ ] Version-pinned data for reproducibility
- [ ] Offline mode with bundled data

### Data Sources
- NIST PQC publications
- IETF RFC tracking (TLS, X.509 extensions)
- Library release tracking
- CVE/vulnerability feeds for PQC implementations

### Update Features
- [ ] Show changelog between versions
- [ ] Validate data integrity (signatures)
- [ ] Rollback to previous data version

---

## v0.6.0 - Advanced Analysis

### Performance Benchmarking
- [ ] Run local benchmarks on user's hardware
- [ ] Compare against reference benchmarks
- [ ] Platform-specific recommendations

### Integration Helpers
- [ ] Generate config snippets (nginx, Apache, HAProxy)
- [ ] OpenSSL configuration templates
- [ ] AWS/GCP/Azure SDK examples

### Risk Assessment
- [ ] Quantitative SNDL risk scoring
- [ ] Cost-benefit analysis for migration
- [ ] Timeline planning tools

---

## v1.0.0 - Production Ready

### Stability
- [ ] Semantic versioning commitment
- [ ] LTS (Long Term Support) data updates
- [ ] Backwards compatibility guarantees

### Enterprise Features
- [ ] Team/organization configuration
- [ ] Policy enforcement (minimum security levels)
- [ ] Audit logging
- [ ] CI/CD integration (GitHub Actions, GitLab CI)

### Documentation
- [ ] Video tutorials
- [ ] Interactive examples
- [ ] Migration case studies

---

## Contributing

We welcome contributions! Priority areas:

1. **Data contributions**: Additional algorithms, frameworks, libraries
2. **Sector expertise**: Industry-specific constraints and regulations
3. **Testing**: Edge cases, real-world validation
4. **Documentation**: Use cases, tutorials, translations

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## Feedback

Have a feature request? Open an issue: [GitHub Issues](https://github.com/csnp/pqc-bench/issues)

Label suggestions:
- `enhancement` - New features
- `data` - Algorithm/framework/library additions
- `docs` - Documentation improvements
