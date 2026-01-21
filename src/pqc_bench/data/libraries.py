"""
Cryptographic library database with production-readiness ratings.

This module addresses a major pain point in PQC adoption: practitioners
often don't know which libraries are safe for production. Key insight:
liboqs is explicitly NOT production-ready (per their own documentation),
yet many developers use it in production unaware of this.

Production-readiness factors:
- FIPS 140-3 validation status
- Side-channel resistance testing
- Security audit history
- Maintainer responsiveness
- Community adoption in production
- Memory safety (language, practices)
"""

from dataclasses import dataclass, field
from enum import Enum


class ProductionReadiness(Enum):
    """Production readiness level for a library."""

    PRODUCTION = "production"  # Actively used in production, audited, maintained
    EXPERIMENTAL = "experimental"  # For research/testing only
    TRANSITIONAL = "transitional"  # Moving toward production, may have gaps
    DEPRECATED = "deprecated"  # Being phased out, avoid for new projects


class FIPSStatus(Enum):
    """FIPS 140-3 validation status."""

    VALIDATED = "validated"  # Full CMVP validation
    IN_PROCESS = "in_process"  # Submitted, awaiting validation
    FIPS_READY = "fips_ready"  # Designed for FIPS, not yet validated
    NOT_VALIDATED = "not_validated"  # No FIPS validation


@dataclass
class SecurityAudit:
    """Record of a security audit."""

    auditor: str
    date: str
    scope: str
    report_url: str | None = None
    findings: str | None = None


@dataclass
class LibraryCaveat:
    """Important caveat about using a library."""

    severity: str  # "critical", "warning", "info"
    description: str
    source: str | None = None


@dataclass
class AlgorithmSupport:
    """Algorithms supported by a library."""

    ml_kem: list[str]  # e.g., ["512", "768", "1024"]
    ml_dsa: list[str]
    slh_dsa: list[str]
    falcon: list[str]
    hybrid_kem: list[str]  # e.g., ["X25519Kyber768"]
    hybrid_sig: list[str]  # e.g., ["ECDSA_P256+ML-DSA-44"]


@dataclass
class LibraryProfile:
    """Complete profile of a cryptographic library."""

    id: str
    name: str
    description: str
    url: str
    language: str
    license: str

    # Production readiness
    production_readiness: ProductionReadiness
    fips_status: FIPSStatus
    fips_cert_number: str | None = None

    # Algorithm support
    algorithms: AlgorithmSupport | None = None

    # Security
    constant_time_verified: bool = False
    memory_safe: bool = False
    audits: list[SecurityAudit] = field(default_factory=list)
    caveats: list[LibraryCaveat] = field(default_factory=list)

    # Platforms
    platforms: list[str] = field(default_factory=list)

    # Adoption
    notable_users: list[str] = field(default_factory=list)
    github_stars: int | None = None

    # Recommendations
    recommended_for: list[str] = field(default_factory=list)
    not_recommended_for: list[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# LIBRARY DATABASE
# ══════════════════════════════════════════════════════════════════════════════

LIBRARIES: dict[str, LibraryProfile] = {
    # ──────────────────────────────────────────────────────────────────────────
    # PRODUCTION-READY LIBRARIES
    # ──────────────────────────────────────────────────────────────────────────
    "aws-lc": LibraryProfile(
        id="aws-lc",
        name="AWS-LC (AWS Libcrypto)",
        description="AWS's fork of BoringSSL with FIPS validation and PQC support",
        url="https://github.com/aws/aws-lc",
        language="C",
        license="Apache-2.0 + ISC",
        production_readiness=ProductionReadiness.PRODUCTION,
        fips_status=FIPSStatus.VALIDATED,
        fips_cert_number="4793",
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["X25519Kyber768Draft00"],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        audits=[
            SecurityAudit(
                auditor="Leviathan Security",
                date="2023",
                scope="FIPS cryptographic module",
                report_url="https://csrc.nist.gov/projects/cryptographic-module-validation-program",
            ),
        ],
        caveats=[
            LibraryCaveat(
                severity="info",
                description="ML-KEM uses draft FIPS 203 implementation pending final validation",
            ),
        ],
        platforms=["linux", "macos", "windows", "android", "ios"],
        notable_users=["AWS SDK", "AWS S3", "AWS KMS", "Amazon CloudFront"],
        github_stars=1400,
        recommended_for=[
            "AWS infrastructure",
            "FIPS-required deployments",
            "Production TLS",
            "High-performance applications",
        ],
        not_recommended_for=[
            "Embedded systems (binary size)",
            "WebAssembly",
        ],
    ),
    "boringssl": LibraryProfile(
        id="boringssl",
        name="BoringSSL",
        description="Google's OpenSSL fork used in Chrome and Cloudflare",
        url="https://boringssl.googlesource.com/boringssl/",
        language="C",
        license="ISC + OpenSSL",
        production_readiness=ProductionReadiness.PRODUCTION,
        fips_status=FIPSStatus.VALIDATED,
        fips_cert_number="4407",
        algorithms=AlgorithmSupport(
            ml_kem=["768"],
            ml_dsa=[],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["X25519Kyber768Draft00"],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="info",
                description="No stable API - Google explicitly says 'not for general consumption'",
                source="BoringSSL README",
            ),
            LibraryCaveat(
                severity="info",
                description="Limited algorithm support - only X25519Kyber768 hybrid KEM",
            ),
        ],
        platforms=["linux", "macos", "windows", "android", "ios"],
        notable_users=["Google Chrome", "Cloudflare", "Android"],
        recommended_for=[
            "Chrome/Chromium-based applications",
            "Cloudflare Workers",
            "When you need battle-tested TLS PQC",
        ],
        not_recommended_for=[
            "Applications needing stable API",
            "Full PQC algorithm suite",
            "Signature algorithms",
        ],
    ),
    "openssl-3.5": LibraryProfile(
        id="openssl-3.5",
        name="OpenSSL 3.5+",
        description="OpenSSL with native ML-KEM/ML-DSA support (as of 3.5)",
        url="https://www.openssl.org/",
        language="C",
        license="Apache-2.0",
        production_readiness=ProductionReadiness.PRODUCTION,
        fips_status=FIPSStatus.IN_PROCESS,
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=[],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="warning",
                description="Native PQC only in 3.5+; earlier versions need oqs-provider",
            ),
            LibraryCaveat(
                severity="info",
                description="FIPS provider for PQC algorithms pending validation",
            ),
        ],
        platforms=["linux", "macos", "windows", "bsd"],
        notable_users=["nginx", "Apache HTTPD", "curl", "Python ssl"],
        github_stars=26000,
        recommended_for=[
            "General-purpose TLS/SSL",
            "Wide platform compatibility",
            "Applications already using OpenSSL",
        ],
        not_recommended_for=[
            "Strict FIPS requirements (until validated)",
            "Embedded systems",
        ],
    ),
    # ──────────────────────────────────────────────────────────────────────────
    # EXPERIMENTAL / RESEARCH LIBRARIES
    # ──────────────────────────────────────────────────────────────────────────
    "liboqs": LibraryProfile(
        id="liboqs",
        name="liboqs (Open Quantum Safe)",
        description="Research library - explicitly NOT for production use",
        url="https://github.com/open-quantum-safe/liboqs",
        language="C",
        license="MIT",
        production_readiness=ProductionReadiness.EXPERIMENTAL,
        fips_status=FIPSStatus.NOT_VALIDATED,
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=["128f", "128s", "192f", "192s", "256f", "256s"],
            falcon=["512", "1024"],
            hybrid_kem=[],
            hybrid_sig=[],
        ),
        constant_time_verified=False,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="critical",
                description="NOT production-ready - liboqs explicitly states this in their README",
                source="https://github.com/open-quantum-safe/liboqs#limitations-and-security",
            ),
            LibraryCaveat(
                severity="warning",
                description="No side-channel protections guaranteed",
            ),
            LibraryCaveat(
                severity="warning",
                description="API may change between releases",
            ),
            LibraryCaveat(
                severity="info",
                description="Excellent for research, testing, and prototyping",
            ),
        ],
        platforms=["linux", "macos", "windows", "wasm"],
        notable_users=["Researchers", "PQC testing frameworks"],
        github_stars=1900,
        recommended_for=[
            "Research and experimentation",
            "Algorithm comparison",
            "Prototyping",
            "Education and learning",
        ],
        not_recommended_for=[
            "Production systems",
            "FIPS-required environments",
            "Security-critical applications",
        ],
    ),
    "pqcrypto": LibraryProfile(
        id="pqcrypto",
        name="pqcrypto (Rust)",
        description="Rust PQC library - experimental quality",
        url="https://github.com/nickelheim/pqcrypto",
        language="Rust",
        license="MIT/Apache-2.0",
        production_readiness=ProductionReadiness.EXPERIMENTAL,
        fips_status=FIPSStatus.NOT_VALIDATED,
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=["128f"],
            falcon=["512", "1024"],
            hybrid_kem=[],
            hybrid_sig=[],
        ),
        memory_safe=True,  # Rust
        constant_time_verified=False,
        caveats=[
            LibraryCaveat(
                severity="warning",
                description="Bindings to reference implementations, not production-hardened",
            ),
        ],
        platforms=["linux", "macos", "windows"],
        recommended_for=[
            "Rust projects needing PQC experimentation",
            "Memory-safe prototyping",
        ],
        not_recommended_for=[
            "Production systems",
            "FIPS requirements",
        ],
    ),
    # ──────────────────────────────────────────────────────────────────────────
    # SPECIALIZED LIBRARIES
    # ──────────────────────────────────────────────────────────────────────────
    "wolfssl": LibraryProfile(
        id="wolfssl",
        name="wolfSSL",
        description="Embedded-focused TLS with PQC support",
        url="https://www.wolfssl.com/",
        language="C",
        license="GPLv2 / Commercial",
        production_readiness=ProductionReadiness.PRODUCTION,
        fips_status=FIPSStatus.VALIDATED,
        fips_cert_number="3389",
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["ECDHE_Kyber"],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="info",
                description="PQC may require commercial license",
            ),
        ],
        platforms=["linux", "embedded", "rtos", "windows", "macos"],
        notable_users=["Automotive", "Industrial IoT", "Medical devices"],
        recommended_for=[
            "Embedded systems",
            "IoT devices",
            "Resource-constrained environments",
            "RTOS",
        ],
        not_recommended_for=[
            "Projects requiring free licensing",
        ],
    ),
    "mbed-tls": LibraryProfile(
        id="mbed-tls",
        name="Mbed TLS (with PQC)",
        description="ARM's embedded TLS library with experimental PQC",
        url="https://github.com/Mbed-TLS/mbedtls",
        language="C",
        license="Apache-2.0 / GPLv2+",
        production_readiness=ProductionReadiness.TRANSITIONAL,
        fips_status=FIPSStatus.NOT_VALIDATED,
        algorithms=AlgorithmSupport(
            ml_kem=["768"],
            ml_dsa=[],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=[],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="warning",
                description="PQC support is experimental and evolving",
            ),
        ],
        platforms=["linux", "embedded", "rtos", "windows", "macos"],
        notable_users=["ARM Cortex-M devices"],
        recommended_for=[
            "ARM-based embedded systems",
            "Resource-constrained devices",
        ],
        not_recommended_for=[
            "Full PQC algorithm suite",
            "FIPS-required deployments",
        ],
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# HYBRID MODE CONFIGURATIONS
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class HybridMode:
    """Configuration for hybrid classical+PQC cryptography."""

    id: str
    name: str
    description: str
    classical_algorithm: str
    pqc_algorithm: str
    kem_or_sig: str  # "kem" or "signature"
    combined_size: int  # Total bytes
    tls_support: bool
    chrome_support: bool
    cloudflare_support: bool
    ietf_draft: str | None
    recommended_until: str  # e.g., "2030" or "until pure PQC widely supported"
    caveats: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)  # Library IDs


HYBRID_MODES: dict[str, HybridMode] = {
    "x25519-kyber768": HybridMode(
        id="x25519-kyber768",
        name="X25519Kyber768",
        description="X25519 ECDH + ML-KEM-768 hybrid key exchange",
        classical_algorithm="X25519",
        pqc_algorithm="ML-KEM-768",
        kem_or_sig="kem",
        combined_size=1184 + 32,  # ML-KEM-768 + X25519
        tls_support=True,
        chrome_support=True,
        cloudflare_support=True,
        ietf_draft="draft-ietf-tls-hybrid-design",
        recommended_until="Until pure PQC is widely trusted (2030+)",
        caveats=[
            "Slightly larger TLS handshake",
            "Both algorithms must be secure for security to hold",
        ],
        libraries=["boringssl", "aws-lc", "openssl-3.5"],
    ),
    "ecdsa-p256-mldsa44": HybridMode(
        id="ecdsa-p256-mldsa44",
        name="ECDSA P-256 + ML-DSA-44",
        description="ECDSA P-256 + ML-DSA-44 hybrid signature",
        classical_algorithm="ECDSA P-256",
        pqc_algorithm="ML-DSA-44",
        kem_or_sig="signature",
        combined_size=64 + 2420,  # ECDSA P-256 + ML-DSA-44
        tls_support=False,  # Not yet standardized
        chrome_support=False,
        cloudflare_support=False,
        ietf_draft="draft-ietf-lamps-pq-composite-sigs",
        recommended_until="Until pure PQC widely trusted",
        caveats=[
            "Certificate chain size increases significantly",
            "Standardization ongoing (X.509 composite signatures)",
        ],
        libraries=["aws-lc"],
    ),
    "ecdsa-p384-mldsa65": HybridMode(
        id="ecdsa-p384-mldsa65",
        name="ECDSA P-384 + ML-DSA-65",
        description="ECDSA P-384 + ML-DSA-65 hybrid signature",
        classical_algorithm="ECDSA P-384",
        pqc_algorithm="ML-DSA-65",
        kem_or_sig="signature",
        combined_size=96 + 3309,  # ECDSA P-384 + ML-DSA-65
        tls_support=False,
        chrome_support=False,
        cloudflare_support=False,
        ietf_draft="draft-ietf-lamps-pq-composite-sigs",
        recommended_until="Until pure PQC widely trusted",
        caveats=[
            "Large combined signature size",
            "Matches CNSA 2.0 security requirements",
        ],
        libraries=["aws-lc"],
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════


def get_library(library_id: str) -> LibraryProfile | None:
    """Get library profile by ID."""
    return LIBRARIES.get(library_id.lower())


def get_production_ready_libraries() -> list[LibraryProfile]:
    """Get all production-ready libraries."""
    return [
        lib
        for lib in LIBRARIES.values()
        if lib.production_readiness == ProductionReadiness.PRODUCTION
    ]


def get_libraries_with_fips() -> list[LibraryProfile]:
    """Get all libraries with FIPS validation."""
    return [
        lib
        for lib in LIBRARIES.values()
        if lib.fips_status == FIPSStatus.VALIDATED
    ]


def get_libraries_for_algorithm(algorithm_id: str) -> list[LibraryProfile]:
    """Get libraries that support a specific algorithm."""
    # Parse algorithm ID (e.g., "ml-kem-768" -> family="ml_kem", variant="768")
    parts = algorithm_id.lower().replace("-", "_").split("_")
    if len(parts) < 3:
        return []

    family = "_".join(parts[:-1])  # e.g., "ml_kem"
    variant = parts[-1]  # e.g., "768"

    result = []
    for lib in LIBRARIES.values():
        if lib.algorithms is None:
            continue

        supported = getattr(lib.algorithms, family, [])
        if variant in supported:
            result.append(lib)

    return result


def get_hybrid_mode(hybrid_id: str) -> HybridMode | None:
    """Get hybrid mode by ID."""
    return HYBRID_MODES.get(hybrid_id.lower().replace(" ", "-"))


def get_recommended_hybrid_for_kem() -> HybridMode:
    """Get the recommended hybrid KEM mode."""
    return HYBRID_MODES["x25519-kyber768"]


def get_hybrid_modes_for_use_case(use_case: str) -> list[HybridMode]:
    """Get hybrid modes suitable for a use case."""
    use_case_lower = use_case.lower()

    if any(
        kw in use_case_lower for kw in ["tls", "https", "web", "browser"]
    ):
        # TLS: X25519Kyber768 is the only one with browser support
        return [HYBRID_MODES["x25519-kyber768"]]

    if any(
        kw in use_case_lower for kw in ["certificate", "signing", "code signing"]
    ):
        # Signatures: composite signature hybrids
        return [
            HYBRID_MODES["ecdsa-p256-mldsa44"],
            HYBRID_MODES["ecdsa-p384-mldsa65"],
        ]

    # Default: return KEM hybrid
    return [HYBRID_MODES["x25519-kyber768"]]
