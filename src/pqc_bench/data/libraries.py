"""
Cryptographic library database with production-readiness ratings.

This module addresses a major pain point in PQC adoption: practitioners
often don't know which libraries are safe for production. liboqs, for
example, is not production-ready: its README says it is meant for research
and prototyping.

Production-readiness factors:
- FIPS 140-3 validation status
- Side-channel resistance testing
- Security audit history
- Maintainer responsiveness
- Community adoption in production
- Memory safety (language, practices)
"""

from dataclasses import dataclass, field, fields
from enum import Enum

from .algorithms import get_algorithm


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
    hybrid_kem: list[str]  # TLS group names, e.g., ["X25519MLKEM768"]
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
    # The algorithm families fips_cert_number lists, by AlgorithmSupport field name ("ml_kem"),
    # or None when they are not recorded here
    fips_cert_families: list[str] | None = None

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
        # CMVP certificate pages, read 2026-11-13: FIPS 140-3 certificates #5298 (AWS-LC 3
        # Cryptographic Module (dynamic), validated 2026-06-03) and #5314 (static, validated
        # 2026-06-05) list ML-KEM KeyGen and EncapDecap, and no ML-DSA or SLH-DSA. AWS-LC
        # certificates #4631, #4816, #5146 and #5429 list no ML-KEM, ML-DSA or SLH-DSA.
        # #4793 is Canonical's Ubuntu 22.04 Libgcrypt module, not an AWS-LC module.
        fips_status=FIPSStatus.VALIDATED,
        fips_cert_number="5298",
        fips_cert_families=["ml_kem"],
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["X25519MLKEM768"],
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
                description="FIPS 140-3 certificates #5298 (dynamic) and #5314 (static) for the AWS-LC 3 "
                "Cryptographic Module list ML-KEM; neither lists ML-DSA or SLH-DSA",
                source="https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298",
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
        # No active CMVP certificate for Google's BoringCrypto module lists ML-KEM, ML-DSA
        # or SLH-DSA. CMVP certificate pages, read 2026-11-13: #4407 is a FIPS 140-2
        # certificate, now historical; active FIPS 140-3 certificates #4735, #5104, #5244
        # and #5296 list no ML-KEM, ML-DSA or SLH-DSA.
        # In process: CMVP's Modules In Process list (updated 2026-11-13) shows four
        # BoringCrypto modules from Google, and BoringSSL's FIPS notes mark three module
        # versions "Review Pending at NIST"; their CAVP validations A6838, A7303 and A7700
        # list ML-KEM (https://boringssl.googlesource.com/boringssl/+/main/crypto/fipsmodule/FIPS.md).
        fips_status=FIPSStatus.IN_PROCESS,
        fips_cert_number=None,
        algorithms=AlgorithmSupport(
            ml_kem=["768"],
            ml_dsa=[],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["X25519MLKEM768"],
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
                description="Limited algorithm support - X25519MLKEM768 is the only hybrid KEM",
            ),
            LibraryCaveat(
                severity="info",
                description="FIPS 140-2 certificate #4407 (now historical) and FIPS 140-3 certificates #4735, "
                "#5104, #5244 and #5296 cover the classical BoringCrypto module; none lists ML-KEM, ML-DSA or SLH-DSA",
                source="https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5296",
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
            hybrid_kem=["X25519MLKEM768", "SecP384r1MLKEM1024"],
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
        # No CMVP certificate covers wolfSSL's PQC algorithms. CMVP certificate pages,
        # read 2026-11-13: #3389 is a FIPS 140-2 wolfCrypt certificate, now historical;
        # FIPS 140-3 certificates #4718, #5041 and #5548 list no ML-KEM, ML-DSA or SLH-DSA.
        # In process: wolfSSL wrote in February 2026 that the CMVP submission of its PQC
        # module "is in process" (https://www.wolfssl.com/?p=47093).
        fips_status=FIPSStatus.IN_PROCESS,
        fips_cert_number=None,
        algorithms=AlgorithmSupport(
            ml_kem=["512", "768", "1024"],
            ml_dsa=["44", "65", "87"],
            slh_dsa=[],
            falcon=[],
            hybrid_kem=["X25519MLKEM768", "SecP384r1MLKEM1024"],
            hybrid_sig=[],
        ),
        constant_time_verified=True,
        memory_safe=False,
        caveats=[
            LibraryCaveat(
                severity="info",
                description="PQC may require commercial license",
            ),
            LibraryCaveat(
                severity="info",
                description="FIPS 140-2 certificate #3389 (now historical) and FIPS 140-3 certificates #4718, "
                "#5041 and #5548 cover the classical wolfCrypt module; none lists ML-KEM, ML-DSA or SLH-DSA",
                source="https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5548",
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
    ietf_reference: str | None  # The RFC that defines the mode, or the draft name until one is published
    recommended_until: str  # e.g., "2030" or "until pure PQC widely supported"
    caveats: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)  # Library IDs


# IETF references, read 2026-11-13 on datatracker.ietf.org and rfc-editor.org:
# draft-ietf-tls-ecdhe-mlkem was published as RFC 10024 (August 2026), which
# defines X25519MLKEM768 (4588) and SecP384r1MLKEM1024 (4589) for TLS 1.3, and
# draft-ietf-lamps-pq-composite-sigs as RFC 10073 (November 2026), which defines
# the composite ML-DSA-44 + ECDSA P-256 and ML-DSA-65 + ECDSA P-384 signatures for X.509.
HYBRID_MODES: dict[str, HybridMode] = {
    "x25519-mlkem768": HybridMode(
        id="x25519-mlkem768",
        name="X25519MLKEM768",
        description="X25519 ECDH + ML-KEM-768 hybrid key exchange (TLS group 4588)",
        classical_algorithm="X25519",
        pqc_algorithm="ML-KEM-768",
        kem_or_sig="kem",
        combined_size=1184 + 32,  # Client key share: ML-KEM-768 + X25519
        tls_support=True,
        chrome_support=True,
        cloudflare_support=True,
        ietf_reference="RFC 10024",
        recommended_until="Until pure PQC is widely trusted (2030+)",
        caveats=[
            "Slightly larger TLS handshake",
            "Both algorithms must be secure for security to hold",
            "Chrome has used this group since Chrome 131, replacing the draft Kyber group",
        ],
        libraries=["boringssl", "aws-lc", "openssl-3.5", "wolfssl"],
    ),
    "secp384r1-mlkem1024": HybridMode(
        id="secp384r1-mlkem1024",
        name="SecP384r1MLKEM1024",
        description="ECDH P-384 + ML-KEM-1024 hybrid key exchange (TLS group 4589, 0x11ED)",
        classical_algorithm="ECDH P-384",
        pqc_algorithm="ML-KEM-1024",
        kem_or_sig="kem",
        combined_size=97 + 1568,  # Client key share: uncompressed P-384 point + ML-KEM-1024
        tls_support=True,
        chrome_support=False,
        cloudflare_support=False,
        ietf_reference="RFC 10024",
        recommended_until="Until pure ML-KEM-1024 is widely trusted",
        caveats=[
            "Carries ML-KEM-1024, the KEM that CNSA 2.0 requires",
            "Larger key share than X25519MLKEM768",
        ],
        libraries=["openssl-3.5", "wolfssl"],
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
        ietf_reference="RFC 10073",
        recommended_until="Until pure PQC widely trusted",
        caveats=[
            "Certificate chain size increases significantly",
            "X.509 composite signatures are specified in RFC 10073 (November 2026)",
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
        ietf_reference="RFC 10073",
        recommended_until="Until pure PQC widely trusted",
        caveats=[
            "Large combined signature size",
            "Does not meet CNSA 2.0, which uses ML-DSA-87 (Level V)",
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


_ALGORITHM_SUPPORT_FIELDS = frozenset(support_field.name for support_field in fields(AlgorithmSupport))

# The name text gives the algorithm family of each AlgorithmSupport field.
ALGORITHM_FAMILY_NAMES: dict[str, str] = {
    "ml_kem": "ML-KEM",
    "ml_dsa": "ML-DSA",
    "slh_dsa": "SLH-DSA",
    "falcon": "Falcon",
    "hybrid_kem": "hybrid KEM",
    "hybrid_sig": "hybrid signature",
}


def _family_and_variant(algorithm_id: str) -> tuple[str, str] | None:
    """The AlgorithmSupport field and variant of an algorithm given by ID, NIST name or legacy name.

    None for a value that names no AlgorithmSupport field.
    """
    algo = get_algorithm(algorithm_id)
    if algo is not None:
        algorithm_id = algo.id

    # Split the ID into an AlgorithmSupport field and a variant:
    # "ml-kem-768" -> "ml_kem", "768" and "falcon-512" -> "falcon", "512"
    family, _, variant = algorithm_id.lower().replace("-", "_").rpartition("_")
    if family not in _ALGORITHM_SUPPORT_FIELDS:
        return None
    return family, variant


def get_algorithm_family(algorithm_id: str) -> str | None:
    """The AlgorithmSupport field of an algorithm given by ID, NIST name or legacy name.

    "ml-dsa-65", "ML-DSA-65" and "Dilithium3" give "ml_dsa". None for a value that names no
    AlgorithmSupport field.
    """
    family_and_variant = _family_and_variant(algorithm_id)
    return None if family_and_variant is None else family_and_variant[0]


def get_fips_certificate_for_family(library: LibraryProfile, family: str) -> str | None:
    """The library's FIPS certificate number, or None when it is not shown for an algorithm family.

    None when the library has no certificate, or when fips_cert_families records the families the
    certificate lists and ``family`` is not one of them. A certificate whose families are not
    recorded is returned for every family.
    """
    if library.fips_cert_families is not None and family not in library.fips_cert_families:
        return None
    return library.fips_cert_number


def get_libraries_for_algorithm(algorithm_id: str) -> list[LibraryProfile]:
    """Get libraries that support an algorithm, given by ID, NIST name or legacy name."""
    family_and_variant = _family_and_variant(algorithm_id)
    if family_and_variant is None:
        return []
    family, variant = family_and_variant

    result = []
    for lib in LIBRARIES.values():
        if lib.algorithms is None:
            continue

        supported = getattr(lib.algorithms, family)
        if variant in supported:
            result.append(lib)

    return result


def _hybrid_key(text: str) -> str:
    """``text`` in lower case with everything but letters and digits removed."""
    return "".join(char for char in text.lower() if char.isalnum())


def get_hybrid_mode(hybrid_id: str) -> HybridMode | None:
    """Get hybrid mode by ID or name ("secp384r1-mlkem1024" or "SecP384r1MLKEM1024")."""
    mode = HYBRID_MODES.get(hybrid_id.lower().replace(" ", "-"))
    if mode is not None:
        return mode
    key = _hybrid_key(hybrid_id)
    for mode in HYBRID_MODES.values():
        if key in (_hybrid_key(mode.id), _hybrid_key(mode.name)):
            return mode
    return None


def get_recommended_hybrid_for_kem() -> HybridMode:
    """Get the recommended hybrid KEM mode."""
    return HYBRID_MODES["x25519-mlkem768"]


# Words that select the hybrid modes for a use case. A use case matches a
# word that occurs anywhere in it, so "code signing" matches "signing".
HYBRID_KEM_USE_CASE_WORDS = ["tls", "https", "web", "browser"]
HYBRID_SIGNATURE_USE_CASE_WORDS = ["certificate", "signing", "signature"]


def get_hybrid_modes_for_use_case(use_case: str) -> list[HybridMode]:
    """Get hybrid modes suitable for a use case; empty when it holds none of the use-case words."""
    use_case_lower = use_case.lower()
    kem_modes = [mode for mode in HYBRID_MODES.values() if mode.kem_or_sig == "kem"]

    if "browser" in use_case_lower:
        # Browsers: KEM hybrids with Chrome support
        return [mode for mode in kem_modes if mode.chrome_support]

    if any(kw in use_case_lower for kw in ["tls", "https", "web"]):
        # TLS: KEM hybrids with TLS support
        return [mode for mode in kem_modes if mode.tls_support]

    if any(
        kw in use_case_lower for kw in HYBRID_SIGNATURE_USE_CASE_WORDS
    ):
        # Signatures: composite signature hybrids
        return [
            HYBRID_MODES["ecdsa-p256-mldsa44"],
            HYBRID_MODES["ecdsa-p384-mldsa65"],
        ]

    return []
