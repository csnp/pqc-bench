"""
Algorithm database with comprehensive profiles.

Each algorithm profile includes security properties, performance data,
compliance status, and implementation requirements with full citations.
"""

from dataclasses import dataclass, field


@dataclass
class AlgorithmNames:
    """Official and legacy names for an algorithm."""

    nist_fips: str
    nist_name: str
    legacy_name: str
    oid: str | None = None
    tls_codepoint: int | None = None


@dataclass
class SecurityCaveat:
    """A security consideration or warning about an algorithm."""

    severity: str  # "info", "warning", "critical"
    description: str
    mitigation: str | None = None
    reference: str | None = None


@dataclass
class Citation:
    """Reference to authoritative source."""

    title: str
    url: str
    date: str | None = None


@dataclass
class SecurityProfile:
    """Security properties of an algorithm."""

    nist_level: int
    classical_bits: int
    quantum_bits: int
    properties: list[str]  # e.g., ["IND-CCA2"] or ["EUF-CMA"]
    constant_time: bool
    caveats: list[SecurityCaveat] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)


@dataclass
class BenchmarkMethodology:
    """Methodology for performance measurements."""

    library: str
    version: str
    compiler: str
    cpu: str
    date: str
    iterations: int
    source: str


@dataclass
class PlatformPerformance:
    """Performance data for a specific platform."""

    platform: str
    keygen_ops: int
    encaps_ops: int | None = None  # KEMs only
    decaps_ops: int | None = None
    sign_ops: int | None = None  # Signatures only
    verify_ops: int | None = None
    methodology: BenchmarkMethodology | None = None


@dataclass
class SizeProfile:
    """Size characteristics of an algorithm."""

    public_key: int
    private_key: int
    ciphertext: int | None = None  # KEMs
    signature: int | None = None  # Signatures
    comparison: str | None = None  # Human-readable comparison


@dataclass
class FrameworkApproval:
    """Approval status within a compliance framework."""

    framework: str
    status: str  # "approved", "recommended", "pending", "not_approved"
    level: str | None = None
    effective_date: str | None = None
    notes: str | None = None


@dataclass
class ComplianceProfile:
    """Compliance status of an algorithm."""

    nist_standardized: bool
    fips_validated: bool
    fips_number: str | None = None
    approved_by: list[FrameworkApproval] = field(default_factory=list)


@dataclass
class Implementation:
    """Available implementation of an algorithm."""

    library: str
    version: str
    platforms: list[str]
    fips_validated: bool = False
    notes: str | None = None


@dataclass
class ImplementationRequirements:
    """Requirements for implementing/using an algorithm."""

    requires_fpu: bool
    min_stack_kb: int
    implementations: list[Implementation] = field(default_factory=list)


@dataclass
class AlgorithmProfile:
    """Complete profile of a PQC algorithm variant."""

    # Identity
    id: str
    family: str
    variant: str
    algorithm_type: str  # "kem" or "signature"
    names: AlgorithmNames

    # Security
    security: SecurityProfile

    # Compliance
    compliance: ComplianceProfile

    # Performance by platform
    performance: dict[str, PlatformPerformance]

    # Sizes
    sizes: SizeProfile

    # Requirements
    requirements: ImplementationRequirements

    # Additional notes
    notes: list[str] = field(default_factory=list)

    @property
    def is_kem(self) -> bool:
        """Whether this is a Key Encapsulation Mechanism."""
        return self.algorithm_type == "kem"

    @property
    def is_signature(self) -> bool:
        """Whether this is a digital signature algorithm."""
        return self.algorithm_type == "signature"


# ══════════════════════════════════════════════════════════════════════════════
# ALGORITHM DATABASE
# ══════════════════════════════════════════════════════════════════════════════

LIBOQS_METHODOLOGY = BenchmarkMethodology(
    library="liboqs",
    version="0.10.0",
    compiler="clang 17.0.0 -O3 -march=native",
    cpu="Intel Xeon Platinum 8375C @ 2.90GHz",
    date="2024-12",
    iterations=10000,
    source="https://github.com/open-quantum-safe/liboqs",
)

ALGORITHMS: dict[str, AlgorithmProfile] = {
    # ══════════════════════════════════════════════════════════════════════════
    # ML-KEM (FIPS 203) - Key Encapsulation Mechanism
    # ══════════════════════════════════════════════════════════════════════════
    "ml-kem-512": AlgorithmProfile(
        id="ml-kem-512",
        family="ML-KEM",
        variant="512",
        algorithm_type="kem",
        names=AlgorithmNames(
            nist_fips="FIPS 203",
            nist_name="ML-KEM-512",
            legacy_name="Kyber512",
            oid="1.3.6.1.4.1.22554.5.6.1",
            tls_codepoint=0x0200,
        ),
        security=SecurityProfile(
            nist_level=1,
            classical_bits=128,
            quantum_bits=118,
            properties=["IND-CCA2"],
            constant_time=True,
            caveats=[
                SecurityCaveat(
                    severity="info",
                    description="Level 1 security; consider ML-KEM-768 for general use",
                    mitigation="Use for constrained environments where Level 1 is acceptable",
                )
            ],
            citations=[
                Citation(
                    title="FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard",
                    url="https://csrc.nist.gov/pubs/fips/203/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 203",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                    notes="Part of FIPS 203",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=85000,
                encaps_ops=100000,
                decaps_ops=90000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=45000,
                encaps_ops=55000,
                decaps_ops=50000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=8000,
                encaps_ops=10000,
                decaps_ops=9000,
            ),
        },
        sizes=SizeProfile(
            public_key=800,
            private_key=1632,
            ciphertext=768,
            comparison="~3x larger than X25519",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=2,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                    fips_validated=False,
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
            ],
        ),
        notes=["Smallest ML-KEM variant", "Good for constrained environments"],
    ),
    "ml-kem-768": AlgorithmProfile(
        id="ml-kem-768",
        family="ML-KEM",
        variant="768",
        algorithm_type="kem",
        names=AlgorithmNames(
            nist_fips="FIPS 203",
            nist_name="ML-KEM-768",
            legacy_name="Kyber768",
            oid="1.3.6.1.4.1.22554.5.6.2",
            tls_codepoint=0x0201,
        ),
        security=SecurityProfile(
            nist_level=3,
            classical_bits=192,
            quantum_bits=161,
            properties=["IND-CCA2"],
            constant_time=True,
            caveats=[],
            citations=[
                Citation(
                    title="FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard",
                    url="https://csrc.nist.gov/pubs/fips/203/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 203",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                    notes="Part of FIPS 203",
                ),
                FrameworkApproval(
                    framework="CNSA 2.0",
                    status="approved",
                    level="Secret",
                    effective_date="2025",
                    notes="Recommended for all key establishment",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=70000,
                encaps_ops=85000,
                decaps_ops=75000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=38000,
                encaps_ops=45000,
                decaps_ops=40000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=6500,
                encaps_ops=8000,
                decaps_ops=7000,
            ),
        },
        sizes=SizeProfile(
            public_key=1184,
            private_key=2400,
            ciphertext=1088,
            comparison="~4x larger than X25519",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=3,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                    fips_validated=False,
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
                Implementation(
                    library="BoringSSL",
                    version="latest",
                    platforms=["x86_64", "arm64"],
                    fips_validated=False,
                    notes="Used in Chrome and Cloudflare",
                ),
            ],
        ),
        notes=[
            "Recommended default for most applications",
            "Best security/performance balance",
            "CNSA 2.0 approved",
        ],
    ),
    "ml-kem-1024": AlgorithmProfile(
        id="ml-kem-1024",
        family="ML-KEM",
        variant="1024",
        algorithm_type="kem",
        names=AlgorithmNames(
            nist_fips="FIPS 203",
            nist_name="ML-KEM-1024",
            legacy_name="Kyber1024",
            oid="1.3.6.1.4.1.22554.5.6.3",
            tls_codepoint=0x0202,
        ),
        security=SecurityProfile(
            nist_level=5,
            classical_bits=256,
            quantum_bits=218,
            properties=["IND-CCA2"],
            constant_time=True,
            caveats=[
                SecurityCaveat(
                    severity="info",
                    description="Highest security level; may be overkill for most applications",
                    mitigation="Use when protecting data with 25+ year lifespan",
                )
            ],
            citations=[
                Citation(
                    title="FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard",
                    url="https://csrc.nist.gov/pubs/fips/203/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 203",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                ),
                FrameworkApproval(
                    framework="CNSA 2.0",
                    status="approved",
                    level="Top Secret",
                    effective_date="2025",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=55000,
                encaps_ops=65000,
                decaps_ops=60000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=28000,
                encaps_ops=35000,
                decaps_ops=32000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=4500,
                encaps_ops=5500,
                decaps_ops=5000,
            ),
        },
        sizes=SizeProfile(
            public_key=1568,
            private_key=3168,
            ciphertext=1568,
            comparison="~5x larger than X25519",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=4,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
            ],
        ),
        notes=[
            "Highest security ML-KEM variant",
            "For long-term secrets and Top Secret classification",
        ],
    ),
    # ══════════════════════════════════════════════════════════════════════════
    # ML-DSA (FIPS 204) - Digital Signature Algorithm
    # ══════════════════════════════════════════════════════════════════════════
    "ml-dsa-44": AlgorithmProfile(
        id="ml-dsa-44",
        family="ML-DSA",
        variant="44",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 204",
            nist_name="ML-DSA-44",
            legacy_name="Dilithium2",
            oid="1.3.6.1.4.1.2.267.12.4.4",
        ),
        security=SecurityProfile(
            nist_level=2,
            classical_bits=128,
            quantum_bits=118,
            properties=["EUF-CMA"],
            constant_time=True,
            caveats=[
                SecurityCaveat(
                    severity="info",
                    description="Level 2 security; adequate for auth, consider Level 3 for long-term signatures",
                )
            ],
            citations=[
                Citation(
                    title="FIPS 204: Module-Lattice-Based Digital Signature Standard",
                    url="https://csrc.nist.gov/pubs/fips/204/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 204",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=35000,
                sign_ops=20000,
                verify_ops=35000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=18000,
                sign_ops=10000,
                verify_ops=18000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=3000,
                sign_ops=1800,
                verify_ops=3000,
            ),
        },
        sizes=SizeProfile(
            public_key=1312,
            private_key=2560,
            signature=2420,
            comparison="~38x larger than ECDSA P-256 signature",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=4,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
            ],
        ),
        notes=[
            "Smallest ML-DSA variant",
            "Good for high-volume signing (JWT, API auth)",
            "Fastest verification in ML-DSA family",
        ],
    ),
    "ml-dsa-65": AlgorithmProfile(
        id="ml-dsa-65",
        family="ML-DSA",
        variant="65",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 204",
            nist_name="ML-DSA-65",
            legacy_name="Dilithium3",
            oid="1.3.6.1.4.1.2.267.12.6.5",
        ),
        security=SecurityProfile(
            nist_level=3,
            classical_bits=192,
            quantum_bits=161,
            properties=["EUF-CMA"],
            constant_time=True,
            caveats=[],
            citations=[
                Citation(
                    title="FIPS 204: Module-Lattice-Based Digital Signature Standard",
                    url="https://csrc.nist.gov/pubs/fips/204/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 204",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                ),
                FrameworkApproval(
                    framework="CNSA 2.0",
                    status="approved",
                    level="Secret",
                    effective_date="2025",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=25000,
                sign_ops=15000,
                verify_ops=25000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=13000,
                sign_ops=7500,
                verify_ops=13000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=2200,
                sign_ops=1300,
                verify_ops=2200,
            ),
        },
        sizes=SizeProfile(
            public_key=1952,
            private_key=4032,
            signature=3309,
            comparison="~52x larger than ECDSA P-256 signature",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=6,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
            ],
        ),
        notes=[
            "Recommended default for most signature use cases",
            "CNSA 2.0 approved",
            "Good balance of security and performance",
        ],
    ),
    "ml-dsa-87": AlgorithmProfile(
        id="ml-dsa-87",
        family="ML-DSA",
        variant="87",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 204",
            nist_name="ML-DSA-87",
            legacy_name="Dilithium5",
            oid="1.3.6.1.4.1.2.267.12.8.7",
        ),
        security=SecurityProfile(
            nist_level=5,
            classical_bits=256,
            quantum_bits=218,
            properties=["EUF-CMA"],
            constant_time=True,
            caveats=[
                SecurityCaveat(
                    severity="info",
                    description="Highest security level; larger signatures may impact bandwidth",
                )
            ],
            citations=[
                Citation(
                    title="FIPS 204: Module-Lattice-Based Digital Signature Standard",
                    url="https://csrc.nist.gov/pubs/fips/204/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 204",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                ),
                FrameworkApproval(
                    framework="CNSA 2.0",
                    status="approved",
                    level="Top Secret",
                    effective_date="2025",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=18000,
                sign_ops=11000,
                verify_ops=18000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=9000,
                sign_ops=5500,
                verify_ops=9000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=1500,
                sign_ops=900,
                verify_ops=1500,
            ),
        },
        sizes=SizeProfile(
            public_key=2592,
            private_key=4896,
            signature=4627,
            comparison="~72x larger than ECDSA P-256 signature",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=8,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                ),
                Implementation(
                    library="AWS-LC",
                    version="1.20.0",
                    platforms=["x86_64", "arm64"],
                    fips_validated=True,
                ),
            ],
        ),
        notes=[
            "Highest security ML-DSA variant",
            "For Top Secret classification",
            "Consider bandwidth impact of larger signatures",
        ],
    ),
    # ══════════════════════════════════════════════════════════════════════════
    # Falcon / FN-DSA (FIPS 206 pending) - Compact Signatures
    # ══════════════════════════════════════════════════════════════════════════
    "falcon-512": AlgorithmProfile(
        id="falcon-512",
        family="Falcon",
        variant="512",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 206 (pending)",
            nist_name="FN-DSA-512",
            legacy_name="Falcon-512",
            oid="1.3.9999.3.6",
        ),
        security=SecurityProfile(
            nist_level=1,
            classical_bits=128,
            quantum_bits=103,
            properties=["EUF-CMA"],
            constant_time=False,
            caveats=[
                SecurityCaveat(
                    severity="warning",
                    description="Signing is NOT constant-time; may leak timing information",
                    mitigation="Use in contexts where signing timing is not observable by attackers",
                    reference="https://falcon-sign.info/falcon.pdf",
                ),
                SecurityCaveat(
                    severity="warning",
                    description="Requires floating-point unit (FPU)",
                    mitigation="Not suitable for embedded systems without FPU",
                ),
                SecurityCaveat(
                    severity="info",
                    description="Not yet NIST standardized (FIPS 206 pending)",
                ),
            ],
            citations=[
                Citation(
                    title="Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU",
                    url="https://falcon-sign.info/",
                    date="2024",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=False,
            fips_validated=False,
            fips_number="FIPS 206 (draft)",
            approved_by=[],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=500,
                sign_ops=10000,
                verify_ops=45000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=200,
                sign_ops=5000,
                verify_ops=25000,
            ),
            "wasm": PlatformPerformance(
                platform="wasm",
                keygen_ops=50,
                sign_ops=800,
                verify_ops=4000,
            ),
        },
        sizes=SizeProfile(
            public_key=897,
            private_key=1281,
            signature=666,
            comparison="~10x larger than ECDSA P-256 signature (smallest PQC signature)",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=True,
            min_stack_kb=8,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64"],
                    notes="Requires FPU",
                ),
            ],
        ),
        notes=[
            "Smallest PQC signatures",
            "Slow key generation (pre-generate keys)",
            "NOT constant-time - use with caution",
            "Requires floating-point unit",
            "Good for bandwidth-constrained scenarios (blockchain, certificates)",
        ],
    ),
    "falcon-1024": AlgorithmProfile(
        id="falcon-1024",
        family="Falcon",
        variant="1024",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 206 (pending)",
            nist_name="FN-DSA-1024",
            legacy_name="Falcon-1024",
            oid="1.3.9999.3.9",
        ),
        security=SecurityProfile(
            nist_level=5,
            classical_bits=256,
            quantum_bits=230,
            properties=["EUF-CMA"],
            constant_time=False,
            caveats=[
                SecurityCaveat(
                    severity="warning",
                    description="Signing is NOT constant-time; may leak timing information",
                    mitigation="Use in contexts where signing timing is not observable",
                    reference="https://falcon-sign.info/falcon.pdf",
                ),
                SecurityCaveat(
                    severity="warning",
                    description="Requires floating-point unit (FPU)",
                ),
                SecurityCaveat(
                    severity="info",
                    description="Not yet NIST standardized (FIPS 206 pending)",
                ),
            ],
            citations=[
                Citation(
                    title="Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU",
                    url="https://falcon-sign.info/",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=False,
            fips_validated=False,
            fips_number="FIPS 206 (draft)",
            approved_by=[],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=200,
                sign_ops=5000,
                verify_ops=25000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=80,
                sign_ops=2500,
                verify_ops=12000,
            ),
        },
        sizes=SizeProfile(
            public_key=1793,
            private_key=2305,
            signature=1280,
            comparison="~20x larger than ECDSA P-256 signature",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=True,
            min_stack_kb=16,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64"],
                    notes="Requires FPU",
                ),
            ],
        ),
        notes=[
            "Compact signatures with Level 5 security",
            "Very slow key generation",
            "NOT constant-time",
            "Requires floating-point unit",
        ],
    ),
    # ══════════════════════════════════════════════════════════════════════════
    # SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
    # ══════════════════════════════════════════════════════════════════════════
    "slh-dsa-128f": AlgorithmProfile(
        id="slh-dsa-128f",
        family="SLH-DSA",
        variant="128f",
        algorithm_type="signature",
        names=AlgorithmNames(
            nist_fips="FIPS 205",
            nist_name="SLH-DSA-SHA2-128f",
            legacy_name="SPHINCS+-SHA2-128f-simple",
            oid="1.3.9999.6.4.13",
        ),
        security=SecurityProfile(
            nist_level=1,
            classical_bits=128,
            quantum_bits=128,
            properties=["EUF-CMA"],
            constant_time=True,
            caveats=[
                SecurityCaveat(
                    severity="info",
                    description="Hash-based security (most conservative assumptions)",
                ),
                SecurityCaveat(
                    severity="info",
                    description="Large signatures; 'f' = fast signing, 's' = small signatures",
                ),
            ],
            citations=[
                Citation(
                    title="FIPS 205: Stateless Hash-Based Digital Signature Standard",
                    url="https://csrc.nist.gov/pubs/fips/205/final",
                    date="2024-08",
                )
            ],
        ),
        compliance=ComplianceProfile(
            nist_standardized=True,
            fips_validated=True,
            fips_number="FIPS 205",
            approved_by=[
                FrameworkApproval(
                    framework="FIPS 140-3",
                    status="approved",
                ),
            ],
        ),
        performance={
            "x86_64_avx2": PlatformPerformance(
                platform="x86_64_avx2",
                keygen_ops=500,
                sign_ops=100,
                verify_ops=2000,
                methodology=LIBOQS_METHODOLOGY,
            ),
            "arm64_neon": PlatformPerformance(
                platform="arm64_neon",
                keygen_ops=200,
                sign_ops=40,
                verify_ops=800,
            ),
        },
        sizes=SizeProfile(
            public_key=32,
            private_key=64,
            signature=17088,
            comparison="~267x larger than ECDSA P-256 signature",
        ),
        requirements=ImplementationRequirements(
            requires_fpu=False,
            min_stack_kb=4,
            implementations=[
                Implementation(
                    library="liboqs",
                    version="0.10.0",
                    platforms=["x86_64", "arm64", "arm32", "wasm"],
                ),
            ],
        ),
        notes=[
            "Hash-based (most conservative cryptographic assumptions)",
            "Slow signing",
            "Large signatures (17KB)",
            "Consider for high-security, low-volume signing",
        ],
    ),
}


def get_algorithm(algorithm_id: str) -> AlgorithmProfile | None:
    """Get algorithm profile by ID."""
    return ALGORITHMS.get(algorithm_id.lower())


def get_algorithms_by_type(algorithm_type: str) -> list[AlgorithmProfile]:
    """Get all algorithms of a given type (kem or signature)."""
    return [a for a in ALGORITHMS.values() if a.algorithm_type == algorithm_type]


def get_algorithms_by_family(family: str) -> list[AlgorithmProfile]:
    """Get all algorithms in a family (e.g., ML-KEM, ML-DSA)."""
    return [a for a in ALGORITHMS.values() if a.family.upper() == family.upper()]


def get_nist_standardized() -> list[AlgorithmProfile]:
    """Get all NIST standardized algorithms."""
    return [a for a in ALGORITHMS.values() if a.compliance.nist_standardized]
