"""
Constraint model for PQC algorithm selection.

This module defines the structured representation of user requirements
that drive algorithm recommendations.
"""

from dataclasses import dataclass, field
from enum import Enum


class Platform(Enum):
    """Target platform for cryptographic operations."""

    X86_64 = "x86_64"
    X86_64_AVX2 = "x86_64_avx2"
    X86_64_AVX512 = "x86_64_avx512"
    ARM64 = "arm64"
    ARM64_NEON = "arm64_neon"
    ARM32 = "arm32"
    WASM = "wasm"
    EMBEDDED = "embedded"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Platform":
        """Parse platform from string, with intelligent matching."""
        value_lower = value.lower()

        mapping = {
            "x86": cls.X86_64,
            "x86_64": cls.X86_64,
            "x64": cls.X86_64,
            "amd64": cls.X86_64,
            "intel": cls.X86_64_AVX2,
            "avx2": cls.X86_64_AVX2,
            "avx512": cls.X86_64_AVX512,
            "arm": cls.ARM64,
            "arm64": cls.ARM64,
            "aarch64": cls.ARM64,
            "neon": cls.ARM64_NEON,
            "arm32": cls.ARM32,
            "wasm": cls.WASM,
            "webassembly": cls.WASM,
            "browser": cls.WASM,
            "embedded": cls.EMBEDDED,
            "mcu": cls.EMBEDDED,
            "iot": cls.EMBEDDED,
        }

        for key, platform in mapping.items():
            if key in value_lower:
                return platform

        return cls.UNKNOWN


class UseCase(Enum):
    """Primary use case for cryptographic operations."""

    TLS = "tls"
    JWT = "jwt"
    FILE_ENCRYPTION = "file_encryption"
    KEY_EXCHANGE = "key_exchange"
    DIGITAL_SIGNATURE = "digital_signature"
    CODE_SIGNING = "code_signing"
    VPN = "vpn"
    SSH = "ssh"
    EMAIL = "email"
    BLOCKCHAIN = "blockchain"
    IOT = "iot"
    DATABASE = "database"
    API = "api"
    CERTIFICATE = "certificate"

    @property
    def needs_kem(self) -> bool:
        """Whether this use case requires key encapsulation."""
        return self in {
            UseCase.TLS,
            UseCase.VPN,
            UseCase.SSH,
            UseCase.KEY_EXCHANGE,
            UseCase.FILE_ENCRYPTION,
            UseCase.EMAIL,
        }

    @property
    def needs_signature(self) -> bool:
        """Whether this use case requires digital signatures."""
        return self in {
            UseCase.TLS,
            UseCase.JWT,
            UseCase.CODE_SIGNING,
            UseCase.DIGITAL_SIGNATURE,
            UseCase.VPN,
            UseCase.SSH,
            UseCase.EMAIL,
            UseCase.BLOCKCHAIN,
            UseCase.CERTIFICATE,
            UseCase.API,
        }

    @property
    def signature_size_sensitive(self) -> bool:
        """Whether signature size is a key concern for this use case."""
        return self in {
            UseCase.JWT,
            UseCase.BLOCKCHAIN,
            UseCase.IOT,
            UseCase.CERTIFICATE,
        }

    @property
    def latency_sensitive(self) -> bool:
        """Whether low latency is critical for this use case."""
        return self in {
            UseCase.TLS,
            UseCase.API,
            UseCase.JWT,
            UseCase.VPN,
        }


class SecurityLevel(Enum):
    """NIST security levels for post-quantum cryptography."""

    LEVEL_1 = 1  # At least as hard as AES-128 key search
    LEVEL_2 = 2  # At least as hard as SHA-256 collision
    LEVEL_3 = 3  # At least as hard as AES-192 key search
    LEVEL_5 = 5  # At least as hard as AES-256 key search

    @property
    def classical_bits(self) -> int:
        """Approximate classical security in bits."""
        return {
            SecurityLevel.LEVEL_1: 128,
            SecurityLevel.LEVEL_2: 128,
            SecurityLevel.LEVEL_3: 192,
            SecurityLevel.LEVEL_5: 256,
        }[self]

    @property
    def description(self) -> str:
        """Human-readable description of security level."""
        return {
            SecurityLevel.LEVEL_1: "128-bit (AES-128 equivalent)",
            SecurityLevel.LEVEL_2: "128-bit (SHA-256 collision equivalent)",
            SecurityLevel.LEVEL_3: "192-bit (AES-192 equivalent)",
            SecurityLevel.LEVEL_5: "256-bit (AES-256 equivalent)",
        }[self]


class ComplianceFramework(Enum):
    """Compliance frameworks that may constrain algorithm choice."""

    FIPS_140_3 = "fips_140_3"
    CNSA_2_0 = "cnsa_2_0"
    COMMON_CRITERIA = "common_criteria"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    FEDRAMP = "fedramp"


@dataclass
class Constraints:
    """
    User constraints extracted from query.

    This is the central data structure that captures all requirements
    that influence algorithm recommendation. Fields are optional to
    allow partial specification.
    """

    # ══════════════════════════════════════════════════════════════════
    # PLATFORM CONSTRAINTS
    # ══════════════════════════════════════════════════════════════════

    platform: Platform | None = None
    has_floating_point: bool | None = None
    max_memory_kb: int | None = None
    max_stack_kb: int | None = None

    # ══════════════════════════════════════════════════════════════════
    # PERFORMANCE CONSTRAINTS
    # ══════════════════════════════════════════════════════════════════

    max_latency_ms: float | None = None
    operations_per_second: int | None = None

    # ══════════════════════════════════════════════════════════════════
    # SIZE CONSTRAINTS
    # ══════════════════════════════════════════════════════════════════

    max_public_key_bytes: int | None = None
    max_private_key_bytes: int | None = None
    max_signature_bytes: int | None = None
    max_ciphertext_bytes: int | None = None

    # ══════════════════════════════════════════════════════════════════
    # CRYPTOGRAPHIC REQUIREMENTS
    # ══════════════════════════════════════════════════════════════════

    use_case: UseCase | None = None
    needs_kem: bool = False
    needs_signature: bool = False
    needs_both: bool = False

    # ══════════════════════════════════════════════════════════════════
    # SECURITY REQUIREMENTS
    # ══════════════════════════════════════════════════════════════════

    min_security_level: SecurityLevel = SecurityLevel.LEVEL_3
    requires_constant_time: bool = True
    requires_nist_standardized: bool = True

    # ══════════════════════════════════════════════════════════════════
    # COMPLIANCE REQUIREMENTS
    # ══════════════════════════════════════════════════════════════════

    compliance_frameworks: list[ComplianceFramework] = field(default_factory=list)
    requires_fips_validated: bool = False

    # ══════════════════════════════════════════════════════════════════
    # ENVIRONMENT FLAGS
    # ══════════════════════════════════════════════════════════════════

    is_mobile: bool = False
    is_embedded: bool = False
    is_browser: bool = False
    is_server: bool = False
    is_high_volume: bool = False

    # ══════════════════════════════════════════════════════════════════
    # PREFERENCES
    # ══════════════════════════════════════════════════════════════════

    prefer_smaller_signatures: bool = False
    prefer_smaller_keys: bool = False
    prefer_faster_signing: bool = False
    prefer_faster_verification: bool = False
    hybrid_with_classical: bool = False
    preferred_library: str | None = None

    def infer_from_use_case(self) -> None:
        """Infer additional constraints from the use case if set."""
        if self.use_case is None:
            return

        # Infer crypto operations needed
        if self.use_case.needs_kem and not self.needs_signature:
            self.needs_kem = True
        if self.use_case.needs_signature and not self.needs_kem:
            self.needs_signature = True
        if self.use_case.needs_kem and self.use_case.needs_signature:
            self.needs_both = True

        # Infer preferences from use case
        if self.use_case.signature_size_sensitive:
            self.prefer_smaller_signatures = True
        if self.use_case.latency_sensitive:
            self.prefer_faster_verification = True

    def apply_compliance_requirements(self) -> None:
        """Apply constraints implied by compliance frameworks."""
        if ComplianceFramework.FIPS_140_3 in self.compliance_frameworks:
            self.requires_nist_standardized = True
            self.requires_fips_validated = True

        if ComplianceFramework.CNSA_2_0 in self.compliance_frameworks:
            self.requires_nist_standardized = True
            self.min_security_level = SecurityLevel.LEVEL_3

        if ComplianceFramework.FEDRAMP in self.compliance_frameworks:
            self.requires_fips_validated = True

    @property
    def confidence(self) -> float:
        """
        Confidence score (0-1) based on how fully specified constraints are.

        Higher confidence means more specific recommendations.
        """
        specified = 0
        total = 0

        # Count key constraint fields
        checks = [
            self.platform is not None,
            self.use_case is not None,
            self.needs_kem or self.needs_signature,
            self.max_latency_ms is not None,
            len(self.compliance_frameworks) > 0,
            self.is_mobile or self.is_server or self.is_embedded or self.is_browser,
        ]

        for check in checks:
            total += 1
            if check:
                specified += 1

        return specified / total if total > 0 else 0.0
