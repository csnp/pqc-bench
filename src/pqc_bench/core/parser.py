"""
Natural language query parser.

Extracts structured constraints from free-form user queries,
with intelligent inference of implicit requirements.
"""

import re

from ..data.compliance import get_frameworks_for_context
from .constraints import (
    ComplianceFramework,
    Constraints,
    Platform,
    SecurityLevel,
    UseCase,
)


class QueryParser:
    """
    Parses natural language queries into structured constraints.

    The parser uses pattern matching and keyword detection to extract
    explicit constraints, then applies inference rules to derive
    implicit requirements based on context.
    """

    # Platform detection patterns
    PLATFORM_PATTERNS: dict[Platform, list[str]] = {
        Platform.X86_64_AVX512: ["avx512", "avx-512"],
        Platform.X86_64_AVX2: [
            "avx2",
            "avx-2",
            "x86",
            "x64",
            "amd64",
            "intel",
            "aws lambda",
            "lambda",
            "ec2",
            "gcp",
            "azure",
            "server",
            "cloud",
        ],
        Platform.ARM64_NEON: [
            "arm64",
            "aarch64",
            "neon",
            "apple m1",
            "apple m2",
            "apple m3",
            "m1",
            "m2",
            "m3",
            "graviton",
            "ios",
            "android",
            "mobile",
        ],
        Platform.ARM32: ["arm32", "armv7", "raspberry pi"],
        Platform.WASM: ["wasm", "webassembly", "browser", "web app", "frontend", "javascript"],
        Platform.EMBEDDED: [
            "embedded",
            "iot",
            "mcu",
            "microcontroller",
            "esp32",
            "arduino",
            "stm32",
            "rtos",
        ],
    }

    # Use case detection patterns - order matters! More specific patterns first
    USECASE_PATTERNS: dict[UseCase, list[str]] = {
        UseCase.BLOCKCHAIN: [
            "blockchain",
            "web3",
            "smart contract",
            "cryptocurrency",
            "ledger",
        ],
        UseCase.TLS: [
            "tls",
            "https",
            "ssl",
            "handshake",
            "web server",
            "nginx",
            "apache",
            "load balancer",
            "reverse proxy",
            "cdn",
        ],
        UseCase.JWT: ["jwt", "json web token", "bearer token", "oauth", "oidc", "api auth"],
        UseCase.CODE_SIGNING: ["code signing", "binary signing", "software signing", "package signing"],
        UseCase.VPN: ["vpn", "tunnel", "wireguard", "ipsec", "openvpn"],
        UseCase.SSH: ["ssh", "secure shell", "remote access"],
        UseCase.EMAIL: ["email", "s/mime", "smime", "pgp", "encrypted email"],
        UseCase.API: ["api", "rest", "graphql", "grpc", "microservice"],
        UseCase.FILE_ENCRYPTION: [
            "file encryption",
            "encrypt files",
            "at rest",
            "storage encryption",
            "disk encryption",
        ],
        UseCase.KEY_EXCHANGE: [
            "key exchange",
            "diffie-hellman",
            "dh",
            "ecdh",
            "session key",
            "ephemeral",
        ],
        UseCase.IOT: ["iot", "sensor", "device", "constrained", "low power"],
        UseCase.CERTIFICATE: ["certificate", "x.509", "pki", "ca", "cert"],
        UseCase.DIGITAL_SIGNATURE: [
            "signature",
            "verify",
            "non-repudiation",
        ],
    }

    # Compliance context patterns
    COMPLIANCE_PATTERNS: dict[ComplianceFramework, list[str]] = {
        ComplianceFramework.FIPS_140_3: ["fips", "fips 140", "federal", "government"],
        ComplianceFramework.CNSA_2_0: [
            "cnsa",
            "nsa",
            "classified",
            "secret",
            "top secret",
            "defense",
        ],
        ComplianceFramework.PCI_DSS: [
            "pci",
            "payment",
            "credit card",
            "card data",
            "merchant",
            "fintech",
            "banking",
        ],
        ComplianceFramework.HIPAA: ["hipaa", "healthcare", "medical", "health", "phi", "patient"],
        ComplianceFramework.SOC2: ["soc2", "soc 2", "audit"],
        ComplianceFramework.FEDRAMP: ["fedramp", "federal cloud"],
    }

    # Volume/scale patterns
    VOLUME_PATTERNS = [
        (r"(\d+)\s*k\s*(?:req|request|op|operation).*(?:sec|second|/s)", 1000),
        (r"(\d+)\s*(?:req|request|op|operation).*(?:sec|second|/s)", 1),
        (r"high.?volume", None),
        (r"high.?throughput", None),
        (r"scale", None),
    ]

    # Latency patterns
    LATENCY_PATTERNS = [
        r"(\d+)\s*ms\s*(?:latency|budget|max|limit)?",
        r"latency\s*(?:of|budget|under|below)?\s*(\d+)\s*ms",
        r"(\d+)\s*millisecond",
    ]

    def parse(self, query: str) -> Constraints:
        """
        Parse a natural language query into structured constraints.

        Args:
            query: Free-form description of requirements

        Returns:
            Constraints object with extracted and inferred requirements
        """
        query_lower = query.lower()
        constraints = Constraints()

        # Extract explicit constraints
        self._detect_platform(query_lower, constraints)
        self._detect_use_case(query_lower, constraints)
        self._detect_compliance(query_lower, constraints)
        self._detect_performance(query_lower, constraints)
        self._detect_environment(query_lower, constraints)
        self._detect_preferences(query_lower, constraints)

        # Apply inference rules
        constraints.infer_from_use_case()
        constraints.apply_compliance_requirements()
        self._apply_context_inference(query_lower, constraints)

        return constraints

    def _detect_platform(self, query: str, constraints: Constraints) -> None:
        """Detect target platform from query."""
        for platform, keywords in self.PLATFORM_PATTERNS.items():
            if any(kw in query for kw in keywords):
                constraints.platform = platform
                return

    def _detect_use_case(self, query: str, constraints: Constraints) -> None:
        """Detect primary use case from query."""
        for use_case, keywords in self.USECASE_PATTERNS.items():
            if any(kw in query for kw in keywords):
                constraints.use_case = use_case
                return

    def _detect_compliance(self, query: str, constraints: Constraints) -> None:
        """Detect compliance requirements from query."""
        for framework, keywords in self.COMPLIANCE_PATTERNS.items():
            if any(kw in query for kw in keywords):
                constraints.compliance_frameworks.append(framework)

        # Also check for implicit compliance based on context
        inferred = get_frameworks_for_context(query)
        for framework in inferred:
            try:
                cf = ComplianceFramework(framework.id)
                if cf not in constraints.compliance_frameworks:
                    constraints.compliance_frameworks.append(cf)
            except ValueError:
                # Framework ID doesn't match enum value, skip
                pass

    def _detect_performance(self, query: str, constraints: Constraints) -> None:
        """Detect performance requirements from query."""
        # Latency detection
        for pattern in self.LATENCY_PATTERNS:
            match = re.search(pattern, query)
            if match:
                constraints.max_latency_ms = float(match.group(1))
                break

        # Volume detection
        for pattern, multiplier in self.VOLUME_PATTERNS:
            match = re.search(pattern, query)
            if match:
                if multiplier is not None:
                    try:
                        constraints.operations_per_second = int(match.group(1)) * multiplier
                    except (ValueError, IndexError):
                        pass
                constraints.is_high_volume = True
                break

    def _detect_environment(self, query: str, constraints: Constraints) -> None:
        """Detect environment flags from query."""
        if any(kw in query for kw in ["mobile", "ios", "android", "phone", "tablet"]):
            constraints.is_mobile = True
            if constraints.platform is None:
                constraints.platform = Platform.ARM64_NEON

        if any(kw in query for kw in [
            "embedded", "iot", "constrained", "mcu", "microcontroller",
            "esp32", "arduino", "stm32", "rtos",
        ]):
            constraints.is_embedded = True
            if constraints.platform is None:
                constraints.platform = Platform.EMBEDDED

        if any(kw in query for kw in ["browser", "web app", "frontend", "wasm"]):
            constraints.is_browser = True
            if constraints.platform is None:
                constraints.platform = Platform.WASM

        if any(kw in query for kw in ["server", "backend", "cloud", "aws", "gcp", "azure"]):
            constraints.is_server = True
            if constraints.platform is None:
                constraints.platform = Platform.X86_64_AVX2

    def _detect_preferences(self, query: str, constraints: Constraints) -> None:
        """Detect user preferences from query."""
        if any(kw in query for kw in ["small signature", "compact", "minimal size", "bandwidth"]):
            constraints.prefer_smaller_signatures = True

        if any(kw in query for kw in ["fast verify", "quick verification", "read heavy"]):
            constraints.prefer_faster_verification = True

        if any(kw in query for kw in ["fast sign", "quick signing", "write heavy"]):
            constraints.prefer_faster_signing = True

        if any(kw in query for kw in ["hybrid", "transition", "migration"]):
            constraints.hybrid_with_classical = True

        # Security level preferences
        if any(kw in query for kw in ["maximum security", "highest security", "level 5"]):
            constraints.min_security_level = SecurityLevel.LEVEL_5
        elif any(kw in query for kw in ["high security", "level 3"]):
            constraints.min_security_level = SecurityLevel.LEVEL_3

    def _apply_context_inference(self, query: str, constraints: Constraints) -> None:
        """Apply inference rules based on overall context."""
        # Constrained/embedded context - prefer smaller algorithms
        if constraints.is_embedded or any(
            kw in query for kw in ["constrained", "limited memory", "low power", "small footprint"]
        ):
            # Lower security level is acceptable for IoT/embedded
            constraints.min_security_level = SecurityLevel.LEVEL_1
            constraints.prefer_smaller_keys = True
            constraints.prefer_smaller_signatures = True
            # Set reasonable size constraints for embedded
            if constraints.max_public_key_bytes is None:
                constraints.max_public_key_bytes = 2000
            if constraints.max_ciphertext_bytes is None:
                constraints.max_ciphertext_bytes = 1500

        # Financial context implies higher security
        if any(kw in query for kw in ["bank", "financial", "payment", "money", "transaction"]):
            if constraints.min_security_level.value < SecurityLevel.LEVEL_3.value:
                constraints.min_security_level = SecurityLevel.LEVEL_3

        # Healthcare implies compliance
        if any(kw in query for kw in ["health", "medical", "patient", "hospital"]):
            if ComplianceFramework.HIPAA not in constraints.compliance_frameworks:
                constraints.compliance_frameworks.append(ComplianceFramework.HIPAA)

        # Startup context - emphasize practicality
        if "startup" in query:
            constraints.is_high_volume = True

        # Blockchain context - signature size matters
        if constraints.use_case == UseCase.BLOCKCHAIN:
            constraints.prefer_smaller_signatures = True
            constraints.needs_signature = True

        # JWT context - signature size matters (HTTP headers)
        if constraints.use_case == UseCase.JWT:
            constraints.needs_signature = True
            constraints.prefer_faster_verification = True

        # TLS context - needs both KEM and signature
        if constraints.use_case == UseCase.TLS:
            constraints.needs_kem = True
            constraints.needs_signature = True
            constraints.needs_both = True

        # If no crypto operation specified, try to infer from keywords
        if not constraints.needs_kem and not constraints.needs_signature:
            if any(kw in query for kw in ["encrypt", "key exchange", "kem", "decryption"]):
                constraints.needs_kem = True
            if any(kw in query for kw in ["sign", "signature", "verify", "authentication"]):
                constraints.needs_signature = True
