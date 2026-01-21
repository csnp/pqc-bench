"""
Protocol impact analysis for PQC adoption.

This module addresses critical practitioner concerns about protocol-level
impacts of PQC, including:
- TLS handshake size explosion
- Certificate chain size impact
- Protocol ossification issues (middleboxes)
- Latency considerations

Key insight: PQC signatures are 30-70x larger than ECDSA, which has
cascading effects on certificate chains, TLS handshakes, and systems
that never anticipated such sizes.
"""

from dataclasses import dataclass, field

from .algorithms import get_algorithm

# ══════════════════════════════════════════════════════════════════════════════
# CLASSICAL ALGORITHM BASELINE DATA
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ClassicalAlgorithmSizes:
    """Size data for classical algorithms (for comparison)."""

    id: str
    public_key: int
    signature: int | None = None
    shared_secret: int | None = None


CLASSICAL_SIZES: dict[str, ClassicalAlgorithmSizes] = {
    "ecdsa-p256": ClassicalAlgorithmSizes(
        id="ecdsa-p256",
        public_key=64,
        signature=64,  # DER encoding can be up to 72 bytes
    ),
    "ecdsa-p384": ClassicalAlgorithmSizes(
        id="ecdsa-p384",
        public_key=96,
        signature=96,
    ),
    "rsa-2048": ClassicalAlgorithmSizes(
        id="rsa-2048",
        public_key=256,
        signature=256,
    ),
    "rsa-4096": ClassicalAlgorithmSizes(
        id="rsa-4096",
        public_key=512,
        signature=512,
    ),
    "x25519": ClassicalAlgorithmSizes(
        id="x25519",
        public_key=32,
        shared_secret=32,
    ),
    "x448": ClassicalAlgorithmSizes(
        id="x448",
        public_key=56,
        shared_secret=56,
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# TLS HANDSHAKE IMPACT
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class TLSHandshakeImpact:
    """Impact of algorithm choice on TLS 1.3 handshake."""

    algorithm_id: str
    algorithm_name: str

    # Size contributions
    client_hello_delta: int  # Additional bytes in ClientHello
    server_hello_delta: int  # Additional bytes in ServerHello
    certificate_delta: int  # Additional bytes per certificate
    total_handshake_delta: int  # Total additional bytes

    # Performance
    additional_rtt_ms: float  # Estimated additional latency
    packet_fragmentation_risk: str  # "low", "medium", "high"

    # Compatibility
    middlebox_compatibility: str  # "good", "moderate", "poor"
    known_issues: list[str] = field(default_factory=list)

    # Comparison
    comparison_baseline: str = "ECDSA P-256 + X25519"


def calculate_tls_kem_impact(kem_algorithm_id: str) -> TLSHandshakeImpact | None:
    """Calculate TLS handshake impact for a KEM algorithm."""
    algo = get_algorithm(kem_algorithm_id)
    if algo is None or not algo.is_kem:
        return None

    x25519 = CLASSICAL_SIZES["x25519"]

    # KEM adds public key in ClientHello, ciphertext in ServerHello
    client_delta = algo.sizes.public_key - x25519.public_key
    server_delta = (algo.sizes.ciphertext or 0) - x25519.public_key

    total = client_delta + server_delta

    # Estimate latency based on size (rough heuristic)
    # ~1ms per 10KB on average network
    additional_latency = total / 10000

    # Fragmentation risk based on size
    if total < 500:
        frag_risk = "low"
    elif total < 1500:
        frag_risk = "medium"
    else:
        frag_risk = "high"

    # Middlebox compatibility based on total size
    if total < 1000:
        middlebox = "good"
        issues = []
    elif total < 2000:
        middlebox = "moderate"
        issues = ["Some corporate proxies may struggle"]
    else:
        middlebox = "poor"
        issues = [
            "May trigger middlebox inspection failures",
            "Some DPI devices may drop packets",
            "Consider TCP fragmentation",
        ]

    return TLSHandshakeImpact(
        algorithm_id=kem_algorithm_id,
        algorithm_name=algo.names.nist_name,
        client_hello_delta=client_delta,
        server_hello_delta=server_delta,
        certificate_delta=0,  # KEMs don't affect certificates
        total_handshake_delta=total,
        additional_rtt_ms=additional_latency,
        packet_fragmentation_risk=frag_risk,
        middlebox_compatibility=middlebox,
        known_issues=issues,
    )


def calculate_tls_signature_impact(
    sig_algorithm_id: str, chain_length: int = 3
) -> TLSHandshakeImpact | None:
    """Calculate TLS handshake impact for a signature algorithm."""
    algo = get_algorithm(sig_algorithm_id)
    if algo is None or not algo.is_signature:
        return None

    ecdsa = CLASSICAL_SIZES["ecdsa-p256"]

    # Signature algorithms affect certificates
    # Each cert has: public key + signature from issuer
    cert_delta = (
        algo.sizes.public_key
        + (algo.sizes.signature or 0)
        - ecdsa.public_key
        - (ecdsa.signature or 0)
    )

    # Total certificate chain impact
    total_cert_delta = cert_delta * chain_length

    # Signatures also appear in CertificateVerify
    cv_delta = (algo.sizes.signature or 0) - (ecdsa.signature or 0)

    total = total_cert_delta + cv_delta

    # Latency estimate
    additional_latency = total / 10000

    # Fragmentation risk
    if total < 3000:
        frag_risk = "low"
    elif total < 10000:
        frag_risk = "medium"
    else:
        frag_risk = "high"

    # Middlebox compatibility
    issues = []
    if total > 16000:
        middlebox = "poor"
        issues = [
            "Certificate chain exceeds single TCP packet",
            "May cause TCP fragmentation issues",
            "Some middleboxes cannot reassemble",
        ]
    elif total > 8000:
        middlebox = "moderate"
        issues = ["May require TCP segmentation"]
    else:
        middlebox = "good"

    return TLSHandshakeImpact(
        algorithm_id=sig_algorithm_id,
        algorithm_name=algo.names.nist_name,
        client_hello_delta=0,
        server_hello_delta=0,
        certificate_delta=cert_delta,
        total_handshake_delta=total,
        additional_rtt_ms=additional_latency,
        packet_fragmentation_risk=frag_risk,
        middlebox_compatibility=middlebox,
        known_issues=issues,
        comparison_baseline=f"ECDSA P-256 (chain of {chain_length})",
    )


# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE CHAIN ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class CertificateChainAnalysis:
    """Analysis of certificate chain size impact."""

    signature_algorithm: str
    chain_length: int

    # Per-certificate sizes
    classical_cert_size: int  # ECDSA P-256 baseline
    pqc_cert_size: int
    size_increase_factor: float

    # Total chain sizes
    classical_chain_size: int
    pqc_chain_size: int
    total_increase_bytes: int

    # TCP/IP impact
    tcp_segments_classical: int
    tcp_segments_pqc: int
    additional_segments: int

    # Recommendations
    mitigations: list[str] = field(default_factory=list)


def analyze_certificate_chain(
    sig_algorithm_id: str, chain_length: int = 3
) -> CertificateChainAnalysis | None:
    """Analyze certificate chain size for a signature algorithm."""
    algo = get_algorithm(sig_algorithm_id)
    if algo is None or not algo.is_signature:
        return None

    ecdsa = CLASSICAL_SIZES["ecdsa-p256"]

    # Baseline ECDSA certificate size (typical)
    # Certificate overhead + public key + signature
    cert_overhead = 300  # ASN.1 encoding, extensions, etc.
    classical_cert = cert_overhead + ecdsa.public_key + (ecdsa.signature or 0)

    # PQC certificate size
    pqc_cert = cert_overhead + algo.sizes.public_key + (algo.sizes.signature or 0)

    # Chain totals
    classical_chain = classical_cert * chain_length
    pqc_chain = pqc_cert * chain_length

    # Size factor
    size_factor = pqc_cert / classical_cert

    # TCP segments (MSS typically 1460 bytes)
    mss = 1460
    tcp_classical = (classical_chain + mss - 1) // mss
    tcp_pqc = (pqc_chain + mss - 1) // mss

    # Mitigations based on size
    mitigations = []
    if pqc_chain > 10000:
        mitigations.append("Consider shorter certificate chains")
        mitigations.append("Use certificate compression (RFC 8879)")
        mitigations.append("Cache intermediate certificates")

    if size_factor > 10:
        mitigations.append("Evaluate Falcon for smaller signatures (with FPU caveat)")
        mitigations.append("Consider using ML-DSA-44 if security level permits")

    if chain_length > 2:
        mitigations.append("Optimize PKI hierarchy to reduce chain length")

    mitigations.append("Use OCSP stapling to reduce OCSP response overhead")

    return CertificateChainAnalysis(
        signature_algorithm=algo.names.nist_name,
        chain_length=chain_length,
        classical_cert_size=classical_cert,
        pqc_cert_size=pqc_cert,
        size_increase_factor=size_factor,
        classical_chain_size=classical_chain,
        pqc_chain_size=pqc_chain,
        total_increase_bytes=pqc_chain - classical_chain,
        tcp_segments_classical=tcp_classical,
        tcp_segments_pqc=tcp_pqc,
        additional_segments=tcp_pqc - tcp_classical,
        mitigations=mitigations,
    )


# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL OSSIFICATION ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class OssificationRisk:
    """Risk of protocol ossification issues."""

    category: str
    description: str
    severity: str  # "low", "medium", "high"
    affected_systems: list[str]
    mitigation: str


def get_ossification_risks(algorithm_id: str) -> list[OssificationRisk]:
    """Get protocol ossification risks for an algorithm."""
    algo = get_algorithm(algorithm_id)
    if algo is None:
        return []

    risks = []

    # Size-based risks
    if algo.is_kem:
        total_size = algo.sizes.public_key + (algo.sizes.ciphertext or 0)
    else:
        total_size = algo.sizes.public_key + (algo.sizes.signature or 0)

    if total_size > 1500:
        risks.append(
            OssificationRisk(
                category="Packet Size",
                description="Algorithm data exceeds typical MTU",
                severity="medium",
                affected_systems=[
                    "Deep packet inspection",
                    "Corporate firewalls",
                    "Some VPN appliances",
                ],
                mitigation="Use TCP segmentation, avoid UDP where possible",
            )
        )

    if total_size > 4000:
        risks.append(
            OssificationRisk(
                category="Middlebox Buffering",
                description="Some middleboxes have limited reassembly buffers",
                severity="high",
                affected_systems=[
                    "Legacy load balancers",
                    "SSL inspection appliances",
                    "Some WAF products",
                ],
                mitigation="Test with production middleboxes before deployment",
            )
        )

    if total_size > 8000:
        risks.append(
            OssificationRisk(
                category="TLS Record Size",
                description="May exceed TLS record size expectations",
                severity="high",
                affected_systems=[
                    "TLS accelerators",
                    "Hardware security modules",
                    "Some IoT gateways",
                ],
                mitigation="Verify TLS stack compatibility, consider fragmentation",
            )
        )

    # Algorithm-specific risks
    if algo.family == "Falcon":
        risks.append(
            OssificationRisk(
                category="Variable Signature Size",
                description="Falcon signatures have variable size",
                severity="low",
                affected_systems=["Fixed-buffer parsers", "Some protocol implementations"],
                mitigation="Use padded signature format where supported",
            )
        )

    if algo.family == "SLH-DSA":
        risks.append(
            OssificationRisk(
                category="Large Signature",
                description="SLH-DSA signatures are 17-50KB",
                severity="high",
                affected_systems=[
                    "HTTP header limits",
                    "Database field sizes",
                    "Log aggregators",
                ],
                mitigation="Store signatures separately, use references",
            )
        )

    return risks


# ══════════════════════════════════════════════════════════════════════════════
# LATENCY ESTIMATION
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class LatencyEstimate:
    """Latency estimate for cryptographic operations."""

    algorithm_id: str
    operation: str  # "keygen", "sign", "verify", "encaps", "decaps"
    platform: str

    # Times
    classical_baseline_us: float
    pqc_time_us: float
    overhead_us: float
    overhead_factor: float

    # Notes
    notes: list[str] = field(default_factory=list)


def estimate_operation_latency(
    algorithm_id: str, operation: str, platform: str = "x86_64_avx2"
) -> LatencyEstimate | None:
    """Estimate latency for a cryptographic operation."""
    algo = get_algorithm(algorithm_id)
    if algo is None:
        return None

    perf = algo.performance.get(platform)
    if perf is None:
        return None

    # Get ops/sec for the operation
    ops_map = {
        "keygen": perf.keygen_ops,
        "sign": perf.sign_ops,
        "verify": perf.verify_ops,
        "encaps": perf.encaps_ops,
        "decaps": perf.decaps_ops,
    }

    ops = ops_map.get(operation)
    if ops is None or ops == 0:
        return None

    # Convert to microseconds per operation
    pqc_us = 1_000_000 / ops

    # Classical baselines (approximate for comparison)
    classical_baselines = {
        "keygen": 50,  # ECDSA P-256 keygen ~50us
        "sign": 100,  # ECDSA P-256 sign ~100us
        "verify": 200,  # ECDSA P-256 verify ~200us
        "encaps": 30,  # X25519 ~30us
        "decaps": 30,
    }

    classical_us = classical_baselines.get(operation, 100)
    overhead = pqc_us - classical_us
    factor = pqc_us / classical_us if classical_us > 0 else 0

    notes = []
    if factor > 10:
        notes.append("Significant overhead - consider impact on latency budget")
    if operation == "keygen" and pqc_us > 10000:
        notes.append("Slow keygen - pre-generate keys where possible")
    if operation == "sign" and pqc_us > 5000:
        notes.append("Consider signing latency in request path")

    return LatencyEstimate(
        algorithm_id=algorithm_id,
        operation=operation,
        platform=platform,
        classical_baseline_us=classical_us,
        pqc_time_us=pqc_us,
        overhead_us=overhead,
        overhead_factor=factor,
        notes=notes,
    )


# ══════════════════════════════════════════════════════════════════════════════
# COMPARISON HELPER
# ══════════════════════════════════════════════════════════════════════════════


def get_size_comparison_table(algorithm_ids: list[str]) -> dict[str, dict[str, int]]:
    """Generate size comparison table for algorithms."""
    result = {}

    for algo_id in algorithm_ids:
        algo = get_algorithm(algo_id)
        if algo is None:
            continue

        sizes = {
            "public_key": algo.sizes.public_key,
            "private_key": algo.sizes.private_key,
        }

        if algo.is_kem:
            sizes["ciphertext"] = algo.sizes.ciphertext or 0
            sizes["total_exchange"] = algo.sizes.public_key + (algo.sizes.ciphertext or 0)
        else:
            sizes["signature"] = algo.sizes.signature or 0
            sizes["total_signed"] = algo.sizes.public_key + (algo.sizes.signature or 0)

        result[algo.names.nist_name] = sizes

    return result
