"""Algorithm and platform data."""

from .algorithms import ALGORITHMS, AlgorithmProfile
from .compliance import COMPLIANCE_FRAMEWORKS, ComplianceFramework
from .libraries import (
    LIBRARIES,
    HYBRID_MODES,
    LibraryProfile,
    HybridMode,
    ProductionReadiness,
    get_production_ready_libraries,
    get_libraries_with_fips,
    get_hybrid_mode,
)
from .protocol_impact import (
    calculate_tls_kem_impact,
    calculate_tls_signature_impact,
    analyze_certificate_chain,
    get_ossification_risks,
    estimate_operation_latency,
    TLSHandshakeImpact,
    CertificateChainAnalysis,
)
from .threat_model import (
    DATA_PROFILES,
    QUANTUM_THREAT_TIMELINE,
    DataLifespanProfile,
    ThreatUrgency,
    assess_sndl_risk,
    calculate_migration_priority,
    get_profiles_by_urgency,
)

__all__ = [
    # Algorithms
    "ALGORITHMS",
    "AlgorithmProfile",
    # Compliance
    "COMPLIANCE_FRAMEWORKS",
    "ComplianceFramework",
    # Libraries
    "LIBRARIES",
    "HYBRID_MODES",
    "LibraryProfile",
    "HybridMode",
    "ProductionReadiness",
    "get_production_ready_libraries",
    "get_libraries_with_fips",
    "get_hybrid_mode",
    # Protocol impact
    "calculate_tls_kem_impact",
    "calculate_tls_signature_impact",
    "analyze_certificate_chain",
    "get_ossification_risks",
    "estimate_operation_latency",
    "TLSHandshakeImpact",
    "CertificateChainAnalysis",
    # Threat model
    "DATA_PROFILES",
    "QUANTUM_THREAT_TIMELINE",
    "DataLifespanProfile",
    "ThreatUrgency",
    "assess_sndl_risk",
    "calculate_migration_priority",
    "get_profiles_by_urgency",
]
