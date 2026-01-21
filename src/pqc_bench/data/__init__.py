"""Algorithm and platform data."""

# Data version - update when algorithms, frameworks, or libraries change
# Format: YYYY-MM (year-month of last significant data update)
DATA_VERSION = "2024-12"
DATA_SOURCES = [
    "NIST FIPS 203/204/205 (August 2024)",
    "NSA CNSA 2.0 (September 2022)",
    "GSMA PQ.03 (2024)",
    "IEC 62443-2-1:2024",
]

from .algorithms import ALGORITHMS, AlgorithmProfile
from .compliance import COMPLIANCE_FRAMEWORKS, ComplianceFramework
from .critical_infrastructure import (
    SECTOR_PROFILES,
    MigrationUrgency,
    Sector,
    SectorProfile,
    detect_sector_from_query,
    get_all_sectors,
    get_compliance_deadlines,
    get_critical_sectors,
    get_sector_profile,
    get_sector_recommendation,
)
from .libraries import (
    HYBRID_MODES,
    LIBRARIES,
    HybridMode,
    LibraryProfile,
    ProductionReadiness,
    get_hybrid_mode,
    get_libraries_with_fips,
    get_production_ready_libraries,
)
from .protocol_impact import (
    CertificateChainAnalysis,
    TLSHandshakeImpact,
    analyze_certificate_chain,
    calculate_tls_kem_impact,
    calculate_tls_signature_impact,
    estimate_operation_latency,
    get_ossification_risks,
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
    # Data versioning
    "DATA_VERSION",
    "DATA_SOURCES",
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
    # Critical infrastructure
    "SECTOR_PROFILES",
    "Sector",
    "SectorProfile",
    "MigrationUrgency",
    "get_sector_profile",
    "get_all_sectors",
    "get_critical_sectors",
    "detect_sector_from_query",
    "get_sector_recommendation",
    "get_compliance_deadlines",
]
