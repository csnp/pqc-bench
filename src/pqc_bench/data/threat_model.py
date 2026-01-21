"""
SNDL (Store Now, Decrypt Later) threat prioritization.

This module helps practitioners prioritize their PQC migration based on
the "Harvest Now, Decrypt Later" (HNDL/SNDL) threat model. The key insight:

    Time to migration + Data lifespan > Time to quantum threat

If your data needs to be secret for 20 years, and quantum computers capable
of breaking RSA/ECC are expected in 10 years, you need to migrate NOW.

This threat model is the primary driver for near-term PQC adoption,
particularly for key exchange (KEMs), since encrypted traffic can be
captured and stored by adversaries.
"""

from dataclasses import dataclass
from enum import Enum


class ThreatUrgency(Enum):
    """Urgency level for PQC migration."""

    CRITICAL = "critical"  # Migrate immediately (2024-2025)
    HIGH = "high"  # Migrate within 2 years (2025-2027)
    MEDIUM = "medium"  # Migrate within 5 years (2027-2030)
    LOW = "low"  # Migrate by 2030
    MONITORING = "monitoring"  # Watch developments, plan for 2030+


class DataClassification(Enum):
    """Data sensitivity classification."""

    TOP_SECRET = "top_secret"  # National security, 75+ year protection
    SECRET = "secret"  # Government classified, 25+ years
    CONFIDENTIAL = "confidential"  # Business sensitive, 10+ years
    INTERNAL = "internal"  # Internal use, 5+ years
    PUBLIC = "public"  # No confidentiality requirement


@dataclass
class DataLifespanProfile:
    """Profile for data with specific lifespan requirements."""

    id: str
    name: str
    description: str
    typical_lifespan_years: int
    classification: DataClassification
    examples: list[str]
    urgency: ThreatUrgency
    rationale: str
    recommended_action: str
    cryptographic_needs: list[str]  # "kem", "signature", "both"


# ══════════════════════════════════════════════════════════════════════════════
# DATA LIFESPAN PROFILES
# ══════════════════════════════════════════════════════════════════════════════

DATA_PROFILES: dict[str, DataLifespanProfile] = {
    # CRITICAL URGENCY
    "national_security": DataLifespanProfile(
        id="national_security",
        name="National Security Data",
        description="Classified government and defense information",
        typical_lifespan_years=75,
        classification=DataClassification.TOP_SECRET,
        examples=[
            "Intelligence reports",
            "Military communications",
            "Diplomatic cables",
            "Nuclear facility data",
        ],
        urgency=ThreatUrgency.CRITICAL,
        rationale=(
            "75-year protection requirement means data encrypted today "
            "must resist quantum attacks expected within 10-15 years"
        ),
        recommended_action="Implement hybrid PQC immediately for all key exchanges",
        cryptographic_needs=["kem", "signature"],
    ),
    "healthcare_records": DataLifespanProfile(
        id="healthcare_records",
        name="Healthcare Records",
        description="Patient health information with lifetime confidentiality",
        typical_lifespan_years=100,
        classification=DataClassification.SECRET,
        examples=[
            "Medical records",
            "Genetic data",
            "Mental health records",
            "HIV/AIDS status",
        ],
        urgency=ThreatUrgency.CRITICAL,
        rationale=(
            "Healthcare data must remain confidential for patient's lifetime; "
            "genetic data is permanent. HIPAA has no expiration."
        ),
        recommended_action="Prioritize PQC for data at rest and in transit",
        cryptographic_needs=["kem"],
    ),
    "financial_long_term": DataLifespanProfile(
        id="financial_long_term",
        name="Long-term Financial Data",
        description="Financial records with regulatory retention requirements",
        typical_lifespan_years=25,
        classification=DataClassification.CONFIDENTIAL,
        examples=[
            "Tax records (7+ years)",
            "Investment account data",
            "Pension records",
            "Estate planning documents",
        ],
        urgency=ThreatUrgency.CRITICAL,
        rationale="SEC requires 7-year retention; some records kept 25+ years",
        recommended_action="Begin hybrid PQC rollout for storage encryption",
        cryptographic_needs=["kem"],
    ),
    # HIGH URGENCY
    "intellectual_property": DataLifespanProfile(
        id="intellectual_property",
        name="Intellectual Property",
        description="Trade secrets, patents, proprietary technology",
        typical_lifespan_years=20,
        classification=DataClassification.CONFIDENTIAL,
        examples=[
            "Trade secrets",
            "R&D data",
            "Patent applications",
            "Source code for core products",
        ],
        urgency=ThreatUrgency.HIGH,
        rationale="Competitive advantage depends on long-term secrecy",
        recommended_action="Implement PQC for key exchange within 2 years",
        cryptographic_needs=["kem", "signature"],
    ),
    "corporate_strategy": DataLifespanProfile(
        id="corporate_strategy",
        name="Corporate Strategic Data",
        description="M&A plans, pricing strategies, competitive intelligence",
        typical_lifespan_years=10,
        classification=DataClassification.CONFIDENTIAL,
        examples=[
            "M&A plans",
            "Pricing algorithms",
            "Customer lists",
            "Board communications",
        ],
        urgency=ThreatUrgency.HIGH,
        rationale="Competitive damage from disclosure remains for years",
        recommended_action="Plan PQC migration for 2025-2027",
        cryptographic_needs=["kem"],
    ),
    "legal_privileged": DataLifespanProfile(
        id="legal_privileged",
        name="Legal Privileged Communications",
        description="Attorney-client privilege, litigation strategy",
        typical_lifespan_years=30,
        classification=DataClassification.SECRET,
        examples=[
            "Legal advice",
            "Litigation strategy",
            "Regulatory investigation responses",
        ],
        urgency=ThreatUrgency.HIGH,
        rationale="Privilege never expires; disclosure would be catastrophic",
        recommended_action="Implement PQC for legal communications",
        cryptographic_needs=["kem", "signature"],
    ),
    # MEDIUM URGENCY
    "authentication_credentials": DataLifespanProfile(
        id="authentication_credentials",
        name="Authentication Credentials",
        description="Passwords, API keys, session tokens",
        typical_lifespan_years=1,
        classification=DataClassification.CONFIDENTIAL,
        examples=[
            "Password hashes",
            "API keys",
            "Session tokens",
            "OAuth tokens",
        ],
        urgency=ThreatUrgency.MEDIUM,
        rationale=(
            "Short-lived but high value; rotation reduces exposure. "
            "Signatures (not encryption) are the primary protection."
        ),
        recommended_action="Focus on PQC signatures for authentication by 2027",
        cryptographic_needs=["signature"],
    ),
    "transactional_data": DataLifespanProfile(
        id="transactional_data",
        name="Transactional Data",
        description="Payment transactions, order data",
        typical_lifespan_years=5,
        classification=DataClassification.CONFIDENTIAL,
        examples=[
            "Credit card transactions",
            "Order history",
            "Payment records",
        ],
        urgency=ThreatUrgency.MEDIUM,
        rationale="PCI-DSS requires protection; most valuable short-term",
        recommended_action="Plan PQC for payment systems by 2027",
        cryptographic_needs=["kem", "signature"],
    ),
    # LOW URGENCY
    "ephemeral_communications": DataLifespanProfile(
        id="ephemeral_communications",
        name="Ephemeral Communications",
        description="Real-time communications with limited retention",
        typical_lifespan_years=1,
        classification=DataClassification.INTERNAL,
        examples=[
            "Chat messages",
            "Video calls",
            "Screen shares",
        ],
        urgency=ThreatUrgency.LOW,
        rationale="Short retention; forward secrecy helps",
        recommended_action="Migrate with normal refresh cycles by 2030",
        cryptographic_needs=["kem"],
    ),
    "public_signatures": DataLifespanProfile(
        id="public_signatures",
        name="Public Signature Verification",
        description="Code signing, software updates, public documents",
        typical_lifespan_years=10,
        classification=DataClassification.PUBLIC,
        examples=[
            "Code signatures",
            "Software updates",
            "Document authenticity",
        ],
        urgency=ThreatUrgency.MEDIUM,
        rationale=(
            "No confidentiality but integrity matters; "
            "forged signatures could enable supply chain attacks"
        ),
        recommended_action="Plan PQC signature migration for 2025-2027",
        cryptographic_needs=["signature"],
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# QUANTUM THREAT TIMELINE
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class QuantumThreatEstimate:
    """Estimate of when quantum computers will break specific algorithms."""

    algorithm: str
    optimistic_years: int  # Earliest threat (aggressive timeline)
    median_years: int  # Most likely timeline
    conservative_years: int  # Conservative estimate
    source: str
    notes: str


QUANTUM_THREAT_TIMELINE: list[QuantumThreatEstimate] = [
    QuantumThreatEstimate(
        algorithm="RSA-2048",
        optimistic_years=10,
        median_years=15,
        conservative_years=25,
        source="NIST PQC Timeline",
        notes="Requires ~4000 logical qubits with error correction",
    ),
    QuantumThreatEstimate(
        algorithm="ECDSA P-256",
        optimistic_years=10,
        median_years=15,
        conservative_years=25,
        source="NIST PQC Timeline",
        notes="Similar to RSA; Shor's algorithm applies",
    ),
    QuantumThreatEstimate(
        algorithm="AES-256",
        optimistic_years=30,
        median_years=50,
        conservative_years=100,
        source="Grover's algorithm analysis",
        notes="Grover's gives quadratic speedup; 256-bit still secure",
    ),
    QuantumThreatEstimate(
        algorithm="SHA-256",
        optimistic_years=30,
        median_years=50,
        conservative_years=100,
        source="Grover's algorithm analysis",
        notes="Pre-image resistance reduced from 256 to 128 bits",
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# THREAT ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class SNDLAssessment:
    """Assessment of SNDL risk for a specific scenario."""

    data_profile: DataLifespanProfile
    data_lifespan_years: int
    migration_timeline_years: int
    quantum_threat_years: int  # Using median estimate

    # Calculated fields
    is_at_risk: bool
    urgency: ThreatUrgency
    years_margin: int  # Negative = already at risk
    risk_explanation: str
    recommended_algorithm: str | None = None
    recommended_hybrid: str | None = None


def assess_sndl_risk(
    data_profile_id: str,
    migration_timeline_years: int = 2,
    quantum_threat_years: int = 15,
) -> SNDLAssessment | None:
    """Assess SNDL risk for a data profile."""
    profile = DATA_PROFILES.get(data_profile_id)
    if profile is None:
        return None

    lifespan = profile.typical_lifespan_years

    # Calculate: Is (lifespan + migration_time) > quantum_threat?
    # If data must be secret for 20 years, and we take 2 years to migrate,
    # data captured today must resist attacks for 22 years
    required_protection = lifespan + migration_timeline_years
    margin = quantum_threat_years - (lifespan + migration_timeline_years)
    at_risk = required_protection > quantum_threat_years

    if at_risk:
        if margin < -10:
            explanation = (
                f"CRITICAL: Data needs {required_protection} years of protection, "
                f"but quantum threat expected in {quantum_threat_years} years. "
                f"You are {abs(margin)} years behind."
            )
        else:
            explanation = (
                f"AT RISK: Data lifespan ({lifespan} years) + migration time "
                f"({migration_timeline_years} years) exceeds quantum timeline "
                f"({quantum_threat_years} years) by {abs(margin)} years."
            )
    else:
        explanation = (
            f"MANAGEABLE: {margin} years margin before quantum threat. "
            f"Plan migration within {margin} years to maintain protection."
        )

    # Recommended algorithms based on needs
    recommended_algo = None
    recommended_hybrid = None

    if "kem" in profile.cryptographic_needs:
        if profile.urgency in [ThreatUrgency.CRITICAL, ThreatUrgency.HIGH]:
            recommended_hybrid = "X25519Kyber768"
            recommended_algo = "ML-KEM-768"
        else:
            recommended_algo = "ML-KEM-768"

    if "signature" in profile.cryptographic_needs and recommended_algo is None:
        recommended_algo = "ML-DSA-65"

    return SNDLAssessment(
        data_profile=profile,
        data_lifespan_years=lifespan,
        migration_timeline_years=migration_timeline_years,
        quantum_threat_years=quantum_threat_years,
        is_at_risk=at_risk,
        urgency=profile.urgency,
        years_margin=margin,
        risk_explanation=explanation,
        recommended_algorithm=recommended_algo,
        recommended_hybrid=recommended_hybrid,
    )


def get_profiles_by_urgency(urgency: ThreatUrgency) -> list[DataLifespanProfile]:
    """Get all data profiles with a specific urgency level."""
    return [p for p in DATA_PROFILES.values() if p.urgency == urgency]


def calculate_migration_deadline(
    data_lifespan_years: int,
    quantum_threat_years: int = 15,
    safety_margin_years: int = 2,
) -> int:
    """Calculate years until migration deadline.

    Returns negative if deadline has passed.
    """
    return quantum_threat_years - data_lifespan_years - safety_margin_years


# ══════════════════════════════════════════════════════════════════════════════
# MIGRATION PRIORITY SCORING
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class MigrationPriority:
    """Priority score for migrating a system to PQC."""

    system_name: str
    data_profile_id: str
    priority_score: float  # 0-100, higher = more urgent
    factors: dict[str, float]
    recommendation: str


def calculate_migration_priority(
    system_name: str,
    data_profile_id: str,
    exposure_level: str = "internal",  # "public", "internal", "isolated"
    data_volume: str = "medium",  # "low", "medium", "high"
    migration_complexity: str = "medium",  # "low", "medium", "high"
) -> MigrationPriority:
    """Calculate migration priority score for a system."""
    profile = DATA_PROFILES.get(data_profile_id)
    if profile is None:
        profile = DATA_PROFILES["transactional_data"]  # Default

    # Base score from urgency
    urgency_scores = {
        ThreatUrgency.CRITICAL: 80,
        ThreatUrgency.HIGH: 60,
        ThreatUrgency.MEDIUM: 40,
        ThreatUrgency.LOW: 20,
        ThreatUrgency.MONITORING: 10,
    }
    base_score = urgency_scores.get(profile.urgency, 40)

    # Exposure modifier
    exposure_modifiers = {
        "public": 15,  # Public-facing = higher risk of capture
        "internal": 5,
        "isolated": -5,
    }
    exposure_mod = exposure_modifiers.get(exposure_level, 5)

    # Volume modifier
    volume_modifiers = {
        "high": 10,  # More data = more value to attackers
        "medium": 0,
        "low": -5,
    }
    volume_mod = volume_modifiers.get(data_volume, 0)

    # Complexity penalty (easier migrations should go first)
    complexity_modifiers = {
        "low": 5,  # Easy wins first
        "medium": 0,
        "high": -10,
    }
    complexity_mod = complexity_modifiers.get(migration_complexity, 0)

    # Calculate final score
    final_score = min(100, max(0, base_score + exposure_mod + volume_mod + complexity_mod))

    factors = {
        "base_urgency": base_score,
        "exposure_modifier": exposure_mod,
        "volume_modifier": volume_mod,
        "complexity_modifier": complexity_mod,
    }

    # Generate recommendation
    if final_score >= 80:
        recommendation = "Immediate action required - begin migration planning now"
    elif final_score >= 60:
        recommendation = "High priority - include in 2025 migration roadmap"
    elif final_score >= 40:
        recommendation = "Medium priority - plan for 2026-2027 migration"
    else:
        recommendation = "Monitor developments - plan for 2028-2030 migration"

    return MigrationPriority(
        system_name=system_name,
        data_profile_id=data_profile_id,
        priority_score=final_score,
        factors=factors,
        recommendation=recommendation,
    )
