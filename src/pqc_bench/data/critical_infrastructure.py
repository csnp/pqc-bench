"""
Critical Infrastructure PQC Guidance Module.

Sector-specific PQC requirements, constraints, and recommendations for:
- Space/Aerospace
- Automotive/EVs (V2X)
- Industrial OT/SCADA
- Energy/Utilities
- Healthcare/Medical Devices
- Financial Services
- Telecommunications/5G

Based on real-world standards, regulations, and deployment constraints.
"""

from dataclasses import dataclass, field
from enum import Enum


class Sector(Enum):
    """Critical infrastructure sectors."""

    SPACE_AEROSPACE = "space_aerospace"
    AUTOMOTIVE = "automotive"
    INDUSTRIAL_OT = "industrial_ot"
    ENERGY_UTILITIES = "energy_utilities"
    HEALTHCARE = "healthcare"
    FINANCIAL = "financial"
    TELECOMMUNICATIONS = "telecommunications"


class MigrationUrgency(Enum):
    """Migration urgency level."""

    CRITICAL = "critical"  # Start now, deadline approaching
    HIGH = "high"  # Start within 1 year
    MEDIUM = "medium"  # Start within 2-3 years
    PLANNING = "planning"  # Begin planning phase


@dataclass
class RegulatoryFramework:
    """Regulatory framework affecting PQC adoption."""

    name: str
    authority: str
    pqc_requirement: str  # "mandatory", "recommended", "none"
    deadline: str | None = None
    notes: str = ""
    url: str | None = None


@dataclass
class TechnicalConstraint:
    """Technical constraint for a sector."""

    name: str
    description: str
    impact: str  # How it affects algorithm choice
    severity: str  # "blocking", "major", "minor"


@dataclass
class SectorProfile:
    """Complete PQC profile for a critical infrastructure sector."""

    id: str
    name: str
    description: str

    # Urgency and timeline
    urgency: MigrationUrgency
    sndl_risk: str  # "extreme", "high", "medium", "low"
    data_lifespan_years: int
    equipment_lifecycle_years: int

    # Regulatory landscape
    regulations: list[RegulatoryFramework]
    compliance_deadline: str | None = None

    # Technical constraints
    constraints: list[TechnicalConstraint] = field(default_factory=list)

    # Platform characteristics
    typical_platform: str = "x86_64"
    has_fpu: bool = True
    max_latency_ms: float | None = None
    max_message_bytes: int | None = None
    bandwidth_limited: bool = False

    # Crypto requirements
    needs_kem: bool = True
    needs_signature: bool = True
    hybrid_recommended: bool = True
    crypto_agility_possible: bool = True

    # Recommendations
    recommended_kem: str = "ML-KEM-768"
    recommended_sig: str = "ML-DSA-65"
    recommended_hybrid_kem: str | None = None
    recommended_hybrid_sig: str | None = None

    # Migration guidance
    migration_priority: list[str] = field(default_factory=list)
    special_considerations: list[str] = field(default_factory=list)

    # References
    key_references: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTOR PROFILES
# ═══════════════════════════════════════════════════════════════════════════════

SECTOR_PROFILES: dict[str, SectorProfile] = {
    # ───────────────────────────────────────────────────────────────────────────
    # SPACE / AEROSPACE
    # ───────────────────────────────────────────────────────────────────────────
    "space_aerospace": SectorProfile(
        id="space_aerospace",
        name="Space & Aerospace",
        description="Satellites, spacecraft, ground stations, and aerospace systems",
        urgency=MigrationUrgency.CRITICAL,
        sndl_risk="extreme",
        data_lifespan_years=50,  # National security data
        equipment_lifecycle_years=25,  # Satellite missions can exceed 20 years
        regulations=[
            RegulatoryFramework(
                name="CNSA 2.0",
                authority="NSA",
                pqc_requirement="mandatory",
                deadline="2030-2033",
                notes="National Security Systems must migrate to PQC",
                url="https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
            ),
            RegulatoryFramework(
                name="NASA-STD-1006A",
                authority="NASA",
                pqc_requirement="recommended",
                notes="Space System Protection Requirements - references FIPS 140",
            ),
            RegulatoryFramework(
                name="CCSDS SDLS",
                authority="CCSDS",
                pqc_requirement="none",
                notes="Space Data Link Security - PQC updates expected",
            ),
        ],
        compliance_deadline="2030",
        constraints=[
            TechnicalConstraint(
                name="No software updates",
                description="Spacecraft cannot receive crypto updates after launch",
                impact="Must choose algorithms that will remain secure for mission lifetime",
                severity="blocking",
            ),
            TechnicalConstraint(
                name="Radiation-hardened processors",
                description="Rad-hard CPUs have limited performance (often 10-100x slower)",
                impact="Algorithm performance is critical; may need simpler variants",
                severity="major",
            ),
            TechnicalConstraint(
                name="High latency",
                description="Deep space: minutes to hours of signal delay",
                impact="Interactive protocols not possible; store-and-forward required",
                severity="major",
            ),
            TechnicalConstraint(
                name="Bandwidth constraints",
                description="Limited RF bandwidth for data transmission",
                impact="Signature/key sizes directly impact mission data capacity",
                severity="major",
            ),
        ],
        typical_platform="embedded",
        has_fpu=False,  # Many rad-hard CPUs lack FPU
        max_message_bytes=8192,  # CCSDS frame limits
        bandwidth_limited=True,
        crypto_agility_possible=False,  # Cannot update after launch
        hybrid_recommended=True,
        recommended_kem="ML-KEM-1024",  # Highest security for long missions
        recommended_sig="ML-DSA-87",  # CNSA 2.0 requires Level 5
        recommended_hybrid_kem="X25519Kyber768",
        migration_priority=[
            "Ground station command authentication (immediate)",
            "Telemetry encryption (before 2027)",
            "Inter-satellite links (new missions only)",
            "Legacy missions - assess data classification",
        ],
        special_considerations=[
            "CRYPTO-AGILITY IMPOSSIBLE: Choose algorithm for entire mission lifetime",
            "Falcon (FN-DSA) NOT suitable: requires FPU, variable timing",
            "Consider SLH-DSA for ultra-long-term archival signatures despite size",
            "Ground segment can use hybrid; spacecraft must commit to one approach",
        ],
        key_references=[
            "CNSA 2.0 FAQ (NSA): https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
            "NASA Quantum Communication 101: https://www.nasa.gov/wp-content/uploads/2024/07/quantum-communication-101-final.pdf",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # AUTOMOTIVE / EVs
    # ───────────────────────────────────────────────────────────────────────────
    "automotive": SectorProfile(
        id="automotive",
        name="Automotive & EVs",
        description="V2X communications, ECUs, EV charging, connected vehicles",
        urgency=MigrationUrgency.HIGH,
        sndl_risk="high",
        data_lifespan_years=15,  # Vehicle lifetime
        equipment_lifecycle_years=15,
        regulations=[
            RegulatoryFramework(
                name="ISO/SAE 21434",
                authority="ISO/SAE",
                pqc_requirement="none",
                notes="Automotive cybersecurity standard - no PQC yet",
            ),
            RegulatoryFramework(
                name="SAE J2735",
                authority="SAE",
                pqc_requirement="none",
                notes="V2X message definitions - PQC not specified",
            ),
            RegulatoryFramework(
                name="UN R155/R156",
                authority="UNECE",
                pqc_requirement="recommended",
                notes="Cybersecurity/software update management - crypto agility implied",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="V2X latency requirement",
                description="Safety messages must be processed within 100ms",
                impact="Large signatures may exceed latency budget on low-power ECUs",
                severity="blocking",
            ),
            TechnicalConstraint(
                name="CAN bus bandwidth",
                description="Legacy CAN: 1 Mbps, CAN-FD: 8 Mbps",
                impact="4.6KB ML-DSA signatures cannot fit in single CAN frame",
                severity="major",
            ),
            TechnicalConstraint(
                name="ECU resource constraints",
                description="Many ECUs have <1MB RAM, no FPU",
                impact="May need smaller algorithm variants or hardware acceleration",
                severity="major",
            ),
            TechnicalConstraint(
                name="AUTOSAR compatibility",
                description="No PQC schemes specified for AUTOSAR",
                impact="Integration requires custom development",
                severity="minor",
            ),
        ],
        typical_platform="arm32",  # Many ECUs are ARM Cortex-M
        has_fpu=False,  # Varies by ECU
        max_latency_ms=100.0,  # V2X safety requirement
        max_message_bytes=4095,  # CAN-FD limit
        bandwidth_limited=True,
        recommended_kem="ML-KEM-512",  # Smaller for latency
        recommended_sig="ML-DSA-44",  # Smallest NIST-approved
        recommended_hybrid_kem="X25519Kyber768",
        recommended_hybrid_sig="ECDSA-P256+ML-DSA-44",
        migration_priority=[
            "V2X PKI certificates (new deployments)",
            "Telematics/cloud communication",
            "OTA update signing",
            "ECU-to-ECU authentication (long-term)",
        ],
        special_considerations=[
            "V2X: Consider Falcon for smaller signatures (666 bytes vs 2420)",
            "BUT Falcon requires FPU - not available on all ECUs",
            "Hybrid mode critical during transition (vehicle lifetime 15+ years)",
            "AUTOCRYPT offers first commercial ML-DSA PKI for vehicles",
        ],
        key_references=[
            "SAE Quantum Technologies Report: https://saemobilus.sae.org/reports/unsettled-topics-concerning-impact-quantum-technologies-automotive-cybersecurity-epr2020026",
            "AUTOCRYPT PKI-Vehicles: https://autocrypt.io/pqc-pki-vehicle-solution/",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # INDUSTRIAL OT / SCADA
    # ───────────────────────────────────────────────────────────────────────────
    "industrial_ot": SectorProfile(
        id="industrial_ot",
        name="Industrial OT & SCADA",
        description="Industrial control systems, SCADA, PLCs, manufacturing",
        urgency=MigrationUrgency.HIGH,
        sndl_risk="high",
        data_lifespan_years=10,
        equipment_lifecycle_years=30,  # IEC 62443-2-1:2024 notes 20+ years
        regulations=[
            RegulatoryFramework(
                name="IEC 62443",
                authority="IEC",
                pqc_requirement="none",
                deadline=None,
                notes="2024 update addresses crypto but no PQC requirements yet",
                url="https://www.iec.ch/taxonomy/term/778",
            ),
            RegulatoryFramework(
                name="NIST SP 800-82",
                authority="NIST",
                pqc_requirement="recommended",
                notes="Guide to ICS Security - references PQC transition",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="30-year equipment lifecycle",
                description="ICS equipment often runs for decades without upgrade",
                impact="Must plan for crypto agility or very long-term algorithm stability",
                severity="blocking",
            ),
            TechnicalConstraint(
                name="Real-time requirements",
                description="Control loops may require <10ms response",
                impact="Crypto operations cannot block control functions",
                severity="major",
            ),
            TechnicalConstraint(
                name="Air-gapped networks",
                description="Many OT networks are isolated from IT",
                impact="Reduces SNDL risk but complicates key distribution",
                severity="minor",
            ),
            TechnicalConstraint(
                name="Legacy protocols",
                description="Modbus, DNP3, OPC-UA have limited crypto support",
                impact="PQC may require protocol upgrades or gateways",
                severity="major",
            ),
        ],
        typical_platform="embedded",
        has_fpu=False,
        max_latency_ms=10.0,  # Real-time control
        recommended_kem="ML-KEM-768",
        recommended_sig="ML-DSA-65",
        hybrid_recommended=True,
        migration_priority=[
            "IT/OT boundary gateways (immediate)",
            "SCADA master stations",
            "HMI authentication",
            "Field devices (long-term, with equipment refresh)",
        ],
        special_considerations=[
            "SNDL risk reduced for air-gapped networks but not eliminated",
            "Focus on securing IT/OT boundaries first",
            "Equipment refresh cycles (30 years) extend beyond threat timeline",
            "Consider PQC-capable secure gateways for legacy device protection",
        ],
        key_references=[
            "IEC 62443-2-1:2024: https://industrialcyber.co/isa-iec-62443/iec-publishes-iec-62443-2-12024-setting-security-standards-for-industrial-automation-and-control-systems/",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # ENERGY / UTILITIES
    # ───────────────────────────────────────────────────────────────────────────
    "energy_utilities": SectorProfile(
        id="energy_utilities",
        name="Energy & Utilities",
        description="Power grid, smart meters, substations, energy trading",
        urgency=MigrationUrgency.HIGH,
        sndl_risk="high",
        data_lifespan_years=20,
        equipment_lifecycle_years=25,
        regulations=[
            RegulatoryFramework(
                name="NERC CIP",
                authority="NERC",
                pqc_requirement="none",
                notes="Critical Infrastructure Protection - crypto requirements exist",
            ),
            RegulatoryFramework(
                name="DOE Cybersecurity",
                authority="DOE",
                pqc_requirement="recommended",
                notes="DOE spearheading PQC for grid security",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="Grid reliability requirements",
                description="Power systems must maintain 99.99%+ uptime",
                impact="Crypto migration cannot disrupt grid operations",
                severity="blocking",
            ),
            TechnicalConstraint(
                name="Smart meter constraints",
                description="Millions of deployed meters with limited compute",
                impact="Meter replacement may be only option for some",
                severity="major",
            ),
            TechnicalConstraint(
                name="Substation isolation",
                description="Many substations have limited connectivity",
                impact="Key distribution and revocation challenging",
                severity="minor",
            ),
        ],
        typical_platform="embedded",
        has_fpu=True,  # Modern grid devices often have capable processors
        recommended_kem="ML-KEM-768",
        recommended_sig="ML-DSA-65",
        migration_priority=[
            "Energy trading platforms (high SNDL risk)",
            "SCADA communications",
            "Substation authentication",
            "Smart meter PKI (with device refresh)",
        ],
        special_considerations=[
            "AES-256 is quantum-resistant for symmetric encryption",
            "Focus PQC migration on asymmetric operations (key exchange, signatures)",
            "Prioritize energy trading - financial data has high SNDL value",
            "DOE funding available for quantum security research",
        ],
        key_references=[
            "CISA PQC Initiative: https://www.cisa.gov/quantum",
            "DOE Quantum Collaboration: https://www.energy.gov/technologytransitions/articles/us-department-energy-announces-first-its-kind-collaboration-quantum",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # HEALTHCARE / MEDICAL DEVICES
    # ───────────────────────────────────────────────────────────────────────────
    "healthcare": SectorProfile(
        id="healthcare",
        name="Healthcare & Medical Devices",
        description="Medical devices, EHR systems, hospital infrastructure, patient data",
        urgency=MigrationUrgency.CRITICAL,
        sndl_risk="extreme",
        data_lifespan_years=100,  # Patient health records - lifetime plus estate
        equipment_lifecycle_years=10,
        regulations=[
            RegulatoryFramework(
                name="FDA 524B",
                authority="FDA",
                pqc_requirement="recommended",
                notes="FDA can refuse devices lacking crypto planning; crypto-agility required",
                url="https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions",
            ),
            RegulatoryFramework(
                name="HIPAA",
                authority="HHS",
                pqc_requirement="none",
                notes="Requires 6+ year data retention; strong SNDL implications",
            ),
            RegulatoryFramework(
                name="NIST Deprecation",
                authority="NIST",
                pqc_requirement="mandatory",
                deadline="2030",
                notes="Non-quantum-resistant crypto deprecated by 2030",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="FDA approval cycles",
                description="510(k) and PMA processes take 6-24 months",
                impact="Crypto changes require re-certification planning",
                severity="major",
            ),
            TechnicalConstraint(
                name="Patient safety",
                description="Device malfunctions can harm patients",
                impact="Crypto updates must not affect device function",
                severity="blocking",
            ),
            TechnicalConstraint(
                name="Legacy device fleet",
                description="Many deployed devices cannot receive updates",
                impact="Network segmentation may be only option",
                severity="major",
            ),
        ],
        typical_platform="arm64",
        has_fpu=True,
        crypto_agility_possible=True,  # FDA now requires this
        recommended_kem="ML-KEM-768",
        recommended_sig="ML-DSA-65",
        hybrid_recommended=True,
        migration_priority=[
            "EHR systems (extreme SNDL risk - 100 year data)",
            "Medical imaging archives (DICOM)",
            "New device submissions (FDA now expects crypto planning)",
            "Hospital network infrastructure",
            "Connected medical devices",
        ],
        special_considerations=[
            "HIPAA 6-year retention is MINIMUM; patient data lives forever",
            "FDA requires crypto-agility in new device submissions",
            "Hybrid cryptography recommended during transition",
            "Legacy devices: focus on network segmentation",
            "SNDL risk is EXTREME - health records are lifetime sensitive",
        ],
        key_references=[
            "FDA Cybersecurity Guidance 2023: https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions",
            "Medcrypt PQC Guide: https://www.medcrypt.com/blog/navigating-post-quantum-cryptography-in-medical-device-cybersecurity",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # FINANCIAL SERVICES
    # ───────────────────────────────────────────────────────────────────────────
    "financial": SectorProfile(
        id="financial",
        name="Financial Services",
        description="Banking, payments, SWIFT, trading, blockchain",
        urgency=MigrationUrgency.CRITICAL,
        sndl_risk="extreme",
        data_lifespan_years=30,  # Financial records, tax implications
        equipment_lifecycle_years=7,
        regulations=[
            RegulatoryFramework(
                name="SWIFT CSP",
                authority="SWIFT",
                pqc_requirement="recommended",
                notes="Customer Security Programme now includes PQC guidance",
            ),
            RegulatoryFramework(
                name="DORA",
                authority="EU",
                pqc_requirement="recommended",
                deadline="2025",
                notes="Digital Operational Resilience Act - requires ICT risk mitigation",
            ),
            RegulatoryFramework(
                name="PCI-DSS 4.0",
                authority="PCI SSC",
                pqc_requirement="none",
                notes="Strong cryptography required; PQC guidance expected",
            ),
            RegulatoryFramework(
                name="NSM-10",
                authority="US Government",
                pqc_requirement="mandatory",
                deadline="2035",
                notes="Federal agencies must complete PQC migration",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="SWIFT network migration",
                description="11,000+ banks must upgrade systems",
                impact="Coordinated migration required across ecosystem",
                severity="major",
            ),
            TechnicalConstraint(
                name="Transaction latency",
                description="Payment processing has strict SLAs",
                impact="PQC overhead must not impact transaction times",
                severity="major",
            ),
            TechnicalConstraint(
                name="HSM replacement",
                description="Hardware Security Modules need PQC support",
                impact="May require hardware refresh before migration",
                severity="major",
            ),
        ],
        typical_platform="x86_64_avx2",
        has_fpu=True,
        recommended_kem="ML-KEM-768",
        recommended_sig="ML-DSA-65",
        hybrid_recommended=True,
        migration_priority=[
            "SWIFT messaging authentication (immediate)",
            "HSM key generation (with hardware refresh)",
            "TLS for banking APIs",
            "Payment card authentication",
            "Blockchain/DLT systems",
        ],
        special_considerations=[
            "BIS Project Leap successfully tested PQC in payment systems",
            "SWIFT already using third-party quantum-resistant algorithm",
            "18 EU member states issued joint statement urging immediate action",
            "Harvest Now, Decrypt Later is PRIMARY threat for financial data",
            "Coordinate with SWIFT and payment networks for timing",
        ],
        key_references=[
            "BIS Project Leap Phase 2: https://www.bis.org/publ/othp107.htm",
            "SWIFT Security Programme: https://www.swift.com/myswift/customer-security-programme-csp",
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────────
    # TELECOMMUNICATIONS / 5G
    # ───────────────────────────────────────────────────────────────────────────
    "telecommunications": SectorProfile(
        id="telecommunications",
        name="Telecommunications & 5G",
        description="Mobile networks (2G-5G), core infrastructure, backhaul",
        urgency=MigrationUrgency.HIGH,
        sndl_risk="high",
        data_lifespan_years=10,
        equipment_lifecycle_years=15,
        regulations=[
            RegulatoryFramework(
                name="GSMA PQ.03",
                authority="GSMA",
                pqc_requirement="recommended",
                notes="Post-Quantum Cryptography Guidelines for Telecom Use",
                url="https://www.gsma.com/newsroom/wp-content/uploads//PQ.03-Post-Quantum-Cryptography-Guidelines-for-Telecom-Use-v1.0.pdf",
            ),
            RegulatoryFramework(
                name="3GPP Standards",
                authority="3GPP",
                pqc_requirement="none",
                notes="5G security specs being updated for PQC",
            ),
        ],
        constraints=[
            TechnicalConstraint(
                name="Multi-generation networks",
                description="2G, 3G, 4G, 5G all coexist with different crypto",
                impact="Phased migration across generations required",
                severity="major",
            ),
            TechnicalConstraint(
                name="Radio interface constraints",
                description="Over-the-air bandwidth is limited",
                impact="Larger keys impact handover latency and battery life",
                severity="major",
            ),
            TechnicalConstraint(
                name="Interoperability requirements",
                description="Devices must work across operator networks",
                impact="Industry-wide coordination required",
                severity="major",
            ),
        ],
        typical_platform="x86_64_avx2",  # Core network
        has_fpu=True,
        recommended_kem="ML-KEM-768",
        recommended_sig="ML-DSA-65",
        hybrid_recommended=True,
        recommended_hybrid_kem="X25519Kyber768",
        migration_priority=[
            "5G core network (SA architecture)",
            "Backhaul encryption",
            "SIM/eSIM authentication (with new SIM issuance)",
            "Radio interface (long-term, with 6G design)",
        ],
        special_considerations=[
            "HPQC (Hybrid PQC) with ECC recommended during transition",
            "5G core can handle PQC overhead without issues",
            "Radio interface migration is long-term (5G/6G transition)",
            "Cryptographic discovery is essential first step",
            "Nokia, Ericsson, Huawei all developing PQC solutions",
        ],
        key_references=[
            "GSMA PQ.03: https://www.gsma.com/newsroom/wp-content/uploads//PQ.03-Post-Quantum-Cryptography-Guidelines-for-Telecom-Use-v1.0.pdf",
            "5G Americas Post-Quantum Security: https://www.5gamericas.org/post-quantum-computing-security/",
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
# QUERY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def get_sector_profile(sector_id: str) -> SectorProfile | None:
    """Get profile for a specific sector."""
    return SECTOR_PROFILES.get(sector_id)


def get_all_sectors() -> list[SectorProfile]:
    """Get all sector profiles."""
    return list(SECTOR_PROFILES.values())


def get_sectors_by_urgency(urgency: MigrationUrgency) -> list[SectorProfile]:
    """Get sectors matching an urgency level."""
    return [s for s in SECTOR_PROFILES.values() if s.urgency == urgency]


def get_critical_sectors() -> list[SectorProfile]:
    """Get sectors with CRITICAL migration urgency."""
    return get_sectors_by_urgency(MigrationUrgency.CRITICAL)


def detect_sector_from_query(query: str) -> SectorProfile | None:
    """Detect sector from natural language query."""
    import re

    query_lower = query.lower()

    # Keywords that need word boundary matching (short words that might be substrings)
    # Use \\b for word boundaries in regex
    sector_keywords: dict[str, list[str]] = {
        "space_aerospace": [
            "satellite", "spacecraft", "space", "aerospace", "nasa", "rocket",
            "ground station", "launch", "orbit", "deep space", "mission",
        ],
        "automotive": [
            "automotive", "vehicle", r"\bcar\b", r"\bev\b", "electric vehicle", "v2x",
            "v2v", "telematics", r"\becu\b", "can bus", "connected car", "adas",
            "charging", r"\boem\b", "tesla", "rivian",
        ],
        "industrial_ot": [
            "scada", r"\bics\b", r"\bplc\b", r"\bhmi\b", "industrial", "manufacturing",
            "factory", r"\bot\b", "operational technology", r"\bdcs\b", "modbus",
            "dnp3", "opc-ua",
        ],
        "energy_utilities": [
            "power grid", "power plant", "utility", "utilities", "energy", "smart meter",
            "substation", "nerc", "electric grid", "smart grid", "energy trading",
            "nuclear", "hydroelectric", "solar farm", "wind farm",
        ],
        "healthcare": [
            "healthcare", "medical", "hospital", "patient", r"\behr\b", r"\bfda\b",
            "hipaa", "medical device", "pacemaker", "insulin pump", "imaging",
            r"\bphi\b", "health record", r"\bmri\b", "ct scan", "x-ray", "diagnostic",
        ],
        "financial": [
            r"\bbank\b", "banking", "payment", "swift", "financial", "trading",
            "credit card", r"\bpci\b", "fintech", "stock", "exchange", "settlement",
            "blockchain", "cryptocurrency", r"\batm\b", "wire transfer",
        ],
        "telecommunications": [
            "telecom", r"\b5g\b", r"\b4g\b", r"\blte\b", "mobile network", "carrier",
            "gsma", r"\bsim\b", "esim", "backhaul", "core network",
        ],
    }

    for sector_id, keywords in sector_keywords.items():
        for kw in keywords:
            # If keyword contains regex pattern (starts with \b), use regex
            if r"\b" in kw:
                if re.search(kw, query_lower):
                    return SECTOR_PROFILES.get(sector_id)
            else:
                if kw in query_lower:
                    return SECTOR_PROFILES.get(sector_id)

    return None


def get_sector_recommendation(sector_id: str) -> dict[str, str]:
    """Get algorithm recommendations for a sector."""
    profile = SECTOR_PROFILES.get(sector_id)
    if not profile:
        return {}

    return {
        "kem": profile.recommended_kem,
        "signature": profile.recommended_sig,
        "hybrid_kem": profile.recommended_hybrid_kem or "X25519Kyber768",
        "hybrid_sig": profile.recommended_hybrid_sig or "ECDSA-P256+ML-DSA-44",
        "urgency": profile.urgency.value,
        "sndl_risk": profile.sndl_risk,
    }


def get_compliance_deadlines() -> list[tuple[str, str, str]]:
    """Get all compliance deadlines across sectors."""
    deadlines = []
    for profile in SECTOR_PROFILES.values():
        for reg in profile.regulations:
            if reg.deadline:
                deadlines.append((profile.name, reg.name, reg.deadline))
    return sorted(deadlines, key=lambda x: x[2])
