"""
Compliance framework definitions and requirements.

Maps industry standards and regulations to algorithm requirements,
enabling automatic constraint inference from compliance contexts.
"""

from dataclasses import dataclass, field


@dataclass
class TimelineRequirement:
    """Timeline for compliance adoption."""

    prefer_by: int | None = None  # Year to prefer PQC
    require_by: int | None = None  # Year PQC becomes mandatory
    exclusive_by: int | None = None  # Year classical is prohibited
    notes: str | None = None


@dataclass
class AlgorithmRequirement:
    """Algorithm requirements for a compliance framework."""

    kem_algorithms: list[str] = field(default_factory=list)
    signature_algorithms: list[str] = field(default_factory=list)
    min_security_level: int = 3
    notes: str | None = None


@dataclass
class ComplianceFramework:
    """Definition of a compliance framework and its PQC requirements."""

    id: str
    name: str
    authority: str
    url: str
    description: str
    requirements: AlgorithmRequirement
    timeline: TimelineRequirement | None = None
    applies_to: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)


COMPLIANCE_FRAMEWORKS: dict[str, ComplianceFramework] = {
    "cnsa_2_0": ComplianceFramework(
        id="cnsa_2_0",
        name="CNSA 2.0",
        authority="National Security Agency (NSA)",
        url="https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
        description="Commercial National Security Algorithm Suite 2.0 - "
        "NSA guidance for protecting classified information",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-768", "ml-kem-1024"],
            signature_algorithms=["ml-dsa-65", "ml-dsa-87"],
            min_security_level=3,
            notes="ML-KEM-768 and ML-DSA-65 for Secret; ML-KEM-1024 and ML-DSA-87 for Top Secret",
        ),
        timeline=TimelineRequirement(
            prefer_by=2025,
            require_by=2030,
            exclusive_by=2033,
            notes="Software/firmware should prefer PQC by 2025; "
            "exclusive PQC use required by 2033",
        ),
        applies_to=[
            "US Government classified systems",
            "Defense contractors",
            "National security systems",
        ],
        citations=[
            "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
        ],
    ),
    "fips_140_3": ComplianceFramework(
        id="fips_140_3",
        name="FIPS 140-3",
        authority="National Institute of Standards and Technology (NIST)",
        url="https://csrc.nist.gov/publications/detail/fips/140/3/final",
        description="Security Requirements for Cryptographic Modules - "
        "required for US federal government use",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-512", "ml-kem-768", "ml-kem-1024"],
            signature_algorithms=[
                "ml-dsa-44",
                "ml-dsa-65",
                "ml-dsa-87",
                "slh-dsa-128f",
                "slh-dsa-128s",
                "slh-dsa-192f",
                "slh-dsa-192s",
                "slh-dsa-256f",
                "slh-dsa-256s",
            ],
            min_security_level=1,
            notes="All NIST-standardized PQC algorithms (FIPS 203, 204, 205) are approved",
        ),
        applies_to=[
            "US Federal agencies",
            "Federal contractors",
            "Healthcare (HIPAA)",
            "Financial services",
        ],
        citations=[
            "https://csrc.nist.gov/pubs/fips/203/final",
            "https://csrc.nist.gov/pubs/fips/204/final",
            "https://csrc.nist.gov/pubs/fips/205/final",
        ],
    ),
    "pci_dss_4": ComplianceFramework(
        id="pci_dss_4",
        name="PCI DSS 4.0",
        authority="Payment Card Industry Security Standards Council",
        url="https://www.pcisecuritystandards.org/",
        description="Payment Card Industry Data Security Standard - "
        "required for organizations handling payment cards",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-768", "ml-kem-1024"],
            signature_algorithms=["ml-dsa-65", "ml-dsa-87"],
            min_security_level=3,
            notes="PCI DSS requires strong cryptography; Level 3+ recommended for PQC",
        ),
        timeline=TimelineRequirement(
            notes="PCI DSS 4.0 requires inventory of cryptographic assets; "
            "PQC migration planning recommended",
        ),
        applies_to=[
            "Payment processors",
            "E-commerce platforms",
            "Financial institutions",
            "Any organization storing card data",
        ],
    ),
    "hipaa": ComplianceFramework(
        id="hipaa",
        name="HIPAA Security Rule",
        authority="US Department of Health and Human Services",
        url="https://www.hhs.gov/hipaa/for-professionals/security/index.html",
        description="Health Insurance Portability and Accountability Act - "
        "security requirements for protected health information",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-768", "ml-kem-1024"],
            signature_algorithms=["ml-dsa-65", "ml-dsa-87"],
            min_security_level=3,
            notes="HIPAA requires encryption of ePHI; recommend Level 3+ for long-term protection",
        ),
        applies_to=[
            "Healthcare providers",
            "Health insurers",
            "Healthcare clearinghouses",
            "Business associates",
        ],
    ),
    "common_criteria": ComplianceFramework(
        id="common_criteria",
        name="Common Criteria",
        authority="Common Criteria Recognition Arrangement",
        url="https://www.commoncriteriaportal.org/",
        description="International standard for computer security certification",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-768", "ml-kem-1024"],
            signature_algorithms=["ml-dsa-65", "ml-dsa-87"],
            min_security_level=3,
            notes="Protection profiles being updated for PQC; follow NIST recommendations",
        ),
        applies_to=[
            "Products requiring security certification",
            "Government IT systems (international)",
            "Critical infrastructure",
        ],
    ),
    "fedramp": ComplianceFramework(
        id="fedramp",
        name="FedRAMP",
        authority="US General Services Administration",
        url="https://www.fedramp.gov/",
        description="Federal Risk and Authorization Management Program - "
        "security assessment for cloud services used by federal agencies",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-768", "ml-kem-1024"],
            signature_algorithms=["ml-dsa-65", "ml-dsa-87"],
            min_security_level=3,
            notes="FedRAMP requires FIPS 140-validated cryptography",
        ),
        applies_to=[
            "Cloud service providers to federal government",
            "SaaS platforms for federal use",
        ],
    ),
}


def get_framework(framework_id: str) -> ComplianceFramework | None:
    """Get compliance framework by ID."""
    return COMPLIANCE_FRAMEWORKS.get(framework_id.lower().replace("-", "_"))


def get_frameworks_for_context(context: str) -> list[ComplianceFramework]:
    """
    Get applicable compliance frameworks based on context keywords.

    Args:
        context: Description that may indicate compliance requirements
                 (e.g., "healthcare", "government", "financial")

    Returns:
        List of potentially applicable frameworks
    """
    context_lower = context.lower()
    applicable = []

    keyword_mapping = {
        "cnsa_2_0": ["government", "defense", "classified", "nsa", "military", "secret"],
        "fips_140_3": ["federal", "government", "fips", "nist"],
        "pci_dss_4": [
            "payment",
            "credit card",
            "financial",
            "banking",
            "fintech",
            "commerce",
            "merchant",
        ],
        "hipaa": ["healthcare", "health", "medical", "hospital", "patient", "phi", "ehr"],
        "fedramp": ["federal", "cloud", "saas", "government cloud"],
    }

    for framework_id, keywords in keyword_mapping.items():
        if any(kw in context_lower for kw in keywords):
            framework = COMPLIANCE_FRAMEWORKS.get(framework_id)
            if framework:
                applicable.append(framework)

    return applicable
