"""
Compliance framework definitions and requirements.

Maps industry standards and regulations to algorithm requirements,
enabling automatic constraint inference from compliance contexts.
"""

import re
from dataclasses import dataclass, field


@dataclass
class CategoryTimeline:
    """Adoption years for one product category within a framework."""

    category: str
    prefer_by: int | None = None  # Year to support and prefer PQC
    exclusive_by: int | None = None  # Year PQC must be used exclusively


@dataclass
class TimelineRequirement:
    """Timeline for compliance adoption."""

    prefer_by: int | None = None  # Year to prefer PQC
    require_by: int | None = None  # Year PQC becomes mandatory
    exclusive_by: int | None = None  # Year classical is prohibited
    complete_by: int | None = None  # Year the whole transition should be finished
    categories: list[CategoryTimeline] = field(default_factory=list)
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
        url="https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF",
        description="Commercial National Security Algorithm Suite 2.0 - "
        "NSA guidance for protecting classified information",
        requirements=AlgorithmRequirement(
            kem_algorithms=["ml-kem-1024"],
            signature_algorithms=["ml-dsa-87", "lms", "xmss"],
            min_security_level=5,
            notes="Level V parameters for all classification levels: "
            "ML-KEM-1024 (FIPS 203, named CRYSTALS-Kyber in the advisory) and "
            "ML-DSA-87 (FIPS 204, named CRYSTALS-Dilithium). "
            "LMS and XMSS (NIST SP 800-208) for signing software and firmware",
        ),
        timeline=TimelineRequirement(
            prefer_by=2025,
            require_by=2030,
            exclusive_by=2033,
            complete_by=2035,
            categories=[
                CategoryTimeline("Software and firmware signing", 2025, 2030),
                CategoryTimeline("Web browsers, servers and cloud services", 2025, 2033),
                CategoryTimeline("Traditional networking equipment (VPNs, routers)", 2026, 2030),
                CategoryTimeline("Operating systems", 2027, 2033),
                CategoryTimeline(
                    "Niche equipment (constrained devices, large PKI systems)", 2030, 2033
                ),
            ],
            notes="Dates differ by product category. Software and firmware signing and "
            "traditional networking equipment use CNSA 2.0 exclusively by 2030, the other "
            "categories by 2033. Custom applications and "
            "legacy equipment should be updated or replaced by 2033, and NSA expects "
            "the transition for national security systems to be complete by 2035",
        ),
        applies_to=[
            "US Government classified systems",
            "Defense contractors",
            "National security systems",
        ],
        citations=[
            "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF",
            "https://web.archive.org/web/20260928212413/https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF",
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


# Short names accepted in addition to the framework IDs.
FRAMEWORK_ALIASES: dict[str, str] = {
    "pci_dss": "pci_dss_4",
}

# "Military" alone also describes people and topics ("military spouse",
# "military history"), so it names a system CNSA 2.0 covers only when one of
# these words follows it, directly ("military drone") or after one other word
# ("military email system", "military ground station").
MILITARY_SYSTEM_WORDS: list[str] = [
    "aircraft",
    "command",
    "communication",
    "communications",
    "data",
    "drone",
    "drones",
    "intelligence",
    "network",
    "networks",
    "radio",
    "radios",
    "satellite",
    "satellites",
    "station",
    "stations",
    "system",
    "systems",
    "vehicle",
    "vehicles",
    "weapon",
    "weapons",
]

# Words that make "military" describe people or a topic. One of them between
# "military" and a system word does not name a military system: "military
# family network", "military history data".
MILITARY_PEOPLE_AND_TOPIC_WORDS: list[str] = [
    "families",
    "family",
    "history",
    "spouse",
    "spouses",
    "veteran",
    "veterans",
]

# Terms other than "military" that name CNSA 2.0 or the classified and
# national security systems it covers. They are matched as whole words,
# because "nsa" also occurs inside "transaction" and "classified" inside
# "unclassified". "cnsa 2" matches the joined spelling "CNSA2.0", where a digit
# follows "cnsa".
CNSA_2_0_TERMS: list[str] = [
    "cnsa",
    "cnsa 2",
    "nsa",
    "classified",
    "top secret",
    "national security",
]

# The CNSA 2.0 terms and the "military" phrases in which a system word follows
# "military" directly. mentions_cnsa_2_0 also accepts one word between them.
CNSA_2_0_KEYWORDS: list[str] = [
    *CNSA_2_0_TERMS,
    *(f"military {word}" for word in MILITARY_SYSTEM_WORDS),
]

# Phrases that contain a CNSA 2.0 keyword but do not describe a system CNSA 2.0
# covers. "Military-grade" describes the strength of commercial encryption.
CNSA_2_0_EXCLUDED_PHRASES: list[str] = [
    "military grade",
]

# A CNSA 2.0 keyword after this prefix is negated: "non-classified",
# "non-military system".
NEGATION_PREFIX = r"non[\s_-]*"


def _phrase_pattern(phrase: str, prefix: str = "") -> re.Pattern[str]:
    """Pattern for ``phrase`` as whole words, with its words joined by spaces,
    hyphens, underscores or nothing, after the optional regex ``prefix``."""
    words = r"[\s_-]*".join(re.escape(word) for word in phrase.lower().split())
    return re.compile(rf"(?<![a-z0-9]){prefix}{words}(?![a-z0-9])")


def contains_phrase(text: str, phrase: str) -> bool:
    """Whether ``phrase`` occurs in ``text`` as whole words, not inside a longer word.

    The words of ``phrase`` may be joined in ``text`` by spaces, hyphens,
    underscores or nothing, so "top secret" also matches "top-secret".
    """
    return _phrase_pattern(phrase).search(text.lower()) is not None


def _cnsa_2_0_patterns(prefix: str = "") -> list[re.Pattern[str]]:
    """Patterns for the CNSA 2.0 terms and for "military" followed by a system
    word, directly or after one other word, after the optional regex ``prefix``.
    The word between them is not one of MILITARY_PEOPLE_AND_TOPIC_WORDS."""
    system_words = "|".join(re.escape(word) for word in MILITARY_SYSTEM_WORDS)
    people_words = "|".join(re.escape(word) for word in MILITARY_PEOPLE_AND_TOPIC_WORDS)
    # The word between "military" and the system word is set apart by
    # separators on both sides, so "military ecosystem" is not "military" +
    # "eco" + "system".
    # The word is captured as "between" so that a negated phrase can be
    # removed without it: "non-military classified data" still names
    # classified data.
    between = rf"[\s_-]+(?!(?:{people_words})[\s_-])(?P<between>[a-z0-9]+)[\s_-]+"
    military = re.compile(
        rf"(?<![a-z0-9]){prefix}military(?:{between}|[\s_-]*)(?:{system_words})(?![a-z0-9])"
    )
    return [*(_phrase_pattern(term, prefix) for term in CNSA_2_0_TERMS), military]


def _keep_between_word(match: re.Match[str]) -> str:
    """Replacement for a negated phrase: the word between "military" and the
    system word, if the phrase has one, between spaces."""
    return f" {match.groupdict().get('between') or ''} "


def find_cnsa_2_0_mention(text: str) -> str | None:
    """The phrase in ``text`` that names CNSA 2.0 or a system that CNSA 2.0
    covers, lowercased, or None when there is none."""
    text = text.lower()
    for phrase in CNSA_2_0_EXCLUDED_PHRASES:
        text = _phrase_pattern(phrase).sub(" ", text)
    for pattern in _cnsa_2_0_patterns(NEGATION_PREFIX):
        text = pattern.sub(_keep_between_word, text)
    for pattern in _cnsa_2_0_patterns():
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def mentions_cnsa_2_0(text: str) -> bool:
    """Whether ``text`` names CNSA 2.0 or a system that CNSA 2.0 covers."""
    return find_cnsa_2_0_mention(text) is not None


# Short use case, compliance and platform keywords that also occur inside
# unrelated words ("ca" in "local", "phi" in "graphics", "nist" in
# "administrator", "ios" in "scenarios", "dhe" in "adhere", "subca" in
# "subcategory", "intel" in "intelligence"). They are matched as whole words.
# Other short keywords such as "ssl" and "tls" are matched anywhere, because
# the longer words that contain them, such as "openssl" and "mtls", name the
# same thing.
WHOLE_WORD_KEYWORDS: frozenset[str] = frozenset(
    {
        "api",
        "ca",
        "cert",
        "dh",
        "dhe",
        "ephi",
        "intel",
        "ios",
        "iot",
        "nist",
        "patient",
        "pci",
        "phi",
        "rest",
        "rootca",
        "subca",
    }
)

# Phrases in which a keyword means something else: "rest" in "data at rest"
# is not a REST API, and "health" in "health check" is service monitoring,
# not health data.
KEYWORD_EXCLUDED_PHRASES: dict[str, list[str]] = {
    "health": ["health check", "health checks"],
    "rest": ["at rest"],
}


def contains_keyword(text: str, keyword: str) -> bool:
    """
    Whether ``keyword`` occurs in ``text``.

    A keyword in WHOLE_WORD_KEYWORDS matches only as a whole word or that word
    followed by "s" ("api" matches "APIs" but not "rapid"). Any other keyword
    matches anywhere, so "health" also matches "healthcare", and the words of
    a keyword with several words may be joined by spaces, hyphens or
    underscores, so "at rest" also matches "data-at-rest". Occurrences inside
    the keyword's KEYWORD_EXCLUDED_PHRASES do not count.
    """
    keyword = keyword.lower()
    text = text.lower()
    for phrase in KEYWORD_EXCLUDED_PHRASES.get(keyword, []):
        text = _phrase_pattern(phrase).sub(" ", text)
    if keyword not in WHOLE_WORD_KEYWORDS:
        words = r"[\s_-]+".join(re.escape(word) for word in keyword.split())
        return re.search(words, text) is not None
    pattern = rf"(?<![a-z0-9]){re.escape(keyword)}s?(?![a-z0-9])"
    return re.search(pattern, text) is not None


def get_framework(framework_id: str) -> ComplianceFramework | None:
    """Get compliance framework by ID or alias (e.g. "cnsa-2.0", "pci-dss")."""
    key = framework_id.lower().replace("-", "_").replace(".", "_")
    return COMPLIANCE_FRAMEWORKS.get(FRAMEWORK_ALIASES.get(key, key))


# Context keywords that suggest a compliance framework, by framework ID.
CONTEXT_FRAMEWORK_KEYWORDS: dict[str, list[str]] = {
    "cnsa_2_0": CNSA_2_0_KEYWORDS,
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
    "hipaa": ["healthcare", "health", "medical", "hospital", "patient", "phi", "ephi", "ehr"],
    "fedramp": ["federal", "cloud", "saas", "government cloud"],
}


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

    for framework_id, keywords in CONTEXT_FRAMEWORK_KEYWORDS.items():
        if framework_id == "cnsa_2_0":
            matched = mentions_cnsa_2_0(context_lower)
        else:
            matched = any(contains_keyword(context_lower, kw) for kw in keywords)
        if matched:
            framework = COMPLIANCE_FRAMEWORKS.get(framework_id)
            if framework:
                applicable.append(framework)

    return applicable
