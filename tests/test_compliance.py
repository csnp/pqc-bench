"""Tests for compliance framework data."""

from typer.testing import CliRunner

from pqc_bench.cli import app
from pqc_bench.data.algorithms import get_algorithm
from pqc_bench.data.compliance import (
    contains_keyword,
    get_framework,
    get_frameworks_for_context,
)

# NSA Cybersecurity Advisory PP-22-1338, "Announcing the Commercial National
# Security Algorithm Suite 2.0", as posted at this address in May 2025.
CNSA_2_0_URL = (
    "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF"
)
RETIRED_CNSA_2_0_URL = (
    "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
)


class TestCNSA20:
    """CNSA 2.0 entry matches NSA advisory PP-22-1338."""

    def test_level_v_algorithms_for_all_classification_levels(self) -> None:
        """Only the Level V lattice parameter sets are listed."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.requirements.kem_algorithms == ["ml-kem-1024"]
        assert fw.requirements.min_security_level == 5

    def test_signatures_include_hash_based_signing(self) -> None:
        """LMS and XMSS are listed for software and firmware signing."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.requirements.signature_algorithms == ["ml-dsa-87", "lms", "xmss"]

    def test_no_level_3_parameter_sets(self) -> None:
        """ML-KEM-768 and ML-DSA-65 are not part of CNSA 2.0."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        listed = fw.requirements.kem_algorithms + fw.requirements.signature_algorithms
        assert "ml-kem-768" not in listed
        assert "ml-dsa-65" not in listed
        assert "all classification levels" in (fw.requirements.notes or "")
        assert "for Secret" not in (fw.requirements.notes or "")

    def test_summary_dates(self) -> None:
        """Earliest prefer, earliest exclusive, last exclusive, and completion years."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.timeline is not None
        assert fw.timeline.prefer_by == 2025
        assert fw.timeline.require_by == 2030
        assert fw.timeline.exclusive_by == 2033
        assert fw.timeline.complete_by == 2035

    def test_category_dates(self) -> None:
        """Each product category carries its own prefer and exclusive year."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.timeline is not None
        dates = {c.category: (c.prefer_by, c.exclusive_by) for c in fw.timeline.categories}
        assert dates == {
            "Software and firmware signing": (2025, 2030),
            "Web browsers, servers and cloud services": (2025, 2033),
            "Traditional networking equipment (VPNs, routers)": (2026, 2030),
            "Operating systems": (2027, 2033),
            "Niche equipment (constrained devices, large PKI systems)": (2030, 2033),
        }

    def test_legacy_equipment_deadline_in_notes(self) -> None:
        """Custom applications and legacy equipment are updated or replaced by 2033."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.timeline is not None
        assert "legacy equipment" in (fw.timeline.notes or "")
        assert "2033" in (fw.timeline.notes or "")

    def test_cites_current_advisory_address(self) -> None:
        """The retired 2022 address returns 404 and is no longer cited."""
        fw = get_framework("cnsa-2.0")
        assert fw is not None
        assert fw.url == CNSA_2_0_URL
        assert CNSA_2_0_URL in fw.citations
        assert RETIRED_CNSA_2_0_URL not in fw.citations
        assert fw.url != RETIRED_CNSA_2_0_URL


def test_compliance_command_accepts_documented_name() -> None:
    """`pqc-bench compliance cnsa-2.0` shows the CNSA 2.0 entry."""
    result = CliRunner().invoke(app, ["compliance", "cnsa-2.0"])
    assert result.exit_code == 0
    assert "ML-KEM-1024" in result.output
    assert "ML-KEM-768" not in result.output
    assert "LMS" in result.output
    assert "XMSS" in result.output
    assert "Transition complete by: 2035" in result.output
    assert "Operating systems: 2027 / 2033" in result.output


def test_compliance_command_accepts_pci_dss() -> None:
    """`pqc-bench compliance pci-dss` (help text and docs) shows PCI DSS 4.0."""
    assert get_framework("pci-dss") is get_framework("pci_dss_4")
    result = CliRunner().invoke(app, ["compliance", "pci-dss"])
    assert result.exit_code == 0
    assert "PCI DSS 4.0" in result.output


def test_context_inference_matches_cnsa_terms_as_whole_words() -> None:
    def inferred(context: str) -> list[str]:
        return [fw.id for fw in get_frameworks_for_context(context)]

    assert "cnsa_2_0" not in inferred("blockchain transaction signing")
    assert "cnsa_2_0" not in inferred("store API secrets in a vault")
    assert "cnsa_2_0" not in inferred("defense in depth for a web server")
    assert "cnsa_2_0" in inferred("NSA approved key exchange")
    assert "cnsa_2_0" in inferred("CNSA 2.0 required")


def test_context_inference_matches_hyphenated_and_joined_cnsa_terms() -> None:
    def inferred(context: str) -> list[str]:
        return [fw.id for fw in get_frameworks_for_context(context)]

    assert "cnsa_2_0" in inferred("top-secret documents")
    assert "cnsa_2_0" in inferred("national-security systems")
    assert "cnsa_2_0" in inferred("CNSA2.0 required")
    assert "cnsa_2_0" in inferred("military communications")
    assert "cnsa_2_0" not in inferred("military-grade encryption")


def test_context_inference_matches_short_terms_as_whole_words() -> None:
    def inferred(context: str) -> list[str]:
        return [fw.id for fw in get_frameworks_for_context(context)]

    assert "hipaa" not in inferred("graphics rendering service")
    assert "hipaa" not in inferred("philosophy course platform")
    assert "hipaa" in inferred("store PHI for a clinic")
    assert "fips_140_3" not in inferred("administrator dashboard")
    assert "fips_140_3" in inferred("NIST approved algorithms")


def test_contains_keyword_matches_whole_word_keywords_as_words_or_plurals() -> None:
    assert contains_keyword("REST APIs", "api")
    assert not contains_keyword("rapid prototyping", "api")
    assert contains_keyword("rotate the CAs", "ca")
    assert not contains_keyword("local cache", "ca")


def test_contains_keyword_matches_other_keywords_inside_words() -> None:
    assert contains_keyword("healthcare records", "health")
    assert contains_keyword("compact signatures", "signature")
    assert contains_keyword("OpenSSL upgrade", "ssl")
    assert contains_keyword("mTLS between services", "tls")


def test_contains_keyword_matches_compound_keywords_as_whole_words() -> None:
    assert contains_keyword("encrypt ePHI backups", "ephi")
    assert contains_keyword("DHE-RSA cipher suites", "dhe")
    assert not contains_keyword("adhere to policy", "dhe")
    assert contains_keyword("rotate the rootCAs", "rootca")
    assert contains_keyword("subCA issuance", "subca")
    assert not contains_keyword("product subcategory", "subca")
    assert contains_keyword("iOS app", "ios")
    assert not contains_keyword("test scenarios", "ios")
    assert not contains_keyword("patriot data archive", "iot")


def test_contains_keyword_ignores_excluded_phrases() -> None:
    assert not contains_keyword("encrypt data at rest", "rest")
    assert not contains_keyword("data-at-rest encryption", "rest")
    assert contains_keyword("REST service", "rest")
    assert not contains_keyword("health check endpoint", "health")
    assert not contains_keyword("healthcheck endpoint", "health")
    assert not contains_keyword("health checks", "health")
    assert contains_keyword("health check for a healthcare portal", "health")
    assert contains_keyword("encrypt data at rest", "at rest")


def test_context_inference_ignores_negated_and_non_system_cnsa_terms() -> None:
    def inferred(context: str) -> list[str]:
        return [fw.id for fw in get_frameworks_for_context(context)]

    assert "cnsa_2_0" not in inferred("non-military drone telemetry")
    assert "cnsa_2_0" not in inferred("nonmilitary drone telemetry")
    assert "cnsa_2_0" not in inferred("non-classified email")
    assert "cnsa_2_0" not in inferred("non-NSA systems")
    assert "cnsa_2_0" not in inferred("military history blog")
    assert "cnsa_2_0" not in inferred("military spouse support app")
    assert "cnsa_2_0" in inferred("military drone telemetry")
    assert "cnsa_2_0" in inferred("military satellites")
    assert "cnsa_2_0" in inferred("non-military app that stores classified files")


def test_context_inference_matches_joined_phi_and_skips_health_checks() -> None:
    def inferred(context: str) -> list[str]:
        return [fw.id for fw in get_frameworks_for_context(context)]

    assert "hipaa" in inferred("encrypt ePHI backups")
    assert "hipaa" not in inferred("health check endpoint")
    assert "hipaa" in inferred("health records storage")


class TestCNSA20AlgorithmApprovals:
    """Per-algorithm CNSA 2.0 approvals agree with the framework entry."""

    @staticmethod
    def _cnsa_status(algorithm_id: str) -> tuple[str, str | None]:
        algo = get_algorithm(algorithm_id)
        assert algo is not None
        approvals = [a for a in algo.compliance.approved_by if a.framework == "CNSA 2.0"]
        assert len(approvals) == 1
        return approvals[0].status, approvals[0].level

    def test_level_v_sets_approved_for_all_levels(self) -> None:
        for algorithm_id in ("ml-kem-1024", "ml-dsa-87"):
            assert self._cnsa_status(algorithm_id) == ("approved", "All classification levels")

    def test_level_3_sets_not_approved(self) -> None:
        for algorithm_id in ("ml-kem-768", "ml-dsa-65"):
            status, level = self._cnsa_status(algorithm_id)
            assert status == "not_approved"
            assert level is None

    def test_level_3_notes_do_not_claim_approval(self) -> None:
        for algorithm_id in ("ml-kem-768", "ml-dsa-65"):
            algo = get_algorithm(algorithm_id)
            assert algo is not None
            assert "CNSA 2.0 approved" not in algo.notes
