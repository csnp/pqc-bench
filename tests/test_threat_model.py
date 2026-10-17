"""Tests for the SNDL threat model module."""

import pytest

from pqc_bench.data.threat_model import (
    DATA_PROFILES,
    QUANTUM_THREAT_TIMELINE,
    ThreatUrgency,
    DataClassification,
    assess_sndl_risk,
    calculate_migration_deadline,
    calculate_migration_priority,
    get_profiles_by_urgency,
)


class TestDataProfiles:
    """Tests for data lifespan profiles."""

    def test_profiles_exist(self) -> None:
        """Data profiles should be defined."""
        assert len(DATA_PROFILES) > 0

    def test_healthcare_profile_is_critical(self) -> None:
        """Healthcare records should be critical urgency."""
        profile = DATA_PROFILES.get("healthcare_records")
        assert profile is not None
        assert profile.urgency == ThreatUrgency.CRITICAL

    def test_national_security_is_critical(self) -> None:
        """National security data should be critical urgency."""
        profile = DATA_PROFILES.get("national_security")
        assert profile is not None
        assert profile.urgency == ThreatUrgency.CRITICAL

    def test_transactional_data_is_medium(self) -> None:
        """Transactional data should be medium urgency."""
        profile = DATA_PROFILES.get("transactional_data")
        assert profile is not None
        assert profile.urgency == ThreatUrgency.MEDIUM

    @pytest.mark.parametrize("profile_id", list(DATA_PROFILES.keys()))
    def test_profile_has_required_fields(self, profile_id: str) -> None:
        """Each profile should have required fields."""
        profile = DATA_PROFILES[profile_id]

        assert profile.id
        assert profile.name
        assert profile.description
        assert profile.typical_lifespan_years > 0
        assert profile.classification is not None
        assert len(profile.examples) > 0
        assert profile.urgency is not None
        assert profile.rationale
        assert profile.recommended_action
        assert len(profile.cryptographic_needs) > 0


class TestQuantumThreatTimeline:
    """Tests for quantum threat timeline."""

    def test_timeline_exists(self) -> None:
        """Quantum threat timeline should be defined."""
        assert len(QUANTUM_THREAT_TIMELINE) > 0

    def test_rsa_2048_in_timeline(self) -> None:
        """RSA-2048 should be in timeline."""
        rsa = next(
            (t for t in QUANTUM_THREAT_TIMELINE if t.algorithm == "RSA-2048"),
            None,
        )
        assert rsa is not None
        assert rsa.optimistic_years > 0
        assert rsa.median_years > rsa.optimistic_years
        assert rsa.conservative_years > rsa.median_years

    def test_aes_256_takes_longer(self) -> None:
        """AES-256 should take longer to break than RSA."""
        rsa = next(
            (t for t in QUANTUM_THREAT_TIMELINE if t.algorithm == "RSA-2048"),
            None,
        )
        aes = next(
            (t for t in QUANTUM_THREAT_TIMELINE if t.algorithm == "AES-256"),
            None,
        )
        assert rsa is not None
        assert aes is not None
        assert aes.median_years > rsa.median_years


class TestSNDLAssessment:
    """Tests for SNDL risk assessment."""

    def test_assess_healthcare_risk(self) -> None:
        """Healthcare records should be at risk."""
        assessment = assess_sndl_risk("healthcare_records")
        assert assessment is not None
        assert assessment.is_at_risk is True
        assert assessment.urgency == ThreatUrgency.CRITICAL

    def test_assess_ephemeral_risk(self) -> None:
        """Ephemeral communications should be manageable."""
        assessment = assess_sndl_risk("ephemeral_communications")
        assert assessment is not None
        # Short-lived data should be less urgent
        assert assessment.urgency == ThreatUrgency.LOW

    def test_assessment_includes_explanation(self) -> None:
        """Assessment should include risk explanation."""
        assessment = assess_sndl_risk("healthcare_records")
        assert assessment is not None
        assert len(assessment.risk_explanation) > 0

    def test_assessment_recommends_algorithm(self) -> None:
        """Assessment should recommend an algorithm."""
        assessment = assess_sndl_risk("healthcare_records")
        assert assessment is not None
        # Healthcare needs KEM, so should recommend ML-KEM
        assert assessment.recommended_algorithm is not None

    def test_critical_urgency_recommends_hybrid(self) -> None:
        """Critical urgency should recommend hybrid mode."""
        assessment = assess_sndl_risk("national_security")
        assert assessment is not None
        assert assessment.recommended_hybrid is not None

    def test_national_security_recommends_cnsa_kem(self) -> None:
        """Top Secret data gets ML-KEM-1024, the CNSA 2.0 key establishment algorithm."""
        assessment = assess_sndl_risk("national_security")
        assert assessment is not None
        assert assessment.recommended_algorithm == "ML-KEM-1024"

    def test_national_security_hybrid_uses_cnsa_kem(self) -> None:
        """The Top Secret hybrid is built on ML-KEM-1024, matching the recommended algorithm."""
        assessment = assess_sndl_risk("national_security")
        assert assessment is not None
        assert assessment.recommended_algorithm == "ML-KEM-1024"
        assert assessment.recommended_hybrid == "SecP384r1MLKEM1024"

    def test_non_national_security_hybrid_is_x25519mlkem768(self) -> None:
        """Profiles outside CNSA 2.0 keep the X25519MLKEM768 hybrid with ML-KEM-768."""
        assessment = assess_sndl_risk("healthcare_records")
        assert assessment is not None
        assert assessment.recommended_algorithm == "ML-KEM-768"
        assert assessment.recommended_hybrid == "X25519MLKEM768"

    def test_unknown_profile_returns_none(self) -> None:
        """Unknown profile should return None."""
        assessment = assess_sndl_risk("unknown_profile")
        assert assessment is None


class TestMigrationDeadline:
    """Tests for migration deadline calculation."""

    def test_long_lifespan_negative_deadline(self) -> None:
        """Long-lifespan data should have negative (overdue) deadline."""
        deadline = calculate_migration_deadline(
            data_lifespan_years=100,  # 100-year protection
            quantum_threat_years=15,
        )
        assert deadline < 0

    def test_short_lifespan_positive_deadline(self) -> None:
        """Short-lifespan data should have positive deadline."""
        deadline = calculate_migration_deadline(
            data_lifespan_years=1,  # 1-year protection
            quantum_threat_years=15,
        )
        assert deadline > 0

    def test_deadline_includes_safety_margin(self) -> None:
        """Deadline should include safety margin."""
        # With 10-year lifespan and 15-year threat, 5 years remain
        # With 2-year safety margin, 3 years remain
        deadline = calculate_migration_deadline(
            data_lifespan_years=10,
            quantum_threat_years=15,
            safety_margin_years=2,
        )
        assert deadline == 3


class TestMigrationPriority:
    """Tests for migration priority scoring."""

    def test_priority_calculation(self) -> None:
        """Should calculate migration priority."""
        priority = calculate_migration_priority(
            system_name="Test System",
            data_profile_id="healthcare_records",
        )
        assert priority is not None
        assert priority.system_name == "Test System"
        assert priority.priority_score > 0

    def test_critical_has_high_score(self) -> None:
        """Critical urgency should have high priority score."""
        priority = calculate_migration_priority(
            system_name="Test System",
            data_profile_id="national_security",
        )
        assert priority.priority_score >= 70

    def test_low_urgency_has_low_score(self) -> None:
        """Low urgency should have lower priority score."""
        priority = calculate_migration_priority(
            system_name="Test System",
            data_profile_id="ephemeral_communications",
        )
        assert priority.priority_score < 50

    def test_exposure_affects_score(self) -> None:
        """Public exposure should increase score."""
        private = calculate_migration_priority(
            system_name="Test",
            data_profile_id="transactional_data",
            exposure_level="isolated",
        )
        public = calculate_migration_priority(
            system_name="Test",
            data_profile_id="transactional_data",
            exposure_level="public",
        )
        assert public.priority_score > private.priority_score

    def test_priority_includes_recommendation(self) -> None:
        """Priority should include recommendation."""
        priority = calculate_migration_priority(
            system_name="Test System",
            data_profile_id="healthcare_records",
        )
        assert len(priority.recommendation) > 0


class TestUrgencyFiltering:
    """Tests for urgency-based filtering."""

    def test_get_critical_profiles(self) -> None:
        """Should return critical urgency profiles."""
        profiles = get_profiles_by_urgency(ThreatUrgency.CRITICAL)
        assert len(profiles) > 0
        for profile in profiles:
            assert profile.urgency == ThreatUrgency.CRITICAL

    def test_get_high_profiles(self) -> None:
        """Should return high urgency profiles."""
        profiles = get_profiles_by_urgency(ThreatUrgency.HIGH)
        assert len(profiles) > 0
        for profile in profiles:
            assert profile.urgency == ThreatUrgency.HIGH

    def test_get_medium_profiles(self) -> None:
        """Should return medium urgency profiles."""
        profiles = get_profiles_by_urgency(ThreatUrgency.MEDIUM)
        assert len(profiles) > 0
        for profile in profiles:
            assert profile.urgency == ThreatUrgency.MEDIUM


class TestDataClassification:
    """Tests for data classification."""

    def test_national_security_is_top_secret(self) -> None:
        """National security should be top secret."""
        profile = DATA_PROFILES.get("national_security")
        assert profile is not None
        assert profile.classification == DataClassification.TOP_SECRET

    def test_ephemeral_is_internal(self) -> None:
        """Ephemeral communications should be internal."""
        profile = DATA_PROFILES.get("ephemeral_communications")
        assert profile is not None
        assert profile.classification == DataClassification.INTERNAL

    def test_public_signatures_is_public(self) -> None:
        """Public signatures should be public classification."""
        profile = DATA_PROFILES.get("public_signatures")
        assert profile is not None
        assert profile.classification == DataClassification.PUBLIC

    @pytest.mark.parametrize(
        ("classification", "label"),
        [
            (DataClassification.TOP_SECRET, "Top Secret"),
            (DataClassification.SECRET, "Secret"),
            (DataClassification.CONFIDENTIAL, "Confidential"),
            (DataClassification.INTERNAL, "Internal"),
            (DataClassification.PUBLIC, "Public"),
        ],
    )
    def test_label(self, classification: DataClassification, label: str) -> None:
        """Users see "Top Secret", not the stored value "top_secret"."""
        assert classification.label == label
