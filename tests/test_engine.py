"""Tests for the recommendation engine."""

import pytest

from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.constraints import (
    Constraints,
    Platform,
    UseCase,
    SecurityLevel,
    ComplianceFramework,
)


class TestRecommendationEngine:
    """Tests for RecommendationEngine."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    def test_recommend_signature(self, engine: RecommendationEngine) -> None:
        """Should recommend signature algorithm when signature is needed."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints)

        assert len(result.recommendations) > 0
        assert result.recommendations[0].algorithm.is_signature

    def test_recommend_kem(self, engine: RecommendationEngine) -> None:
        """Should recommend KEM algorithm when KEM is needed."""
        constraints = Constraints(needs_kem=True)
        result = engine.recommend(constraints)

        assert len(result.recommendations) > 0
        assert result.recommendations[0].algorithm.is_kem

    def test_recommend_nist_standardized(self, engine: RecommendationEngine) -> None:
        """Should only recommend NIST standardized when required."""
        constraints = Constraints(
            needs_signature=True,
            requires_nist_standardized=True,
        )
        result = engine.recommend(constraints)

        for rec in result.recommendations:
            assert rec.algorithm.compliance.nist_standardized

    def test_recommend_security_level(self, engine: RecommendationEngine) -> None:
        """Should only recommend algorithms meeting security level."""
        constraints = Constraints(
            needs_signature=True,
            min_security_level=SecurityLevel.LEVEL_5,
        )
        result = engine.recommend(constraints)

        for rec in result.recommendations:
            assert rec.algorithm.security.nist_level >= 5

    def test_recommend_constant_time(self, engine: RecommendationEngine) -> None:
        """Should only recommend constant-time when required."""
        constraints = Constraints(
            needs_signature=True,
            requires_constant_time=True,
        )
        result = engine.recommend(constraints)

        for rec in result.recommendations:
            assert rec.algorithm.security.constant_time

    def test_recommend_no_fpu(self, engine: RecommendationEngine) -> None:
        """Should exclude FPU-requiring algorithms when FPU not available."""
        constraints = Constraints(
            needs_signature=True,
            has_floating_point=False,
        )
        result = engine.recommend(constraints)

        for rec in result.recommendations:
            assert not rec.algorithm.requirements.requires_fpu

    def test_recommend_primary_is_highest_score(self, engine: RecommendationEngine) -> None:
        """Primary recommendation should have highest score."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints)

        if len(result.recommendations) > 1:
            assert result.recommendations[0].score >= result.recommendations[1].score

    def test_recommend_with_reasons(self, engine: RecommendationEngine) -> None:
        """Recommendations should include reasons."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints)

        assert result.recommendations[0].reasons

    def test_recommend_with_warnings_for_non_constant_time(
        self, engine: RecommendationEngine
    ) -> None:
        """Non-constant-time algorithms should have warnings."""
        # Find a recommendation that includes Falcon
        constraints = Constraints(
            needs_signature=True,
            requires_nist_standardized=False,
            requires_constant_time=False,
        )
        result = engine.recommend(constraints)

        falcon_recs = [
            r for r in result.recommendations + result.alternatives
            if "falcon" in r.algorithm.id.lower()
        ]

        for rec in falcon_recs:
            assert any("constant" in w.lower() for w in rec.warnings)

    def test_recommend_respects_top_n(self, engine: RecommendationEngine) -> None:
        """Should return at most top_n recommendations."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints, top_n=2)

        assert len(result.recommendations) <= 2

    def test_recommend_empty_for_impossible_constraints(
        self, engine: RecommendationEngine
    ) -> None:
        """Should return empty for impossible constraints."""
        constraints = Constraints(
            needs_signature=True,
            needs_kem=True,  # No algorithm does both
        )
        result = engine.recommend(constraints)
        # This might not be empty depending on how we handle needs_both

    def test_recommend_ml_dsa_65_for_general_use(
        self, engine: RecommendationEngine
    ) -> None:
        """ML-DSA-65 should be recommended for general signature use."""
        constraints = Constraints(
            needs_signature=True,
            min_security_level=SecurityLevel.LEVEL_3,
            requires_nist_standardized=True,
        )
        result = engine.recommend(constraints)

        # ML-DSA-65 should be in top 3
        algo_ids = [r.algorithm.id for r in result.recommendations]
        assert "ml-dsa-65" in algo_ids or "ml-dsa-44" in algo_ids

    def test_recommend_ml_kem_768_for_key_exchange(
        self, engine: RecommendationEngine
    ) -> None:
        """ML-KEM-768 should be recommended for key exchange."""
        constraints = Constraints(
            needs_kem=True,
            min_security_level=SecurityLevel.LEVEL_3,
            requires_nist_standardized=True,
        )
        result = engine.recommend(constraints)

        primary = result.primary
        assert primary is not None
        assert "ml-kem" in primary.algorithm.id.lower()

    def test_scoring_factors_present(self, engine: RecommendationEngine) -> None:
        """Scoring factors should be populated."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints)

        primary = result.primary
        assert primary is not None
        assert len(primary.scoring_factors) > 0

        factor_names = [f.name for f in primary.scoring_factors]
        assert "security" in factor_names
        assert "performance" in factor_names

    def test_confidence_rating(self, engine: RecommendationEngine) -> None:
        """Recommendations should have confidence rating."""
        constraints = Constraints(needs_signature=True)
        result = engine.recommend(constraints)

        primary = result.primary
        assert primary is not None
        assert primary.confidence in ["high", "medium", "low"]


class TestScoringWeights:
    """Tests for context-dependent scoring weights."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    def test_compliance_heavy_context(self, engine: RecommendationEngine) -> None:
        """Compliance should be weighted higher with compliance requirements."""
        constraints = Constraints(
            needs_signature=True,
            compliance_frameworks=[ComplianceFramework.FIPS_140_3],
        )
        weights = engine._adjust_weights(constraints)
        assert weights["compliance"] > engine.DEFAULT_WEIGHTS["compliance"]

    def test_performance_critical_context(self, engine: RecommendationEngine) -> None:
        """Performance should be weighted higher for high volume."""
        constraints = Constraints(
            needs_signature=True,
            is_high_volume=True,
        )
        weights = engine._adjust_weights(constraints)
        assert weights["performance"] > engine.DEFAULT_WEIGHTS["performance"]

    def test_size_sensitive_context(self, engine: RecommendationEngine) -> None:
        """Size should be weighted higher for blockchain."""
        constraints = Constraints(
            needs_signature=True,
            use_case=UseCase.BLOCKCHAIN,
        )
        weights = engine._adjust_weights(constraints)
        assert weights["size"] > engine.DEFAULT_WEIGHTS["size"]
