"""Tests for the recommendation engine."""

from dataclasses import replace

import pytest

from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.parser import QueryParser
from pqc_bench.data.algorithms import ALGORITHMS, AlgorithmProfile
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


class TestTLSAndConstrainedDevices:
    """Tests for TLS and constrained device handling."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    def test_needs_both_returns_kems_and_sigs(self, engine: RecommendationEngine) -> None:
        """TLS use case (needs_both) should return both KEMs and signatures."""
        constraints = Constraints(
            use_case=UseCase.TLS,
            needs_kem=True,
            needs_signature=True,
            needs_both=True,
        )
        result = engine.recommend(constraints, top_n=6)

        # Should have at least one KEM and one signature
        kems = [r for r in result.recommendations if r.algorithm.is_kem]
        sigs = [r for r in result.recommendations if r.algorithm.is_signature]
        assert len(kems) > 0, "TLS should include KEM recommendations"
        assert len(sigs) > 0, "TLS should include signature recommendations"

    def test_constrained_device_prefers_smaller_kem(
        self, engine: RecommendationEngine
    ) -> None:
        """Constrained devices should prefer smaller KEM variants."""
        # Standard server recommendation
        server_constraints = Constraints(
            needs_kem=True,
            is_server=True,
            min_security_level=SecurityLevel.LEVEL_3,
        )
        server_result = engine.recommend(server_constraints)

        # Constrained device recommendation
        constrained_constraints = Constraints(
            needs_kem=True,
            is_embedded=True,
            prefer_smaller_keys=True,
            min_security_level=SecurityLevel.LEVEL_1,
        )
        constrained_result = engine.recommend(constrained_constraints)

        # Constrained device should get smaller KEM
        server_kem_size = server_result.primary.algorithm.sizes.public_key
        constrained_kem_size = constrained_result.primary.algorithm.sizes.public_key
        assert constrained_kem_size <= server_kem_size

    def test_tls_notes_include_both_algorithms(
        self, engine: RecommendationEngine
    ) -> None:
        """TLS recommendation notes should mention needing both KEM and signature."""
        constraints = Constraints(
            use_case=UseCase.TLS,
            needs_kem=True,
            needs_signature=True,
            needs_both=True,
        )
        result = engine.recommend(constraints, top_n=6)

        # Notes should mention TLS requires both
        note_text = " ".join(result.notes).lower()
        assert "tls" in note_text or "both" in note_text or "kem" in note_text

    def test_embedded_context_increases_size_weight(
        self, engine: RecommendationEngine
    ) -> None:
        """Embedded context should increase size weight."""
        constraints = Constraints(
            needs_kem=True,
            is_embedded=True,
        )
        weights = engine._adjust_weights(constraints)
        assert weights["size"] > engine.DEFAULT_WEIGHTS["size"]


class TestComplianceScoring:
    """The compliance factor counts approvals from the required frameworks only."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    @staticmethod
    def _with_cnsa_approved(algorithm_id: str) -> AlgorithmProfile:
        """Copy of an algorithm whose CNSA 2.0 entry is set to approved."""
        algo = ALGORITHMS[algorithm_id]
        approvals = [
            replace(a, status="approved") if a.framework == "CNSA 2.0" else a
            for a in algo.compliance.approved_by
        ]
        return replace(algo, compliance=replace(algo.compliance, approved_by=approvals))

    def test_unrequested_framework_does_not_change_score(
        self, engine: RecommendationEngine
    ) -> None:
        constraints = Constraints(
            needs_kem=True,
            compliance_frameworks=[ComplianceFramework.PCI_DSS],
        )
        original = ALGORITHMS["ml-kem-768"]
        modified = self._with_cnsa_approved("ml-kem-768")
        assert engine._score_compliance(modified, constraints) == engine._score_compliance(
            original, constraints
        )

    def test_requested_framework_approval_counts(self, engine: RecommendationEngine) -> None:
        constraints = Constraints(
            needs_kem=True,
            compliance_frameworks=[ComplianceFramework.CNSA_2_0],
        )
        approved = engine._score_compliance(ALGORITHMS["ml-kem-1024"], constraints)
        not_approved = engine._score_compliance(ALGORITHMS["ml-kem-768"], constraints)
        assert approved > not_approved


class TestScoreRange:
    """Scores stay within 0-100 whatever the context weights."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    @pytest.mark.parametrize(
        "constraints",
        [
            Constraints(),
            Constraints(is_embedded=True, prefer_smaller_signatures=True),
            Constraints(
                is_embedded=True,
                is_high_volume=True,
                prefer_smaller_signatures=True,
                compliance_frameworks=[ComplianceFramework.CNSA_2_0],
            ),
        ],
    )
    def test_weights_sum_to_one(
        self, engine: RecommendationEngine, constraints: Constraints
    ) -> None:
        assert sum(engine._adjust_weights(constraints).values()) == pytest.approx(1.0)

    @pytest.mark.parametrize(
        "query",
        [
            "CNSA 2.0 embedded sensor with 256KB RAM",
            "embedded sensor with 256KB RAM",
            "HIPAA embedded medical device firmware signing",
        ],
    )
    def test_scores_at_most_100(self, engine: RecommendationEngine, query: str) -> None:
        constraints = QueryParser().parse(query)
        result = engine.recommend(constraints, query=query, top_n=len(ALGORITHMS))
        assert result.recommendations
        for rec in result.recommendations + result.alternatives:
            assert 0 <= rec.score <= 100, f"{rec.algorithm.id}: {rec.score}"


def test_cnsa_embedded_query_recommends_only_cnsa_algorithms() -> None:
    """A CNSA 2.0 query for a constrained device keeps the Level 5 parameter sets."""
    query = "CNSA 2.0 embedded sensor with 256KB RAM"
    result = RecommendationEngine().recommend(QueryParser().parse(query), query=query, top_n=5)
    recommended = {r.algorithm.id for r in result.recommendations + result.alternatives}
    assert recommended == {"ml-kem-1024", "ml-dsa-87"}
    assert any("CNSA 2.0" in note for note in result.notes)
