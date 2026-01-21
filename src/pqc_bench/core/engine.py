"""
Recommendation engine for PQC algorithm selection.

Scores and ranks algorithms based on user constraints,
providing explanations for each recommendation.
"""

from dataclasses import dataclass, field

from ..data.algorithms import ALGORITHMS, AlgorithmProfile
from .constraints import Constraints, UseCase


@dataclass
class ScoringFactor:
    """A factor that contributed to an algorithm's score."""

    name: str
    weight: float
    score: float  # 0-100
    reason: str


@dataclass
class Recommendation:
    """A scored algorithm recommendation with explanation."""

    algorithm: AlgorithmProfile
    score: float  # 0-100
    rank: int
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scoring_factors: list[ScoringFactor] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        """Confidence level based on score."""
        if self.score >= 85:
            return "high"
        elif self.score >= 70:
            return "medium"
        else:
            return "low"


@dataclass
class RecommendationResult:
    """Complete result of a recommendation query."""

    query: str
    constraints: Constraints
    recommendations: list[Recommendation]
    alternatives: list[Recommendation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def primary(self) -> Recommendation | None:
        """Get the primary (top) recommendation."""
        return self.recommendations[0] if self.recommendations else None


class RecommendationEngine:
    """
    Scores and ranks algorithms based on constraints.

    The engine uses a multi-stage pipeline:
    1. Filter: Remove algorithms that don't meet hard requirements
    2. Score: Apply weighted scoring based on soft preferences
    3. Rank: Sort by score and generate explanations
    """

    # Scoring weights by context
    DEFAULT_WEIGHTS = {
        "security": 0.25,
        "performance": 0.20,
        "compliance": 0.20,
        "maturity": 0.15,
        "size": 0.10,
        "implementation": 0.10,
    }

    def __init__(self) -> None:
        self.algorithms = ALGORITHMS

    def recommend(
        self,
        constraints: Constraints,
        query: str = "",
        top_n: int = 3,
    ) -> RecommendationResult:
        """
        Generate algorithm recommendations based on constraints.

        Args:
            constraints: User requirements and preferences
            query: Original query string (for result context)
            top_n: Number of top recommendations to return

        Returns:
            RecommendationResult with ranked recommendations
        """
        # Stage 1: Filter
        candidates = self._filter_algorithms(constraints)

        if not candidates:
            return RecommendationResult(
                query=query,
                constraints=constraints,
                recommendations=[],
                notes=["No algorithms match the specified constraints."],
            )

        # Stage 2: Score
        scored = []
        for algo in candidates:
            score, factors, reasons, warnings = self._score_algorithm(algo, constraints)
            scored.append(
                Recommendation(
                    algorithm=algo,
                    score=score,
                    rank=0,
                    reasons=reasons,
                    warnings=warnings,
                    scoring_factors=factors,
                )
            )

        # Stage 3: Rank
        scored.sort(key=lambda r: r.score, reverse=True)
        for i, rec in enumerate(scored):
            rec.rank = i + 1

        # Split into recommendations and alternatives
        recommendations = scored[:top_n]
        alternatives = scored[top_n : top_n + 3]

        # Generate result notes
        notes = self._generate_notes(constraints, recommendations)

        return RecommendationResult(
            query=query,
            constraints=constraints,
            recommendations=recommendations,
            alternatives=alternatives,
            notes=notes,
        )

    def _filter_algorithms(self, constraints: Constraints) -> list[AlgorithmProfile]:
        """Filter algorithms based on hard requirements."""
        candidates = []

        for algo in self.algorithms.values():
            # Type filter
            # If needs_both (TLS), include both KEMs and signatures
            if constraints.needs_both:
                # Accept either KEM or signature algorithms
                if not algo.is_kem and not algo.is_signature:
                    continue
            else:
                # Normal filtering: match exactly what's needed
                if constraints.needs_kem and not algo.is_kem:
                    continue
                if constraints.needs_signature and not algo.is_signature:
                    continue

            # NIST standardization requirement
            if constraints.requires_nist_standardized and not algo.compliance.nist_standardized:
                continue

            # FIPS validation requirement
            if constraints.requires_fips_validated and not algo.compliance.fips_validated:
                continue

            # Security level requirement
            if algo.security.nist_level < constraints.min_security_level.value:
                continue

            # Floating point requirement
            if constraints.has_floating_point is False and algo.requirements.requires_fpu:
                continue

            # Stack size requirement
            if (
                constraints.max_stack_kb is not None
                and algo.requirements.min_stack_kb > constraints.max_stack_kb
            ):
                continue

            # Constant-time requirement
            if constraints.requires_constant_time and not algo.security.constant_time:
                continue

            candidates.append(algo)

        return candidates

    def _score_algorithm(
        self,
        algo: AlgorithmProfile,
        constraints: Constraints,
    ) -> tuple[float, list[ScoringFactor], list[str], list[str]]:
        """Score an algorithm against constraints."""
        factors = []
        reasons = []
        warnings = []

        # Adjust weights based on context
        weights = self._adjust_weights(constraints)

        # Score each factor
        security_score = self._score_security(algo, constraints)
        factors.append(
            ScoringFactor(
                name="security",
                weight=weights["security"],
                score=security_score,
                reason=f"NIST Level {algo.security.nist_level}",
            )
        )

        performance_score = self._score_performance(algo, constraints)
        factors.append(
            ScoringFactor(
                name="performance",
                weight=weights["performance"],
                score=performance_score,
                reason=self._get_performance_reason(algo, constraints),
            )
        )

        compliance_score = self._score_compliance(algo, constraints)
        factors.append(
            ScoringFactor(
                name="compliance",
                weight=weights["compliance"],
                score=compliance_score,
                reason=self._get_compliance_reason(algo),
            )
        )

        maturity_score = self._score_maturity(algo)
        factors.append(
            ScoringFactor(
                name="maturity",
                weight=weights["maturity"],
                score=maturity_score,
                reason="NIST standardized" if algo.compliance.nist_standardized else "Pending",
            )
        )

        size_score = self._score_size(algo, constraints)
        factors.append(
            ScoringFactor(
                name="size",
                weight=weights["size"],
                score=size_score,
                reason=self._get_size_reason(algo),
            )
        )

        implementation_score = self._score_implementation(algo, constraints)
        factors.append(
            ScoringFactor(
                name="implementation",
                weight=weights["implementation"],
                score=implementation_score,
                reason=f"{len(algo.requirements.implementations)} implementations available",
            )
        )

        # Calculate weighted score
        total_score = sum(f.weight * f.score for f in factors)

        # Generate reasons
        reasons = self._generate_reasons(algo, constraints, factors)

        # Generate warnings
        warnings = self._generate_warnings(algo, constraints)

        return total_score, factors, reasons, warnings

    def _adjust_weights(self, constraints: Constraints) -> dict[str, float]:
        """Adjust scoring weights based on context."""
        weights = self.DEFAULT_WEIGHTS.copy()

        # Compliance-heavy context
        if constraints.compliance_frameworks:
            weights["compliance"] = 0.30
            weights["performance"] = 0.15

        # Performance-critical context
        if constraints.is_high_volume or constraints.max_latency_ms is not None:
            weights["performance"] = 0.30
            weights["security"] = 0.20

        # Size-sensitive context (blockchain, JWT, IoT)
        if constraints.prefer_smaller_signatures or constraints.use_case in [
            UseCase.BLOCKCHAIN,
            UseCase.JWT,
            UseCase.IOT,
        ]:
            weights["size"] = 0.20
            weights["maturity"] = 0.10

        # Embedded/constrained context
        if constraints.is_embedded:
            weights["size"] = 0.25
            weights["implementation"] = 0.15

        return weights

    def _score_security(self, algo: AlgorithmProfile, constraints: Constraints) -> float:
        """Score security properties."""
        score = 70.0

        # Base score on security level match
        level_diff = algo.security.nist_level - constraints.min_security_level.value
        if level_diff >= 2:
            score += 20  # Exceeds requirements
        elif level_diff == 1:
            score += 10  # Above minimum
        elif level_diff == 0:
            score += 5  # Meets minimum

        # Constant-time bonus
        if algo.security.constant_time:
            score += 10

        # Caveat penalties
        for caveat in algo.security.caveats:
            if caveat.severity == "warning":
                score -= 10
            elif caveat.severity == "critical":
                score -= 25

        return min(100, max(0, score))

    def _score_performance(self, algo: AlgorithmProfile, constraints: Constraints) -> float:
        """Score performance characteristics."""
        score = 60.0

        # Get platform-specific performance if available
        platform_key = constraints.platform.value if constraints.platform else "x86_64_avx2"
        perf = algo.performance.get(platform_key) or algo.performance.get("x86_64_avx2")

        if perf is None:
            return 50.0  # No data, neutral score

        # Check against latency requirement
        if constraints.max_latency_ms:
            if algo.is_signature and perf.verify_ops:
                time_ms = 1000 / perf.verify_ops
                if time_ms <= constraints.max_latency_ms:
                    score += 20
                elif time_ms <= constraints.max_latency_ms * 2:
                    score += 10
                else:
                    score -= 20
            elif algo.is_kem and perf.decaps_ops:
                time_ms = 1000 / perf.decaps_ops
                if time_ms <= constraints.max_latency_ms:
                    score += 20

        # Check against throughput requirement
        if constraints.operations_per_second:
            ops = (
                perf.verify_ops
                if algo.is_signature
                else perf.decaps_ops if algo.is_kem else None
            )
            if ops:
                if ops >= constraints.operations_per_second:
                    score += 20
                elif ops >= constraints.operations_per_second * 0.5:
                    score += 10
                else:
                    score -= 10

        # Platform optimization bonus
        if platform_key in algo.performance:
            score += 10

        return min(100, max(0, score))

    def _score_compliance(self, algo: AlgorithmProfile, constraints: Constraints) -> float:
        """Score compliance status."""
        score = 60.0

        if not constraints.compliance_frameworks:
            return 80.0 if algo.compliance.nist_standardized else 50.0

        # Check each required framework
        approved_count = 0
        for approval in algo.compliance.approved_by:
            if approval.status == "approved":
                approved_count += 1

        if approved_count > 0:
            score += min(30, approved_count * 15)

        if algo.compliance.fips_validated:
            score += 10

        return min(100, max(0, score))

    def _score_maturity(self, algo: AlgorithmProfile) -> float:
        """Score algorithm maturity and standardization status."""
        if algo.compliance.nist_standardized:
            return 100.0
        elif algo.compliance.fips_number:
            return 70.0
        else:
            return 40.0

    def _score_size(self, algo: AlgorithmProfile, constraints: Constraints) -> float:
        """Score size characteristics."""
        score = 70.0

        if algo.is_signature:
            sig_size = algo.sizes.signature or 0
            if constraints.prefer_smaller_signatures:
                if sig_size < 1000:
                    score += 30
                elif sig_size < 3000:
                    score += 15
                else:
                    score -= 10

            # Check against max signature size
            if constraints.max_signature_bytes and sig_size > constraints.max_signature_bytes:
                score -= 30

        if algo.is_kem:
            ct_size = algo.sizes.ciphertext or 0
            pk_size = algo.sizes.public_key or 0

            # Prefer smaller KEMs for constrained/embedded
            if constraints.prefer_smaller_keys or constraints.is_embedded:
                if pk_size < 900:  # ML-KEM-512 is ~800
                    score += 25
                elif pk_size < 1300:  # ML-KEM-768 is ~1184
                    score += 10
                else:
                    score -= 5

            if constraints.max_ciphertext_bytes and ct_size > constraints.max_ciphertext_bytes:
                score -= 30

            if constraints.max_public_key_bytes and pk_size > constraints.max_public_key_bytes:
                score -= 30

        return min(100, max(0, score))

    def _score_implementation(self, algo: AlgorithmProfile, constraints: Constraints) -> float:
        """Score implementation availability."""
        score = 50.0

        impls = algo.requirements.implementations
        score += min(30, len(impls) * 10)

        # FIPS-validated implementation bonus
        if any(impl.fips_validated for impl in impls):
            score += 20

        # Preferred library bonus
        if constraints.preferred_library:
            if any(
                constraints.preferred_library.lower() in impl.library.lower() for impl in impls
            ):
                score += 10

        return min(100, max(0, score))

    def _generate_reasons(
        self,
        algo: AlgorithmProfile,
        constraints: Constraints,
        factors: list[ScoringFactor],
    ) -> list[str]:
        """Generate human-readable reasons for recommendation."""
        reasons = []

        # Top reason: standardization
        if algo.compliance.nist_standardized:
            reasons.append(f"NIST standardized ({algo.names.nist_fips})")

        # Security level
        if algo.security.nist_level >= 3:
            reasons.append(f"Strong security (NIST Level {algo.security.nist_level})")

        # Constant-time
        if algo.security.constant_time:
            reasons.append("Constant-time implementation (side-channel resistant)")

        # Platform optimization
        if constraints.platform and constraints.platform.value in algo.performance:
            reasons.append(f"Optimized for {constraints.platform.value}")

        # Compliance
        for approval in algo.compliance.approved_by:
            if approval.status == "approved":
                reasons.append(f"{approval.framework} approved")

        # Size (for size-sensitive use cases)
        if constraints.prefer_smaller_signatures and algo.is_signature:
            if algo.sizes.signature and algo.sizes.signature < 1500:
                reasons.append(f"Compact signatures ({algo.sizes.signature} bytes)")

        return reasons[:4]  # Limit to top 4 reasons

    def _generate_warnings(
        self,
        algo: AlgorithmProfile,
        constraints: Constraints,
    ) -> list[str]:
        """Generate warnings about an algorithm."""
        warnings = []

        # Security caveats
        for caveat in algo.security.caveats:
            if caveat.severity in ["warning", "critical"]:
                warnings.append(caveat.description)

        # FPU requirement
        if algo.requirements.requires_fpu:
            warnings.append("Requires floating-point unit (FPU)")

        # Not yet standardized
        if not algo.compliance.nist_standardized:
            warnings.append(f"Not yet NIST standardized ({algo.names.nist_fips})")

        # Large signatures
        if algo.is_signature and algo.sizes.signature and algo.sizes.signature > 4000:
            warnings.append(f"Large signatures ({algo.sizes.signature} bytes)")

        return warnings

    def _generate_notes(
        self,
        constraints: Constraints,
        recommendations: list[Recommendation],
    ) -> list[str]:
        """Generate notes about the recommendation result."""
        notes = []

        if constraints.confidence < 0.5:
            notes.append(
                "Limited constraints provided; consider specifying platform or use case "
                "for more tailored recommendations."
            )

        if constraints.needs_both:
            # Separate KEM and signature recommendations
            kems = [r for r in recommendations if r.algorithm.is_kem]
            sigs = [r for r in recommendations if r.algorithm.is_signature]
            if kems and sigs:
                notes.append(
                    f"TLS requires both: Use {kems[0].algorithm.names.nist_name} (KEM) + "
                    f"{sigs[0].algorithm.names.nist_name} (signature). "
                    "For hybrid: pqc-bench hybrid"
                )
            else:
                notes.append(
                    "TLS/VPN requires both KEM and signature algorithms. "
                    "See 'pqc-bench hybrid' for hybrid modes."
                )

        if constraints.is_embedded:
            notes.append(
                "Constrained device: smaller algorithms preferred for memory/bandwidth."
            )

        return notes

    def _get_performance_reason(self, algo: AlgorithmProfile, constraints: Constraints) -> str:
        """Get performance-related reason string."""
        platform_key = constraints.platform.value if constraints.platform else "x86_64_avx2"
        perf = algo.performance.get(platform_key) or algo.performance.get("x86_64_avx2")

        if perf is None:
            return "No benchmark data"

        if algo.is_signature and perf.verify_ops:
            return f"~{1000/perf.verify_ops:.2f}ms verify"
        elif algo.is_kem and perf.decaps_ops:
            return f"~{1000/perf.decaps_ops:.2f}ms decaps"

        return "Performance data available"

    def _get_compliance_reason(self, algo: AlgorithmProfile) -> str:
        """Get compliance-related reason string."""
        if algo.compliance.fips_validated:
            return f"FIPS validated ({algo.compliance.fips_number})"
        elif algo.compliance.nist_standardized:
            return f"NIST standardized ({algo.names.nist_fips})"
        else:
            return "Pending standardization"

    def _get_size_reason(self, algo: AlgorithmProfile) -> str:
        """Get size-related reason string."""
        if algo.is_signature and algo.sizes.signature:
            return f"{algo.sizes.signature} byte signatures"
        elif algo.is_kem and algo.sizes.ciphertext:
            return f"{algo.sizes.ciphertext} byte ciphertext"
        return "Size data available"
