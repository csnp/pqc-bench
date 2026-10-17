"""Tests for the algorithm database."""

import re

import pytest

from pqc_bench.data.algorithms import (
    ALGORITHMS,
    get_algorithm,
    get_algorithms_by_type,
    get_algorithms_by_family,
    get_nist_standardized,
)


class TestAlgorithmDatabase:
    """Tests for the algorithm database."""

    def test_algorithms_exist(self) -> None:
        """Algorithm database should contain algorithms."""
        assert len(ALGORITHMS) > 0

    def test_get_algorithm_by_id(self) -> None:
        """Should retrieve algorithm by ID."""
        algo = get_algorithm("ml-kem-768")
        assert algo is not None
        assert algo.id == "ml-kem-768"

    def test_get_algorithm_case_insensitive(self) -> None:
        """Algorithm lookup should be case insensitive."""
        algo = get_algorithm("ML-KEM-768")
        assert algo is not None

    def test_get_algorithm_unknown(self) -> None:
        """Should return None for unknown algorithm."""
        algo = get_algorithm("unknown-algo")
        assert algo is None

    def test_get_algorithms_by_type_kem(self) -> None:
        """Should return only KEM algorithms."""
        kems = get_algorithms_by_type("kem")
        assert len(kems) > 0
        for algo in kems:
            assert algo.is_kem

    def test_get_algorithms_by_type_signature(self) -> None:
        """Should return only signature algorithms."""
        sigs = get_algorithms_by_type("signature")
        assert len(sigs) > 0
        for algo in sigs:
            assert algo.is_signature

    def test_get_algorithms_by_family(self) -> None:
        """Should return algorithms in a family."""
        ml_kem = get_algorithms_by_family("ML-KEM")
        assert len(ml_kem) >= 3  # 512, 768, 1024
        for algo in ml_kem:
            assert algo.family == "ML-KEM"

    def test_get_nist_standardized(self) -> None:
        """Should return only NIST standardized algorithms."""
        standardized = get_nist_standardized()
        for algo in standardized:
            assert algo.compliance.nist_standardized


class TestAlgorithmProfiles:
    """Tests for algorithm profile completeness."""

    @pytest.mark.parametrize("algo_id", list(ALGORITHMS.keys()))
    def test_algorithm_has_required_fields(self, algo_id: str) -> None:
        """Each algorithm should have all required fields."""
        algo = ALGORITHMS[algo_id]

        # Identity
        assert algo.id
        assert algo.family
        assert algo.variant
        assert algo.algorithm_type in ["kem", "signature"]

        # Names
        assert algo.names.nist_fips
        assert algo.names.nist_name
        assert algo.names.legacy_name

        # Security
        assert algo.security.nist_level in [1, 2, 3, 5]
        assert algo.security.classical_bits > 0
        assert algo.security.quantum_bits > 0
        assert len(algo.security.properties) > 0

        # Sizes
        assert algo.sizes.public_key > 0
        assert algo.sizes.private_key > 0

    @pytest.mark.parametrize("algo_id", list(ALGORITHMS.keys()))
    def test_algorithm_has_performance_data(self, algo_id: str) -> None:
        """Each algorithm should have performance data."""
        algo = ALGORITHMS[algo_id]
        assert len(algo.performance) > 0

        # Should have at least x86 data
        assert any("x86" in p for p in algo.performance.keys())

    @pytest.mark.parametrize("algo_id", list(ALGORITHMS.keys()))
    def test_algorithm_has_implementation(self, algo_id: str) -> None:
        """Each algorithm should have at least one implementation."""
        algo = ALGORITHMS[algo_id]
        assert len(algo.requirements.implementations) > 0

    def test_ml_kem_variants(self) -> None:
        """ML-KEM should have 512, 768, 1024 variants."""
        variants = [a.variant for a in get_algorithms_by_family("ML-KEM")]
        assert "512" in variants
        assert "768" in variants
        assert "1024" in variants

    def test_ml_dsa_variants(self) -> None:
        """ML-DSA should have 44, 65, 87 variants."""
        variants = [a.variant for a in get_algorithms_by_family("ML-DSA")]
        assert "44" in variants
        assert "65" in variants
        assert "87" in variants

    def test_falcon_requires_fpu(self) -> None:
        """Falcon should require FPU."""
        falcon = get_algorithm("falcon-512")
        assert falcon is not None
        assert falcon.requirements.requires_fpu

    def test_falcon_not_constant_time(self) -> None:
        """Falcon should not be constant-time."""
        falcon = get_algorithm("falcon-512")
        assert falcon is not None
        assert not falcon.security.constant_time

    def test_ml_dsa_is_constant_time(self) -> None:
        """ML-DSA should be constant-time."""
        for algo in get_algorithms_by_family("ML-DSA"):
            assert algo.security.constant_time

    def test_security_levels_make_sense(self) -> None:
        """Higher variants should have higher security levels."""
        ml_kem_512 = get_algorithm("ml-kem-512")
        ml_kem_768 = get_algorithm("ml-kem-768")
        ml_kem_1024 = get_algorithm("ml-kem-1024")

        assert ml_kem_512 is not None
        assert ml_kem_768 is not None
        assert ml_kem_1024 is not None

        assert ml_kem_512.security.nist_level < ml_kem_768.security.nist_level
        assert ml_kem_768.security.nist_level < ml_kem_1024.security.nist_level

    def test_signature_sizes_are_populated(self) -> None:
        """Signature algorithms should have signature sizes."""
        for algo in get_algorithms_by_type("signature"):
            assert algo.sizes.signature is not None
            assert algo.sizes.signature > 0

    def test_kem_ciphertext_sizes_are_populated(self) -> None:
        """KEM algorithms should have ciphertext sizes."""
        for algo in get_algorithms_by_type("kem"):
            assert algo.sizes.ciphertext is not None
            assert algo.sizes.ciphertext > 0


# Classical reference sizes the comparison strings are measured against.
X25519_PUBLIC_KEY_BYTES = 32
ECDSA_P256_SIGNATURE_BYTES = 64


class TestSizeComparisons:
    """The "~Nx larger" text must match the sizes printed above it."""

    def test_comparisons_exist(self) -> None:
        """At least one KEM and one signature carry a comparison string."""
        types = {a.algorithm_type for a in ALGORITHMS.values() if a.sizes.comparison}
        assert {"kem", "signature"} <= types

    @pytest.mark.parametrize(
        "algo_id",
        [k for k, a in ALGORITHMS.items() if a.sizes.comparison],
    )
    def test_comparison_ratio_matches_sizes(self, algo_id: str) -> None:
        """The leading ~Nx is the size divided by the classical reference."""
        algo = ALGORITHMS[algo_id]
        comparison = algo.sizes.comparison
        assert comparison is not None
        match = re.match(r"~(\d+)x ", comparison)
        assert match, f"{algo_id}: comparison does not start with ~Nx: {comparison!r}"
        ratio = int(match.group(1))

        if algo.algorithm_type == "kem":
            expected = round(algo.sizes.public_key / X25519_PUBLIC_KEY_BYTES)
            assert "X25519" in comparison
        elif algo.algorithm_type == "signature":
            assert algo.sizes.signature is not None
            expected = round(algo.sizes.signature / ECDSA_P256_SIGNATURE_BYTES)
            assert "ECDSA P-256" in comparison
        else:
            pytest.fail(f"{algo_id}: no reference size for type {algo.algorithm_type!r}")

        assert ratio == expected, f"{algo_id}: says ~{ratio}x, sizes give ~{expected}x"
