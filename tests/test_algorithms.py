"""Tests for the algorithm database."""

import re

import pytest
from typer.testing import CliRunner

from pqc_bench import cli
from pqc_bench.data.algorithms import (
    ALGORITHMS,
    FrameworkApproval,
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

    @pytest.mark.parametrize(
        ("name", "algo_id"),
        [
            ("Kyber768", "ml-kem-768"),
            ("kyber768", "ml-kem-768"),
            ("Dilithium3", "ml-dsa-65"),
            ("dilithium3", "ml-dsa-65"),
            ("SPHINCS+-SHA2-128f-simple", "slh-dsa-128f"),
            ("FN-DSA-512", "falcon-512"),
            ("SLH-DSA-SHA2-128f", "slh-dsa-128f"),
        ],
    )
    def test_get_algorithm_by_legacy_or_nist_name(self, name: str, algo_id: str) -> None:
        """A legacy or NIST name finds the same algorithm as its ID."""
        algo = get_algorithm(name)
        assert algo is not None
        assert algo.id == algo_id

    @pytest.mark.parametrize("algo_id", list(ALGORITHMS.keys()))
    def test_every_name_explain_prints_finds_its_algorithm(self, algo_id: str) -> None:
        """The ID, NIST name and legacy name of an algorithm all find that algorithm."""
        algo = ALGORITHMS[algo_id]
        for name in (algo.id, algo.names.nist_name, algo.names.legacy_name):
            found = get_algorithm(name)
            assert found is not None, name
            assert found.id == algo_id, name

    @pytest.mark.parametrize("name", ["", "kyber", "dilithium", "ml-kem", "Kyber769", "X25519MLKEM768"])
    def test_get_algorithm_partial_or_other_names(self, name: str) -> None:
        """A family name, a wrong variant or a hybrid mode name finds no algorithm."""
        assert get_algorithm(name) is None

    @pytest.mark.parametrize(
        ("name", "nist_name"),
        [("kyber768", "ML-KEM-768"), ("dilithium3", "ML-DSA-65"), ("FN-DSA-512", "FN-DSA-512")],
    )
    def test_explain_accepts_the_names_it_prints(self, name: str, nist_name: str) -> None:
        """explain shows the algorithm for a legacy or NIST name instead of "Unknown algorithm"."""
        result = CliRunner().invoke(cli.app, ["explain", name])
        assert result.exit_code == 0
        assert "Unknown algorithm" not in result.output
        assert f"NIST Name:     {nist_name}" in result.output

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


# NIST Computer Security Objects Register, algorithm registration:
# https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
NIST_ALGORITHMS_ARC = "2.16.840.1.101.3.4."
NIST_OIDS = {
    "ml-kem-512": "2.16.840.1.101.3.4.4.1",
    "ml-kem-768": "2.16.840.1.101.3.4.4.2",
    "ml-kem-1024": "2.16.840.1.101.3.4.4.3",
    "ml-dsa-44": "2.16.840.1.101.3.4.3.17",
    "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
    "ml-dsa-87": "2.16.840.1.101.3.4.3.19",
    "slh-dsa-128f": "2.16.840.1.101.3.4.3.21",
}


class TestAlgorithmOids:
    """Tests for the object identifiers printed by explain."""

    @pytest.mark.parametrize("algo_id,oid", list(NIST_OIDS.items()))
    def test_standardized_oid_matches_nist_registration(self, algo_id: str, oid: str) -> None:
        """FIPS 203, 204 and 205 algorithms carry the OID NIST registered for them."""
        algo = get_algorithm(algo_id)
        assert algo is not None
        assert algo.names.oid == oid

    @pytest.mark.parametrize("algo_id", ["falcon-512", "falcon-1024"])
    def test_fn_dsa_has_no_oid(self, algo_id: str) -> None:
        """FN-DSA has no NIST-registered OID until FIPS 206 is final."""
        algo = get_algorithm(algo_id)
        assert algo is not None
        assert algo.names.oid is None

    @pytest.mark.parametrize("algo_id", list(ALGORITHMS.keys()))
    def test_every_oid_is_under_the_nist_algorithms_arc(self, algo_id: str) -> None:
        """No algorithm carries an OID from a draft or experimental arc."""
        oid = ALGORITHMS[algo_id].names.oid
        if oid is not None:
            assert oid.startswith(NIST_ALGORITHMS_ARC)

    def test_explain_prints_the_nist_oid(self) -> None:
        """explain shows the registered OID for a standardized algorithm."""
        result = CliRunner().invoke(cli.app, ["explain", "ml-kem-768"])
        assert result.exit_code == 0
        assert "OID:           2.16.840.1.101.3.4.4.2" in result.output

    def test_explain_says_when_no_oid_is_assigned(self) -> None:
        """explain keeps the OID line for FN-DSA and says no OID is assigned yet."""
        result = CliRunner().invoke(cli.app, ["explain", "falcon-512"])
        assert result.exit_code == 0
        assert "OID:           not assigned yet" in result.output


class TestFrameworkApprovalLabels:
    """Tests for the approval status explain prints."""

    @pytest.mark.parametrize(
        ("status", "label"),
        [
            ("approved", "Approved"),
            ("not_approved", "Not approved"),
            ("recommended", "Recommended"),
            ("pending", "Pending"),
        ],
    )
    def test_status_label(self, status: str, label: str) -> None:
        assert FrameworkApproval(framework="CNSA 2.0", status=status).status_label == label

    def test_explain_prints_labels_not_status_values(self) -> None:
        """explain ml-dsa-65 says "Not approved" for CNSA 2.0, not the stored value "not_approved"."""
        result = CliRunner().invoke(cli.app, ["explain", "ml-dsa-65"])
        assert result.exit_code == 0
        assert "CNSA 2.0: Not approved" in result.output
        assert "FIPS 140-3: Approved" in result.output
        assert "not_approved" not in result.output
