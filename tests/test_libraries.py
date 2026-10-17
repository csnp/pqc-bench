"""Tests for the library database."""

import pytest

from pqc_bench.data.libraries import (
    LIBRARIES,
    HYBRID_MODES,
    ProductionReadiness,
    FIPSStatus,
    get_library,
    get_production_ready_libraries,
    get_libraries_with_fips,
    get_libraries_for_algorithm,
    get_hybrid_mode,
    get_recommended_hybrid_for_kem,
    get_hybrid_modes_for_use_case,
)


class TestLibraryDatabase:
    """Tests for the library database."""

    def test_libraries_exist(self) -> None:
        """Library database should contain libraries."""
        assert len(LIBRARIES) > 0

    def test_get_library_by_id(self) -> None:
        """Should retrieve library by ID."""
        lib = get_library("aws-lc")
        assert lib is not None
        assert lib.id == "aws-lc"

    def test_get_library_case_insensitive(self) -> None:
        """Library lookup should be case insensitive."""
        lib = get_library("AWS-LC")
        assert lib is not None

    def test_get_library_unknown(self) -> None:
        """Should return None for unknown library."""
        lib = get_library("unknown-lib")
        assert lib is None

    def test_production_ready_libraries(self) -> None:
        """Should return only production-ready libraries."""
        libs = get_production_ready_libraries()
        assert len(libs) > 0
        for lib in libs:
            assert lib.production_readiness == ProductionReadiness.PRODUCTION

    def test_fips_validated_libraries(self) -> None:
        """Should return only FIPS-validated libraries."""
        libs = get_libraries_with_fips()
        assert len(libs) > 0
        for lib in libs:
            assert lib.fips_status == FIPSStatus.VALIDATED

    def test_libraries_for_algorithm(self) -> None:
        """Should return libraries supporting an algorithm."""
        libs = get_libraries_for_algorithm("ml-kem-768")
        assert len(libs) > 0
        # AWS-LC should support ML-KEM-768
        lib_ids = [lib.id for lib in libs]
        assert "aws-lc" in lib_ids

    @pytest.mark.parametrize("variant", ["512", "1024"])
    def test_libraries_for_falcon(self, variant: str) -> None:
        """A two-part ID such as falcon-512 finds the libraries whose data lists that Falcon variant."""
        listed = [lib.id for lib in LIBRARIES.values() if lib.algorithms and variant in lib.algorithms.falcon]
        assert "liboqs" in listed
        assert [lib.id for lib in get_libraries_for_algorithm(f"falcon-{variant}")] == listed

    @pytest.mark.parametrize(
        ("name", "algo_id"),
        [("Kyber768", "ml-kem-768"), ("Dilithium3", "ml-dsa-65"), ("FN-DSA-512", "falcon-512")],
    )
    def test_libraries_for_a_legacy_or_nist_name(self, name: str, algo_id: str) -> None:
        """A legacy or NIST name finds the same libraries as the algorithm ID."""
        assert get_libraries_for_algorithm(algo_id)
        assert get_libraries_for_algorithm(name) == get_libraries_for_algorithm(algo_id)

    def test_libraries_for_an_slh_dsa_set_without_an_algorithm_profile(self) -> None:
        """slh-dsa-128s has no algorithm profile; its ID still finds the libraries that list it."""
        listed = [lib.id for lib in LIBRARIES.values() if lib.algorithms and "128s" in lib.algorithms.slh_dsa]
        assert listed
        assert [lib.id for lib in get_libraries_for_algorithm("slh-dsa-128s")] == listed

    @pytest.mark.parametrize("value", ["", "falcon", "bogus", "x-512", "__class___x", "__dict___x"])
    def test_libraries_for_an_unknown_value_is_empty(self, value: str) -> None:
        """A value that names no supported family finds no library and raises nothing."""
        assert get_libraries_for_algorithm(value) == []

    def test_liboqs_is_experimental(self) -> None:
        """liboqs should be marked as experimental."""
        liboqs = get_library("liboqs")
        assert liboqs is not None
        assert liboqs.production_readiness == ProductionReadiness.EXPERIMENTAL

    def test_aws_lc_is_production(self) -> None:
        """AWS-LC should be marked as production-ready."""
        aws_lc = get_library("aws-lc")
        assert aws_lc is not None
        assert aws_lc.production_readiness == ProductionReadiness.PRODUCTION
        assert aws_lc.fips_status == FIPSStatus.VALIDATED

    def test_liboqs_has_critical_caveat(self) -> None:
        """liboqs should have a critical caveat about production use."""
        liboqs = get_library("liboqs")
        assert liboqs is not None
        critical_caveats = [c for c in liboqs.caveats if c.severity == "critical"]
        assert len(critical_caveats) > 0


class TestHybridModes:
    """Tests for hybrid mode database."""

    def test_hybrid_modes_exist(self) -> None:
        """Hybrid modes should be defined."""
        assert len(HYBRID_MODES) > 0

    def test_get_hybrid_mode(self) -> None:
        """Should retrieve hybrid mode by ID."""
        mode = get_hybrid_mode("x25519-mlkem768")
        assert mode is not None
        assert mode.classical_algorithm == "X25519"
        assert mode.pqc_algorithm == "ML-KEM-768"

    def test_recommended_hybrid_for_kem(self) -> None:
        """Should recommend X25519MLKEM768 for KEM."""
        mode = get_recommended_hybrid_for_kem()
        assert mode.id == "x25519-mlkem768"
        assert mode.chrome_support is True
        assert mode.cloudflare_support is True

    def test_hybrid_modes_for_tls(self) -> None:
        """Should return appropriate hybrid modes for TLS."""
        modes = get_hybrid_modes_for_use_case("tls")
        assert len(modes) > 0
        # X25519MLKEM768 should be recommended for TLS
        assert any(m.id == "x25519-mlkem768" for m in modes)

    @pytest.mark.parametrize("use_case", ["tls", "https", "web"])
    def test_hybrid_modes_for_tls_list_each_tls_kem_hybrid(self, use_case: str) -> None:
        """TLS use cases list each KEM hybrid with TLS support, SecP384r1MLKEM1024 included."""
        tls_kem_hybrids = [m.id for m in HYBRID_MODES.values() if m.kem_or_sig == "kem" and m.tls_support]
        assert "secp384r1-mlkem1024" in tls_kem_hybrids
        assert [m.id for m in get_hybrid_modes_for_use_case(use_case)] == tls_kem_hybrids

    @pytest.mark.parametrize("use_case", ["browser", "web browser"])
    def test_hybrid_modes_for_browser_have_chrome_support(self, use_case: str) -> None:
        """Browser use cases list only the KEM hybrids with Chrome support."""
        browser_kem_hybrids = [m.id for m in HYBRID_MODES.values() if m.kem_or_sig == "kem" and m.chrome_support]
        assert "secp384r1-mlkem1024" not in browser_kem_hybrids
        assert [m.id for m in get_hybrid_modes_for_use_case(use_case)] == browser_kem_hybrids

    def test_hybrid_modes_for_certificates(self) -> None:
        """Should return signature hybrids for certificates."""
        modes = get_hybrid_modes_for_use_case("certificate")
        assert len(modes) > 0
        # Should be signature hybrids
        for mode in modes:
            assert mode.kem_or_sig == "signature"

    @pytest.mark.parametrize("use_case", ["signature", "signatures", "code signing"])
    def test_hybrid_modes_for_signatures(self, use_case: str) -> None:
        """"signature" selects the composite signature hybrids, like "certificate" and "signing"."""
        modes = get_hybrid_modes_for_use_case(use_case)
        assert [mode.id for mode in modes] == [
            mode.id for mode in HYBRID_MODES.values() if mode.kem_or_sig == "signature"
        ]

    @pytest.mark.parametrize("use_case", ["", "bogus", "kem", "database"])
    def test_hybrid_modes_for_an_unknown_use_case_is_empty(self, use_case: str) -> None:
        """A use case that holds none of the use-case words selects no hybrid mode."""
        assert get_hybrid_modes_for_use_case(use_case) == []

    def test_hybrid_mode_has_combined_size(self) -> None:
        """Hybrid modes should have combined size calculated."""
        mode = get_hybrid_mode("x25519-mlkem768")
        assert mode is not None
        # Should be ML-KEM-768 public key + X25519 public key
        assert mode.combined_size > 1000  # More than 1KB

    def test_hybrid_mode_has_library_support(self) -> None:
        """Hybrid modes should list supporting libraries."""
        mode = get_hybrid_mode("x25519-mlkem768")
        assert mode is not None
        assert len(mode.libraries) > 0
        # BoringSSL and AWS-LC should support it
        assert "boringssl" in mode.libraries or "aws-lc" in mode.libraries


class TestLibraryProfiles:
    """Tests for library profile completeness."""

    @pytest.mark.parametrize("lib_id", list(LIBRARIES.keys()))
    def test_library_has_required_fields(self, lib_id: str) -> None:
        """Each library should have all required fields."""
        lib = LIBRARIES[lib_id]

        # Identity
        assert lib.id
        assert lib.name
        assert lib.description
        assert lib.url
        assert lib.language
        assert lib.license

        # Readiness
        assert lib.production_readiness is not None
        assert lib.fips_status is not None

    @pytest.mark.parametrize("lib_id", list(LIBRARIES.keys()))
    def test_library_has_platforms(self, lib_id: str) -> None:
        """Each library should list supported platforms."""
        lib = LIBRARIES[lib_id]
        assert len(lib.platforms) > 0

    @pytest.mark.parametrize("lib_id", list(LIBRARIES.keys()))
    def test_library_has_recommendations(self, lib_id: str) -> None:
        """Each library should have usage recommendations."""
        lib = LIBRARIES[lib_id]
        assert len(lib.recommended_for) > 0 or len(lib.not_recommended_for) > 0
