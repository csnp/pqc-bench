"""Tests for the library database."""

import pytest

from pqc_bench.data.libraries import (
    HYBRID_MODES,
    LIBRARIES,
    FIPSStatus,
    ProductionReadiness,
    get_hybrid_mode,
    get_hybrid_modes_for_use_case,
    get_libraries_for_algorithm,
    get_libraries_with_fips,
    get_library,
    get_production_ready_libraries,
    get_recommended_hybrid_for_kem,
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

    def test_wolfssl_has_no_pqc_fips_certificate(self) -> None:
        """No wolfCrypt certificate lists ML-KEM, ML-DSA or SLH-DSA, so wolfSSL is not in the FIPS list."""
        wolfssl = get_library("wolfssl")
        assert wolfssl is not None
        assert wolfssl.production_readiness == ProductionReadiness.PRODUCTION
        assert wolfssl.fips_cert_number is None
        assert wolfssl.fips_status == FIPSStatus.IN_PROCESS
        assert wolfssl not in get_libraries_with_fips()
        scope = [c.description for c in wolfssl.caveats if "#3389" in c.description]
        assert scope == [
            "FIPS 140-2 certificate #3389 (now historical) and FIPS 140-3 certificates #4718, #5041 and #5548 "
            "cover the classical wolfCrypt module; none lists ML-KEM, ML-DSA or SLH-DSA"
        ]

    def test_aws_lc_cites_a_certificate_that_lists_ml_kem(self) -> None:
        """AWS-LC cites #5298, an AWS-LC 3 module certificate that lists ML-KEM, not #4793 (another vendor's)."""
        aws_lc = get_library("aws-lc")
        assert aws_lc is not None
        assert aws_lc.fips_cert_number == "5298"
        assert aws_lc.fips_status == FIPSStatus.VALIDATED
        assert aws_lc in get_libraries_with_fips()
        scope = [c.description for c in aws_lc.caveats if "#5298" in c.description]
        assert scope == [
            "FIPS 140-3 certificates #5298 (dynamic) and #5314 (static) for the AWS-LC 3 Cryptographic Module "
            "list ML-KEM; neither lists ML-DSA or SLH-DSA"
        ]
        assert not [c for c in aws_lc.caveats if "pending final validation" in c.description]

    def test_boringssl_has_no_pqc_fips_certificate(self) -> None:
        """BoringSSL has no certificate number and is not in the FIPS list: #4407 is historical and lists no PQC."""
        boringssl = get_library("boringssl")
        assert boringssl is not None
        assert boringssl.production_readiness == ProductionReadiness.PRODUCTION
        assert boringssl.fips_cert_number is None
        assert boringssl.fips_status == FIPSStatus.IN_PROCESS
        assert boringssl not in get_libraries_with_fips()
        scope = [c.description for c in boringssl.caveats if "#4407" in c.description]
        assert scope == [
            "FIPS 140-2 certificate #4407 (now historical) and FIPS 140-3 certificates #4735, #5104, #5244 and #5296 "
            "cover the classical BoringCrypto module; none lists ML-KEM, ML-DSA or SLH-DSA"
        ]

    def test_boringssl_lists_the_parameter_sets_its_headers_declare(self) -> None:
        """BoringSSL lists the ML-KEM, ML-DSA and SLH-DSA sets declared in mlkem.h, mldsa.h and slhdsa.h."""
        boringssl = get_library("boringssl")
        assert boringssl is not None
        assert boringssl.algorithms is not None
        # mlkem.h declares MLKEM768_* and MLKEM1024_*, mldsa.h MLDSA44_*, MLDSA65_* and
        # MLDSA87_*, slhdsa.h SLHDSA_SHA2_128S_* and SLHDSA_SHAKE_256F_* (read 2026-11-13).
        # The slh_dsa IDs name the FIPS 205 SHA2 sets, so SHAKE-256f has no ID here.
        assert boringssl.algorithms.ml_kem == ["768", "1024"]
        assert boringssl.algorithms.ml_dsa == ["44", "65", "87"]
        assert boringssl.algorithms.slh_dsa == ["128s"]
        assert boringssl.algorithms.falcon == []

    @pytest.mark.parametrize("algorithm_id", ["ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
    def test_boringssl_is_listed_for_the_sets_it_declares(self, algorithm_id: str) -> None:
        """The libraries table for each declared ML-KEM and ML-DSA set includes BoringSSL."""
        assert "boringssl" in [lib.id for lib in get_libraries_for_algorithm(algorithm_id)]

    def test_boringssl_is_not_listed_for_ml_kem_512(self) -> None:
        """mlkem.h declares no ML-KEM-512, so BoringSSL is not listed for it."""
        assert "boringssl" not in [lib.id for lib in get_libraries_for_algorithm("ml-kem-512")]

    def test_boringssl_names_the_gaps_it_has_rather_than_signatures(self) -> None:
        """The not-recommended list names Falcon and the undeclared SLH-DSA sets, not signatures as a whole."""
        boringssl = get_library("boringssl")
        assert boringssl is not None
        assert "Signature algorithms" not in boringssl.not_recommended_for
        assert "Full PQC algorithm suite" not in boringssl.not_recommended_for
        assert "Falcon (FN-DSA) signatures" in boringssl.not_recommended_for


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
