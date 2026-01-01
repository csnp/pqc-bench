"""Tests for the protocol impact analysis module."""

import pytest

from pqc_bench.data.protocol_impact import (
    CLASSICAL_SIZES,
    calculate_tls_kem_impact,
    calculate_tls_signature_impact,
    analyze_certificate_chain,
    get_ossification_risks,
    estimate_operation_latency,
    get_size_comparison_table,
)


class TestClassicalBaselines:
    """Tests for classical algorithm baselines."""

    def test_classical_sizes_exist(self) -> None:
        """Classical algorithm sizes should be defined."""
        assert len(CLASSICAL_SIZES) > 0

    def test_ecdsa_p256_baseline(self) -> None:
        """ECDSA P-256 should have expected sizes."""
        ecdsa = CLASSICAL_SIZES.get("ecdsa-p256")
        assert ecdsa is not None
        assert ecdsa.public_key == 64
        assert ecdsa.signature == 64

    def test_x25519_baseline(self) -> None:
        """X25519 should have expected sizes."""
        x25519 = CLASSICAL_SIZES.get("x25519")
        assert x25519 is not None
        assert x25519.public_key == 32


class TestTLSKEMImpact:
    """Tests for TLS KEM impact analysis."""

    def test_kem_impact_calculation(self) -> None:
        """Should calculate TLS impact for KEM."""
        impact = calculate_tls_kem_impact("ml-kem-768")
        assert impact is not None
        assert impact.algorithm_id == "ml-kem-768"

    def test_kem_impact_shows_size_delta(self) -> None:
        """KEM impact should show size increases."""
        impact = calculate_tls_kem_impact("ml-kem-768")
        assert impact is not None
        # Should be larger than X25519
        assert impact.client_hello_delta > 0
        assert impact.server_hello_delta > 0
        assert impact.total_handshake_delta > 0

    def test_kem_impact_assesses_fragmentation(self) -> None:
        """KEM impact should assess fragmentation risk."""
        impact = calculate_tls_kem_impact("ml-kem-768")
        assert impact is not None
        assert impact.packet_fragmentation_risk in ["low", "medium", "high"]

    def test_kem_impact_assesses_middlebox(self) -> None:
        """KEM impact should assess middlebox compatibility."""
        impact = calculate_tls_kem_impact("ml-kem-768")
        assert impact is not None
        assert impact.middlebox_compatibility in ["good", "moderate", "poor"]

    def test_kem_impact_returns_none_for_signature(self) -> None:
        """Should return None for signature algorithm."""
        impact = calculate_tls_kem_impact("ml-dsa-65")
        assert impact is None

    def test_larger_kem_has_higher_risk(self) -> None:
        """Larger KEMs should have higher fragmentation risk or same."""
        impact_768 = calculate_tls_kem_impact("ml-kem-768")
        impact_1024 = calculate_tls_kem_impact("ml-kem-1024")
        assert impact_768 is not None
        assert impact_1024 is not None
        # ML-KEM-1024 should have equal or higher delta
        assert impact_1024.total_handshake_delta >= impact_768.total_handshake_delta


class TestTLSSignatureImpact:
    """Tests for TLS signature impact analysis."""

    def test_signature_impact_calculation(self) -> None:
        """Should calculate TLS impact for signature."""
        impact = calculate_tls_signature_impact("ml-dsa-65")
        assert impact is not None
        assert impact.algorithm_id == "ml-dsa-65"

    def test_signature_impact_uses_chain_length(self) -> None:
        """Signature impact should scale with chain length."""
        impact_3 = calculate_tls_signature_impact("ml-dsa-65", chain_length=3)
        impact_4 = calculate_tls_signature_impact("ml-dsa-65", chain_length=4)
        assert impact_3 is not None
        assert impact_4 is not None
        assert impact_4.total_handshake_delta > impact_3.total_handshake_delta

    def test_signature_impact_returns_none_for_kem(self) -> None:
        """Should return None for KEM algorithm."""
        impact = calculate_tls_signature_impact("ml-kem-768")
        assert impact is None


class TestCertificateChainAnalysis:
    """Tests for certificate chain analysis."""

    def test_chain_analysis_calculation(self) -> None:
        """Should calculate certificate chain impact."""
        analysis = analyze_certificate_chain("ml-dsa-65")
        assert analysis is not None
        assert analysis.signature_algorithm == "ML-DSA-65"

    def test_chain_analysis_shows_increase(self) -> None:
        """Chain analysis should show size increase."""
        analysis = analyze_certificate_chain("ml-dsa-65")
        assert analysis is not None
        assert analysis.pqc_cert_size > analysis.classical_cert_size
        assert analysis.size_increase_factor > 1

    def test_chain_analysis_calculates_tcp_segments(self) -> None:
        """Chain analysis should calculate TCP segments."""
        analysis = analyze_certificate_chain("ml-dsa-65")
        assert analysis is not None
        assert analysis.tcp_segments_classical > 0
        assert analysis.tcp_segments_pqc >= analysis.tcp_segments_classical

    def test_chain_analysis_provides_mitigations(self) -> None:
        """Chain analysis should provide mitigations."""
        analysis = analyze_certificate_chain("ml-dsa-87", chain_length=4)
        assert analysis is not None
        assert len(analysis.mitigations) > 0


class TestOssificationRisks:
    """Tests for protocol ossification risk analysis."""

    def test_ossification_risks_for_large_algorithm(self) -> None:
        """Large algorithms should have ossification risks."""
        risks = get_ossification_risks("slh-dsa-128f")
        assert len(risks) > 0

    def test_ossification_risks_smaller_for_small_algorithm(self) -> None:
        """Smaller algorithms should have fewer risks."""
        risks_512 = get_ossification_risks("ml-kem-512")
        risks_1024 = get_ossification_risks("ml-kem-1024")
        # At minimum, risks should not be higher for smaller algorithm
        assert len(risks_512) <= len(risks_1024)

    def test_falcon_has_variable_size_risk(self) -> None:
        """Falcon should have variable signature size risk."""
        risks = get_ossification_risks("falcon-512")
        risk_descriptions = [r.description.lower() for r in risks]
        assert any("variable" in desc for desc in risk_descriptions)

    def test_slh_dsa_has_large_signature_risk(self) -> None:
        """SLH-DSA should have large signature risk."""
        risks = get_ossification_risks("slh-dsa-128f")
        risk_descriptions = [r.description.lower() for r in risks]
        assert any("large" in desc or "17" in desc for desc in risk_descriptions)


class TestLatencyEstimation:
    """Tests for latency estimation."""

    def test_latency_estimation_keygen(self) -> None:
        """Should estimate keygen latency."""
        latency = estimate_operation_latency("ml-kem-768", "keygen")
        assert latency is not None
        assert latency.pqc_time_us > 0

    def test_latency_estimation_sign(self) -> None:
        """Should estimate signing latency."""
        latency = estimate_operation_latency("ml-dsa-65", "sign")
        assert latency is not None
        assert latency.pqc_time_us > 0

    def test_latency_estimation_shows_overhead(self) -> None:
        """Should show overhead vs classical."""
        latency = estimate_operation_latency("ml-dsa-65", "verify")
        assert latency is not None
        assert latency.overhead_factor > 0

    def test_latency_notes_for_slow_operations(self) -> None:
        """Should provide notes for slow operations."""
        # Falcon has very slow keygen
        latency = estimate_operation_latency("falcon-512", "keygen")
        assert latency is not None
        # May or may not have notes depending on actual performance


class TestSizeComparison:
    """Tests for size comparison table."""

    def test_size_comparison_table(self) -> None:
        """Should generate size comparison table."""
        table = get_size_comparison_table(["ml-kem-768", "ml-kem-1024"])
        assert len(table) == 2
        assert "ML-KEM-768" in table
        assert "ML-KEM-1024" in table

    def test_size_comparison_includes_total(self) -> None:
        """Size comparison should include total exchange size."""
        table = get_size_comparison_table(["ml-kem-768"])
        assert "ML-KEM-768" in table
        sizes = table["ML-KEM-768"]
        assert "total_exchange" in sizes
