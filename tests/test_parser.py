"""Tests for the query parser."""

import pytest

from pqc_bench.core.parser import QueryParser
from pqc_bench.core.constraints import Platform, UseCase, SecurityLevel, ComplianceFramework


class TestQueryParser:
    """Tests for QueryParser."""

    @pytest.fixture
    def parser(self) -> QueryParser:
        return QueryParser()

    def test_parse_empty_query(self, parser: QueryParser) -> None:
        """Empty query should return default constraints."""
        constraints = parser.parse("")
        assert constraints.platform is None
        assert constraints.use_case is None
        assert constraints.min_security_level == SecurityLevel.LEVEL_3

    def test_parse_mobile_platform(self, parser: QueryParser) -> None:
        """Mobile keywords should detect ARM platform."""
        constraints = parser.parse("mobile app for iOS")
        assert constraints.platform == Platform.ARM64_NEON
        assert constraints.is_mobile is True

    def test_parse_server_platform(self, parser: QueryParser) -> None:
        """Server keywords should detect x86 platform."""
        constraints = parser.parse("running on AWS Lambda")
        assert constraints.platform == Platform.X86_64_AVX2
        assert constraints.is_server is True

    def test_parse_browser_platform(self, parser: QueryParser) -> None:
        """Browser keywords should detect WASM platform."""
        constraints = parser.parse("web app running in the browser")
        assert constraints.platform == Platform.WASM
        assert constraints.is_browser is True

    def test_parse_jwt_use_case(self, parser: QueryParser) -> None:
        """JWT keywords should detect JWT use case."""
        constraints = parser.parse("JWT authentication for REST API")
        assert constraints.use_case == UseCase.JWT
        assert constraints.needs_signature is True

    def test_parse_tls_use_case(self, parser: QueryParser) -> None:
        """TLS keywords should detect TLS use case."""
        constraints = parser.parse("TLS for web server")
        assert constraints.use_case == UseCase.TLS
        assert constraints.needs_kem is True
        assert constraints.needs_signature is True

    def test_parse_blockchain_use_case(self, parser: QueryParser) -> None:
        """Blockchain keywords should detect blockchain use case."""
        constraints = parser.parse("blockchain smart contract signing")
        assert constraints.use_case == UseCase.BLOCKCHAIN
        assert constraints.prefer_smaller_signatures is True

    def test_parse_latency_requirement(self, parser: QueryParser) -> None:
        """Latency in ms should be extracted."""
        constraints = parser.parse("need 10ms latency")
        assert constraints.max_latency_ms == 10.0

    def test_parse_volume_requirement(self, parser: QueryParser) -> None:
        """Volume requirements should be extracted."""
        constraints = parser.parse("handling 10k requests per second")
        assert constraints.operations_per_second == 10000
        assert constraints.is_high_volume is True

    def test_parse_compliance_fips(self, parser: QueryParser) -> None:
        """FIPS keywords should detect compliance requirement."""
        constraints = parser.parse("need FIPS 140 compliance")
        assert ComplianceFramework.FIPS_140_3 in constraints.compliance_frameworks

    def test_parse_compliance_healthcare(self, parser: QueryParser) -> None:
        """Healthcare context should infer HIPAA."""
        constraints = parser.parse("healthcare application")
        assert ComplianceFramework.HIPAA in constraints.compliance_frameworks

    def test_parse_high_security(self, parser: QueryParser) -> None:
        """High security keywords should set Level 5."""
        constraints = parser.parse("need maximum security level 5")
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    def test_parse_complex_query(self, parser: QueryParser) -> None:
        """Complex query should extract multiple constraints."""
        constraints = parser.parse(
            "REST API with JWT auth for a fintech startup, "
            "running on AWS Lambda, need 50ms latency"
        )
        assert constraints.use_case in [UseCase.JWT, UseCase.API]
        assert constraints.platform == Platform.X86_64_AVX2
        assert constraints.max_latency_ms == 50.0
        assert constraints.is_server is True

    def test_parse_signature_preference(self, parser: QueryParser) -> None:
        """Small signature keywords should set preference."""
        constraints = parser.parse("need compact signatures for bandwidth")
        assert constraints.prefer_smaller_signatures is True

    def test_confidence_increases_with_constraints(self, parser: QueryParser) -> None:
        """Confidence should increase as more constraints are specified."""
        basic = parser.parse("signature")
        detailed = parser.parse(
            "JWT auth for mobile iOS app with FIPS compliance"
        )
        assert detailed.confidence > basic.confidence
