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

    def test_parse_cnsa_requires_level_5(self, parser: QueryParser) -> None:
        """CNSA 2.0 uses Level V parameters for all classification levels."""
        constraints = parser.parse("classified government system, CNSA 2.0 required")
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    @pytest.mark.parametrize(
        "query",
        [
            "blockchain transaction signing",
            "store API secrets in a vault",
            "defense in depth for a web server",
            "derive a shared secret for session keys",
            "unclassified internal reporting tool",
        ],
    )
    def test_cnsa_not_inferred_from_words_containing_keywords(
        self, parser: QueryParser, query: str
    ) -> None:
        """CNSA 2.0 keywords inside other words or phrases do not select CNSA 2.0."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 not in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_3

    @pytest.mark.parametrize(
        "query",
        [
            "NSA approved key exchange",
            "top secret document storage",
            "national security system messaging",
            "classified network VPN",
        ],
    )
    def test_cnsa_inferred_from_whole_words(self, parser: QueryParser, query: str) -> None:
        """Naming CNSA, the NSA or classified systems selects CNSA 2.0."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    def test_embedded_context_keeps_cnsa_level_5(self, parser: QueryParser) -> None:
        """The embedded Level 1 floor does not lower the CNSA 2.0 Level 5 floor."""
        constraints = parser.parse("CNSA 2.0 embedded sensor with 256KB RAM")
        assert constraints.is_embedded is True
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

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

    def test_parse_nginx_as_tls(self, parser: QueryParser) -> None:
        """nginx keyword should detect TLS use case."""
        constraints = parser.parse("nginx reverse proxy")
        assert constraints.use_case == UseCase.TLS
        assert constraints.needs_both is True

    def test_parse_apache_as_tls(self, parser: QueryParser) -> None:
        """apache keyword should detect TLS use case."""
        constraints = parser.parse("apache web server")
        assert constraints.use_case == UseCase.TLS

    def test_parse_load_balancer_as_tls(self, parser: QueryParser) -> None:
        """load balancer keyword should detect TLS use case."""
        constraints = parser.parse("load balancer with TLS termination")
        assert constraints.use_case == UseCase.TLS

    def test_parse_constrained_device(self, parser: QueryParser) -> None:
        """Constrained device should lower security level and prefer smaller sizes."""
        constraints = parser.parse("constrained IoT device with limited memory")
        assert constraints.is_embedded is True
        assert constraints.min_security_level == SecurityLevel.LEVEL_1
        assert constraints.prefer_smaller_keys is True
        assert constraints.max_public_key_bytes is not None

    def test_parse_embedded_platform(self, parser: QueryParser) -> None:
        """Embedded keywords should detect embedded platform."""
        constraints = parser.parse("ESP32 microcontroller with RTOS")
        assert constraints.platform == Platform.EMBEDDED
        assert constraints.is_embedded is True

    def test_parse_low_power_device(self, parser: QueryParser) -> None:
        """Low power keywords should trigger constrained device handling."""
        constraints = parser.parse("low power sensor device")
        assert constraints.min_security_level == SecurityLevel.LEVEL_1
        assert constraints.prefer_smaller_keys is True
