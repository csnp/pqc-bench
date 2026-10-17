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

    @pytest.mark.parametrize(
        "query",
        [
            "top-secret documents",
            "topsecret archive",
            "national-security system messaging",
            "CNSA2.0 compliant VPN",
            "cnsa-2.0 key exchange",
        ],
    )
    def test_cnsa_inferred_from_hyphenated_and_joined_spellings(
        self, parser: QueryParser, query: str
    ) -> None:
        """Hyphenated and joined spellings of CNSA 2.0 terms select CNSA 2.0."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    def test_cnsa_inferred_from_military_communications(self, parser: QueryParser) -> None:
        """Military communications, a national security data example, select CNSA 2.0."""
        constraints = parser.parse("military communications system")
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    @pytest.mark.parametrize(
        "query",
        [
            "military-grade encryption for a chat app",
            "military grade TLS for a web server",
            "paramilitary history blog",
        ],
    )
    def test_cnsa_not_inferred_from_military_grade(
        self, parser: QueryParser, query: str
    ) -> None:
        """Military-grade describes commercial encryption, not a military system."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 not in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_3

    def test_embedded_context_keeps_cnsa_level_5(self, parser: QueryParser) -> None:
        """The embedded Level 1 floor does not lower the CNSA 2.0 Level 5 floor."""
        constraints = parser.parse("CNSA 2.0 embedded sensor with 256KB RAM")
        assert constraints.is_embedded is True
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    @pytest.mark.parametrize(
        "query",
        ["graphics rendering service", "philosophy course platform"],
    )
    def test_hipaa_not_inferred_from_words_containing_phi(
        self, parser: QueryParser, query: str
    ) -> None:
        """"phi" inside another word does not select HIPAA."""
        constraints = parser.parse(query)
        assert ComplianceFramework.HIPAA not in constraints.compliance_frameworks

    def test_hipaa_inferred_from_phi_as_a_word(self, parser: QueryParser) -> None:
        """PHI as a word selects HIPAA."""
        constraints = parser.parse("store PHI for a clinic")
        assert ComplianceFramework.HIPAA in constraints.compliance_frameworks

    @pytest.mark.parametrize(
        "query",
        [
            "local cache encryption",
            "encrypt application data",
            "scalable encryption service",
        ],
    )
    def test_certificate_use_case_not_detected_inside_other_words(
        self, parser: QueryParser, query: str
    ) -> None:
        """"ca" inside another word does not select the certificate use case."""
        constraints = parser.parse(query)
        assert constraints.use_case != UseCase.CERTIFICATE
        assert constraints.needs_kem is True
        assert constraints.needs_signature is False

    @pytest.mark.parametrize(
        "query",
        ["run a private CA", "rotate the CAs", "renew expiring certs"],
    )
    def test_certificate_use_case_detected_from_whole_words(
        self, parser: QueryParser, query: str
    ) -> None:
        """"ca" and "cert" as words, or their plurals, select the certificate use case."""
        constraints = parser.parse(query)
        assert constraints.use_case == UseCase.CERTIFICATE

    @pytest.mark.parametrize(
        ("query", "use_case"),
        [
            ("rapid key rotation", UseCase.API),
            ("restore encrypted backups", UseCase.API),
            ("handheld scanner", UseCase.KEY_EXCHANGE),
            ("biotech research data", UseCase.IOT),
            ("not certain which algorithm to use", UseCase.CERTIFICATE),
        ],
    )
    def test_short_use_case_keywords_not_matched_inside_other_words(
        self, parser: QueryParser, query: str, use_case: UseCase
    ) -> None:
        """"api", "rest", "dh", "iot" and "cert" inside other words select no use case."""
        constraints = parser.parse(query)
        assert constraints.use_case != use_case

    @pytest.mark.parametrize("query", ["mTLS between services", "OpenSSL upgrade"])
    def test_tls_detected_inside_longer_words(self, parser: QueryParser, query: str) -> None:
        """"tls" and "ssl" inside mTLS and OpenSSL still select TLS."""
        constraints = parser.parse(query)
        assert constraints.use_case == UseCase.TLS

    def test_pci_dss_not_inferred_from_pcie(self, parser: QueryParser) -> None:
        """"pci" inside "PCIe" does not select PCI DSS."""
        constraints = parser.parse("PCIe HSM card")
        assert ComplianceFramework.PCI_DSS not in constraints.compliance_frameworks

    @pytest.mark.parametrize(
        ("query", "framework"),
        [
            ("encrypt ePHI backups", ComplianceFramework.HIPAA),
            ("store ePHI in the cloud", ComplianceFramework.HIPAA),
            ("encrypt e-PHI backups", ComplianceFramework.HIPAA),
            ("PCIDSS scope encryption", ComplianceFramework.PCI_DSS),
            ("PCI-DSS scope encryption", ComplianceFramework.PCI_DSS),
        ],
    )
    def test_joined_compliance_terms_select_their_framework(
        self, parser: QueryParser, query: str, framework: ComplianceFramework
    ) -> None:
        """"ePHI" selects HIPAA and "PCIDSS" selects PCI DSS, like "e-PHI" and "PCI-DSS"."""
        constraints = parser.parse(query)
        assert framework in constraints.compliance_frameworks

    @pytest.mark.parametrize("query", ["graphics rendering service", "philosophy course platform", "PCIe HSM card"])
    def test_phi_and_pci_inside_other_words_select_no_framework(self, parser: QueryParser, query: str) -> None:
        """"graphics", "philosophy" and "PCIe" select neither HIPAA nor PCI DSS."""
        constraints = parser.parse(query)
        assert ComplianceFramework.HIPAA not in constraints.compliance_frameworks
        assert ComplianceFramework.PCI_DSS not in constraints.compliance_frameworks

    @pytest.mark.parametrize(
        ("query", "use_case"),
        [
            ("DHE key agreement", UseCase.KEY_EXCHANGE),
            ("FFDHE key agreement", UseCase.KEY_EXCHANGE),
            ("ffdhe2048 group support", UseCase.KEY_EXCHANGE),
            ("rootCA rotation", UseCase.CERTIFICATE),
            ("subCA issuance", UseCase.CERTIFICATE),
            ("OpenAPI service for partners", UseCase.API),
            ("RESTful service authentication", UseCase.API),
            ("IIoT gateway firmware", UseCase.IOT),
        ],
    )
    def test_compound_terms_select_their_use_case(
        self, parser: QueryParser, query: str, use_case: UseCase
    ) -> None:
        """DHE, FFDHE, rootCA, subCA, OpenAPI, RESTful and IIoT select their use case."""
        constraints = parser.parse(query)
        assert constraints.use_case == use_case

    @pytest.mark.parametrize(
        "query",
        ["handheld scanner", "local backup", "rapid prototyping", "biotech research data", "adhere to the subcategory"],
    )
    def test_compound_keywords_not_matched_inside_other_words(self, parser: QueryParser, query: str) -> None:
        """"dhe" in "handheld" and "adhere", "subca" in "subcategory" and similar select no use case."""
        constraints = parser.parse(query)
        assert constraints.use_case is None

    def test_dhe_query_needs_a_kem(self, parser: QueryParser) -> None:
        """A DHE key agreement query asks for a KEM, not a signature."""
        constraints = parser.parse("DHE key agreement")
        assert constraints.needs_kem is True
        assert constraints.needs_signature is False

    @pytest.mark.parametrize(
        "query",
        [
            "encrypt data at rest",
            "data at rest encryption for a database",
            "data-at-rest encryption",
            "data_at_rest encryption",
        ],
    )
    def test_data_at_rest_selects_file_encryption(self, parser: QueryParser, query: str) -> None:
        """"rest" in "at rest" is not the REST API keyword."""
        constraints = parser.parse(query)
        assert constraints.use_case == UseCase.FILE_ENCRYPTION
        assert constraints.needs_kem is True
        assert constraints.needs_signature is False

    def test_rest_api_still_selects_api(self, parser: QueryParser) -> None:
        """"REST" outside "at rest" still selects the API use case."""
        assert parser.parse("REST service for partners").use_case == UseCase.API

    @pytest.mark.parametrize(
        "query",
        ["biotech research data", "patriot data archive", "test scenarios for a payroll service"],
    )
    def test_iot_and_ios_inside_other_words_select_no_platform(self, parser: QueryParser, query: str) -> None:
        """"iot" in "biotech" and "patriot" and "ios" in "scenarios" set no embedded or mobile platform."""
        constraints = parser.parse(query)
        assert constraints.platform is None
        assert constraints.is_embedded is False
        assert constraints.is_mobile is False
        assert constraints.min_security_level == SecurityLevel.LEVEL_3

    @pytest.mark.parametrize(
        ("query", "platform"),
        [("IIoT gateway firmware", Platform.EMBEDDED), ("iOS app", Platform.ARM64_NEON)],
    )
    def test_iiot_and_ios_select_their_platform(self, parser: QueryParser, query: str, platform: Platform) -> None:
        """IIoT selects the embedded platform and iOS the mobile one."""
        assert parser.parse(query).platform == platform

    @pytest.mark.parametrize("query", ["military intelligence", "intelligent document processing"])
    def test_intel_inside_other_words_selects_no_platform(self, parser: QueryParser, query: str) -> None:
        """"intel" in "intelligence" and "intelligent" sets no x86_64 platform."""
        assert parser.parse(query).platform is None

    @pytest.mark.parametrize("query", ["Intel NUC", "Intel-based laptop", "Intel Xeon server"])
    def test_intel_selects_x86_64(self, parser: QueryParser, query: str) -> None:
        """"Intel" as a word still selects the x86_64 AVX2 platform."""
        assert parser.parse(query).platform == Platform.X86_64_AVX2

    @pytest.mark.parametrize(
        "query",
        [
            "non-military drone telemetry",
            "military history blog",
            "military spouse support app",
            "non-classified email",
            "non national security workload",
            "US military",
            "non-military email system",
            "military tech ecosystem",
        ],
    )
    def test_negated_and_non_system_military_terms_do_not_select_cnsa(self, parser: QueryParser, query: str) -> None:
        """Negated CNSA 2.0 terms and "military" that names no system keep the Level 3 floor."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 not in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_3

    @pytest.mark.parametrize(
        "query",
        [
            "military communications system",
            "military drone telemetry",
            "classified email",
            "military email system",
            "military ground station",
            "military secure communications",
        ],
    )
    def test_military_systems_and_classified_data_select_cnsa(self, parser: QueryParser, query: str) -> None:
        """A military system or classified data still selects CNSA 2.0 and the Level 5 floor."""
        constraints = parser.parse(query)
        assert ComplianceFramework.CNSA_2_0 in constraints.compliance_frameworks
        assert constraints.min_security_level == SecurityLevel.LEVEL_5

    @pytest.mark.parametrize(
        "query", ["health check endpoint", "healthcheck endpoint", "health-checks for a worker pool"]
    )
    def test_health_check_does_not_select_hipaa(self, parser: QueryParser, query: str) -> None:
        """A service health check is not health data."""
        constraints = parser.parse(query)
        assert ComplianceFramework.HIPAA not in constraints.compliance_frameworks

    @pytest.mark.parametrize("query", ["healthcare", "health records storage", "health check for a healthcare portal"])
    def test_health_data_still_selects_hipaa(self, parser: QueryParser, query: str) -> None:
        """"healthcare" and "health records" still select HIPAA."""
        constraints = parser.parse(query)
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
