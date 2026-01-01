"""Tests for critical infrastructure sector module."""

from __future__ import annotations

import pytest

from pqc_bench.data.critical_infrastructure import (
    SECTOR_PROFILES,
    Sector,
    SectorProfile,
    MigrationUrgency,
    RegulatoryFramework,
    TechnicalConstraint,
    get_sector_profile,
    get_all_sectors,
    get_critical_sectors,
    detect_sector_from_query,
    get_sector_recommendation,
    get_compliance_deadlines,
)


class TestSectorProfiles:
    """Tests for sector profile data."""

    def test_all_sectors_defined(self) -> None:
        """All 7 critical infrastructure sectors are defined."""
        assert len(SECTOR_PROFILES) == 7
        expected = {
            "space_aerospace",
            "automotive",
            "industrial_ot",
            "energy_utilities",
            "healthcare",
            "financial",
            "telecommunications",
        }
        assert set(SECTOR_PROFILES.keys()) == expected

    def test_sector_profile_structure(self) -> None:
        """Each sector has required fields."""
        for sector_id, profile in SECTOR_PROFILES.items():
            assert isinstance(profile, SectorProfile)
            assert profile.id == sector_id
            assert profile.name
            assert profile.description
            assert isinstance(profile.urgency, MigrationUrgency)
            assert profile.sndl_risk in ("extreme", "high", "medium", "low")
            assert profile.data_lifespan_years > 0
            assert profile.equipment_lifecycle_years > 0
            assert len(profile.regulations) > 0
            assert len(profile.constraints) > 0
            assert profile.recommended_kem
            assert profile.recommended_sig

    def test_space_sector_is_critical(self) -> None:
        """Space sector has correct urgency and constraints."""
        space = SECTOR_PROFILES["space_aerospace"]
        assert space.urgency == MigrationUrgency.CRITICAL
        assert space.sndl_risk == "extreme"
        assert space.data_lifespan_years >= 50
        # Check for no-software-updates constraint
        blocking_constraints = [c for c in space.constraints if c.severity == "blocking"]
        assert len(blocking_constraints) > 0

    def test_automotive_v2x_latency_constraint(self) -> None:
        """Automotive sector includes V2X latency constraint."""
        auto = SECTOR_PROFILES["automotive"]
        constraint_names = [c.name for c in auto.constraints]
        assert "V2X latency requirement" in constraint_names

    def test_industrial_ot_lifecycle(self) -> None:
        """Industrial OT has 30-year equipment lifecycle."""
        ot = SECTOR_PROFILES["industrial_ot"]
        assert ot.equipment_lifecycle_years == 30

    def test_financial_has_deadlines(self) -> None:
        """Financial sector has explicit compliance deadlines."""
        fin = SECTOR_PROFILES["financial"]
        deadlines = [r.deadline for r in fin.regulations if r.deadline]
        assert len(deadlines) > 0
        # Should have DORA 2025 and NSM-10 2035
        assert any("2025" in d for d in deadlines)


class TestSectorLookup:
    """Tests for sector lookup functions."""

    def test_get_sector_profile_by_id(self) -> None:
        """Can retrieve sector by full ID."""
        profile = get_sector_profile("space_aerospace")
        assert profile is not None
        assert profile.name == "Space & Aerospace"

    def test_get_sector_profile_by_full_id(self) -> None:
        """Can retrieve sector by full ID."""
        profile = get_sector_profile("automotive")
        assert profile is not None
        assert profile.id == "automotive"

        profile = get_sector_profile("industrial_ot")
        assert profile is not None
        assert profile.id == "industrial_ot"

    def test_get_sector_profile_invalid(self) -> None:
        """Returns None for invalid sector."""
        profile = get_sector_profile("not_a_sector")
        assert profile is None

    def test_get_all_sectors(self) -> None:
        """Returns all sector profiles."""
        sectors = get_all_sectors()
        assert len(sectors) == 7

    def test_get_critical_sectors(self) -> None:
        """Returns only CRITICAL urgency sectors."""
        critical = get_critical_sectors()
        assert len(critical) >= 3  # space, healthcare, financial
        for sector in critical:
            assert sector.urgency == MigrationUrgency.CRITICAL


class TestSectorDetection:
    """Tests for detecting sectors from queries."""

    @pytest.mark.parametrize(
        "query,expected_sector",
        [
            ("satellite communication encryption", "space_aerospace"),
            ("spacecraft telemetry protection", "space_aerospace"),
            ("NASA ground station security", "space_aerospace"),
            ("V2X vehicle-to-everything security", "automotive"),
            ("automotive ECU signing", "automotive"),
            ("telematics gateway protection", "automotive"),
            ("SCADA system protection", "industrial_ot"),
            ("PLC authentication for factory", "industrial_ot"),
            ("modbus industrial protocol security", "industrial_ot"),
            ("smart grid encryption", "energy_utilities"),
            ("power grid NERC CIP compliance", "energy_utilities"),
            ("hospital HIPAA encryption", "healthcare"),
            ("patient health record protection", "healthcare"),
            ("SWIFT banking network security", "financial"),
            ("banking transaction signing", "financial"),
            ("stock exchange trading encryption", "financial"),
            ("5G mobile network security", "telecommunications"),
            ("SIM authentication quantum-safe", "telecommunications"),
        ],
    )
    def test_detect_sector_from_query(self, query: str, expected_sector: str) -> None:
        """Correctly detects sector from domain-specific queries."""
        detected = detect_sector_from_query(query)
        assert detected is not None, f"Failed to detect sector for: {query}"
        assert detected.id == expected_sector

    def test_detect_sector_no_match(self) -> None:
        """Returns None for generic queries."""
        detected = detect_sector_from_query("general encryption algorithm")
        assert detected is None


class TestSectorRecommendations:
    """Tests for sector-specific recommendations."""

    def test_get_sector_recommendation_space(self) -> None:
        """Space sector gets appropriate recommendations."""
        rec = get_sector_recommendation("space_aerospace")
        assert rec is not None
        assert "ML-KEM-1024" in rec["kem"]
        assert "ML-DSA-87" in rec["signature"]
        assert rec["urgency"] == "critical"
        assert rec["sndl_risk"] == "extreme"

    def test_get_sector_recommendation_automotive(self) -> None:
        """Automotive sector gets smaller algorithm variants."""
        rec = get_sector_recommendation("automotive")
        assert rec is not None
        # Should recommend smaller variants for constrained ECUs
        assert "ML-KEM-512" in rec["kem"] or "ML-KEM-768" in rec["kem"]

    def test_get_sector_recommendation_invalid(self) -> None:
        """Returns empty dict for invalid sector."""
        rec = get_sector_recommendation("invalid")
        assert rec == {}


class TestComplianceDeadlines:
    """Tests for compliance deadline functionality."""

    def test_get_compliance_deadlines(self) -> None:
        """Returns deadlines sorted by date."""
        deadlines = get_compliance_deadlines()
        assert len(deadlines) > 0

        # Check structure - returns list of (sector_name, framework, deadline) tuples
        for deadline in deadlines:
            assert len(deadline) == 3
            sector_name, framework, date = deadline
            assert isinstance(sector_name, str)
            assert isinstance(framework, str)
            assert isinstance(date, str)

    def test_deadlines_are_sorted(self) -> None:
        """Deadlines are returned in chronological order."""
        deadlines = get_compliance_deadlines()
        dates = [d[2] for d in deadlines]  # Third element is deadline
        # Should be sorted (note: string sort works for YYYY format)
        assert dates == sorted(dates)


class TestRegulatoryFramework:
    """Tests for regulatory framework data."""

    def test_cnsa_2_in_space(self) -> None:
        """CNSA 2.0 is listed for space sector."""
        space = SECTOR_PROFILES["space_aerospace"]
        framework_names = [r.name for r in space.regulations]
        assert "CNSA 2.0" in framework_names

    def test_iec_62443_in_industrial(self) -> None:
        """IEC 62443 is listed for industrial OT."""
        ot = SECTOR_PROFILES["industrial_ot"]
        framework_names = [r.name for r in ot.regulations]
        assert "IEC 62443" in framework_names

    def test_nerc_cip_in_energy(self) -> None:
        """NERC CIP is listed for energy sector."""
        energy = SECTOR_PROFILES["energy_utilities"]
        framework_names = [r.name for r in energy.regulations]
        assert "NERC CIP" in framework_names


class TestTechnicalConstraints:
    """Tests for technical constraint data."""

    def test_constraint_severity_levels(self) -> None:
        """All constraints have valid severity levels."""
        valid_severities = {"blocking", "major", "minor"}
        for profile in SECTOR_PROFILES.values():
            for constraint in profile.constraints:
                assert constraint.severity in valid_severities

    def test_blocking_constraints_have_impact(self) -> None:
        """Blocking constraints include impact description."""
        for profile in SECTOR_PROFILES.values():
            for constraint in profile.constraints:
                if constraint.severity == "blocking":
                    assert constraint.impact, f"Missing impact for {constraint.name}"
