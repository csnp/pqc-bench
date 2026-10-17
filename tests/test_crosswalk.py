"""Tests for the compliance framework to sector and data profile crosswalk."""

from __future__ import annotations

import pytest

from pqc_bench.data.algorithms import ALGORITHMS
from pqc_bench.data.compliance import COMPLIANCE_FRAMEWORKS
from pqc_bench.data.critical_infrastructure import SECTOR_PROFILES
from pqc_bench.data.crosswalk import FRAMEWORK_CROSSWALK, get_crosswalk
from pqc_bench.data.threat_model import DATA_PROFILES, assess_sndl_risk


def test_hipaa_maps_to_healthcare() -> None:
    assert FRAMEWORK_CROSSWALK["hipaa"] == ("healthcare", "healthcare_records")


@pytest.mark.parametrize(("framework_id", "row"), sorted(FRAMEWORK_CROSSWALK.items()))
def test_every_id_exists_in_its_source_table(
    framework_id: str, row: tuple[str, str]
) -> None:
    sector_id, data_profile_id = row
    assert framework_id in COMPLIANCE_FRAMEWORKS
    assert sector_id in SECTOR_PROFILES
    assert data_profile_id in DATA_PROFILES


@pytest.mark.parametrize(("framework_id", "row"), sorted(FRAMEWORK_CROSSWALK.items()))
def test_sector_baseline_names_are_known_algorithms(
    framework_id: str, row: tuple[str, str]
) -> None:
    """The recommend note compares by NIST name, so each baseline must be in ALGORITHMS."""
    sector = SECTOR_PROFILES[row[0]]
    names = {algo.names.nist_name for algo in ALGORITHMS.values()}
    assert sector.recommended_kem in names
    assert sector.recommended_sig in names


@pytest.mark.parametrize(("framework_id", "row"), sorted(FRAMEWORK_CROSSWALK.items()))
def test_sector_and_threat_give_the_same_kem(framework_id: str, row: tuple[str, str]) -> None:
    """The note cites both commands as one baseline, so they must agree on the KEM."""
    sector_id, data_profile_id = row
    assessment = assess_sndl_risk(data_profile_id)
    assert assessment is not None
    assert assessment.recommended_algorithm == SECTOR_PROFILES[sector_id].recommended_kem


@pytest.mark.parametrize(
    ("framework_id", "expected"),
    [
        ("hipaa", ("healthcare", "healthcare_records")),
        ("pci_dss", ("financial", "transactional_data")),
        ("pci-dss", ("financial", "transactional_data")),
        ("fips_140_3", None),
        ("soc2", None),
        ("unknown", None),
    ],
)
def test_get_crosswalk_accepts_ids_and_aliases(
    framework_id: str, expected: tuple[str, str] | None
) -> None:
    assert get_crosswalk(framework_id) == expected
