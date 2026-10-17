"""
Crosswalk from compliance frameworks to sector and data profiles.

`recommend` ranks algorithms against a framework's minimum security level,
while `sector` and `threat` give one baseline for a sector and a kind of data.
This table links a framework to the sector and data profile that describe the
same data, so `recommend` can name that baseline when its top pick differs.

A framework has a row only when both a sector profile and a data profile plainly
cover it. CNSA 2.0 has no row: its data profile ("national_security") has no
matching sector profile.
"""

from .compliance import get_framework

# Framework ID (COMPLIANCE_FRAMEWORKS) -> (sector ID, data profile ID)
FRAMEWORK_CROSSWALK: dict[str, tuple[str, str]] = {
    "hipaa": ("healthcare", "healthcare_records"),
    "pci_dss_4": ("financial", "transactional_data"),
}


def get_crosswalk(framework_id: str) -> tuple[str, str] | None:
    """Get the (sector ID, data profile ID) for a framework ID or alias."""
    framework = get_framework(framework_id)
    if framework is None:
        return None
    return FRAMEWORK_CROSSWALK.get(framework.id)
