"""Tests for CLI output formats."""

import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pqc_bench import cli


@pytest.mark.parametrize(
    "query",
    [
        "TLS for a web server",
        "CNSA 2.0 embedded sensor with 256KB RAM",
    ],
)
def test_recommend_json_is_valid_on_a_narrow_console(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    """--json writes a parseable document even when its lines are wider than the console."""
    monkeypatch.setattr(cli, "console", Console(width=40))
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["query"] == query
    assert data["recommendations"]


@pytest.mark.parametrize(
    "query",
    [
        "top-secret documents",
        "CNSA2.0 compliant VPN",
        "military communications system",
        "military email system",
        "military ground station",
        "military secure communications",
    ],
)
def test_recommend_json_selects_cnsa_for_hyphenated_joined_and_military_terms(
    query: str,
) -> None:
    """These queries require CNSA 2.0 and recommend only its Level 5 algorithms."""
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["compliance_frameworks"] == ["cnsa_2_0"]
    assert data["constraints"]["min_security_level"] == 5
    recommended = {rec["algorithm_id"] for rec in data["recommendations"]}
    assert recommended
    assert recommended <= {"ml-kem-1024", "ml-dsa-87"}


def test_recommend_json_ignores_short_keywords_inside_other_words() -> None:
    """"phi" in "graphics" and "ca" in "local cache" select neither HIPAA nor certificates."""
    runner = CliRunner()

    result = runner.invoke(cli.app, ["recommend", "graphics rendering service", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["constraints"]["compliance_frameworks"] == []

    result = runner.invoke(cli.app, ["recommend", "local cache encryption", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["use_case"] != "certificate"
    assert data["constraints"]["needs_kem"] is True
    assert data["recommendations"]
    assert all(rec["type"] == "kem" for rec in data["recommendations"])


@pytest.mark.parametrize(
    "query",
    [
        "non-military drone telemetry",
        "military history blog",
        "military spouse support app",
        "non-classified email",
        "US military",
    ],
)
def test_recommend_json_keeps_level_3_for_negated_and_non_system_military_terms(query: str) -> None:
    """These queries select no CNSA 2.0 and keep Level 3 options such as ML-KEM-768."""
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["compliance_frameworks"] == []
    assert data["constraints"]["min_security_level"] == 3
    assert "ml-kem-768" in {rec["algorithm_id"] for rec in data["recommendations"]}


@pytest.mark.parametrize(
    ("query", "use_case", "algorithm_type"),
    [
        ("encrypt data at rest", "file_encryption", "kem"),
        ("data at rest encryption for a database", "file_encryption", "kem"),
        ("data-at-rest encryption", "file_encryption", "kem"),
        ("DHE key agreement", "key_exchange", "kem"),
        ("rootCA rotation", "certificate", "signature"),
    ],
)
def test_recommend_json_selects_the_use_case_and_algorithm_type(
    query: str, use_case: str, algorithm_type: str
) -> None:
    """Data at rest gets KEMs, DHE gets KEMs and rootCA gets signature algorithms."""
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["use_case"] == use_case
    assert data["recommendations"]
    assert all(rec["type"] == algorithm_type for rec in data["recommendations"])


@pytest.mark.parametrize(
    ("query", "platform"),
    [
        ("military intelligence", None),
        ("intelligent document processing", None),
        ("Intel Xeon server", "x86_64_avx2"),
    ],
)
def test_recommend_json_matches_intel_only_as_a_word(query: str, platform: str | None) -> None:
    """"intelligence" and "intelligent" set no platform; "Intel" selects x86_64 AVX2."""
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["constraints"]["platform"] == platform
