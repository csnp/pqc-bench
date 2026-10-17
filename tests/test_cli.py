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
