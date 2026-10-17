"""Tests for CLI output formats."""

import json
import re
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pqc_bench import cli
from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.parser import QueryParser
from pqc_bench.output.terminal import TerminalOutput


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
    "query",
    [
        "encrypt non-military classified data",
        "non-military classified system",
        "non-military nsa network",
    ],
)
def test_recommend_json_keeps_cnsa_for_a_cnsa_term_after_non_military(query: str) -> None:
    """A CNSA 2.0 term between "non-military" and a system word still selects CNSA 2.0."""
    result = CliRunner().invoke(cli.app, ["recommend", query, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["compliance_frameworks"] == ["cnsa_2_0"]
    assert data["constraints"]["min_security_level"] == 5


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


KEM_SECTION = "Key Encapsulation (KEM):"
SIGNATURE_SECTION = "Digital Signatures:"


def test_compliance_use_case_tls_changes_the_page() -> None:
    """--use-case tls says what it shows, so the page differs from the unfiltered one."""
    unfiltered = CliRunner().invoke(cli.app, ["compliance", "fips-140-3"])
    filtered = CliRunner().invoke(cli.app, ["compliance", "fips-140-3", "--use-case", "tls"])
    assert unfiltered.exit_code == 0
    assert filtered.exit_code == 0
    assert filtered.output != unfiltered.output
    assert "Showing requirements for: tls (key establishment and signatures)" in filtered.output
    assert KEM_SECTION in filtered.output
    assert SIGNATURE_SECTION in filtered.output


@pytest.mark.parametrize(
    ("use_case", "shown", "hidden"),
    [
        ("jwt", SIGNATURE_SECTION, KEM_SECTION),
        ("JWT", SIGNATURE_SECTION, KEM_SECTION),
        ("file-encryption", KEM_SECTION, SIGNATURE_SECTION),
        ("file_encryption", KEM_SECTION, SIGNATURE_SECTION),
        ("signatures", SIGNATURE_SECTION, KEM_SECTION),
        ("kem", KEM_SECTION, SIGNATURE_SECTION),
        ("key-exchange", KEM_SECTION, SIGNATURE_SECTION),
    ],
)
def test_compliance_use_case_shows_only_the_algorithms_it_needs(
    use_case: str, shown: str, hidden: str
) -> None:
    """A signature-only use case hides the KEM list; a KEM-only use case hides the signature list."""
    result = CliRunner().invoke(cli.app, ["compliance", "fips-140-3", "--use-case", use_case])
    assert result.exit_code == 0
    assert shown in result.output
    assert hidden not in result.output
    assert "Minimum Security Level:" in result.output
    assert "References" in result.output


def test_compliance_use_case_jwt_lists_no_kem_algorithm() -> None:
    """The FIPS 140-3 page for jwt names no ML-KEM parameter set."""
    result = CliRunner().invoke(cli.app, ["compliance", "fips-140-3", "--use-case", "jwt"])
    assert result.exit_code == 0
    assert "ML-KEM" not in result.output
    assert "ML-DSA-44" in result.output


def test_compliance_use_case_signatures_runs_for_cnsa() -> None:
    """The user guide example `compliance cnsa-2.0 --use-case signatures` exits 0."""
    result = CliRunner().invoke(cli.app, ["compliance", "cnsa-2.0", "--use-case", "signatures"])
    assert result.exit_code == 0
    assert "Showing requirements for: signatures (signatures only)" in result.output
    assert "ML-DSA-87" in result.output
    assert KEM_SECTION not in result.output


def test_compliance_unknown_use_case_exits_1_and_lists_accepted_values() -> None:
    """An unknown use case is an error that names the values the option accepts."""
    result = CliRunner().invoke(cli.app, ["compliance", "fips-140-3", "--use-case", "bogus"])
    assert result.exit_code == 1
    assert "Unknown use case: bogus" in result.output
    assert "tls" in result.output
    assert "file-encryption" in result.output
    assert "signatures" in result.output
    assert "Algorithm Requirements" not in result.output


def test_user_guide_names_every_accepted_compliance_use_case() -> None:
    """The user guide sentence on --use-case lists exactly the values the option accepts."""
    guide = (Path(__file__).parent.parent / "docs" / "USER_GUIDE.md").read_text()
    sentence = next(line for line in guide.splitlines() if line.startswith("`--use-case` shows"))
    named = re.findall(r"`([a-z-]+)`", sentence.split("It accepts", 1)[1])
    assert named == list(cli.COMPLIANCE_USE_CASES)


@pytest.mark.parametrize(
    ("args", "value", "exit_code"),
    [
        (["explain", "[/bold]"], "[/bold]", 1),
        (["explain", "[bold]x[/bold]"], "[bold]x[/bold]", 1),
        (["compare", "[/bold]", "ml-kem-768"], "[/bold]", 1),
        (["compare", "ml-kem-768", "[/bold]"], "[/bold]", 1),
        (["migrate", "--from", "[/red]"], "[/red]", 1),
        (["compliance", "[red]zzz[/red]"], "[red]zzz[/red]", 1),
        (["libraries", "--algorithm", "[/bold]"], "[/bold]", 0),
        (["threat", "--urgency", "[/red]"], "[/red]", 1),
        (["threat", "--data-type", "[/red]"], "[/red]", 1),
        (["impact", "[/bold]"], "[/bold]", 1),
        (["sector", "[/red]"], "[/red]", 1),
    ],
)
def test_a_value_with_square_brackets_is_shown_as_typed_and_does_not_crash(
    monkeypatch: pytest.MonkeyPatch, args: list[str], value: str, exit_code: int
) -> None:
    """An unknown value that holds square brackets is printed exactly as typed."""
    monkeypatch.setattr(cli, "console", Console(width=200))
    result = CliRunner().invoke(cli.app, args)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert value in result.output
    assert result.exit_code == exit_code


def _sector_baseline_notes(notes: list[str]) -> list[str]:
    return [note for note in notes if note.startswith("Sector baseline")]


@pytest.mark.parametrize("verbose", [False, True])
def test_recommend_names_the_healthcare_sector_baseline(
    monkeypatch: pytest.MonkeyPatch, verbose: bool
) -> None:
    """Both text modes name the level that sector and threat give for healthcare data."""
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=200)))
    args = ["recommend", "file encryption for healthcare"] + (["--verbose"] if verbose else [])
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0
    output = " ".join(result.output.split())
    assert "Sector baseline" in output
    assert "ML-KEM-768" in output
    assert "pqc-bench sector healthcare" in output
    assert "pqc-bench threat --data-type healthcare_records" in output


def test_recommend_json_has_the_healthcare_sector_baseline_note() -> None:
    """The JSON notes say why rank 1 differs from the healthcare baseline."""
    result = CliRunner().invoke(
        cli.app, ["recommend", "file encryption for healthcare", "--json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["compliance_frameworks"] == ["hipaa"]
    assert data["recommendations"][0]["algorithm_id"] == "ml-kem-1024"
    notes = _sector_baseline_notes(data["notes"])
    assert len(notes) == 1
    assert "ML-KEM-768 (KEM) and ML-DSA-65 (signature)" in notes[0]
    assert "pqc-bench sector healthcare" in notes[0]
    assert "pqc-bench threat --data-type healthcare_records" in notes[0]
    assert "HIPAA" in notes[0]
    assert "Level 3" in notes[0]


def test_recommend_json_has_no_sector_baseline_note_without_a_framework() -> None:
    result = CliRunner().invoke(cli.app, ["recommend", "TLS for a web server", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["compliance_frameworks"] == []
    assert _sector_baseline_notes(data["notes"]) == []


@pytest.mark.parametrize(
    "args",
    [
        ["sector", "healthcare"],
        ["threat", "--data-type", "healthcare_records"],
    ],
)
def test_commands_named_in_the_healthcare_baseline_note_run(args: list[str]) -> None:
    """Each command the note cites runs and prints the baseline KEM it names."""
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0
    assert "ML-KEM-768" in result.output


def _recommend_text(monkeypatch: pytest.MonkeyPatch, *args: str) -> str:
    """Run recommend in text mode on a 100-column console and return its output."""
    console = Console(width=100)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli.terminal, "console", console)
    result = CliRunner().invoke(cli.app, ["recommend", *args])
    assert result.exit_code == 0
    return result.output


@pytest.mark.parametrize("mode", [[], ["--verbose"]])
def test_recommend_text_shows_every_top_rank_before_the_alternatives(
    monkeypatch: pytest.MonkeyPatch, mode: list[str]
) -> None:
    """The default --top 3 shows ranks 1, 2 and 3, then rank 4 under Alternatives."""
    output = _recommend_text(monkeypatch, "mobile banking app", *mode)
    for rank in ("#1", "#2", "#3"):
        assert rank in output
        assert output.index(rank) < output.index("Alternatives")
    assert output.index("#4") > output.index("Alternatives")


def test_recommend_text_top_1_lists_the_next_ranks_as_alternatives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--top 1 shows the panel, then ranks 2 and 3 under Alternatives."""
    output = _recommend_text(monkeypatch, "mobile banking app", "--top", "1")
    assert "#1" in output
    assert output.index("#2") > output.index("Alternatives")
    assert output.index("#3") > output.index("Alternatives")
    assert "#4" not in output


def test_recommend_top_above_the_candidate_count_recommends_every_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--top 99 recommends every candidate with contiguous ranks and leaves no alternatives."""
    query = "mobile banking app"
    result = CliRunner().invoke(cli.app, ["recommend", query, "--top", "99", "--json"])
    assert result.exit_code == 0
    ranks = [rec["rank"] for rec in json.loads(result.output)["recommendations"]]
    assert ranks == list(range(1, len(ranks) + 1))

    engine_result = RecommendationEngine().recommend(
        QueryParser().parse(query), query=query, top_n=99
    )
    assert len(engine_result.recommendations) == len(ranks)
    assert engine_result.alternatives == []

    output = _recommend_text(monkeypatch, query, "--top", "99")
    assert "Alternatives" not in output
    for rank in ranks:
        assert f"#{rank} " in output


@pytest.mark.parametrize("top", ["0", "-1"])
def test_recommend_rejects_a_top_below_1(top: str) -> None:
    """--top 0 and --top -1 are usage errors that name the option."""
    result = CliRunner().invoke(cli.app, ["recommend", "x", "--top", top])
    assert result.exit_code == 2
    assert "--top" in result.output


@pytest.mark.parametrize("mode", [[], ["--top", "1"]])
def test_recommend_text_brief_lines_do_not_end_in_a_dash(
    monkeypatch: pytest.MonkeyPatch, mode: list[str]
) -> None:
    """A ranked line with no warning ends after its score."""
    output = _recommend_text(monkeypatch, "mobile banking app", *mode)
    assert re.search(r"\(Score: \d+\)", output)
    assert not re.search(r"\(Score: \d+\) -\s*$", output, re.MULTILINE)
