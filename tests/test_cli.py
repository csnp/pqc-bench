"""Tests for CLI output formats."""

import inspect
import io
import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import get_args, get_type_hints

import pytest
import typer
import typer.core
import typer.main
from rich.console import Console
from typer.testing import CliRunner

from pqc_bench import __version__, cli
from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.parser import QueryParser
from pqc_bench.data import threat_model
from pqc_bench.data.algorithms import ALGORITHMS
from pqc_bench.data.critical_infrastructure import SECTOR_PROFILES
from pqc_bench.data.libraries import (
    HYBRID_KEM_USE_CASE_WORDS,
    HYBRID_MODES,
    HYBRID_SIGNATURE_USE_CASE_WORDS,
)
from pqc_bench.data.threat_model import ThreatUrgency, get_profiles_by_urgency
from pqc_bench.output.terminal import TerminalOutput, print_rule


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
    monkeypatch.setattr(cli, "console", Console(width=40, force_terminal=False))
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
    monkeypatch.setattr(cli, "console", Console(width=200, force_terminal=False))
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
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=200, force_terminal=False)))
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
    console = Console(width=100, force_terminal=False)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli.terminal, "console", console)
    result = CliRunner().invoke(cli.app, ["recommend", *args])
    assert result.exit_code == 0
    return result.output


def _level_3_default_notes(notes: list[str]) -> list[str]:
    return [note for note in notes if note.startswith("Level 3 default:")]


@pytest.mark.parametrize("mode", [[], ["--verbose"]])
def test_recommend_text_names_the_level_3_default(
    monkeypatch: pytest.MonkeyPatch, mode: list[str]
) -> None:
    """Both text modes say which Level 3 default the Level 5 pick ranks above."""
    output = " ".join(_recommend_text(monkeypatch, "TLS for a web server", *mode).split())
    assert "Level 3 default: ML-KEM-768 (KEM) and ML-DSA-65 (signature)" in output
    assert "ML-KEM-1024 ranks above ML-KEM-768 here" in output
    assert "ML-DSA-87 ranks above ML-DSA-65 here" in output


def test_recommend_json_has_one_level_3_default_note_and_the_same_ranking() -> None:
    result = CliRunner().invoke(cli.app, ["recommend", "TLS for a web server", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(_level_3_default_notes(data["notes"])) == 1
    assert [rec["algorithm_id"] for rec in data["recommendations"]] == [
        "ml-kem-1024",
        "ml-dsa-87",
        "ml-kem-768",
    ]


def test_commands_named_in_the_level_3_default_note_run() -> None:
    """Each command the note cites runs and shows the default it names."""
    query = "TLS for a web server"
    result = RecommendationEngine().recommend(QueryParser().parse(query), query=query)
    notes = _level_3_default_notes(result.notes)
    assert len(notes) == 1
    commands = re.findall(r"'(pqc-bench [^']+)'", notes[0])
    assert commands == ["pqc-bench explain ml-kem-768", "pqc-bench explain ml-dsa-65"]
    for command in commands:
        run = CliRunner().invoke(cli.app, command.split()[1:])
        assert run.exit_code == 0, command
        assert "Level 3 default" in " ".join(run.output.split()), command


def _explain_notes(algorithm_id: str) -> str:
    """The Notes section of `explain <algorithm_id>`, with whitespace collapsed."""
    result = CliRunner().invoke(cli.app, ["explain", algorithm_id])
    assert result.exit_code == 0
    notes = result.output.split("\nNotes\n", 1)[1].split("\nReferences\n", 1)[0]
    return " ".join(notes.split())


@pytest.mark.parametrize(
    ("algorithm_id", "ranked_above"),
    [("ml-kem-768", "ML-KEM-1024"), ("ml-dsa-65", "ML-DSA-87")],
)
def test_explain_says_which_algorithm_recommend_ranks_above_the_default(
    algorithm_id: str, ranked_above: str
) -> None:
    notes = _explain_notes(algorithm_id)
    assert "Level 3 default" in notes
    assert "Recommended default" not in notes
    assert f"ranks {ranked_above} above it" in notes


def test_explain_ml_dsa_44_says_when_recommend_lists_it() -> None:
    """ML-DSA-44 is not offered as the JWT choice; its note says when recommend lists it."""
    notes = _explain_notes("ml-dsa-44")
    assert "JWT, API auth" not in notes
    assert "Level 3" in notes
    assert "Smallest ML-DSA variant" in notes
    assert "Fastest verification in ML-DSA family" in notes


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


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# Rich renders the usage error in colour whenever FORCE_COLOR is set and TERM is not dumb,
# which is what the GitHub Actions runners do.
COLOUR_FORCED = {"FORCE_COLOR": "1", "NO_COLOR": None, "TERM": "xterm-256color"}


def _without_ansi(text: str) -> str:
    """Return the text with every ANSI escape sequence removed."""
    return ANSI_ESCAPE.sub("", text)


@pytest.mark.parametrize("top", ["0", "-1"])
@pytest.mark.parametrize("env", [{}, COLOUR_FORCED], ids=["plain", "colour"])
def test_recommend_rejects_a_top_below_1(top: str, env: dict[str, str | None]) -> None:
    """--top 0 and --top -1 are usage errors that name the option, with the error plain or coloured."""
    result = CliRunner().invoke(cli.app, ["recommend", "x", "--top", top], env=env)
    assert result.exit_code == 2
    if env:
        assert "\x1b[" in result.output
    assert "--top" in _without_ansi(result.output)


@pytest.mark.parametrize("mode", [[], ["--top", "1"]])
def test_recommend_text_brief_lines_do_not_end_in_a_dash(
    monkeypatch: pytest.MonkeyPatch, mode: list[str]
) -> None:
    """A ranked line with no warning ends after its score."""
    output = _recommend_text(monkeypatch, "mobile banking app", *mode)
    assert re.search(r"\(Score: \d+\)", output)
    assert not re.search(r"\(Score: \d+\) -\s*$", output, re.MULTILINE)


NO_REQUIREMENT = "No requirement was recognised in your query"
UNRECOGNISED_QUERY = "zzzz qqqq nothing matches"


def test_recommend_says_first_that_no_requirement_was_recognised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defaults note is printed before the recommendation panel."""
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=100, force_terminal=False)))
    result = CliRunner().invoke(cli.app, ["recommend", UNRECOGNISED_QUERY])
    assert result.exit_code == 0
    assert NO_REQUIREMENT in result.output
    assert 'pqc-bench recommend "TLS for a web server"' in result.output
    assert result.output.index(NO_REQUIREMENT) < result.output.index("╭")
    assert "Limited constraints provided" not in result.output


def test_recommend_verbose_states_the_defaults_in_the_query_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Query Analysis names the defaults instead of being blank, and the note is printed once."""
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=100, force_terminal=False)))
    result = CliRunner().invoke(cli.app, ["recommend", UNRECOGNISED_QUERY, "--verbose"])
    assert result.exit_code == 0
    analysis = result.output.split("Query Analysis", 1)[1].split("╭", 1)[0]
    assert "Nothing recognised; defaults applied: NIST standardized, Level 3 or higher" in analysis
    assert result.output.count(NO_REQUIREMENT) == 1
    assert result.output.index(NO_REQUIREMENT) < result.output.index("╭")
    assert "Limited constraints provided" not in result.output


def test_recommend_json_reports_no_matched_terms_and_the_defaults_note() -> None:
    result = CliRunner().invoke(cli.app, ["recommend", UNRECOGNISED_QUERY, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["constraints"]["matched_terms"] == []
    assert data["notes"][0].startswith(NO_REQUIREMENT)
    assert not any("Limited constraints provided" in note for note in data["notes"])


def test_recommend_json_lists_the_matched_terms_of_a_recognised_query() -> None:
    result = CliRunner().invoke(cli.app, ["recommend", "TLS for a web server", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "tls" in data["constraints"]["matched_terms"]
    assert not any(NO_REQUIREMENT in note for note in data["notes"])


@pytest.mark.parametrize("query", ["", "   "])
@pytest.mark.parametrize("extra", [[], ["--json"]])
def test_recommend_rejects_an_empty_query(query: str, extra: list[str]) -> None:
    """An empty or blank query is a usage error, and --json writes no document."""
    result = CliRunner().invoke(cli.app, ["recommend", query, *extra])
    assert result.exit_code == 2
    assert "{" not in result.stdout
    assert "empty" in result.output
    assert "TLS for a web server" in result.output


def _wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Print to a 200-column console so that no message is wrapped."""
    monkeypatch.setattr(cli, "console", Console(width=200, force_terminal=False))


@pytest.mark.parametrize("value", ["bogus", "kemx", "s", ""])
def test_list_unknown_type_exits_1_and_names_the_valid_types(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """An unknown --type names the valid types and exits 1 instead of printing an empty table."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["list", "--type", value])
    assert result.exit_code == 1
    assert f"Unknown algorithm type: {value}" in result.output
    assert "Valid types: kem, signature" in result.output
    assert "Available Algorithms" not in result.output


@pytest.mark.parametrize(
    ("value", "algorithm_type"),
    [("kem", "kem"), ("KEM", "kem"), ("kems", "kem"), ("signature", "signature"), ("Signatures", "signature")],
)
def test_list_type_shows_only_that_type(monkeypatch: pytest.MonkeyPatch, value: str, algorithm_type: str) -> None:
    """--type accepts either type in any case, singular or plural, and lists only its algorithms."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["list", "--type", value])
    assert result.exit_code == 0
    for algo_id, algo in ALGORITHMS.items():
        assert (f" {algo_id} " in result.output) == (algo.algorithm_type == algorithm_type), algo_id


@pytest.mark.parametrize("value", ["bogus", "kem", ""])
def test_hybrid_unknown_use_case_exits_1_and_lists_the_accepted_words(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """A use case that matches no use-case word lists the accepted words instead of one hybrid."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["hybrid", "--use-case", value])
    assert result.exit_code == 1
    assert f"Unknown use case: {value}" in result.output
    assert f"{', '.join(HYBRID_KEM_USE_CASE_WORDS)}: hybrid key exchange" in result.output
    assert f"{', '.join(HYBRID_SIGNATURE_USE_CASE_WORDS)}: hybrid signatures" in result.output
    assert "Hybrid Cryptography Modes" not in result.output


def _hybrid_sections(output: str) -> list[str]:
    """The names of the hybrid modes printed, each on a line of its own."""
    lines = output.splitlines()
    return [mode.name for mode in HYBRID_MODES.values() if mode.name in lines]


@pytest.mark.parametrize(
    ("use_case", "kind"), [("signature", "signature"), ("certificate", "signature"), ("tls", "kem")]
)
def test_hybrid_use_case_lists_the_hybrids_of_its_kind(
    monkeypatch: pytest.MonkeyPatch, use_case: str, kind: str
) -> None:
    """--use-case signature lists the composite signature hybrids, as certificate does."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["hybrid", "--use-case", use_case])
    assert result.exit_code == 0
    shown = _hybrid_sections(result.output)
    assert shown
    assert all(mode.kem_or_sig == kind for mode in HYBRID_MODES.values() if mode.name in shown)
    if kind == "signature":
        assert shown == [mode.name for mode in HYBRID_MODES.values() if mode.kem_or_sig == "signature"]


def test_hybrid_lists_tls_support_on_its_own_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """TLS is not named as a browser or CDN; each mode has a TLS support line of its own."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["hybrid"])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.splitlines()]
    browser_lines = [line for line in lines if line.startswith("Browser/CDN support:")]
    tls_lines = [line for line in lines if line.startswith("TLS support:")]
    assert len(browser_lines) == len(HYBRID_MODES)
    assert not any("TLS" in line for line in browser_lines)
    assert "Browser/CDN support: Chrome, Cloudflare" in browser_lines
    assert tls_lines == [
        f"TLS support: {'Yes' if mode.tls_support else 'Not yet'}" for mode in HYBRID_MODES.values()
    ]


@pytest.mark.parametrize(
    ("args", "value"),
    [(["list", "--type", "[/red]"], "[/red]"), (["hybrid", "--use-case", "[/bold]"], "[/bold]")],
)
def test_a_new_error_shows_a_value_with_square_brackets_as_typed(
    monkeypatch: pytest.MonkeyPatch, args: list[str], value: str
) -> None:
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 1
    assert value in result.output


def _cli_commands() -> dict[str, typer.core.TyperCommand]:
    """The commands of the CLI by name, as Typer builds them from the app.

    Typer 0.26.0 and later do not depend on the click package, so these tests read the commands
    through typer.core and the functions the commands run, and import nothing from click.
    """
    group = typer.main.get_command(cli.app)
    assert isinstance(group, typer.core.TyperGroup)
    commands: dict[str, typer.core.TyperCommand] = {}
    for name, command in group.commands.items():
        assert isinstance(command, typer.core.TyperCommand)
        commands[name] = command
    return commands


def _takes_text(command: typer.core.TyperCommand, parameter: str) -> bool:
    """Whether the function that ``command`` runs declares ``parameter`` as str, alone or in a union
    such as str | None."""
    assert command.callback is not None
    hint = get_type_hints(inspect.unwrap(command.callback))[parameter]
    return str in (hint, *get_args(hint))


CLI_COMMANDS = _cli_commands()

# Every text argument and option of every command, as (command, parameter name). The list is read
# from the CLI, so a command or an option added later is in it too.
TEXT_PARAMETERS = [
    (name, str(param.name))
    for name, command in CLI_COMMANDS.items()
    for param in command.params
    if _takes_text(command, str(param.name))
]

# An accepted value for each required parameter that a command needs besides the one under test.
ACCEPTED_VALUES = {
    ("compare", "algorithm1"): "ml-kem-768",
    ("compare", "algorithm2"): "ml-kem-512",
    ("compliance", "framework"): "fips-140-3",
}

# Values that name nothing the CLI knows, each with the way a message shows it: as typed when every
# character is printable, otherwise in quotes with each character that is not printable escaped.
UNKNOWN_VALUES = [
    pytest.param("[red]bogus[/red]", "[red]bogus[/red]", id="square brackets"),
    pytest.param(":warning:", ":warning:", id="emoji code"),
    pytest.param("bögus", "bögus", id="non-ASCII letter"),
    pytest.param("bogus\nextra", "'bogus\\nextra'", id="line break"),
    pytest.param("\x1b[31mbogus\x1b[0m", "'\\x1b[31mbogus\\x1b[0m'", id="escape sequence"),
    # Python passes on the byte 0xE9 of a command-line argument that is not valid UTF-8 as "\udce9".
    pytest.param("bogus\udce9", "'bogus\\udce9'", id="not UTF-8"),
    pytest.param("bogus\r", "'bogus\\r'", id="carriage return"),
    pytest.param("bogus\tvalue", "'bogus\\tvalue'", id="tab"),
    pytest.param("bogus\x9b", "'bogus\\x9b'", id="C1 control"),
    pytest.param("bogus\N{RIGHT-TO-LEFT OVERRIDE}", "'bogus\\u202e'", id="right-to-left override"),
    pytest.param("[/red]\n", "'[/red]\\n'", id="square brackets and line break"),
]


def _arguments(command: str, parameter: str, value: str) -> list[str]:
    """The arguments that run ``command`` with ``value`` for ``parameter``, an accepted value for
    each other required parameter, and no other parameter."""
    arguments = [command]
    for param in CLI_COMMANDS[command].params:
        if param.name == parameter:
            given = value
        elif param.required:
            given = ACCEPTED_VALUES[(command, str(param.name))]
        else:
            continue
        arguments += [given] if isinstance(param, typer.core.TyperArgument) else [param.opts[0], given]
    return arguments


def test_the_text_parameters_read_from_the_cli_include_those_of_today() -> None:
    """Reading TEXT_PARAMETERS, which the next test runs, from the CLI finds the text parameters it has today."""
    assert set(TEXT_PARAMETERS) >= {
        ("recommend", "query"),
        ("explain", "algorithm"),
        ("compare", "algorithm1"),
        ("compare", "algorithm2"),
        ("migrate", "from_algo"),
        ("compliance", "framework"),
        ("compliance", "use_case"),
        ("list", "algorithm_type"),
        ("libraries", "algorithm"),
        ("hybrid", "use_case"),
        ("threat", "data_type"),
        ("threat", "urgency"),
        ("impact", "algorithm"),
        ("sector", "sector_name"),
    }


@pytest.mark.parametrize(
    ("command", "parameter"), TEXT_PARAMETERS, ids=[" ".join(pair) for pair in TEXT_PARAMETERS]
)
@pytest.mark.parametrize(("value", "shown"), UNKNOWN_VALUES)
def test_an_unknown_value_is_shown_as_typed_or_escaped(
    monkeypatch: pytest.MonkeyPatch, command: str, parameter: str, value: str, shown: str
) -> None:
    """The output is the output for bogus with the value shown in place of bogus, and the exit code is the same.

    A line break or a control character in the value is written as an escape on the line of the
    message, a value that is not valid UTF-8 gives the message instead of a traceback, and square
    brackets and emoji codes are shown as typed.
    """
    _wide_console(monkeypatch)
    reference = CliRunner().invoke(cli.app, _arguments(command, parameter, "bogus"))
    result = CliRunner().invoke(cli.app, _arguments(command, parameter, value))
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == reference.exit_code
    assert result.output == reference.output.replace("bogus", shown)


def test_a_shown_value_is_one_line_of_printable_characters() -> None:
    """Each C0 and C1 control character, DEL, lone surrogate, line and paragraph separator and the
    right-to-left override is written as an escape, as repr writes it."""
    for code in [*range(0x20), 0x7F, *range(0x80, 0xA0), *range(0xD800, 0xE000), 0x2028, 0x2029, 0x202E]:
        value = f"bogus{chr(code)}"
        shown = cli._shown(value).plain
        assert shown == repr(value)
        assert shown.isprintable(), shown


@pytest.mark.parametrize(
    ("data_type", "label"), [("healthcare_records", "Secret"), ("national_security", "Top Secret")]
)
def test_threat_shows_the_classification_as_a_label(data_type: str, label: str) -> None:
    """The classification reads "Top Secret", not the stored value "top_secret"."""
    result = CliRunner().invoke(cli.app, ["threat", "--data-type", data_type])
    assert result.exit_code == 0
    assert f"Classification: {label}" in [line.strip() for line in result.output.splitlines()]
    assert "_" not in next(line for line in result.output.splitlines() if "Classification:" in line)


def _option_help(command: Callable[..., object], parameter: str) -> str:
    """The help text of a typer option, as declared on the command function."""
    option = inspect.signature(command).parameters[parameter].default
    return str(option.help)


def test_threat_urgency_help_and_error_list_the_same_levels(monkeypatch: pytest.MonkeyPatch) -> None:
    """--help and the error for an unknown level list every urgency level, in the same order."""
    help_match = re.fullmatch(r"Filter by urgency level \((.*)\)", _option_help(cli.threat, "urgency"))
    assert help_match is not None
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--urgency", "bogus"])
    assert result.exit_code == 1
    error_match = re.search(r"Valid levels: (.*)", result.output)
    assert error_match is not None
    levels = ", ".join(level.value for level in ThreatUrgency)
    assert help_match.group(1) == levels
    assert error_match.group(1).strip() == levels


@pytest.mark.parametrize("level", [level.value for level in ThreatUrgency])
def test_threat_accepts_every_listed_urgency_level(level: str) -> None:
    result = CliRunner().invoke(cli.app, ["threat", "--urgency", level])
    assert result.exit_code == 0


@pytest.mark.parametrize("level", list(ThreatUrgency), ids=lambda level: level.value)
def test_threat_urgency_lists_the_profiles_of_the_level_or_says_it_has_none(
    monkeypatch: pytest.MonkeyPatch, level: ThreatUrgency
) -> None:
    """Each level lists its profiles, or says that no profile has it and names the levels that do."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--urgency", level.value])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.splitlines()]
    profiles = get_profiles_by_urgency(level)
    if profiles:
        for profile in profiles:
            assert f"• {profile.name}" in lines
        assert not any(line.startswith("No data profile has") for line in lines)
    else:
        assert f"No data profile has {level.value.upper()} urgency." in lines
        levels = ", ".join(other.value for other in ThreatUrgency if get_profiles_by_urgency(other))
        assert f"Levels that have profiles: {levels}" in lines


def test_threat_urgency_with_no_profile_names_the_levels_that_have_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    """With only critical and low profiles, --urgency high says it has none and names critical and low."""
    _wide_console(monkeypatch)
    kept = {ThreatUrgency.CRITICAL, ThreatUrgency.LOW}
    monkeypatch.setattr(
        threat_model,
        "DATA_PROFILES",
        {key: profile for key, profile in threat_model.DATA_PROFILES.items() if profile.urgency in kept},
    )
    result = CliRunner().invoke(cli.app, ["threat", "--urgency", "high"])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.splitlines()]
    assert "No data profile has HIGH urgency." in lines
    assert "Levels that have profiles: critical, low" in lines
    assert "Action:" not in result.output


@pytest.mark.parametrize("chain_length", ["0", "-3"])
@pytest.mark.parametrize("env", [{}, COLOUR_FORCED], ids=["plain", "colour"])
def test_impact_rejects_a_chain_length_below_1(chain_length: str, env: dict[str, str | None]) -> None:
    """--chain-length 0 and -3 are usage errors that name the option, with no impact table."""
    result = CliRunner().invoke(cli.app, ["impact", "ml-dsa-65", "--chain-length", chain_length], env=env)
    assert result.exit_code == 2
    assert "--chain-length" in _without_ansi(result.output)
    assert "Chain (" not in result.output


def test_impact_accepts_a_chain_length_of_1() -> None:
    result = CliRunner().invoke(cli.app, ["impact", "ml-dsa-65", "--chain-length", "1"])
    assert result.exit_code == 0
    assert "Chain (1)" in result.output


HANDSHAKE_ROW = re.compile(r"(ClientHello|ServerHello|Total Handshake)\s+\+([\d,]+) bytes")


def _handshake_rows(output: str) -> list[tuple[str, str]]:
    """The ClientHello, ServerHello and Total Handshake figures in the output, in order."""
    return HANDSHAKE_ROW.findall(output)


def _migrate(monkeypatch: pytest.MonkeyPatch, from_algo: str) -> str:
    """Run migrate on a 200-column console and return its output."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["migrate", "--from", from_algo])
    assert result.exit_code == 0
    return result.output


def _impact_analysis(output: str) -> str:
    """The Impact Analysis section of migrate's output."""
    return output.split("Impact Analysis", 1)[1].split("Alternative", 1)[0]


def test_migrate_from_x25519_counts_the_handshake_in_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ClientHello and the ServerHello both grow, so the total is more than the ciphertext growth."""
    analysis = _impact_analysis(_migrate(monkeypatch, "x25519"))
    assert "TLS 1.3 handshake vs X25519, both directions" in analysis
    assert "+1,152" in analysis
    assert "+1,056" in analysis
    assert "2,208" in analysis
    assert _handshake_rows(analysis) == [
        ("ClientHello", "1,152"),
        ("ServerHello", "1,056"),
        ("Total Handshake", "2,208"),
    ]
    assert "~1,056 more bytes" not in analysis


def test_migrate_from_ecdh_p256_counts_the_handshake_against_its_own_key_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The figures use the 64-byte key share of migrate's ECDH P-256 row and are not labelled as X25519."""
    analysis = _impact_analysis(_migrate(monkeypatch, "ecdh-p256"))
    assert "TLS 1.3 handshake vs ECDH P-256, both directions" in analysis
    assert "2,144" in analysis
    assert _handshake_rows(analysis) == [
        ("ClientHello", "1,120"),
        ("ServerHello", "1,024"),
        ("Total Handshake", "2,144"),
    ]
    assert "X25519" not in analysis


def test_migrate_from_x25519_and_impact_give_the_same_handshake_figures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both commands describe the X25519 to ML-KEM-768 migration with the same three figures."""
    migrate_rows = _handshake_rows(_migrate(monkeypatch, "x25519"))
    impact = CliRunner().invoke(cli.app, ["impact", "ml-kem-768"])
    assert impact.exit_code == 0
    impact_rows = _handshake_rows(impact.output)
    assert [label for label, _ in impact_rows] == ["ClientHello", "ServerHello", "Total Handshake"]
    assert dict(migrate_rows).get("Total Handshake") == dict(impact_rows)["Total Handshake"]
    assert migrate_rows == impact_rows


@pytest.mark.parametrize(
    ("from_algo", "commands"),
    [
        ("x25519", ["pqc-bench impact ml-kem-768", "pqc-bench explain ml-kem-768"]),
        ("ecdh-p256", ["pqc-bench impact ml-kem-768", "pqc-bench explain ml-kem-768"]),
        ("rsa-2048", ["pqc-bench explain ml-dsa-65"]),
    ],
)
def test_commands_named_in_migrate_run(
    monkeypatch: pytest.MonkeyPatch, from_algo: str, commands: list[str]
) -> None:
    """Every pqc-bench command that migrate tells the reader to run exits 0."""
    output = _migrate(monkeypatch, from_algo)
    named = re.findall(r"\bRun (pqc-bench .+?) for ", output)
    assert named == commands
    assert output.count("pqc-bench ") == len(named)
    for command in named:
        result = CliRunner().invoke(cli.app, shlex.split(command)[1:])
        assert result.exit_code == 0, f"{command}\n{result.output}"


@pytest.mark.parametrize(("width", "printed"), [(80, 70), (70, 70), (60, 60), (20, 20)])
def test_print_rule_is_capped_at_the_console_width(width: int, printed: int) -> None:
    buffer = io.StringIO()
    print_rule(Console(file=buffer, width=width), "═", 70)
    assert buffer.getvalue() == "═" * printed + "\n"


RULE_LINE = re.compile(r"═+|─+")


@pytest.mark.parametrize("width", [30, 60])
@pytest.mark.parametrize(
    "args",
    [
        ["list"],
        ["compare", "ml-dsa-44", "falcon-512"],
        ["migrate", "--from", "rsa-2048"],
        ["compliance", "cnsa-2.0"],
        ["libraries"],
        ["hybrid"],
        ["threat", "--list"],
        ["threat", "--data-type", "healthcare_records"],
        ["impact", "ml-dsa-65"],
        ["impact", "ml-kem-768"],
        ["sector", "--list"],
        ["sector", "--deadlines"],
        ["sector", "space"],
        ["explain", "ml-kem-768"],
        ["recommend", "TLS for a web server", "--verbose"],
    ],
)
def test_rules_fit_a_narrow_console(monkeypatch: pytest.MonkeyPatch, width: int, args: list[str]) -> None:
    """Each rule prints as one line no wider than the console instead of wrapping onto a second line."""
    console = Console(width=width, force_terminal=False)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli, "terminal", TerminalOutput(console))
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0
    lines = result.output.splitlines()
    rules = [index for index, line in enumerate(lines) if RULE_LINE.fullmatch(line)]
    assert rules
    for index in rules:
        assert len(lines[index]) <= width
        assert index + 1 not in rules, f"the rule on line {index + 1} wrapped onto the next line"


@pytest.mark.parametrize("algorithm", ["falcon-512", "falcon-1024", "FN-DSA-512"])
def test_libraries_algorithm_lists_the_falcon_libraries(monkeypatch: pytest.MonkeyPatch, algorithm: str) -> None:
    """falcon-512 finds the libraries the data lists for Falcon instead of "No libraries found"."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["libraries", "--algorithm", algorithm])
    assert result.exit_code == 0
    assert "No libraries found" not in result.output
    assert "liboqs (Open Quantum Safe)" in result.output


COMPARE_COMMAND = re.compile(r"pqc-bench compare (\S+) (\S+)")


def _compare_commands(output: str) -> list[tuple[str, str]]:
    """The two algorithm IDs of each ``pqc-bench compare`` command in the output, in order."""
    return COMPARE_COMMAND.findall(output)


def _table_rows(output: str) -> list[str]:
    """The first cell of each line of the table in the output, header included."""
    return [line.split("│")[1].strip() for line in output.splitlines() if line.startswith("│")]


def _assert_like_for_like(runner: CliRunner, first: str, second: str) -> None:
    """``compare first second`` names two different algorithms of one type, runs, and names a winner."""
    assert first in ALGORITHMS
    assert second in ALGORITHMS
    assert first != second
    assert ALGORITHMS[first].algorithm_type == ALGORITHMS[second].algorithm_type
    result = runner.invoke(cli.app, ["compare", first, second])
    assert result.exit_code == 0, result.output
    assert "Winner" in result.output


@pytest.mark.parametrize(
    ("args", "suggested"),
    [
        (["ml-kem-1024", "ml-dsa-65"], [("ml-kem-1024", "ml-kem-768"), ("ml-dsa-65", "ml-dsa-87")]),
        (["ml-dsa-65", "ml-kem-1024"], [("ml-dsa-65", "ml-dsa-87"), ("ml-kem-1024", "ml-kem-768")]),
    ],
)
def test_compare_of_a_kem_and_a_signature_scheme_names_no_winner_and_suggests_like_for_like_pairs(
    monkeypatch: pytest.MonkeyPatch, args: list[str], suggested: list[tuple[str, str]]
) -> None:
    """A KEM and a signature scheme do different jobs: no Winner column, and a same-type pair for each."""
    _wide_console(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(cli.app, ["compare", *args])
    assert result.exit_code == 0
    assert "different jobs" in result.output
    assert "Winner" not in result.output
    assert _table_rows(result.output) == [
        "Property",
        "Security Level",
        "Public Key",
        "Constant-time",
        "NIST Standard",
        "Requires FPU",
    ]
    assert result.output.index("different jobs") < result.output.index("Property")
    assert result.output.index("like-for-like") > result.output.index("Requires FPU")
    assert _compare_commands(result.output) == suggested
    for first, second in suggested:
        assert f"pqc-bench compare {first} {second}" in result.output
        _assert_like_for_like(runner, first, second)


@pytest.mark.parametrize(
    ("args", "line"),
    [
        (
            ["ml-dsa-44", "ml-dsa-44"],
            "ML-DSA-44 compared with itself: every row would be a tie. "
            "Pick a second algorithm, for example: pqc-bench compare ml-dsa-44 ml-dsa-65",
        ),
        (
            ["kyber768", "ml-kem-768"],
            "ML-KEM-768 compared with itself: every row would be a tie. "
            "Pick a second algorithm, for example: pqc-bench compare ml-kem-768 ml-kem-1024",
        ),
    ],
)
def test_compare_of_an_algorithm_with_itself_says_so_in_one_line(
    monkeypatch: pytest.MonkeyPatch, args: list[str], line: str
) -> None:
    """The same algorithm twice, by any of its names, prints one line instead of a table of ties."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["compare", *args])
    assert result.exit_code == 0
    assert "compared with itself" in result.output
    assert "Property" not in result.output
    assert result.output.strip() == line


@pytest.mark.parametrize("algorithm_id", list(ALGORITHMS))
def test_compare_of_any_algorithm_with_itself_suggests_a_second_one_of_its_type_that_runs(
    monkeypatch: pytest.MonkeyPatch, algorithm_id: str
) -> None:
    """The example in the one line compares the algorithm with another of its type, and that command runs."""
    _wide_console(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(cli.app, ["compare", algorithm_id, algorithm_id])
    assert result.exit_code == 0
    assert len(result.output.strip().splitlines()) == 1
    [(first, second)] = _compare_commands(result.output)
    assert first == algorithm_id
    _assert_like_for_like(runner, first, second)


def test_compare_without_a_second_algorithm_of_the_type_points_at_the_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """With one algorithm of each type, compare names pqc-bench list and makes up no like-for-like pair."""
    _wide_console(monkeypatch)
    monkeypatch.setattr(
        cli, "ALGORITHMS", {algo_id: ALGORITHMS[algo_id] for algo_id in ("ml-kem-768", "ml-dsa-44")}
    )
    runner = CliRunner()

    result = runner.invoke(cli.app, ["compare", "ml-dsa-44", "ml-dsa-44"])
    assert result.exit_code == 0
    assert result.output.strip() == (
        "ML-DSA-44 compared with itself: every row would be a tie. "
        "Pick a second algorithm. To see them all: pqc-bench list"
    )
    assert runner.invoke(cli.app, ["list"]).exit_code == 0

    result = runner.invoke(cli.app, ["compare", "ml-dsa-44", "ml-kem-768"])
    assert result.exit_code == 0
    assert "different jobs" in result.output
    assert "like-for-like" not in result.output
    assert _compare_commands(result.output) == []


def test_compare_of_two_algorithms_of_one_type_still_names_a_winner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two signature schemes are compared as before: a Winner column and no note about different jobs."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["compare", "ml-dsa-44", "falcon-512"])
    assert result.exit_code == 0
    assert "Winner" in result.output
    assert "different jobs" not in result.output
    assert "like-for-like" not in result.output


def _recommend_on_a_wide_console(monkeypatch: pytest.MonkeyPatch, query: str) -> str:
    """Run recommend in text mode on a 200-column console and return its output."""
    console = Console(width=200, force_terminal=False)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli, "terminal", TerminalOutput(console))
    result = CliRunner().invoke(cli.app, ["recommend", query])
    assert result.exit_code == 0
    return result.output


@pytest.mark.parametrize(
    "query",
    ["mobile banking app", "TLS for a web server", "REST API with JWT auth", "file encryption for healthcare"],
)
def test_recommend_footer_compares_only_algorithms_of_one_type(monkeypatch: pytest.MonkeyPatch, query: str) -> None:
    """The compare command in the Commands footer, when there is one, pairs two algorithms of the same type."""
    output = _recommend_on_a_wide_console(monkeypatch, query)
    pairs = _compare_commands(output)
    assert len(pairs) <= 1
    for first, second in pairs:
        _assert_like_for_like(CliRunner(), first, second)


def test_recommend_footer_for_mobile_banking_compares_two_kems(monkeypatch: pytest.MonkeyPatch) -> None:
    """The top pick is a KEM, so the footer compares it with the next ranked KEM, not with a signature scheme."""
    output = _recommend_on_a_wide_console(monkeypatch, "mobile banking app")
    [(first, second)] = _compare_commands(output)
    assert ALGORITHMS[first].is_kem
    assert ALGORITHMS[second].is_kem


def _options_declaring(flag: str) -> dict[str, str | None]:
    """The name of the option that ``flag`` stands for, by the command that declares it."""
    group = typer.main.get_command(cli.app)
    assert isinstance(group, typer.core.TyperGroup)
    commands = {"pqc-bench": group, **{f"pqc-bench {name}": command for name, command in group.commands.items()}}
    return {
        where: param.name
        for where, command in commands.items()
        for param in command.params
        if flag in (*param.opts, *param.secondary_opts)
    }


def test_v_stands_for_verbose_wherever_it_is_declared_and_capital_v_for_version() -> None:
    """-v has one meaning, --verbose; the version option is -V."""
    assert set(_options_declaring("-v").values()) == {"verbose"}
    assert _options_declaring("-V") == {"pqc-bench": "version"}


@pytest.mark.parametrize("flag", ["-V", "--version"])
def test_the_version_options_print_the_version(flag: str) -> None:
    result = CliRunner().invoke(cli.app, [flag])
    assert result.exit_code == 0
    assert result.output.strip() == f"pqc-bench {__version__}"


@pytest.mark.parametrize("env", [{}, COLOUR_FORCED], ids=["plain", "colour"])
def test_the_bare_command_prints_the_help_and_exits_0_as_help_does(env: dict[str, str | None]) -> None:
    """pqc-bench with no arguments is not a usage error: it prints what --help prints."""
    bare = CliRunner().invoke(cli.app, [], env=env)
    with_help = CliRunner().invoke(cli.app, ["--help"], env=env)
    assert with_help.exit_code == 0
    assert bare.exit_code == 0
    assert bare.output == with_help.output
    assert "recommend" in _without_ansi(bare.output)


def _error_words(output: str) -> str:
    """The words of the output with ANSI escapes, panel borders and line breaks removed."""
    return " ".join(_without_ansi(output).replace("│", " ").split())


@pytest.mark.parametrize(
    "args",
    [
        ["--list", "--data-type", "healthcare_records"],
        ["--list", "--urgency", "critical"],
        ["--data-type", "healthcare_records", "--urgency", "critical"],
        ["--list", "--data-type", "healthcare_records", "--urgency", "critical"],
    ],
)
@pytest.mark.parametrize("env", [{}, COLOUR_FORCED], ids=["plain", "colour"])
def test_threat_rejects_two_views_at_once_and_names_the_options(
    args: list[str], env: dict[str, str | None]
) -> None:
    """--list, --data-type and --urgency each choose a view, so a second one is not silently ignored."""
    result = CliRunner().invoke(cli.app, ["threat", *args], env=env)
    assert result.exit_code == 2
    words = _error_words(result.output)
    options = [arg for arg in args if arg.startswith("--")]
    assert f"{', '.join(options[:-1])} and {options[-1]} cannot be used together" in words
    assert "SNDL Threat Assessment" not in words


def test_sector_list_at_80_columns_shows_every_sector_name_in_full(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sector name wraps at a space in the Sector column instead of being cut short with an ellipsis."""
    monkeypatch.setattr(cli, "console", Console(width=80, force_terminal=False))
    result = CliRunner().invoke(cli.app, ["sector", "--list"])
    assert result.exit_code == 0
    column = " ".join(cell for cell in _table_rows(result.output) if cell)
    assert "…" not in column
    for profile in SECTOR_PROFILES.values():
        assert profile.name in column


@pytest.mark.parametrize("width", [30, 40, 60])
def test_sector_list_on_a_narrow_console_cuts_no_sector_name_short(
    monkeypatch: pytest.MonkeyPatch, width: int
) -> None:
    """Below 80 columns a name too long for the Sector column carries on onto the next line."""
    monkeypatch.setattr(cli, "console", Console(width=width, force_terminal=False))
    result = CliRunner().invoke(cli.app, ["sector", "--list"])
    assert result.exit_code == 0
    cells = _table_rows(result.output)
    assert cells
    assert not any("…" in cell for cell in cells)


def test_sector_names_list_every_sector_profile_once_in_order() -> None:
    assert list(cli.SECTOR_NAMES.values()) == list(SECTOR_PROFILES)


def test_sector_list_unknown_sector_and_help_give_the_same_sector_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """The --list footer, the unknown-sector error and the argument help name the same sectors, each of which runs."""
    _wide_console(monkeypatch)
    listed = CliRunner().invoke(cli.app, ["sector", "--list"])
    assert listed.exit_code == 0
    footer = re.search(r"Sector IDs: (.*)", listed.output)
    assert footer is not None
    names = footer.group(1).strip().split(", ")
    unknown = CliRunner().invoke(cli.app, ["sector", "banana"])
    assert unknown.exit_code == 1
    assert re.findall(r"^  • (\S+)$", unknown.output, re.MULTILINE) == names
    assert _option_help(cli.sector, "sector_name") == f"Sector to analyze ({', '.join(names)})"
    for name in names:
        assert CliRunner().invoke(cli.app, ["sector", name]).exit_code == 0, name


def _performance_section(output: str) -> str:
    """The Performance section of explain output, up to the Compliance heading."""
    return output.split("\nPerformance\n", 1)[1].split("\nCompliance\n", 1)[0]


@pytest.mark.parametrize("algorithm_id", sorted(ALGORITHMS))
def test_explain_says_where_the_figures_of_each_platform_come_from(
    monkeypatch: pytest.MonkeyPatch, algorithm_id: str
) -> None:
    """Under the Performance table, each platform's figures carry their recorded method or the label estimates."""
    console = Console(width=300, force_terminal=False)
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli, "terminal", TerminalOutput(console))
    result = CliRunner().invoke(cli.app, ["explain", algorithm_id])
    assert result.exit_code == 0
    section = _performance_section(result.output)
    source_lines = [line.strip() for line in section.splitlines() if " figures: " in line]
    for platform, perf in ALGORITHMS[algorithm_id].performance.items():
        [line] = [
            line
            for line in source_lines
            if platform in line.split(" figures: ")[0].replace(" and ", ", ").split(", ")
        ]
        method = perf.methodology
        if method is None:
            assert line.endswith(" figures: estimates, no benchmark methodology recorded")
            continue
        for detail in (
            f"{method.library} {method.version} benchmark",
            method.compiler,
            method.cpu,
            f"{method.iterations:,} iterations",
            method.date,
        ):
            assert detail in line
        assert method.source in [line.strip() for line in section.splitlines()]


@pytest.mark.parametrize(
    ("query", "platform"),
    [
        ("TLS for a web server", "x86_64_avx2"),
        ("TLS on AWS Graviton", "arm64_neon"),
        # No figures are recorded for embedded platforms, so the score uses the x86_64_avx2 ones.
        ("embedded sensor with 256KB RAM", "x86_64_avx2"),
    ],
)
def test_recommend_verbose_names_the_figures_its_performance_score_uses(
    monkeypatch: pytest.MonkeyPatch, query: str, platform: str
) -> None:
    """The line under the Scoring Factors table names the platform whose figures give the Performance reason."""
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=300, force_terminal=False)))
    result = CliRunner().invoke(cli.app, ["recommend", query, "--verbose"])
    assert result.exit_code == 0
    [line] = [line.strip() for line in result.output.splitlines() if "Performance uses the " in line]
    assert line.startswith(f"Performance uses the {platform} figures: ")
    engine_result = RecommendationEngine().recommend(QueryParser().parse(query), query=query)
    assert engine_result.primary is not None
    algo = engine_result.primary.algorithm
    perf = algo.performance[platform]
    ops = perf.verify_ops if algo.is_signature else perf.decaps_ops
    assert ops is not None
    operation = "verify" if algo.is_signature else "decaps"
    reason = re.search(r"^\s*Performance\s+\d+%\s+\d+\s+(\S.*?)\s*$", result.output, re.MULTILINE)
    assert reason is not None
    assert reason.group(1) == f"~{1000 / ops:.2f}ms {operation}"
    if perf.methodology is None:
        assert line.endswith("figures: estimates, no benchmark methodology recorded")
    else:
        assert f"{perf.methodology.library} {perf.methodology.version} benchmark" in line


@pytest.mark.parametrize(
    "args",
    [
        ["explain", ":warning:"],
        ["compare", ":warning:", "ml-kem-768"],
        ["compare", "ml-kem-768", ":warning:"],
        ["migrate", "--from", ":warning:"],
        ["compliance", ":warning:"],
        ["compliance", "fips-140-3", "--use-case", ":warning:"],
        ["list", "--type", ":warning:"],
        ["libraries", "--algorithm", ":warning:"],
        ["hybrid", "--use-case", ":warning:"],
        ["threat", "--urgency", ":warning:"],
        ["threat", "--data-type", ":warning:"],
        ["impact", ":warning:"],
        ["sector", ":warning:"],
    ],
    ids=" ".join,
)
def test_an_unknown_value_holding_an_emoji_code_is_shown_as_typed(
    monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    """Rich would print the warning-sign emoji for :warning:; the message keeps the text the user typed."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, args)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert ":warning:" in result.output
    assert "⚠" not in result.output


def _printed_lines(output: str) -> list[str]:
    """The non-blank lines of the output, without their surrounding spaces."""
    return [line.strip() for line in output.splitlines() if line.strip()]


@pytest.mark.parametrize("data_type", list(threat_model.DATA_PROFILES))
def test_threat_ends_with_a_next_step_command_that_runs(monkeypatch: pytest.MonkeyPatch, data_type: str) -> None:
    """The assessment ends with the command to run next, and that command lists libraries."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--data-type", data_type])
    assert result.exit_code == 0
    *_, step, command = _printed_lines(result.output)
    assert step.startswith("Next step: ")
    assert command.startswith("pqc-bench libraries --algorithm ")
    follow = CliRunner().invoke(cli.app, shlex.split(command)[1:])
    assert follow.exit_code == 0
    assert "No libraries found" not in follow.output


def test_threat_healthcare_states_the_facts_without_the_alarm_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """No "CRITICAL: ... You are 87 years behind.": the 102, 15 and 87 years, then the next step."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--data-type", "healthcare_records"])
    assert result.exit_code == 0
    assert "CRITICAL" not in result.output
    assert "behind" not in result.output
    lines = _printed_lines(result.output)
    assert (
        "Data needs 102 years of protection (a 100-year lifespan plus 2 years to migrate), and the quantum "
        "threat is expected in 15 years, so the data outlives that window by 87 years."
    ) in lines
    assert lines[-2:] == [
        "Next step: find a library that implements ML-KEM-768",
        "pqc-bench libraries --algorithm ml-kem-768",
    ]


@pytest.mark.parametrize(
    ("data_type", "status"),
    [("healthcare_records", "⚠ At risk"), ("corporate_strategy", "✓ Manageable")],
    ids=["at-risk", "manageable"],
)
def test_threat_status_line_is_not_in_capitals(monkeypatch: pytest.MonkeyPatch, data_type: str, status: str) -> None:
    """The status above the explanation reads "⚠ At risk" or "✓ Manageable", not "⚠ AT RISK" or "✓ MANAGEABLE"."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--data-type", data_type])
    assert result.exit_code == 0
    assert status in _printed_lines(result.output)
    assert status.upper() not in result.output


def test_threat_list_deadline_column_is_not_in_capitals(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Deadline column reads "87y overdue", not "87y OVERDUE"."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["threat", "--list"])
    assert result.exit_code == 0
    assert "OVERDUE" not in result.output
    row = next(line for line in result.output.splitlines() if "Healthcare Records" in line)
    assert [cell.strip() for cell in row.split("│")[1:-1]] == ["Healthcare Records", "100y", "CRITICAL", "87y overdue"]


def test_libraries_states_the_liboqs_fact_and_the_next_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """No "CRITICAL WARNING": liboqs is not production-ready, what its README says, and the command to run next."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["libraries"])
    assert result.exit_code == 0
    assert "CRITICAL" not in result.output
    assert "NOT" not in result.output
    lines = _printed_lines(result.output)
    assert "liboqs is not production-ready" in lines
    assert lines[-2:] == ["Next step: list the production-ready libraries", "pqc-bench libraries --production"]
    follow = CliRunner().invoke(cli.app, ["libraries", "--production"])
    assert follow.exit_code == 0
    assert "liboqs" not in follow.output


def test_libraries_help_has_no_aside_about_developers() -> None:
    """--help says liboqs is not production-ready and names --production, without "many developers ... unaware"."""
    result = CliRunner().invoke(cli.app, ["libraries", "--help"])
    assert result.exit_code == 0
    text = " ".join(result.output.split())
    assert "developers" not in text
    assert "unaware" not in text
    assert "NOT" not in text
    assert "liboqs is a research library and is not production-ready" in text


def _library_rows(output: str) -> dict[str, list[str]]:
    """The cells of each library table row, by the library name in its first cell."""
    rows = [[cell.strip() for cell in line.split("│")[1:-1]] for line in output.splitlines() if line.startswith("│")]
    return {row[0]: row for row in rows if row and row[0]}


def test_libraries_shows_no_fips_certificate_for_wolfssl_pqc(monkeypatch: pytest.MonkeyPatch) -> None:
    """wolfSSL's #3389 is a FIPS 140-2 certificate that lists no PQC algorithm: the FIPS column reads No."""
    _wide_console(monkeypatch)
    listed = CliRunner().invoke(cli.app, ["libraries"])
    assert listed.exit_code == 0
    assert _library_rows(listed.output)["wolfSSL"][1:3] == ["Production", "No"]
    assert "3389" not in listed.output
    fips = CliRunner().invoke(cli.app, ["libraries", "--fips"])
    assert fips.exit_code == 0
    assert "wolfSSL" not in fips.output
    assert "3389" not in fips.output


@pytest.mark.parametrize("options", [[], ["--production"], ["--fips"]])
def test_libraries_cites_an_aws_lc_certificate_that_lists_ml_kem(
    monkeypatch: pytest.MonkeyPatch, options: list[str]
) -> None:
    """AWS-LC's FIPS column shows #5298 (AWS-LC 3, lists ML-KEM), not #4793 (Canonical's Libgcrypt module)."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["libraries", *options])
    assert result.exit_code == 0
    assert _library_rows(result.output)["AWS-LC (AWS Libcrypto)"][1:3] == ["Production", "#5298"]
    assert "4793" not in result.output


def test_libraries_shows_no_fips_certificate_for_boringssl_pqc(monkeypatch: pytest.MonkeyPatch) -> None:
    """BoringSSL's #4407 is a historical FIPS 140-2 certificate that lists no PQC: the FIPS column reads No."""
    _wide_console(monkeypatch)
    listed = CliRunner().invoke(cli.app, ["libraries"])
    assert listed.exit_code == 0
    assert _library_rows(listed.output)["BoringSSL"][1:3] == ["Production", "No"]
    assert "4407" not in listed.output
    fips = CliRunner().invoke(cli.app, ["libraries", "--fips"])
    assert fips.exit_code == 0
    assert "BoringSSL" not in fips.output
    assert "4407" not in fips.output


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_explain_prints_no_quantum_security_bits(algorithm: str) -> None:
    """explain shows no quantum security bit figure, a number with no cited source."""
    result = CliRunner().invoke(cli.app, ["explain", algorithm])
    assert result.exit_code == 0
    assert "Quantum:" not in result.output
    assert "NIST Level:" in result.output


def test_recommend_json_security_has_no_quantum_bits() -> None:
    """The security object of each --json recommendation has no quantum_bits field."""
    result = CliRunner().invoke(cli.app, ["recommend", "TLS for a web server", "--json"])
    assert result.exit_code == 0
    recommendations = json.loads(result.output)["recommendations"]
    assert recommendations
    for rec in recommendations:
        assert set(rec["security"]) == {"nist_level", "classical_bits", "constant_time"}


# RFC 10024 (August 2026) defines X25519MLKEM768 and SecP384r1MLKEM1024 for TLS 1.3;
# RFC 10073 (November 2026), published from draft-ietf-lamps-pq-composite-sigs, defines
# the composite ML-DSA-44 + ECDSA P-256 and ML-DSA-65 + ECDSA P-384 signatures for X.509.
HYBRID_IETF_REFERENCES = {
    "x25519-mlkem768": "RFC 10024",
    "secp384r1-mlkem1024": "RFC 10024",
    "ecdsa-p256-mldsa44": "RFC 10073",
    "ecdsa-p384-mldsa65": "RFC 10073",
}


def test_each_hybrid_mode_names_the_rfc_that_defines_it() -> None:
    """The field is ietf_reference and holds the RFC: every hybrid mode's document is published."""
    assert {mode_id: mode.ietf_reference for mode_id, mode in HYBRID_MODES.items()} == HYBRID_IETF_REFERENCES
    assert not any(hasattr(mode, "ietf_draft") for mode in HYBRID_MODES.values())


def test_hybrid_prints_the_rfc_of_each_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """hybrid prints "IETF reference: RFC 10024" for the KEM hybrids and RFC 10073 for the composite signatures."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["hybrid"])
    assert result.exit_code == 0
    references = [line for line in _printed_lines(result.output) if line.startswith("IETF reference:")]
    assert references == [f"IETF reference: {HYBRID_IETF_REFERENCES[mode_id]}" for mode_id in HYBRID_MODES]


def test_sector_deadlines_list_only_dated_pqc_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    """DORA sets no PQC date, so it has no row; the NIST row names IR 8547 and its 2030-2035 window."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["sector", "--deadlines"])
    assert result.exit_code == 0
    lines = [line for line in result.output.splitlines() if line.startswith("│")]
    rows = [[cell.strip() for cell in line.split("│")[1:-1]] for line in lines]
    assert rows[0] == ["Sector", "Framework", "Deadline"]
    assert not any(row[1] == "DORA" for row in rows)
    assert ["Healthcare & Medical Devices", "NIST IR 8547", "2030-2035"] in rows
    assert ["Financial Services", "NSM-10", "2035"] in rows


def test_sector_healthcare_cites_nist_ir_8547_for_its_dates(monkeypatch: pytest.MonkeyPatch) -> None:
    """The NIST entry names the final report and says what happens after 2030 and after 2035."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["sector", "healthcare"])
    assert result.exit_code == 0
    assert "NIST Deprecation" not in result.output
    lines = _printed_lines(result.output)
    start = lines.index("• NIST IR 8547 (NIST)")
    assert lines[start + 1 : start + 4] == [
        "PQC Requirement: MANDATORY",
        "Deadline: 2030-2035",
        "Quantum-vulnerable public-key algorithms are deprecated after 2030 and disallowed under NIST "
        "standards and guidelines after 2035 (NIST IR 8547, final, October 2026)",
    ]


def test_sector_financial_says_dora_sets_no_pqc_date(monkeypatch: pytest.MonkeyPatch) -> None:
    """DORA shows no deadline line, and its note says when it applies and that it sets no PQC date."""
    _wide_console(monkeypatch)
    result = CliRunner().invoke(cli.app, ["sector", "financial"])
    assert result.exit_code == 0
    lines = _printed_lines(result.output)
    start = lines.index("• DORA (EU)")
    assert lines[start + 1 : start + 3] == [
        "PQC Requirement: RECOMMENDED",
        "Digital Operational Resilience Act, applies from 17 January 2025: requires ICT risk mitigation "
        "and sets no PQC date",
    ]
