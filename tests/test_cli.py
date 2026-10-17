"""Tests for CLI output formats."""

import inspect
import io
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pqc_bench import cli
from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.parser import QueryParser
from pqc_bench.data import threat_model
from pqc_bench.data.algorithms import ALGORITHMS
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
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=100)))
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
    monkeypatch.setattr(cli, "terminal", TerminalOutput(Console(width=100)))
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
    monkeypatch.setattr(cli, "console", Console(width=200))


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
    console = Console(width=width)
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
