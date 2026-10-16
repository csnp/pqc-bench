"""The documentation agrees with the CLI."""

import re
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pqc_bench.cli import app
from pqc_bench.core.engine import RecommendationEngine
from pqc_bench.core.parser import QueryParser

ROOT = Path(__file__).resolve().parent.parent
USER_DOCS = [ROOT / "README.md", ROOT / "ROADMAP.md", *sorted((ROOT / "docs").glob("*.md"))]
ALL_DOCS = [ROOT / "README.md", ROOT / "ROADMAP.md", *sorted((ROOT / "docs").rglob("*.md"))]
HELP_TEXT = ROOT / "src" / "pqc_bench" / "cli.py"

COMMAND = re.compile(r"^\s*(?:\$\s+)?(pqc-bench\s.*?)\s*(?:#.*)?$")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _documented_commands() -> list[tuple[str, str]]:
    """Every pqc-bench command line in the user docs and the CLI help text."""
    commands: dict[str, str] = {}
    for path in [*USER_DOCS, HELP_TEXT]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = COMMAND.match(line)
            if not match:
                continue
            command = match.group(1).strip().strip("`")
            if any(marker in command for marker in ("<", "[", "...")):
                continue  # placeholder syntax, not a runnable command
            commands.setdefault(command, f"{path.relative_to(ROOT)}:{number}")
    return sorted(commands.items())


DOCUMENTED_COMMANDS = _documented_commands()


def test_documented_commands_are_found() -> None:
    assert DOCUMENTED_COMMANDS


@pytest.mark.parametrize(
    ("command", "where"),
    DOCUMENTED_COMMANDS,
    ids=[where for _, where in DOCUMENTED_COMMANDS],
)
def test_documented_command_runs(command: str, where: str) -> None:
    result = CliRunner().invoke(app, shlex.split(command)[1:])
    assert result.exit_code == 0, f"{where}: {command}\n{result.output}"


def _primary_algorithm(query: str) -> str:
    result = RecommendationEngine().recommend(QueryParser().parse(query), query=query)
    assert result.primary is not None
    return result.primary.algorithm.names.nist_name


def test_readme_example_results_match_the_cli() -> None:
    """Each README recommend example shows the algorithm the CLI recommends."""
    lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    checked = []
    for index, line in enumerate(lines):
        match = re.match(r'^(?:\$\s+)?pqc-bench recommend "([^"]+)"\s*$', line)
        if not match:
            continue
        query = match.group(1)
        shown = None
        for following in lines[index + 1 : index + 5]:
            result_comment = re.match(r"^# → (\S+)", following)
            panel_line = re.match(r"^│ (\S+)\s", following)
            if result_comment or panel_line:
                shown = (result_comment or panel_line).group(1)  # type: ignore[union-attr]
                break
        if shown is None:
            continue
        assert shown == _primary_algorithm(query), f"README example: {query}"
        checked.append(query)
    assert {
        "mobile banking app",
        "embedded sensor with 256KB RAM",
        "REST API with JWT auth, running on AWS Lambda",
    } <= set(checked)


@pytest.mark.parametrize("path", ALL_DOCS, ids=[str(p.relative_to(ROOT)) for p in ALL_DOCS])
def test_relative_links_resolve(path: Path) -> None:
    broken = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        for target in LINK.findall(line):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            if not (path.parent / target.split("#", 1)[0]).exists():
                broken.append(f"{path.relative_to(ROOT)}:{number}: {target}")
    assert broken == []


def test_license_is_the_unmodified_apache_2_0_text() -> None:
    """Sections 1 and 8 and the appendix match the Apache License 2.0 text."""
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "submitted to Licensor for inclusion in the Work by the copyright owner" in text
    assert (
        "8. Limitation of Liability. In no event and under no legal theory,\n"
        "      whether in tort (including negligence), contract, or otherwise,\n"
        "      unless required by applicable law (such as deliberate and grossly\n"
        "      negligent acts) or agreed to in writing, shall any Contributor be\n"
    ) in text
    assert "APPENDIX: How to apply the Apache License to your work." in text
