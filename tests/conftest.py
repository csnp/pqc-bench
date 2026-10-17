"""Fixtures shared by the test modules."""

import pytest
from rich.console import Console

from pqc_bench import cli
from pqc_bench.output.terminal import TerminalOutput

# test_forced_colour.py runs test files in a new pytest process through the pytester fixture.
pytest_plugins = ["pytester"]

# With rich 15.0.0 and TERM=xterm-256color, setting either of these to 1 puts escape sequences
# in CliRunner output, which splits text the tests look for, such as ML-KEM-768.
COLOUR_FORCING_VARIABLES = ("FORCE_COLOR", "TTY_COMPATIBLE")


@pytest.fixture(autouse=True)
def plain_cli_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the variables that force colour and give the CLI a console built without them.

    pqc_bench.cli builds its console when it is imported, before this fixture runs, and a
    console built while one of the variables is set keeps writing escape sequences after the
    variable is removed.

    With pytest -s in a terminal, sys.stdout is the terminal when a console is built, so Rich
    picks a colour system for it and takes its width from the terminal. TTY_COMPATIBLE=0 makes
    rich 15.0.0 treat the output as not a terminal without checking isatty, and COLUMNS=80 gives
    the width Rich falls back to when pytest captures output, for the consoles that this fixture
    and the tests build without a width.
    """
    for name in COLOUR_FORCING_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TTY_COMPATIBLE", "0")
    monkeypatch.setenv("COLUMNS", "80")
    console = Console()
    monkeypatch.setattr(cli, "console", console)
    monkeypatch.setattr(cli, "terminal", TerminalOutput(console))
