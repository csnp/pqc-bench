"""Checks that the CLI tests pass when the shell that runs pytest forces colour."""

from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
CLI_TEXT_TESTS = ["test_cli.py", "test_algorithms.py", "test_compliance.py", "test_hybrid_group_names.py"]


@pytest.mark.parametrize("variable", ["FORCE_COLOR", "TTY_COMPATIBLE"])
def test_cli_tests_pass_when_the_shell_forces_colour(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    """These files pass in a new pytest process started with the variable set to 1 and TERM=xterm-256color."""
    monkeypatch.setenv(variable, "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    result = pytester.runpytest_subprocess(
        "-p", "no:cacheprovider", "--color=no", *(str(TESTS / name) for name in CLI_TEXT_TESTS)
    )
    assert result.ret == pytest.ExitCode.OK, "\n".join(result.outlines[-40:])
