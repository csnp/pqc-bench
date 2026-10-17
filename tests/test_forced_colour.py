"""Checks that the CLI tests pass when the shell that runs pytest forces colour or is a terminal."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
CLI_TEXT_TESTS = ["test_cli.py", "test_algorithms.py", "test_compliance.py", "test_hybrid_group_names.py"]

# The autouse fixture in conftest.py sets TTY_COMPATIBLE to 0 and COLUMNS to 80; a new pytest
# process started by these tests must not inherit those values.
COLOUR_VARIABLES = ("FORCE_COLOR", "TTY_COMPATIBLE", "NO_COLOR")


@pytest.mark.parametrize("variable", ["FORCE_COLOR", "TTY_COMPATIBLE"])
def test_cli_tests_pass_when_the_shell_forces_colour(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    """These files pass in a new pytest process started with the variable set to 1 and TERM=xterm-256color."""
    for name in COLOUR_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    result = pytester.runpytest_subprocess(
        "-p", "no:cacheprovider", "--color=no", *(str(TESTS / name) for name in CLI_TEXT_TESTS)
    )
    assert result.ret == pytest.ExitCode.OK, "\n".join(result.outlines[-40:])


def run_in_terminal(args: list[str], cwd: Path, env: dict[str, str], columns: int) -> tuple[int, str]:
    """Run args with stdin, stdout and stderr on a new pseudo-terminal and return the exit code and output."""
    import fcntl
    import pty
    import struct
    import termios

    controller, terminal = pty.openpty()
    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 24, columns, 0, 0))
    process = subprocess.Popen(args, cwd=cwd, env=env, stdin=terminal, stdout=terminal, stderr=terminal)  # noqa: S603
    os.close(terminal)
    chunks = []
    while True:
        try:
            chunk = os.read(controller, 65536)
        except OSError:  # Linux reports EIO once the process has closed the terminal
            break
        if not chunk:
            break
        chunks.append(chunk)
    os.close(controller)
    return process.wait(timeout=300), b"".join(chunks).decode(errors="replace")


@pytest.mark.skipif(sys.platform == "win32", reason="needs a pseudo-terminal")
def test_cli_tests_pass_when_pytest_writes_to_a_terminal(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """These files pass under pytest -s in a new process writing to a 50-column terminal, with TERM=xterm-256color."""
    for name in (*COLOUR_VARIABLES, "COLUMNS", "LINES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    files = [str(TESTS / name) for name in [*CLI_TEXT_TESTS, "test_docs.py"]]
    options = ["-s", "-p", "no:cacheprovider", "--color=no", f"--basetemp={pytester.path / 'basetemp'}"]
    code, output = run_in_terminal(
        [sys.executable, "-m", "pytest", *options, *files],
        cwd=pytester.path,
        env=dict(os.environ),
        columns=50,
    )
    assert code == pytest.ExitCode.OK, "\n".join(output.splitlines()[-40:])
