"""Ctrl+C ends the pqc-bench command with exit status 130 and nothing on stderr."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="sends SIGINT to the process with os.kill")

# Calls the entry point of the pqc-bench script the way the installed launcher
# does, after arranging for SIGINT to arrive while the CLI modules are
# imported or while the recommend command runs.
LAUNCHER = """
import importlib, os, signal, sys

sys.path.insert(0, {src!r})
sys.argv = ["pqc-bench", "recommend", "tls"]


def interrupt():
    os.kill(os.getpid(), signal.SIGINT)


class InterruptWhenTyperIsImported:
    def find_spec(self, name, path=None, target=None):
        if name == "typer":
            interrupt()
        return None


if {during!r} == "import":
    sys.meta_path.insert(0, InterruptWhenTyperIsImported())
else:
    from pqc_bench.core.parser import QueryParser

    QueryParser.parse = lambda self, query: interrupt()

entry_point = getattr(importlib.import_module({module!r}), {function!r})
sys.exit(entry_point())
"""


def _entry_point() -> tuple[str, str]:
    """The module and function that pyproject.toml names for the pqc-bench script."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^pqc-bench = "([\w.]+):(\w+)"$', pyproject, re.MULTILINE)
    assert match is not None, "pyproject.toml declares no pqc-bench script"
    return match.group(1), match.group(2)


@pytest.mark.parametrize("during", ["import", "command"])
def test_ctrl_c_exits_130_without_a_traceback(during: str) -> None:
    """SIGINT while the CLI modules load or while a command runs ends the script with status 130."""
    module, function = _entry_point()
    code = LAUNCHER.format(src=str(ROOT / "src"), during=during, module=module, function=function)
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.stderr == ""
    assert result.returncode == 130
