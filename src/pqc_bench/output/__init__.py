"""Output formatting for terminal and JSON."""

from .json import JsonOutput
from .terminal import TerminalOutput

__all__ = [
    "TerminalOutput",
    "JsonOutput",
]
