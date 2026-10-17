"""Entry point for the pqc-bench command and ``python -m pqc_bench``."""

import signal
import sys
from types import FrameType


def _exit_on_interrupt(signum: int, frame: FrameType | None) -> None:
    """End the program with exit status 130, the shell convention for Ctrl+C."""
    sys.exit(130)


def main() -> None:
    """Run the CLI. Ctrl+C ends it with exit status 130 and no traceback."""
    # Installed before the CLI modules are imported, so Ctrl+C while they
    # load is handled the same way as Ctrl+C while a command runs.
    signal.signal(signal.SIGINT, _exit_on_interrupt)

    from .cli import app

    app()


if __name__ == "__main__":
    main()
