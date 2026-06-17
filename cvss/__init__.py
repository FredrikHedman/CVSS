"""Shared utilities used by both cvss2 and cvss4."""

import contextlib
import io
import sys
from collections.abc import Callable
from typing import NoReturn


class InvalidVectorError(Exception):
    """Raised when a CVSS vector string is malformed or invalid."""


def exit_with_error(e: Exception) -> NoReturn:
    """Print an error message and exit with status 1."""
    print(e)
    sys.exit(1)


def capture_output(fn: Callable[[], None]) -> str:
    """Capture everything printed by fn and return it as a string."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()
