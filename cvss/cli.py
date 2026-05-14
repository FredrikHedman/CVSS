"""Shared CLI utilities used by both cvss2 and cvss4."""

import sys
from typing import NoReturn


def exit_with_error(e: Exception) -> NoReturn:
    """Print an error message and exit with status 1."""
    print(e)
    sys.exit(1)
