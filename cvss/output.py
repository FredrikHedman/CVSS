"""Shared output utilities used by both cvss2 and cvss4."""

import contextlib
import io
from collections.abc import Callable


def capture_output(fn: Callable[[], None]) -> str:
    """Capture everything printed by fn and return it as a string."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()
