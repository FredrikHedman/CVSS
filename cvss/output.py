"""Shared output utilities used by cvss2 and cvss4."""

import contextlib
import io
from collections.abc import Callable

from cvss.metric import Metric

_W = 44
_SEP = "=" * (_W * 2 + 6)


def capture_output(fn: Callable[[], None]) -> str:
    """Capture everything printed by fn and return it as a string."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()


def print_separator() -> None:
    """Print the standard separator line used in metric group tables."""
    print(_SEP)


def print_metric_group(header: str, metrics: list[Metric]) -> None:
    """Print one metric group as an aligned table with separator lines."""
    print(_SEP)
    print(f"{header:<{_W}}{'EVALUATION':<{_W}}{'ABBREV'}")
    print(_SEP)
    for m in metrics:
        print(f"{m.name:<{_W}}{m.selected.metric:<{_W}}{m.index}")
