"""Shared output utilities used by both cvss2 and cvss4."""

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


def qualitative_rating(score: float) -> str:
    """Map a CVSS v4.0 score to a severity label (Spec §9)."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


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
