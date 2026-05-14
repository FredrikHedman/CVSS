"""Unit tests for shared cvss output utilities."""

from cvss.metric import Metric
from cvss.output import capture_output, print_metric_group

_AV_VALUES: list[tuple[str, str, float, str]] = [
    ("Local", "L", 0.395, "Local access"),
    ("Adjacent Network", "A", 0.646, "Adjacent network access"),
    ("Network", "N", 1.0, "Network access"),
]


def _av_metric(index: str = "N") -> Metric:
    return Metric("Access Vector", "AV", _AV_VALUES, index=index)


def test_print_metric_group_separator_and_header() -> None:
    out = capture_output(lambda: print_metric_group("BASE METRICS", []))
    lines = out.splitlines()
    assert lines[0] == lines[2]         # both separator lines are equal
    assert "=" in lines[0]
    assert "BASE METRICS" in lines[1]
    assert "EVALUATION" in lines[1]
    assert "ABBREV" in lines[1]


def test_print_metric_group_metric_row() -> None:
    m = _av_metric("N")
    out = capture_output(lambda: print_metric_group("BASE METRICS", [m]))
    assert "Access Vector" in out
    assert "Network" in out
    assert "N" in out
