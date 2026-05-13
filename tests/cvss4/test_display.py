"""Unit tests for cvss4 output functions."""

import io
import sys

import pytest

from cvss4.cvss_40 import CommonVulnerabilityScore40
from cvss4.cvss_output import qualitative_rating, render_output
from cvss4.vulnerability_40 import VulnerabilityVector40

_V40_BASE = (
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)


@pytest.mark.parametrize("score,expected", [
    (0.0, "None"),
    (0.1, "Low"),
    (3.9, "Low"),
    (4.0, "Medium"),
    (6.9, "Medium"),
    (7.0, "High"),
    (8.9, "High"),
    (9.0, "Critical"),
    (10.0, "Critical"),
])
def test_qualitative_rating(score: float, expected: str) -> None:
    assert qualitative_rating(score) == expected


def test_render_output_prints_score_and_severity() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    captured = io.StringIO()
    sys.stdout = captured
    try:
        render_output(cvs)
    finally:
        sys.stdout = sys.__stdout__
    out = captured.getvalue()
    assert "CVSS v4.0 Score = 7.3" in out
    assert "Severity = High" in out
    assert "CVSS v4.0 Vulnerability Vector = " in out


def test_render_output_includes_vector(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    render_output(cvs)
    out = capsys.readouterr().out
    assert cvs.base_vulnerability_vector in out
