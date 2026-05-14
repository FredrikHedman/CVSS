"""Unit tests for cvss4 output functions."""

import pytest

from cvss4.cvss_40 import CommonVulnerabilityScore40
from cvss4.cvss_output import format_output, qualitative_rating
from cvss4.cvss_types import CvssArgs
from cvss4.vulnerability_40 import VulnerabilityVector40

_V40_BASE = (
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)
_V40_WITH_THREAT = _V40_BASE + "/E:A"
_V40_WITH_ENV = _V40_BASE + "/CR:H"
_V40_WITH_BOTH = _V40_BASE + "/E:A/CR:H"


def _clarg(verbose: bool = False) -> CvssArgs:
    return {
        "verbose": verbose, "base": True,
        "vector": None, "vulnerability": None,
    }


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


@pytest.mark.parametrize("vector,expected_label", [
    (_V40_BASE, "CVSS-B"),
    (_V40_WITH_THREAT, "CVSS-BT"),
    (_V40_WITH_ENV, "CVSS-BE"),
    (_V40_WITH_BOTH, "CVSS-BTE"),
])
def test_score_label(vector: str, expected_label: str) -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(vector).parsed)
    out = format_output(cvs, _clarg())
    assert f"{expected_label} Score = " in out


def test_format_output_score_and_severity() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    out = format_output(cvs, _clarg())
    assert "CVSS-B Score = 7.3" in out
    assert "Severity = High" in out
    assert "CVSS v4.0 Vulnerability Vector = " in out


def test_format_output_includes_vector() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    out = format_output(cvs, _clarg())
    assert cvs.base_vulnerability_vector in out


def test_verbose_output_shows_all_groups() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    out = format_output(cvs, _clarg(verbose=True))
    assert "BASE METRICS" in out
    assert "THREAT METRICS" in out
    assert "ENVIRONMENTAL METRICS" in out
    assert "SUPPLEMENTAL METRICS" in out
    assert "MacroVector EQ:" in out
    assert "CVSS-B Score = 7.3" in out


def test_verbose_output_non_verbose_unchanged() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_V40_BASE).parsed)
    out = format_output(cvs, _clarg(verbose=False))
    assert "BASE METRICS" not in out
    assert "CVSS-B Score = 7.3" in out
