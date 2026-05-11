"""Unit tests for ScoreDisplayData and render_output."""

import io
import sys
from unittest.mock import MagicMock, patch

import pytest

from cvss.cvss_output import (
    ScoreDisplayData,
    qualitative_rating,
    render_output,
)
from cvss.cvss_types import CvssArgs


def test_score_display_data_construction() -> None:
    d = ScoreDisplayData(
        header=("A", "B", "C"),
        footer_labels=["X", "Y"],
        metrics=[],
        footer_data=[("Score", 7.5)],
        vector_label=("Base", "AV:L"),
    )
    assert d.header == ("A", "B", "C")
    assert d.footer_labels == ["X", "Y"]
    assert d.metrics == []
    assert d.footer_data == [("Score", 7.5)]
    assert d.vector_label == ("Base", "AV:L")


def test_score_display_data_immutable() -> None:
    from dataclasses import FrozenInstanceError

    d = ScoreDisplayData(
        header=("A", "B", "C"),
        footer_labels=["X", "Y"],
        metrics=[],
        footer_data=[],
        vector_label=("V", "vec"),
    )
    with pytest.raises(FrozenInstanceError):
        d.header = ("X", "Y", "Z")  # type: ignore[misc]


_BASE_CLARG: CvssArgs = {
    "verbose": False,
    "interactive": False,
    "all": False,
    "base": True,
    "temporal": False,
    "environmental": False,
    "vector": None,
    "vulnerability": None,
    "cvss_version": "2.10",
}


def test_render_output_non_verbose() -> None:
    clarg: CvssArgs = {**_BASE_CLARG, "verbose": False}
    with patch("cvss.cvss_output._generate_output") as mock_out, \
         patch("cvss.cvss_output._generate_verbose_output") as mock_verb:
        render_output(MagicMock(), clarg)
    mock_out.assert_called_once()
    mock_verb.assert_not_called()


def test_render_output_verbose() -> None:
    clarg: CvssArgs = {**_BASE_CLARG, "verbose": True}
    with patch("cvss.cvss_output._generate_output") as mock_out, \
         patch("cvss.cvss_output._generate_verbose_output") as mock_verb:
        render_output(MagicMock(), clarg)
    mock_verb.assert_called_once()
    mock_out.assert_not_called()


# ---------------------------------------------------------------------------
# CVSS v4.0 output: qualitative_rating and render_output dispatch
# ---------------------------------------------------------------------------


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
def testqualitative_rating(score: float, expected: str) -> None:
    assert qualitative_rating(score) == expected


def test_render_output_v40_dispatches_to_render_v40() -> None:
    cvs = MagicMock()
    cvs.version = "4.0"
    clarg: CvssArgs = {**_BASE_CLARG, "cvss_version": "4.0"}
    with patch("cvss.cvss_output._render_v40") as mock_v40, \
         patch("cvss.cvss_output._generate_output") as mock_out:
        render_output(cvs, clarg)
    mock_v40.assert_called_once_with(cvs)
    mock_out.assert_not_called()


def test_render_output_v40_prints_score_and_severity() -> None:
    cvs = MagicMock()
    cvs.version = "4.0"
    cvs.base_score = 7.3
    cvs.base_vulnerability_vector = (
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    clarg: CvssArgs = {**_BASE_CLARG, "cvss_version": "4.0"}
    captured = io.StringIO()
    sys.stdout = captured
    try:
        render_output(cvs, clarg)
    finally:
        sys.stdout = sys.__stdout__
    out = captured.getvalue()
    assert "CVSS v4.0 Score = 7.3" in out
    assert "Severity = High" in out
    assert "CVSS v4.0 Vulnerability Vector = " in out
