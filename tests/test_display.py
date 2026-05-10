"""Unit tests for ScoreDisplayData and render_output."""

from unittest.mock import MagicMock, patch

import pytest

from cvss.cvss_output import ScoreDisplayData, render_output
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
