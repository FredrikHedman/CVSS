"""Unit tests for cvss2 ScoreDisplayData and render_output."""

from unittest.mock import MagicMock, patch

import pytest

from cvss2.cvss_output import (
    ScoreDisplayData,
    _show_flags,  # pyright: ignore[reportPrivateUsage]
    display_score,
    render_output,
)
from cvss2.cvss_types import CvssArgs


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


def test_display_score_prints_header(
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = ScoreDisplayData(
        header=("BASE METRIC", "EVALUATION", "SCORE"),
        footer_labels=["FORMULA", "BASE SCORE"],
        metrics=[],
        footer_data=[("Base Score", 7.5)],
        vector_label=("Base", "AV:N/AC:L"),
    )
    display_score(data)
    out = capsys.readouterr().out
    assert "BASE METRIC" in out
    assert "BASE SCORE" in out
    assert "7.50" in out


@pytest.fixture
def base_clarg() -> CvssArgs:
    return {
        "verbose": False, "interactive": False, "all": False,
        "base": True, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": None,
    }


def test_render_output_non_verbose(base_clarg: CvssArgs) -> None:
    clarg: CvssArgs = {**base_clarg, "verbose": False}
    with patch("cvss2.cvss_output._generate_output") as mock_out, \
         patch("cvss2.cvss_output._generate_verbose_output") as mock_verb:
        render_output(MagicMock(), clarg)
    mock_out.assert_called_once()
    mock_verb.assert_not_called()


def test_render_output_verbose(base_clarg: CvssArgs) -> None:
    clarg: CvssArgs = {**base_clarg, "verbose": True}
    with patch("cvss2.cvss_output._generate_output") as mock_out, \
         patch("cvss2.cvss_output._generate_verbose_output") as mock_verb:
        render_output(MagicMock(), clarg)
    mock_verb.assert_called_once()
    mock_out.assert_not_called()


def _clarg(**kwargs: bool) -> CvssArgs:
    base: CvssArgs = {
        "verbose": False, "interactive": False, "all": False,
        "base": False, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": None,
    }
    return {**base, **kwargs}  # type: ignore[misc]


@pytest.mark.parametrize("flags,expected", [
    ({"base": True},                    (True,  False, False)),
    ({"temporal": True},                (False, True,  False)),
    ({"environmental": True},           (False, False, True)),
    ({"all": True},                     (True,  True,  True)),
    ({"all": True, "base": False},      (True,  True,  True)),
    ({},                                (False, False, False)),
    ({"base": True, "temporal": True},  (True,  True,  False)),
])
def test_show_flags(
    flags: dict[str, bool],
    expected: tuple[bool, bool, bool],
) -> None:
    assert _show_flags(_clarg(**flags)) == expected
