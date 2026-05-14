"""Unit tests for cvss2 ScoreDisplayData and render_output."""

from unittest.mock import MagicMock, patch

import pytest

from cvss2.cvss_210 import CommonVulnerabilityScore
from cvss2.cvss_output import (
    ScoreDisplayData,
    _footer_labels,  # pyright: ignore[reportPrivateUsage]
    _group_header,  # pyright: ignore[reportPrivateUsage]
    _show_flags,  # pyright: ignore[reportPrivateUsage]
    format_output,
)
from cvss2.cvss_types import CvssArgs
from cvss2.vulnerability import cvs_factory


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


def test_format_output_verbose_contains_base_table(
    base_clarg: CvssArgs,
) -> None:
    cvs = cvs_factory(CommonVulnerabilityScore)
    out = format_output(cvs, {**base_clarg, "verbose": True})
    assert "BASE METRIC" in out
    assert "BASE SCORE" in out
    assert isinstance(out, str)


@pytest.fixture
def base_clarg() -> CvssArgs:
    return {
        "verbose": False, "interactive": False, "all": False,
        "base": True, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": None,
    }


def test_format_output_non_verbose(base_clarg: CvssArgs) -> None:
    clarg: CvssArgs = {**base_clarg, "verbose": False}
    with patch("cvss2.cvss_output._generate_output") as mock_out, \
         patch("cvss2.cvss_output._generate_verbose_output") as mock_verb:
        result = format_output(MagicMock(), clarg)
    mock_out.assert_called_once()
    mock_verb.assert_not_called()
    assert isinstance(result, str)


def test_format_output_verbose(base_clarg: CvssArgs) -> None:
    clarg: CvssArgs = {**base_clarg, "verbose": True}
    with patch("cvss2.cvss_output._generate_output") as mock_out, \
         patch("cvss2.cvss_output._generate_verbose_output") as mock_verb:
        result = format_output(MagicMock(), clarg)
    mock_verb.assert_called_once()
    mock_out.assert_not_called()
    assert isinstance(result, str)


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


@pytest.mark.parametrize("name,expected_header,expected_footer", [
    ("BASE",
     ("BASE METRIC", "EVALUATION", "SCORE"),
     ["FORMULA", "BASE SCORE"]),
    ("TEMPORAL",
     ("TEMPORAL METRIC", "EVALUATION", "SCORE"),
     ["FORMULA", "TEMPORAL SCORE"]),
    ("EVIRONMENTAL",
     ("EVIRONMENTAL METRIC", "EVALUATION", "SCORE"),
     ["FORMULA", "EVIRONMENTAL SCORE"]),
])
def test_group_header(
    name: str,
    expected_header: tuple[str, str, str],
    expected_footer: list[str],
) -> None:
    assert _group_header(name) == expected_header
    assert _footer_labels(name) == expected_footer
