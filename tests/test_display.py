"""Unit tests for ScoreDisplayData."""

import pytest

from cvss.cvss_interactive import ScoreDisplayData


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
