"""Unit tests for the Metric class."""

import pytest

from cvss.metric import Metric


@pytest.fixture
def av() -> Metric:
    return Metric(
        "Access Vector",
        "AV",
        [
            ("Local", "L", 0.395, "Local access"),
            ("Network", "N", 1.0, "Network access"),
        ],
    )


def test_default_index_is_first_value(av: Metric) -> None:
    assert av.index == "L"


def test_set_valid_index(av: Metric) -> None:
    av.index = "N"
    assert av.index == "N"


def test_set_invalid_index_raises(av: Metric) -> None:
    with pytest.raises(ValueError):
        av.index = "X"


def test_selected_reflects_index(av: Metric) -> None:
    av.index = "N"
    assert float(av) == 1.0
    assert str(av) == "N"


def test_values_list(av: Metric) -> None:
    assert len(av.values) == 2


def test_name_and_short_name(av: Metric) -> None:
    assert av.name == "Access Vector"
    assert av.short_name == "AV"


def test_explicit_index_at_construction() -> None:
    m = Metric(
        "AC",
        "AC",
        [("High", "H", 0.35, "High"), ("Low", "L", 0.71, "Low")],
        index="L",
    )
    assert m.index == "L"


def test_empty_metric_values_raises() -> None:
    with pytest.raises(ValueError):
        _ = Metric("X", "X", [])
