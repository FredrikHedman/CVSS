"""Unit tests for the MetricValue frozen dataclass."""

import pytest
from dataclasses import FrozenInstanceError

from cvss2.metric_value import MetricValue


@pytest.fixture
def local() -> MetricValue:
    return MetricValue("Local", "L", 0.395, "Local access")


def test_str(local: MetricValue) -> None:
    assert str(local) == "L"


def test_float(local: MetricValue) -> None:
    assert float(local) == 0.395


def test_field_access(local: MetricValue) -> None:
    assert local.metric == "Local"
    assert local.value == "L"
    assert local.number == 0.395
    assert local.description == "Local access"


def test_immutable(local: MetricValue) -> None:
    with pytest.raises(FrozenInstanceError):
        local.value = "X"  # type: ignore[misc]


def test_hashable(local: MetricValue) -> None:
    s: set[MetricValue] = {local}
    assert local in s


def test_equality() -> None:
    mv1 = MetricValue("Local", "L", 0.395, "Local access")
    mv2 = MetricValue("Local", "L", 0.395, "Local access")
    assert mv1 == mv2


def test_inequality() -> None:
    mv1 = MetricValue("Local", "L", 0.395, "Local access")
    mv2 = MetricValue("Network", "N", 1.0, "Network access")
    assert mv1 != mv2
