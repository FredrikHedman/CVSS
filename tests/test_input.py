"""Unit tests for cvss_input interactive selection."""

from unittest.mock import patch

import pytest

from cvss.cvss_input import (
    read_metrics,
    read_metrics_as_dict,
    select_metric_value,
)
from cvss.vulnerability import base_metrics
from cvss.vulnerability_40 import base_metrics_40


def test_select_valid_input(capsys: pytest.CaptureFixture[str]) -> None:
    m = base_metrics()[0]  # AccessVector: L / A / N
    with patch("builtins.input", return_value="N"):
        result = select_metric_value(m)
    assert result == "N"
    assert "Access Vector" in capsys.readouterr().out


def test_select_empty_uses_default() -> None:
    m = base_metrics()[0]  # default index is "L" (first value)
    with patch("builtins.input", return_value=""):
        assert select_metric_value(m) == "L"


def test_select_retry_on_invalid(capsys: pytest.CaptureFixture[str]) -> None:
    m = base_metrics()[0]
    with patch("builtins.input", side_effect=["INVALID", "A"]):
        result = select_metric_value(m)
    assert result == "A"
    assert "Not valid" in capsys.readouterr().out


def test_read_metrics_returns_selected_values() -> None:
    metrics = base_metrics()[:2]  # AccessVector, AccessComplexity
    with patch("builtins.input", side_effect=["N", "L"]):
        result = read_metrics(metrics)
    assert result == ["N", "L"]


def test_read_metrics_as_dict_maps_abbrev_to_value() -> None:
    metrics = base_metrics_40()[:3]  # AV, AC, AT
    with patch("builtins.input", side_effect=["N", "L", "N"]):
        result = read_metrics_as_dict(metrics)
    assert result == {"AV": "N", "AC": "L", "AT": "N"}
