"""Unit tests for MetricDefinition and derived validation dicts."""

from cvss2.vulnerability import (
    BASE,
    BASE_DEFINITIONS,
    ENVIRONMENTAL,
    ENVIRONMENTAL_DEFINITIONS,
    TEMPORAL,
    TEMPORAL_DEFINITIONS,
    MetricValueDef,
    all_metrics,
)


def test_base_validation_dict_keys() -> None:
    assert list(BASE.keys()) == ["AV", "AC", "Au", "C", "I", "A"]


def test_temporal_validation_dict_keys() -> None:
    assert list(TEMPORAL.keys()) == ["E", "RL", "RC"]


def test_environmental_validation_dict_keys() -> None:
    assert list(ENVIRONMENTAL.keys()) == ["CDP", "TD", "CR", "IR", "AR"]


def test_base_av_values() -> None:
    assert BASE["AV"] == ["L", "A", "N"]


def test_definition_allowed_abbrevs() -> None:
    av = BASE_DEFINITIONS[0]
    assert av.abbrev == "AV"
    assert av.allowed_abbrevs() == ["L", "A", "N"]


def test_definition_metric_values_tuple_shape() -> None:
    av = BASE_DEFINITIONS[0]
    first = av.metric_values()[0]
    assert first == ("Local", "L", 0.395, "Local access")


def test_all_metrics_count() -> None:
    total = (
        len(BASE_DEFINITIONS)
        + len(TEMPORAL_DEFINITIONS)
        + len(ENVIRONMENTAL_DEFINITIONS)
    )
    assert len(all_metrics()) == total


def test_definition_immutable() -> None:
    import pytest
    from dataclasses import FrozenInstanceError

    d = BASE_DEFINITIONS[0]
    with pytest.raises(FrozenInstanceError):
        d.abbrev = "XX"  # type: ignore[misc]


def test_metric_value_def_as_tuple() -> None:
    mvd = MetricValueDef("Local", "L", 0.395, "Local access")
    assert mvd.as_tuple() == ("Local", "L", 0.395, "Local access")


def test_validation_dicts_derived_from_definitions() -> None:
    """Verify validation dicts match MetricDefinition.allowed_abbrevs."""
    for d in BASE_DEFINITIONS:
        assert BASE[d.abbrev] == d.allowed_abbrevs()
    for d in TEMPORAL_DEFINITIONS:
        assert TEMPORAL[d.abbrev] == d.allowed_abbrevs()
    for d in ENVIRONMENTAL_DEFINITIONS:
        assert ENVIRONMENTAL[d.abbrev] == d.allowed_abbrevs()
