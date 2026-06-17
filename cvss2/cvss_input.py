"""Interactive terminal input for CVSS metric selection."""

from .metric import Metric
from .vulnerability import MetricDefinition


def select_metric_value(m: MetricDefinition) -> str:
    """Interactive selection of a metric value.

    Input:
       m : MetricDefinition describing the metric and its allowed values
    Return:
       a valid index for the Metric

    """
    metric = Metric(m.name, m.abbrev, m.metric_values())
    default_metric_value = metric.index
    sep = 10 * "+"
    print(f"\n{sep} {metric.name} {metric.short_name} {sep}")
    while True:
        for v in metric.values:
            print(v, v.description)
        idx = input(f"Select one [{default_metric_value}]: ").upper()

        if not idx:
            idx = default_metric_value

        try:
            metric.index = idx
        except ValueError:
            print("Not valid")
        else:
            return metric.index


def read_metrics(L: list[MetricDefinition]) -> list[str]:
    """Interactively read metric values and return them as a list."""
    return [select_metric_value(m) for m in L]


