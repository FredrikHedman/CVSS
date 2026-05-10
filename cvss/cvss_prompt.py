"""Interactive CLI prompting for CVSS metric selection."""

import sys

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_types import CvssArgs
from .metric import Metric
from .vulnerability import (
    InvalidBaseVectorError,
    MetricDefinition,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
)


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


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSS:
    selected: list[str] = []
    if clarg["base"]:
        if clarg["vector"]:
            try:
                vvec = VulnerabilityVector(clarg["vector"])
                selected.extend(vvec.valid().complete().metric_values())
            except (InvalidBaseVectorError, ValueError) as e:
                print(e)
                sys.exit(1)
        else:
            selected.extend(read_metrics(base_metrics()))
    if clarg["temporal"]:
        selected.extend(read_metrics(temporal_metrics()))
    if clarg["temporal"] and clarg["environmental"]:
        selected.extend(read_metrics(environmental_metrics()))
    if clarg["all"]:
        selected.extend(read_metrics(base_metrics()))
        selected.extend(read_metrics(temporal_metrics()))
        selected.extend(read_metrics(environmental_metrics()))
    return cvs_factory(CommonVulnerabilityScore, selected)
