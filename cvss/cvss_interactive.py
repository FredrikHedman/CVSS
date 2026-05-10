#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
"""Extracted interactive functions."""

from dataclasses import dataclass

from .cvss_base import CVSS
from .cvss_types import CvssArgs, ScoreEntry
from .metric import Metric
from .vulnerability import MetricDefinition


@dataclass(frozen=True)
class ScoreDisplayData:
    """All data needed to render one score table via display_score."""

    header: tuple[str, str, str]
    footer_labels: list[str]
    metrics: list[Metric]
    footer_data: list[tuple[str, float]]
    vector_label: tuple[str, str]


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


def display_score(data: ScoreDisplayData) -> None:
    """Formatted score that recreates format of the CVSS examples."""

    def display_header() -> None:
        print(s1)
        h = data.header
        print(f"{h[0]:<{w0}}{h[1]:<{w0}}{h[2]}")

    def display_metrics() -> None:
        print(s1)
        for m in data.metrics:
            print(
                f"{m.name:<{w0}}{m.selected.metric:<{w0}}"
                + f"{m.selected.number:>{w1}.2f}"
            )

    def display_footer() -> None:
        print(s1)
        w2 = len(s1) - len(data.footer_labels[1])
        print(f"{data.footer_labels[0]:<{w2}}{data.footer_labels[1]}")

    def display_footer_data() -> None:
        print(s1)
        for label, value in data.footer_data:
            print(f"{label + ' =':<{2 * w0}}{value:>{w1}.2f}")
        vl = data.vector_label
        print(f"{vl[0]} Vulnerability Vector: {vl[1]}")
        print(s1)

    w0 = 30
    w1 = len(data.header[2])
    s1 = (w0 * 2 + w1) * "="
    display_header()
    display_metrics()
    display_footer()
    display_footer_data()


def generate_output(cvs: CVSS, clarg: CvssArgs) -> None:
    """Print requested scores."""
    entries: list[tuple[bool, ScoreEntry]] = [
        (clarg["base"] or clarg["all"],
         ScoreEntry("Base", cvs.base_score, cvs.base_vulnerability_vector)),
        (clarg["temporal"] or clarg["all"],
         ScoreEntry("Temporal", cvs.temporal_score,
                    cvs.temporal_vulnerability_vector)),
        (clarg["environmental"] or clarg["all"],
         ScoreEntry("Environmental", cvs.environmental_score,
                    cvs.environmental_vulnerability_vector)),
    ]
    print()
    for show, score in entries:
        if show:
            print(f"{score.name} Score = {score.value}")
            print(f"{score.name} Vulnerability Vector = {score.vector}")
    print()


def generate_verbose_output(cvs: CVSS, clarg: CvssArgs) -> None:
    """Generate output when verbose output requested."""
    entries: list[tuple[bool, ScoreDisplayData]] = [
        (clarg["base"] or clarg["all"],
         ScoreDisplayData(
             header=("BASE METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "BASE SCORE"],
             metrics=cvs.base_metrics(),
             footer_data=[
                 ("Impact", cvs.impact),
                 ("Exploitability", cvs.exploitability),
                 ("Base Score", cvs.base_score),
             ],
             vector_label=("Base", cvs.base_vulnerability_vector),
         )),
        (clarg["temporal"] or clarg["all"],
         ScoreDisplayData(
             header=("TEMPORAL METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "TEMPORAL SCORE"],
             metrics=cvs.temporal_metrics(),
             footer_data=[("Temporal Score", cvs.temporal_score)],
             vector_label=("Temporal", cvs.temporal_vulnerability_vector),
         )),
        (clarg["environmental"] or clarg["all"],
         ScoreDisplayData(
             header=("ENIRONMENTAL METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "ENIRONMENTAL SCORE"],
             metrics=cvs.environmental_metrics(),
             footer_data=[
                 ("Adjusted Impact", cvs.adjusted_impact),
                 ("Adjusted Base", cvs.adjusted_base_score),
                 ("Adjusted Temporal", cvs.adjusted_temporal_score),
                 ("Environmental Score", cvs.environmental_score),
             ],
             vector_label=(
                 "Environmental",
                 cvs.environmental_vulnerability_vector,
             ),
         )),
    ]
    for show, data in entries:
        if show:
            display_score(data)
