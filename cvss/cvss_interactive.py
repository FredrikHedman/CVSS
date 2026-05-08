#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
"""Extracted interactive functions."""

from .metric import Metric


def select_metric_value(m):
    """Interactive selection of a metric value.

    Input:
       m : list of values that can be unpacked into valid
           parameters for constructing a Metric
    Return:
       a valid index for the Metric

    """
    m = Metric(*m)
    default_metric_value = m.index
    sep = 10 * "+"
    print(f"\n{sep} {m.name} {m.short_name} {sep}")
    while True:
        for v in m.values:
            print(v, v.description)
        idx = input(f"Select one [{default_metric_value}]: ").upper()

        if not idx:
            idx = default_metric_value

        print("Selected metric value ###|", idx, "|###")

        try:
            m.index = idx
        except AssertionError:
            print("Not valid")
        else:
            return m.index


def display_score(H, F, ML, FD, VEC):
    """Formatted score that recreates format of the CVSS examples."""

    def display_header(H):
        print(s1)
        print(f"{H[0]:<{w0}}{H[1]:<{w0}}{H[2]}")

    def display_metrics(ML):
        print(s1)
        for m in ML:
            print(
                f"{m.name:<{w0}}{m.selected.metric:<{w0}}"
                f"{m.selected.number:>{w1}.2f}"
            )

    def display_footer(F):
        print(s1)
        w2 = len(s1) - len(F[1])
        print(f"{F[0]:<{w2}}{F[1]}")

    def display_footer_data(FD, VEC):
        print(s1)
        for d in FD:
            print(f"{d[0] + ' =':<{2 * w0}}{d[1]:>{w1}.2f}")
        print(f"{VEC[0]} Vulnerability Vector: {VEC[1]}")
        print(s1)

    #
    w0 = 30
    w1 = len(H[2])
    s1 = (w0 * 2 + w1) * "="
    #
    display_header(H)
    display_metrics(ML)
    display_footer(F)
    display_footer_data(FD, VEC)


def generate_output(cvs, clarg):
    """Print requested scores."""
    show = [
        clarg["--base"] or clarg["--all"],
        clarg["--temporal"] or clarg["--all"],
        clarg["--environmental"] or clarg["--all"],
    ]
    list_of_scores = [
        ("Base", cvs.base_score, cvs.base_vulnerability_vector),
        ("Temporal", cvs.temporal_score, cvs.temporal_vulnerability_vector),
        (
            "Environmental",
            cvs.environmental_score,
            cvs.environmental_vulnerability_vector,
        ),
    ]
    print()
    for s, score in zip(show, list_of_scores):
        if s:
            print(
                f"{score[0]} Score = {score[1]}\n"
                f"{score[0]} Vulnerability Vector = {score[2]}"
            )
    print()


def generate_verbose_output(cvs, clarg):
    """Generate output when verbose output requested."""
    show = [clarg["--base"], clarg["--temporal"], clarg["--environmental"]]
    if show[0] or clarg["--all"]:
        display_score(
            ["BASE METRIC", "EVALUATION", "SCORE"],
            ["FORMULA", "BASE SCORE"],
            cvs.base_metrics(),
            [
                ("Impact", cvs.impact),
                ("Exploitability", cvs.exploitability),
                ("Base Score", cvs.base_score),
            ],
            ("Base", cvs.base_vulnerability_vector),
        )
    if show[1] or clarg["--all"]:
        display_score(
            ["TEMPORAL METRIC", "EVALUATION", "SCORE"],
            ["FORMULA", "TEMPORAL SCORE"],
            cvs.temporal_metrics(),
            [("Temporal Score", cvs.temporal_score)],
            ("Temporal", cvs.temporal_vulnerability_vector),
        )
    if show[2] or clarg["--all"]:
        display_score(
            ["ENIRONMENTAL METRIC", "EVALUATION", "SCORE"],
            ["FORMULA", "ENIRONMENTAL SCORE"],
            cvs.environmental_metrics(),
            [
                ("Adjusted Impact", cvs.adjusted_impact),
                ("Adjusted Base", cvs.adjusted_base_score),
                ("Adjusted Temporal", cvs.adjusted_temporal_score),
                ("Environmental Score", cvs.environmental_score),
            ],
            ("Environmental", cvs.environmental_vulnerability_vector),
        )
