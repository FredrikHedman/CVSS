#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20
# LICENSE: MIT LICENSE
#
"""Extracted interactive functions.

These need to use print and input and be indepenet of version.
"""
from __future__ import print_function
from metric import Metric

# Cater for PEP 3111 so that python3 code can still work when using python2.
try:
    import __builtin__
    input = getattr(__builtin__, 'raw_input')
except (ImportError, AttributeError):
    pass


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
    print("\n{0} {1} {2} {0}".format(10 * "+", m.name, m.short_name))
    while True:
        for v in m.values:
            print(v, v.description)
        idx = input('Select one [{0}]: '.format(default_metric_value)).upper()

        if not idx:
            idx = default_metric_value

        print('Selected metric value ###|', idx, '|###')

        try:
            m.index = idx
        except AssertionError:
            print('Not valid')
        else:
            return m.index


def display_score(H, F, ML, FD, VEC):
    """Formatted score that recreates format of the CVSS examples."""
    def display_header(H):
        print('{0:<{3}}{1:<{3}}{2}'.format(H[0], H[1], H[2], W0))

    def display_metrics(ML):
        for m in ML:
            print('{0:<{3}}{1:<{3}}{2:>{4}.2f}'.format(m.name,
                                                       m.selected.metric,
                                                       m.selected.number,
                                                       W0, W1))

    def display_footer(F):
        W2 = len(S1) - len(F[1])
        print('{0:<{2}}{1}'.format(F[0], F[1], W2))

    def display_footer_data(FD, VEC):
        for d in FD:
            print('{0:<{2}}{1:>{3}.2f}'.format(d[0] + ' =', d[1], 2 * W0, W1))
        print('{1} Vulnerability Vector: {0}'.format(VEC[1], VEC[0]))
    #
    W0 = 30
    W1 = len(H[2])
    S1 = (W0 * 2 + W1) * '='
    #
    print(S1)
    display_header(H)
    print(S1)
    display_metrics(ML)
    print(S1)
    display_footer(F)
    print(S1)
    display_footer_data(FD, VEC)
    print(S1)


def generate_output(cvs, clarg):
    """Print requested scores."""
    show = [clarg["--base"] or clarg["--all"],
            clarg["--temporal"] or clarg["--all"],
            clarg["--environmental"] or clarg["--all"]]
    list_of_scores = [
        ('Base',
         cvs.base_score, cvs.base_vulnerability_vector),
        ('Temporal',
         cvs.temporal_score, cvs.temporal_vulnerability_vector),
        ('Environmental',
         cvs.environmental_score, cvs.environmental_vulnerability_vector),
    ]
    output_line = "{0[0]} Score = {0[1]}\n{0[0]} Vulnerability Vector = {0[2]}"
    print()
    for s, score in zip(show, list_of_scores):
        if s:
            print(output_line.format(score))
    print()


def generate_verbose_output(cvs, clarg):
    """Generate output when verbose output requested."""
    show = [clarg["--base"], clarg["--temporal"], clarg["--environmental"]]
    if show[0] or clarg["--all"]:
        display_score(["BASE METRIC", "EVALUATION", "SCORE"],
                      ["FORMULA", "BASE SCORE"],
                      cvs.base_metrics(),
                      [('Impact', cvs.impact),
                       ('Exploitability', cvs.exploitability),
                       ('Base Score', cvs.base_score)],
                      ('Base', cvs.base_vulnerability_vector))
    if show[1] or clarg["--all"]:
        display_score(["TEMPORAL METRIC", "EVALUATION", "SCORE"],
                      ["FORMULA", "TEMPORAL SCORE"],
                      cvs.temporal_metrics(),
                      [('Temporal Score', cvs.temporal_score)],
                      ('Temporal', cvs.temporal_vulnerability_vector))
    if show[2] or clarg["--all"]:
        display_score(["ENIRONMENTAL METRIC", "EVALUATION", "SCORE"],
                      ["FORMULA", "ENIRONMENTAL SCORE"],
                      cvs.environmental_metrics(),
                      [('Adjusted Impact', cvs.adjusted_impact),
                       ('Adjusted Base', cvs.adjusted_base_score),
                       ('Adjusted Temporal', cvs.adjusted_temporal_score),
                       ('Environmental Score', cvs.environmental_score)],
                      ('Environmental',
                       cvs.environmental_vulnerability_vector))
