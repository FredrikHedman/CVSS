#!/usr/bin/env python3
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""
Calculate CVSS metrics based on a list of Metrics.

Usage:
  {PGM} [-v] --interactive --all
  {PGM} [-v] --interactive [--temporal] --base [<vector>]
  {PGM} [-v] --interactive [--environmental] --temporal --base [<vector>]
  {PGM} [-v] --base <vector>
  {PGM} [-v] --vulnerability <vector>
  {PGM} (--help | --version)

Options:
  -i --interactive          select metric values interactively
  -a --all                  ask for all metrics
  -b --base                 ask for base metrics
  -t --temporal             ask for temporal metrics
  -e --environmental        ask for environmental metrics
  <vector>                  base vulnerability vector
  --vulnerability <vector>  calculate score from vector

  -v --verbose              print verbose results
  -h --help                 show this help message and exit
  --version                 show version and exit

"""
VERSION = "1.17"

import sys
from os.path import basename
from docopt import docopt
from metric import Metric
from cvss_210 import CommonVulnerabilityScore

from vulnerability import VulnerabilityVector


def all_metrics():
    L = []
    L.extend(base_metrics())
    L.extend(temporal_metrics())
    L.extend(environmental_metrics())
    return L


def base_metrics():
    BASE_METRICS = [
        ["Access Vector", "AV",
         [("Local", "L", 0.395, "Local access"),
          ("Adjecent Network", "A", 0.646, "Adjacent network access"),
          ("Network", "N", 1.0, "Network access"), ]],
        ["Access Complexity", "AC",
         [("High", "H", 0.35, "Specialized access conditions exist"),
          ("Medium", "M", 0.61,
           "The access conditions are somewhat specialized"),
          ("Low", "L", 0.71, "No specialized access exist"), ]],
        ["Authentication", "Au",
         [("None", "N", 0.704, "Authentication not required"),
          ("Multiple", "M", 0.45, "Authenticate two or more times"),
          ("Single", "S", 0.56, "Logged into the system"), ]],
        ["Confidentiality Impact", "C",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275, "Considerable disclosure"),
          ("Complete", "C", 0.660, "Total inforamtion disclosure"), ]],
        ["Integrity Impact", "I",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275,
           "Possible to modify some system files or information"),
          ("Complete", "C", 0.660, "Total compromise of system integrity"), ]],
        ["Availability Impact", "A",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275,
           "Reduced performance or interruptions in resource availability"),
          ("Complete", "C", 0.660,
           "Total shutdown of the affected resource"), ]],
    ]
    return BASE_METRICS


def temporal_metrics():
    TEMPORAL_METRICS = [
        ["Exploitability", "E",
         [("Not Defined", "ND", 1.0, "Skip this metric"),
          ("Unproven", "U", 0.85, "No exploit code is available"),
          ("Proof-of-Concept", "POC", 0.9,
           "Proof-of-concept exploit code exists"),
          ("Functional", "F", 0.95, "Functional exploit code is available"),
          ("High", "H", 1.0,
           "Exploitable by functional mobile autonomous code"), ]],
        ["Remediation Level", "RL",
         [("Not Defined", "ND", 1.0,
           "Skip this metric"),
          ("Official Fix", "OF", 0.87,
           "Complete vendor solution is available"),
          ("Temporary Fix", "TF", 0.90,
           "Official but temporary fix available"),
          ("Workaround", "W", 0.95,
           "Unofficial, non-vendor solution available"),
          ("Unavailable", "U", 1.0,
           "No solution available or it is impossible to apply"), ]],
        ["Report Confidence", "RC",
         [("Not Defined", "ND", 1.0,
           "Skip this metric"),
          ("Unconfirmed", "UC", 0.90,
           "Single unconfirmed source"),
          ("Uncorroborated", "UR", 0.95,
           "Multiple non-official sources"),
          ("Confirmed", "C", 1.0,
           "Acknowledged by the vendor or author"), ]],
    ]
    return TEMPORAL_METRICS


def environmental_metrics():
    ENVIRONMENTAL_METRICS = [
        ["Collateral Damage Potential", "CDP",
         [("Not Defined", "ND", 0.0, "Skip this metric"),
          ("None", "N", 0.0, "No potential for loss of life"),
          ("Low", "L", 0.1,
           "Potential for slight physical or property damage"),
          ("Low-Medium", "LM", 0.3, "Moderate physical or property damage"),
          ("Medium-High", "MH", 0.4,
           "Significant physical or property damage or loss"),
          ("High", "H", 0.5,
           "Catastrophic physical or property damage and loss"), ]],
        ["Target Distribution", "TD",
         [("Not Defined", "ND", 1.0, "Skip this metric"),
          ("None", "N", 0.0, "No target systems exist"),
          ("Low", "L", 0.25,
           "Targets exist on a small scale inside the environment"),
          ("Medium", "M", 0.75, "Targets exist on a medium scale"),
          ("High", "H", 1.0, "Targets exist on a considerable scale"), ]],
        ["Confidentiality Requirement", "CR",
         [("Not Defined", "ND", 1.0, "Skip this metric"),
          ("Low", "L", 0.5, "Limited adverse effect"),
          ("Medium", "M", 1.0, "Serious adverse effect"),
          ("High", "H", 1.51, "Catastrophic adverse effect"), ]],
        ["Integrity Requirement", "IR",
         [("Not Defined", "ND", 1.0, "Skip this metric"),
          ("Low", "L", 0.5, "Limited adverse effect"),
          ("Medium", "M", 1.0, "Serious adverse effect"),
          ("High", "H", 1.51, "Catastrophic adverse effect"), ]],
        ["Availability Requirement", "AR",
         [("Not Defined", "ND", 1.0, "Skip this metric"),
          ("Low", "L", 0.5, "Limited adverse effect"),
          ("Medium", "M", 1.0, "Serious adverse effect"),
          ("High", "H", 1.51, "Catastrophic adverse effect"), ]],
    ]
    return ENVIRONMENTAL_METRICS


def add_padding(to_length, selected):
    if selected is None:
        selected = []
    padding = to_length - len(selected)
    if padding:
        selected.extend(padding * [None])
    return selected


def prepare_metrics(L, selected):
    lmetrics = []
    for ii, mm in enumerate(L):
        lmetrics.append(Metric(*mm, index=selected[ii]))
    return lmetrics


def cvs_factory(cls, selected=None):
    L = base_metrics()
    L.extend(temporal_metrics())
    L.extend(environmental_metrics())
    selected = add_padding(len(L), selected)
    lmetrics = prepare_metrics(L, selected)
    return cls(lmetrics)


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


def read_and_set(L, selected):
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)
    return selected


def generate_verbose_output(cvs, clarg):
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


def generate_output(cvs, clarg):
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


def cmd_line_syntax(str):
    return __doc__.format(PGM=basename(sys.argv[0]))


if __name__ == "__main__":
    clarg = docopt(cmd_line_syntax(__doc__), version=VERSION)

    if clarg["--interactive"]:
        selected = []
        if clarg["--base"]:
            if clarg["<vector>"]:
                try:
                    vvec = VulnerabilityVector(clarg["<vector>"])
                    selected.extend(vvec.valid().complete().metric_values())
                except Exception as e:
                    sys.exit(1)
            else:
                selected = read_and_set(base_metrics(), selected)
        if clarg["--temporal"]:
            selected = read_and_set(temporal_metrics(), selected)
        if clarg["--temporal"] and clarg["--environmental"]:
            selected = read_and_set(environmental_metrics(), selected)
        if clarg["--all"]:
            selected = read_and_set(base_metrics(), selected)
            selected = read_and_set(temporal_metrics(), selected)
            selected = read_and_set(environmental_metrics(), selected)
        cvs = cvs_factory(CommonVulnerabilityScore, selected)
    elif clarg["--base"]:
        try:
            vvec = VulnerabilityVector(clarg["<vector>"])
            cvs = cvs_factory(CommonVulnerabilityScore,
                              vvec.valid().complete().metric_values())
        except Exception as e:
            sys.exit(1)
    elif clarg["--vulnerability"]:
        clarg["--all"] = True
        vvec = VulnerabilityVector(clarg["--vulnerability"])
        cvs = cvs_factory(CommonVulnerabilityScore,
                          vvec.valid().metric_values())
    else:
        print('You need to use --help ...')
        sys.exit(1)

    if clarg["--verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)
