#!/usr/bin/env python
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
VERSION = "1.20"

import sys
from os.path import basename
from docopt import docopt
from metric import Metric
from cvss_210 import CommonVulnerabilityScore
from vulnerability import VulnerabilityVector
from cvss_interactive import select_metric_value
from cvss_interactive import display_score
from cvss_interactive import generate_output


def all_metrics():
    """Build and return a list of all metrics."""
    L = []
    L.extend(base_metrics())
    L.extend(temporal_metrics())
    L.extend(environmental_metrics())
    return L


def base_metrics():
    """Wrap base metrics data and possible values."""
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
    """Wrap temporal metrics data and possible values."""
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
    """Wrap environmental metrics data and possible values."""
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
    """Extend selected to_length elements."""
    if selected is None:
        selected = []
    padding = to_length - len(selected)
    if padding > 0:
        selected.extend(padding * [None])
    return selected


def prepare_metrics(L, selected):
    """Prepare a list of selected metrics."""
    lmetrics = []
    for ii, mm in enumerate(L):
        lmetrics.append(Metric(*mm, index=selected[ii]))
    return lmetrics


def cvs_factory(cls, selected=None):
    """Common Vulnerability Score factory."""
    L = all_metrics()
    selected = add_padding(len(L), selected)
    lmetrics = prepare_metrics(L, selected)
    return cls(lmetrics)


def read_and_set(L, selected):
    """Read and set selected metrics."""
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)
    return selected


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


def cmd_line_syntax(str):
    """Parameterized help message."""
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
