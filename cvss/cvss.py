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

import sys
from importlib.metadata import version
from os.path import basename
from typing import Any

from docopt import docopt  # type: ignore[import-untyped]

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_interactive import (
    generate_output,
    generate_verbose_output,
    select_metric_value,
)
from .vulnerability import (
    MetricDef,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
)

_USAGE: str = __doc__ or ""
VERSION = version("cvss")


def read_and_set(L: list[MetricDef], selected: list[str]) -> list[str]:
    """Read and set selected metrics."""
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)
    return selected


def cmd_line_syntax(s: str) -> str:
    """Parameterized help message."""
    return _USAGE.format(PGM=basename(sys.argv[0]))


def process_cmd_line_interactive(clarg: dict[str, Any]) -> CVSS:
    selected: list[str] = []
    if clarg["--base"]:
        if clarg["<vector>"]:
            try:
                vvec = VulnerabilityVector(clarg["<vector>"])
                selected.extend(vvec.valid().complete().metric_values())
            except Exception as e:
                print(e)
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
    return cvs


def process_cmd_line_base(clarg: dict[str, Any]) -> CVSS:
    try:
        vvec = VulnerabilityVector(clarg["<vector>"])
        cvs = cvs_factory(
            CommonVulnerabilityScore, vvec.valid().complete().metric_values()
        )
    except Exception as e:
        print(e)
        sys.exit(1)
    return cvs


def process_cmd_line_vulnerability(clarg: dict[str, Any]) -> CVSS:
    clarg["--all"] = True
    vvec = VulnerabilityVector(clarg["--vulnerability"])
    cvs = cvs_factory(CommonVulnerabilityScore, vvec.valid().metric_values())
    return cvs


def process_cmd_line(clarg: dict[str, Any]) -> CVSS:
    """React to the command line."""
    if clarg["--interactive"]:
        cvs = process_cmd_line_interactive(clarg)
    elif clarg["--base"]:
        cvs = process_cmd_line_base(clarg)
    elif clarg["--vulnerability"]:
        cvs = process_cmd_line_vulnerability(clarg)
    else:
        print("You need to use --help ...")
        sys.exit(1)
    return cvs


def main() -> None:
    # Create command line parser and parse it.
    clarg = docopt(cmd_line_syntax(_USAGE), version=VERSION)

    cvs = process_cmd_line(clarg)

    if clarg["--verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)


if __name__ == "__main__":
    main()
