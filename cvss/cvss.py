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
VERSION = "1.20.1"

import sys
from os.path import basename
from docopt import docopt

from cvss.cvss_210 import CommonVulnerabilityScore

from cvss.vulnerability import VulnerabilityVector
from cvss.vulnerability import cvs_factory
from cvss.vulnerability import base_metrics
from cvss.vulnerability import temporal_metrics
from cvss.vulnerability import environmental_metrics

from cvss.cvss_interactive import select_metric_value
from cvss.cvss_interactive import generate_output
from cvss.cvss_interactive import generate_verbose_output


def read_and_set(L, selected):
    """Read and set selected metrics."""
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)
    return selected


def cmd_line_syntax(str):
    """Parameterized help message."""
    return __doc__.format(PGM=basename(sys.argv[0]))


def process_cmd_line(clarg):
    """React to the command line."""
    if clarg["--interactive"]:
        selected = []
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
    elif clarg["--base"]:
        try:
            vvec = VulnerabilityVector(clarg["<vector>"])
            cvs = cvs_factory(CommonVulnerabilityScore,
                              vvec.valid().complete().metric_values())
        except Exception as e:
            print(e)
            sys.exit(1)
    elif clarg["--vulnerability"]:
        clarg["--all"] = True
        vvec = VulnerabilityVector(clarg["--vulnerability"])
        cvs = cvs_factory(CommonVulnerabilityScore,
                          vvec.valid().metric_values())
    else:
        print('You need to use --help ...')
        sys.exit(1)
    return cvs


def main():
    # Create command line parser and parse it.
    clarg = docopt(cmd_line_syntax(__doc__), version=VERSION)

    cvs = process_cmd_line(clarg)

    if clarg["--verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)


if __name__ == "__main__":
    main()
