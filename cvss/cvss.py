#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Calculate CVSS metrics based on a list of Metrics."""

from .cvss_handlers import process_cmd_line
from .cvss_output import generate_output, generate_verbose_output
from .cvss_parser import parse_and_validate


def main() -> None:
    clarg = parse_and_validate()
    cvs = process_cmd_line(clarg)
    if clarg["verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)


if __name__ == "__main__":
    main()
