#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Calculate CVSS v2.10 metrics."""

from .cvss_handlers import process_cmd_line
from .cvss_output import render_output
from .cvss_parser import parse_and_validate


def main() -> None:
    clarg = parse_and_validate()
    cvs = process_cmd_line(clarg)
    render_output(cvs, clarg)


if __name__ == "__main__":
    main()
