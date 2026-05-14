#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Calculate CVSS v4.0 metrics."""

import sys

from .cvss_handlers import process_cmd_line
from .cvss_output import format_output
from .cvss_parser import parse_and_validate


def main() -> None:
    clarg = parse_and_validate()
    cvs = process_cmd_line(clarg)
    _ = sys.stdout.write(format_output(cvs, clarg))


if __name__ == "__main__":
    main()
