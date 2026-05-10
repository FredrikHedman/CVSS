#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Calculate CVSS metrics based on a list of Metrics."""

from typing import cast

from .cvss_base import CVSS
from .cvss_handlers import (
    process_cmd_line_base,
    process_cmd_line_vulnerability,
)
from .cvss_interactive import (
    generate_output,
    generate_verbose_output,
    process_cmd_line_interactive,
)
from .cvss_parser import parse_and_validate
from .cvss_types import CvssArgs


def process_cmd_line(clarg: CvssArgs) -> CVSS:
    """Dispatch to the appropriate command-line handler."""
    if clarg["interactive"]:
        return process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        return process_cmd_line_base(cast(str, clarg["vector"]))
    elif clarg["vulnerability"]:
        return process_cmd_line_vulnerability(clarg["vulnerability"])
    raise RuntimeError("unreachable")


def main() -> None:
    clarg = parse_and_validate()
    cvs = process_cmd_line(clarg)
    if clarg["verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)


if __name__ == "__main__":
    main()
