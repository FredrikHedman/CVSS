"""CVSS command handlers and dispatch for all CLI modes."""

import sys
from typing import NoReturn, cast

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_interactive import process_cmd_line_interactive
from .cvss_types import CvssArgs
from .vulnerability import (
    InvalidBaseVectorError,
    VulnerabilityVector,
    cvs_factory,
)


def _exit_with_error(e: Exception) -> NoReturn:
    print(e)
    sys.exit(1)


def process_cmd_line_base(vector: str) -> CVSS:
    try:
        vvec = VulnerabilityVector(vector)
        cvs = cvs_factory(
            CommonVulnerabilityScore, vvec.valid().complete().metric_values()
        )
    except (InvalidBaseVectorError, ValueError) as e:
        _exit_with_error(e)
    return cvs


def process_cmd_line_vulnerability(vulnerability: str) -> CVSS:
    try:
        vvec = VulnerabilityVector(vulnerability)
        cvs = cvs_factory(
            CommonVulnerabilityScore, vvec.valid().metric_values()
        )
    except (InvalidBaseVectorError, ValueError) as e:
        _exit_with_error(e)
    return cvs


def process_cmd_line(clarg: CvssArgs) -> CVSS:
    """Dispatch to the appropriate command-line handler."""
    if clarg["interactive"]:
        return process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        return process_cmd_line_base(cast(str, clarg["vector"]))
    elif clarg["vulnerability"]:
        return process_cmd_line_vulnerability(clarg["vulnerability"])
    raise RuntimeError("unreachable")
