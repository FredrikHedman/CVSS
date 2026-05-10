"""CVSS command handlers and dispatch for all CLI modes."""

import sys
from typing import NoReturn, cast

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_input import read_metrics
from .cvss_types import CvssArgs
from .vulnerability import (
    InvalidBaseVectorError,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
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


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSS:
    selected: list[str] = []
    if clarg["all"]:
        selected.extend(read_metrics(base_metrics()))
        selected.extend(read_metrics(temporal_metrics()))
        selected.extend(read_metrics(environmental_metrics()))
    elif clarg["base"]:
        if clarg["vector"]:
            try:
                vvec = VulnerabilityVector(clarg["vector"])
                selected.extend(vvec.valid().complete().metric_values())
            except (InvalidBaseVectorError, ValueError) as e:
                _exit_with_error(e)
        else:
            selected.extend(read_metrics(base_metrics()))
        if clarg["temporal"]:
            selected.extend(read_metrics(temporal_metrics()))
            if clarg["environmental"]:
                selected.extend(read_metrics(environmental_metrics()))
    return cvs_factory(CommonVulnerabilityScore, selected)


def process_cmd_line(clarg: CvssArgs) -> CVSS:
    """Dispatch to the appropriate command-line handler."""
    if clarg["interactive"]:
        return process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        return process_cmd_line_base(cast(str, clarg["vector"]))
    elif clarg["vulnerability"]:
        return process_cmd_line_vulnerability(clarg["vulnerability"])
    raise RuntimeError("unreachable")
