"""CVSS command handlers and dispatch for all CLI modes."""

import sys
from typing import NoReturn, cast

from .cvss_210 import CommonVulnerabilityScore
from .cvss_40 import CommonVulnerabilityScore40
from .cvss_base import CVSS
from .cvss_input import read_metrics
from .cvss_types import CVSSResult, CvssArgs
from .vulnerability import (
    InvalidBaseVectorError,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
)
from .vulnerability_40 import (
    InvalidVectorError,
    VulnerabilityVector40,
    base_metrics_40,
    environmental_metrics_40,
    supplemental_metrics_40,
    threat_metrics_40,
)

_V40_PREFIX = "CVSS:4.0/"


def _exit_with_error(e: Exception) -> NoReturn:
    print(e)
    sys.exit(1)


def process_cmd_line_base(vector: str) -> CVSSResult:
    if vector.startswith(_V40_PREFIX):
        try:
            vvec = VulnerabilityVector40(vector)
            return CommonVulnerabilityScore40(
                vvec.valid().complete().parsed
            )
        except (InvalidVectorError, ValueError) as e:
            _exit_with_error(e)
    else:
        try:
            vvec = VulnerabilityVector(vector)
            cvs: CVSS = cvs_factory(
                CommonVulnerabilityScore,
                vvec.valid().complete().metric_values(),
            )
        except (InvalidBaseVectorError, ValueError) as e:
            _exit_with_error(e)
        return cvs


def process_cmd_line_vulnerability(vulnerability: str) -> CVSSResult:
    if vulnerability.startswith(_V40_PREFIX):
        try:
            vvec = VulnerabilityVector40(vulnerability)
            return CommonVulnerabilityScore40(vvec.valid().complete().parsed)
        except (InvalidVectorError, ValueError) as e:
            _exit_with_error(e)
    else:
        try:
            vvec = VulnerabilityVector(vulnerability)
            cvs: CVSS = cvs_factory(
                CommonVulnerabilityScore, vvec.valid().metric_values()
            )
        except (InvalidBaseVectorError, ValueError) as e:
            _exit_with_error(e)
        return cvs


def _interactive_v40(clarg: CvssArgs) -> CVSSResult:
    selected: list[str] = []
    all_defs = (
        list(base_metrics_40())
        + list(threat_metrics_40())
        + list(environmental_metrics_40())
        + list(supplemental_metrics_40())
    )
    if clarg["all"]:
        selected.extend(read_metrics(base_metrics_40()))
        selected.extend(read_metrics(threat_metrics_40()))
        selected.extend(read_metrics(environmental_metrics_40()))
        selected.extend(read_metrics(supplemental_metrics_40()))
    elif clarg["base"]:
        if clarg["vector"] and clarg["vector"].startswith(_V40_PREFIX):
            try:
                vvec = VulnerabilityVector40(clarg["vector"])
                return CommonVulnerabilityScore40(
                    vvec.valid().complete().parsed
                )
            except (InvalidVectorError, ValueError) as e:
                _exit_with_error(e)
        else:
            selected.extend(read_metrics(base_metrics_40()))
        if clarg["temporal"]:
            selected.extend(read_metrics(threat_metrics_40()))
            if clarg["environmental"]:
                selected.extend(read_metrics(environmental_metrics_40()))
    parsed: dict[str, str] = {}
    for i, d in enumerate(all_defs):
        if i < len(selected):
            parsed[d.abbrev] = selected[i]
    return CommonVulnerabilityScore40(parsed)


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSSResult:
    if clarg["cvss_version"] == "4.0":
        return _interactive_v40(clarg)
    # v2.10 interactive path
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
    cvs: CVSS = cvs_factory(CommonVulnerabilityScore, selected)
    return cvs


def process_cmd_line(clarg: CvssArgs) -> CVSSResult:
    """Dispatch to the appropriate command-line handler."""
    if clarg["interactive"]:
        return process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        return process_cmd_line_base(cast(str, clarg["vector"]))
    elif clarg["vulnerability"]:
        return process_cmd_line_vulnerability(clarg["vulnerability"])
    raise RuntimeError("unreachable")
