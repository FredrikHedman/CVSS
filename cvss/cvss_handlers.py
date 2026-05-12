"""CVSS command handlers and dispatch for all CLI modes."""

import sys
from collections.abc import Callable
from typing import NoReturn, cast

from .cvss_210 import CommonVulnerabilityScore
from .cvss_40 import CommonVulnerabilityScore40
from .cvss_base import CVSS
from .cvss_input import read_metrics
from .cvss_types import CVSSResult, CvssArgs
from .vulnerability import (
    InvalidBaseVectorError,
    MetricDefinition,
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
_MetricFn = Callable[[], list[MetricDefinition]]


def _exit_with_error(e: Exception) -> NoReturn:
    print(e)
    sys.exit(1)


def _cvs_from_vector(
    vector: str, require_complete: bool = True
) -> CVSSResult:
    if vector.startswith(_V40_PREFIX):
        try:
            return CommonVulnerabilityScore40(
                VulnerabilityVector40(vector).parsed
            )
        except (InvalidVectorError, ValueError) as e:
            _exit_with_error(e)
    else:
        try:
            vvec = VulnerabilityVector(vector)
            mvs = (
                vvec.complete().metric_values()
                if require_complete
                else vvec.valid().metric_values()
            )
            cvs: CVSS = cvs_factory(CommonVulnerabilityScore, mvs)
        except (InvalidBaseVectorError, ValueError) as e:
            _exit_with_error(e)
        return cvs


def process_cmd_line_base(vector: str) -> CVSSResult:
    return _cvs_from_vector(vector, require_complete=True)


def process_cmd_line_vulnerability(vulnerability: str) -> CVSSResult:
    return _cvs_from_vector(vulnerability, require_complete=False)


def _accumulate_groups(
    clarg: CvssArgs,
    all_fns: list[_MetricFn],
    base_fn: _MetricFn,
    temporal_fn: _MetricFn,
    env_fn: _MetricFn,
) -> list[str]:
    """Read metrics interactively (no pre-existing vector)."""
    selected: list[str] = []
    if clarg["all"]:
        for fn in all_fns:
            selected.extend(read_metrics(fn()))
    elif clarg["base"]:
        selected.extend(read_metrics(base_fn()))
        if clarg["temporal"]:
            selected.extend(read_metrics(temporal_fn()))
            if clarg["environmental"]:
                selected.extend(read_metrics(env_fn()))
    return selected


def _interactive_v40(clarg: CvssArgs) -> CVSSResult:
    vec = clarg["vector"]
    if clarg["base"] and vec and vec.startswith(_V40_PREFIX):
        try:
            return CommonVulnerabilityScore40(
                VulnerabilityVector40(vec).parsed
            )
        except (InvalidVectorError, ValueError) as e:
            _exit_with_error(e)
    all_defs = (
        list(base_metrics_40()) + list(threat_metrics_40())
        + list(environmental_metrics_40()) + list(supplemental_metrics_40())
    )
    selected = _accumulate_groups(
        clarg,
        all_fns=[
            base_metrics_40, threat_metrics_40,
            environmental_metrics_40, supplemental_metrics_40,
        ],
        base_fn=base_metrics_40,
        temporal_fn=threat_metrics_40,
        env_fn=environmental_metrics_40,
    )
    parsed: dict[str, str] = {
        d.abbrev: selected[i]
        for i, d in enumerate(all_defs)
        if i < len(selected)
    }
    return CommonVulnerabilityScore40(parsed)


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSSResult:
    if clarg["cvss_version"] == "4.0":
        return _interactive_v40(clarg)
    # v2.10 interactive path
    if clarg["base"] and clarg["vector"]:
        try:
            vvec = VulnerabilityVector(clarg["vector"])
            selected = list(vvec.complete().metric_values())
        except (InvalidBaseVectorError, ValueError) as e:
            _exit_with_error(e)
        if clarg["temporal"]:
            selected.extend(read_metrics(temporal_metrics()))
            if clarg["environmental"]:
                selected.extend(read_metrics(environmental_metrics()))
    else:
        selected = _accumulate_groups(
            clarg,
            all_fns=[base_metrics, temporal_metrics, environmental_metrics],
            base_fn=base_metrics,
            temporal_fn=temporal_metrics,
            env_fn=environmental_metrics,
        )
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
